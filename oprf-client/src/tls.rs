//! TLS client configuration with optional certificate pinning.
//!
//! With pins, a server is accepted only if its end-entity certificate is byte-for-byte one of the
//! pinned certificates. The hostname and chain are not checked and there is no CA fallback, but the
//! handshake signature is always verified, so the server must hold the pinned certificate's key.
//! Without pins the usual webpki-roots verification applies.
//!
//! Signature algorithms come from the aws-lc-rs provider, which the config is built with
//! explicitly, so no process-default provider is needed.

use std::sync::Arc;

use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, aws_lc_rs},
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject};
use tokio_tungstenite::Connector;

/// Errors building a pinned TLS configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// The pinned PEM could not be parsed.
    #[error("invalid pinned certificate PEM: {0}")]
    Pem(#[from] rustls_pki_types::pem::Error),
    /// The pinned PEM contains no certificate.
    #[error("pinned certificate PEM contains no certificate")]
    NoCertificate,
    /// The TLS configuration could not be built.
    #[error(transparent)]
    Rustls(#[from] RustlsError),
}

#[derive(Debug)]
struct PinnedVerifier {
    pins: Vec<CertificateDer<'static>>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if self
            .pins
            .iter()
            .any(|pin| pin.as_ref() == end_entity.as_ref())
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::General(
                "server certificate does not match any pinned certificate".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Builds a client TLS config. `pinned_pem` is a PEM bundle of pinned certificates; `None` or an
/// empty string selects plain webpki-roots verification.
pub fn pinned_client_config(pinned_pem: Option<&str>) -> Result<Arc<ClientConfig>, TlsError> {
    pinned_client_config_with_roots(pinned_pem, &[])
}

fn pinned_client_config_with_roots(
    pinned_pem: Option<&str>,
    extra_roots: &[CertificateDer<'static>],
) -> Result<Arc<ClientConfig>, TlsError> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()?;
    let config = if let Some(pem) = pinned_pem.filter(|pem| !pem.trim().is_empty()) {
        let pins = CertificateDer::pem_slice_iter(pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        if pins.is_empty() {
            return Err(TlsError::NoCertificate);
        }
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
                pins,
                algs: provider.signature_verification_algorithms,
            }))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for root in extra_roots {
            roots.add(root.clone())?;
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    Ok(Arc::new(config))
}

/// WebSocket connector using `cfg`.
#[must_use]
pub fn connector(cfg: &Arc<ClientConfig>) -> Connector {
    Connector::Rustls(Arc::clone(cfg))
}

/// HTTP client using `cfg`.
pub fn http_client(cfg: &Arc<ClientConfig>) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .tls_backend_preconfigured(ClientConfig::clone(cfg))
        .build()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::let_underscore_must_use,
    clippy::missing_assert_message,
    clippy::assertions_on_result_states,
    reason = "test code"
)]
mod tests {
    use std::{future::Future, time::Duration};

    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair,
        generate_simple_self_signed,
    };
    use rustls::{ServerConfig, sign::CertifiedKey};
    use rustls_pki_types::PrivateKeyDer;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;

    async fn deadline<T>(f: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), f)
            .await
            .expect("test exceeded 10 s")
    }

    #[derive(Debug)]
    struct Fixed(Arc<CertifiedKey>);

    impl rustls::server::ResolvesServerCert for Fixed {
        fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(Arc::clone(&self.0))
        }
    }

    /// Server key material that may be inconsistent (cert and key from different pairs).
    struct Server {
        chain: Vec<CertificateDer<'static>>,
        key: Vec<u8>,
    }

    impl Server {
        fn self_signed(names: &[&str]) -> (Self, String) {
            let ck = generate_simple_self_signed(
                names.iter().map(ToString::to_string).collect::<Vec<_>>(),
            )
            .unwrap();
            let pem = ck.cert.pem();
            let server = Self {
                chain: vec![ck.cert.der().clone()],
                key: ck.signing_key.serialize_der(),
            };
            (server, pem)
        }

        fn acceptor(&self) -> TlsAcceptor {
            let provider = Arc::new(aws_lc_rs::default_provider());
            let key = provider
                .key_provider
                .load_private_key(PrivateKeyDer::Pkcs8(self.key.clone().into()))
                .unwrap();
            // CertifiedKey::new skips the cert/key consistency check so a mismatched pair can be served
            let certified = Arc::new(CertifiedKey::new(self.chain.clone(), key));
            let config = ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(Fixed(certified)));
            TlsAcceptor::from(Arc::new(config))
        }
    }

    /// Serves one TLS connection, answering any request with a tiny HTTP/1.1 response.
    async fn spawn_server(server: &Server) -> u16 {
        let acceptor = server.acceptor();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = [0u8; 1024];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        port
    }

    async fn handshake(
        cfg: &Arc<ClientConfig>,
        port: u16,
        host: &'static str,
    ) -> std::io::Result<()> {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
        let name = ServerName::try_from(host).unwrap();
        let mut tls = TlsConnector::from(Arc::clone(cfg))
            .connect(name, tcp)
            .await?;
        // TLS 1.3 reports a late alert on first read, not on connect
        tls.write_all(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n").await?;
        let mut buf = [0u8; 16];
        let n = tls.read(&mut buf).await?;
        assert!(n > 0);
        Ok(())
    }

    #[tokio::test]
    async fn pinned_cert_is_accepted_without_hostname() {
        deadline(async {
            let (server, pem) = Server::self_signed(&["whatever"]);
            let port = spawn_server(&server).await;
            let cfg = pinned_client_config(Some(&pem)).unwrap();
            handshake(&cfg, port, "localhost").await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn unpinned_self_signed_is_rejected() {
        deadline(async {
            let (server, _) = Server::self_signed(&["localhost"]);
            let (_, other_pem) = Server::self_signed(&["localhost"]);
            let port = spawn_server(&server).await;
            let cfg = pinned_client_config(Some(&other_pem)).unwrap();
            let err = handshake(&cfg, port, "localhost").await.unwrap_err();
            assert!(err.to_string().contains("pinned"), "{err}");
        })
        .await;
    }

    #[tokio::test]
    async fn pinned_cert_with_wrong_key_is_rejected() {
        deadline(async {
            let (pinned, pem) = Server::self_signed(&["localhost"]);
            let (other, _) = Server::self_signed(&["localhost"]);
            let forged = Server {
                chain: pinned.chain.clone(),
                key: other.key,
            };
            let port = spawn_server(&forged).await;
            let cfg = pinned_client_config(Some(&pem)).unwrap();
            let err = handshake(&cfg, port, "localhost").await.unwrap_err();
            assert!(!err.to_string().contains("pinned certificate"), "{err}");

            // Positive control: the genuine key passes.
            let port = spawn_server(&pinned).await;
            handshake(&cfg, port, "localhost").await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn ca_valid_cert_does_not_bypass_pin() {
        deadline(async {
            let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
            let leaf_key = KeyPair::generate().unwrap();
            let leaf = CertificateParams::new(vec!["localhost".to_string()])
                .unwrap()
                .signed_by(&leaf_key, &ca)
                .unwrap();
            let server = Server {
                chain: vec![leaf.der().clone()],
                key: leaf_key.serialize_der(),
            };
            let port = spawn_server(&server).await;
            let roots = [ca.der().clone()];

            // Positive control: with the test CA trusted and no pins the server is accepted.
            let cfg = pinned_client_config_with_roots(None, &roots).unwrap();
            handshake(&cfg, port, "localhost").await.unwrap();

            let (_, other_pem) = Server::self_signed(&["localhost"]);
            let cfg = pinned_client_config_with_roots(Some(&other_pem), &roots).unwrap();
            let err = handshake(&cfg, port, "localhost").await.unwrap_err();
            assert!(err.to_string().contains("pinned"), "{err}");
        })
        .await;
    }

    #[tokio::test]
    async fn no_pins_means_webpki() {
        deadline(async {
            let (server, _) = Server::self_signed(&["localhost"]);
            let port = spawn_server(&server).await;
            for pem in [None, Some("  \n")] {
                let cfg = pinned_client_config(pem).unwrap();
                let err = handshake(&cfg, port, "localhost").await.unwrap_err();
                assert!(
                    err.to_string().to_lowercase().contains("unknownissuer"),
                    "{err}"
                );
            }
        })
        .await;
    }

    #[test]
    fn pem_without_certificate_is_an_error() {
        let key_only = generate_simple_self_signed(vec!["a".to_string()])
            .unwrap()
            .signing_key
            .serialize_pem();
        assert!(matches!(
            pinned_client_config(Some(&key_only)),
            Err(TlsError::NoCertificate)
        ));
    }

    #[tokio::test]
    async fn http_client_honours_pins() {
        deadline(async {
            let (server, pem) = Server::self_signed(&["whatever"]);
            let (_, wrong_pem) = Server::self_signed(&["whatever"]);
            let port = spawn_server(&server).await;
            let url = format!("https://127.0.0.1:{port}/");

            let client = http_client(&pinned_client_config(Some(&pem)).unwrap()).unwrap();
            assert_eq!(
                client.get(&url).send().await.unwrap().text().await.unwrap(),
                "ok"
            );

            let client = http_client(&pinned_client_config(Some(&wrong_pem)).unwrap()).unwrap();
            assert!(client.get(&url).send().await.is_err());
        })
        .await;
    }
}
