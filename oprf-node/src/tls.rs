//! Optional TLS termination for the node's HTTP listener.
//!
//! With a [`NodeTlsConfig`] the listener speaks TLS (aws-lc-rs provider, installed as the process
//! default in `main`); without one it serves plain HTTP exactly as before.

use std::future::Future;

use axum::Router;
use axum_server::{Handle, tls_rustls::RustlsConfig};
use eyre::Context;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tokio::net::TcpListener;

/// Certificate chain and private key the node serves TLS with.
#[derive(Clone, Debug, Deserialize)]
pub struct NodeTlsConfig {
    /// PEM certificate chain (public).
    pub cert_pem: String,
    /// PEM private key (secret).
    pub key_pem: SecretString,
}

impl NodeTlsConfig {
    /// Builds the rustls server config. Fails if the PEMs are invalid or the key does not match
    /// the certificate.
    pub async fn rustls_config(&self) -> eyre::Result<RustlsConfig> {
        RustlsConfig::from_pem(
            self.cert_pem.clone().into_bytes(),
            self.key_pem.expose_secret().as_bytes().to_vec(),
        )
        .await
        .context("while loading TLS certificate and key")
    }
}

/// Serves `router` on `listener` until `shutdown` resolves, over TLS if `tls` is set.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    tls: Option<RustlsConfig>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> eyre::Result<()> {
    if let Some(tls) = tls {
        let handle = Handle::new();
        let graceful = handle.clone();
        tokio::spawn(async move {
            shutdown.await;
            graceful.graceful_shutdown(None);
        });
        axum_server::from_tcp_rustls(listener.into_std()?, tls)?
            .handle(handle)
            .serve(router.into_make_service())
            .await?;
    } else {
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::let_underscore_must_use,
    clippy::assertions_on_result_states,
    reason = "test code"
)]
mod tests {
    use std::{future::Future, time::Duration};

    use axum::routing::get;
    use oprf_client::tls::{http_client, pinned_client_config};
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    use super::*;

    async fn deadline<T>(f: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), f)
            .await
            .expect("test exceeded 10 s")
    }

    fn self_signed() -> CertifiedKey<rcgen::KeyPair> {
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap()
    }

    fn tls_config(ck: &CertifiedKey<rcgen::KeyPair>) -> NodeTlsConfig {
        NodeTlsConfig {
            cert_pem: ck.cert.pem(),
            key_pem: SecretString::from(ck.signing_key.serialize_pem()),
        }
    }

    fn install_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    async fn start(tls: Option<RustlsConfig>) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new().route("/health", get(|| async { "ok" }));
        tokio::spawn(serve(listener, router, tls, std::future::pending()));
        addr
    }

    #[tokio::test]
    async fn serves_https_with_configured_cert() {
        install_provider();
        let ck = self_signed();
        let tls = tls_config(&ck).rustls_config().await.unwrap();
        let addr = start(Some(tls)).await;
        let client = http_client(&pinned_client_config(Some(&ck.cert.pem())).unwrap()).unwrap();
        let res = deadline(client.get(format!("https://{addr}/health")).send())
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
    }

    #[tokio::test]
    async fn plain_http_without_tls_config() {
        let addr = start(None).await;
        let res = deadline(reqwest::get(format!("http://{addr}/health")))
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
    }

    #[tokio::test]
    async fn rejects_mismatched_key_and_cert() {
        install_provider();
        let mut cfg = tls_config(&self_signed());
        cfg.key_pem = tls_config(&self_signed()).key_pem;
        assert!(deadline(cfg.rustls_config()).await.is_err());
    }

    #[test]
    fn tls_config_loads_multiline_pem_from_env() {
        let ck = self_signed();
        let env = std::collections::HashMap::from([
            ("TACEO_OPRF_NODE__TLS__CERT_PEM".to_owned(), ck.cert.pem()),
            (
                "TACEO_OPRF_NODE__TLS__KEY_PEM".to_owned(),
                ck.signing_key.serialize_pem(),
            ),
        ]);
        let cfg = config::Config::builder()
            .add_source(
                config::Environment::with_prefix("TACEO_OPRF_NODE")
                    .separator("__")
                    .try_parsing(true)
                    .source(Some(env)),
            )
            .build()
            .unwrap();
        let tls: NodeTlsConfig = cfg.get("tls").unwrap();
        assert_eq!(tls.cert_pem, ck.cert.pem());
        assert_eq!(tls.key_pem.expose_secret(), ck.signing_key.serialize_pem());
    }
}
