//! Each transport of the dev client (HTTP health check, WebSocket session, `/delegate` request)
//! against a local TLS server with a self-signed certificate: the right pin connects, a wrong pin
//! fails on that transport with a certificate error.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_assert_message,
    clippy::let_underscore_must_use,
    reason = "test code"
)]

use std::{
    error::Error,
    future::Future,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use alloy::primitives::U160;
use ark_ff::UniformRand as _;
use oprf_core::oprf::BlindingFactor;
use oprf_types::{OprfKeyId, ShareEpoch, api::OprfRequest};
use rand::SeedableRng as _;
use rcgen::generate_simple_self_signed;
use rustls::{ServerConfig, crypto::aws_lc_rs};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use taceo_oprf_dev_client::{health_checks, load_tls_config, setup_connector};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use uuid::Uuid;

const DEADLINE: Duration = Duration::from_secs(10);

async fn deadline<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, f)
        .await
        .expect("test exceeded its deadline")
}

/// A self-signed certificate for `localhost` (the tests connect to 127.0.0.1: no hostname check).
fn self_signed() -> (CertificateDer<'static>, Vec<u8>, String) {
    let ck = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    (
        ck.cert.der().clone(),
        ck.signing_key.serialize_der(),
        ck.cert.pem(),
    )
}

/// Local TLS server. `served` counts connections that completed the TLS handshake.
struct TlsServer {
    port: u16,
    served: Arc<AtomicUsize>,
    pin_pem: String,
}

impl TlsServer {
    async fn spawn<H, Fut>(handler: H) -> Self
    where
        H: Fn(TlsStream<TcpStream>) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (cert, key, pin_pem) = self_signed();
        let provider = Arc::new(aws_lc_rs::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], PrivateKeyDer::Pkcs8(key.into()))
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = Arc::new(AtomicUsize::new(0));
        tokio::spawn({
            let served = Arc::clone(&served);
            async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    let handler = handler.clone();
                    let served = Arc::clone(&served);
                    tokio::spawn(async move {
                        if let Ok(tls) = acceptor.accept(tcp).await {
                            served.fetch_add(1, Ordering::SeqCst);
                            handler(tls).await;
                        }
                    });
                }
            }
        });
        Self {
            port,
            served,
            pin_pem,
        }
    }

    fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    fn served(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }
}

/// Writes `pem` to a file and loads the TLS config from it, as the CLI flag does.
fn tls_config_from_file(name: &str, pem: &str) -> Arc<rustls::ClientConfig> {
    let path: PathBuf = std::env::temp_dir().join(format!("{name}-{}.pem", std::process::id()));
    std::fs::write(&path, pem).unwrap();
    let config = load_tls_config(Some(&path)).unwrap();
    std::fs::remove_file(&path).unwrap();
    config
}

fn error_chain(err: &dyn Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(err) = source {
        out.push_str(": ");
        out.push_str(&err.to_string());
        source = err.source();
    }
    out
}

async fn http_ok(mut tls: TlsStream<TcpStream>) {
    let mut buf = [0u8; 2048];
    let _ = tls.read(&mut buf).await;
    let _ = tls
        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 7\r\nconnection: close\r\n\r\nhealthy")
        .await;
    let _ = tls.shutdown().await;
}

#[tokio::test]
async fn health_check_uses_pinned_client() {
    let server = TlsServer::spawn(http_ok).await;
    let (_, _, wrong_pem) = self_signed();

    let right =
        oprf_client::tls::http_client(&tls_config_from_file("hc-right", &server.pin_pem)).unwrap();
    deadline(health_checks::services_health_check(
        &right,
        &[server.url()],
        Duration::from_secs(5),
    ))
    .await
    .unwrap();
    assert_eq!(server.served(), 1);

    // the health check retries until its deadline; a wrong pin never reaches the server
    let before = server.served();
    let wrong =
        oprf_client::tls::http_client(&tls_config_from_file("hc-wrong", &wrong_pem)).unwrap();
    let err = deadline(health_checks::services_health_check(
        &wrong,
        &[server.url()],
        Duration::from_secs(2),
    ))
    .await
    .unwrap_err();
    assert!(err.to_string().contains("not healthy"), "{err}");
    assert!(
        err.to_string()
            .contains("does not match any pinned certificate"),
        "{err}"
    );
    assert_eq!(server.served(), before, "wrong pin completed a handshake");
}

fn oprf_request() -> OprfRequest<String> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();
    let blinded = oprf_core::oprf::client::blind_query(
        ark_babyjubjub::Fq::rand(&mut rng),
        BlindingFactor::rand(&mut rng),
    );
    OprfRequest {
        request_id: Uuid::new_v4(),
        blinded_query: blinded.blinded_query(),
        auth: "module".to_owned(),
    }
}

#[tokio::test]
async fn websocket_session_uses_pinned_connector() {
    let upgrades = Arc::new(AtomicUsize::new(0));
    let server = TlsServer::spawn({
        let upgrades = Arc::clone(&upgrades);
        move |tls| {
            let upgrades = Arc::clone(&upgrades);
            async move {
                if tokio_tungstenite::accept_async(tls).await.is_ok() {
                    upgrades.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    })
    .await;
    let (_, _, wrong_pem) = self_signed();
    let uris = oprf_client::to_oprf_uri_many([server.url()], "module").unwrap();

    // right pin: TLS and the WebSocket upgrade succeed (the session then fails at protocol level)
    let connector = setup_connector(&tls_config_from_file("ws-right", &server.pin_pem));
    let errs = deadline(oprf_client::init_sessions(
        Uuid::new_v4(),
        &uris,
        1,
        oprf_request(),
        connector,
    ))
    .await
    .err()
    .expect("server speaks no OPRF");
    assert_eq!(upgrades.load(Ordering::SeqCst), 1, "{errs:?}");
    assert!(
        !errs
            .iter()
            .any(|e| error_chain(e).to_lowercase().contains("certificate")),
        "{errs:?}"
    );

    // wrong pin: the connect fails in TLS, before any upgrade
    let connector = setup_connector(&tls_config_from_file("ws-wrong", &wrong_pem));
    let errs = deadline(oprf_client::init_sessions(
        Uuid::new_v4(),
        &uris,
        1,
        oprf_request(),
        connector,
    ))
    .await
    .err()
    .expect("wrong pin must fail");
    assert_eq!(errs.len(), 1);
    let chain = error_chain(&errs[0]);
    assert!(
        matches!(errs[0], oprf_client::NodeError::WsError(_)),
        "{chain}"
    );
    assert!(
        chain.contains("does not match any pinned certificate"),
        "{chain}"
    );
    assert_eq!(upgrades.load(Ordering::SeqCst), 1, "wrong pin upgraded");
}

#[tokio::test]
async fn delegate_request_uses_pinned_client() {
    let server = TlsServer::spawn(http_ok).await;
    let (_, _, wrong_pem) = self_signed();
    let url = oprf_client::to_delegate_oprf_url(&server.url(), "module").unwrap();

    let delegate = |client| {
        let url = url.clone();
        async move {
            let mut rng = rand_chacha::ChaCha12Rng::from_entropy();
            oprf_client::delegate_distributed_oprf(
                &url,
                ark_babyjubjub::Fq::rand(&mut rng),
                BlindingFactor::rand(&mut rng),
                ark_babyjubjub::Fq::rand(&mut rng),
                "module".to_owned(),
                &client,
            )
            .await
        }
    };

    // right pin: the request reaches the server (whose "healthy" body is no valid delegate response)
    let right =
        oprf_client::tls::http_client(&tls_config_from_file("dg-right", &server.pin_pem)).unwrap();
    let err = deadline(delegate(right)).await.unwrap_err();
    assert_eq!(server.served(), 1);
    assert!(
        !error_chain(&err).to_lowercase().contains("certificate"),
        "{err}"
    );

    let wrong =
        oprf_client::tls::http_client(&tls_config_from_file("dg-wrong", &wrong_pem)).unwrap();
    let err = deadline(delegate(wrong)).await.unwrap_err();
    let chain = error_chain(&err);
    assert!(
        chain.contains("does not match any pinned certificate"),
        "{chain}"
    );
    assert_eq!(server.served(), 1, "wrong pin completed a handshake");
}

#[tokio::test]
async fn public_key_fetch_uses_pinned_client() {
    let server = TlsServer::spawn(http_ok).await;
    let (_, _, wrong_pem) = self_signed();
    let key_id = OprfKeyId::new(U160::from(1u32));

    // right pin: the request reaches the server (whose body is no valid public key), so the
    // fetch keeps retrying until its deadline without a certificate error
    let right =
        oprf_client::tls::http_client(&tls_config_from_file("pk-right", &server.pin_pem)).unwrap();
    let err = deadline(health_checks::oprf_public_key_from_services(
        &right,
        key_id,
        ShareEpoch::default(),
        &[server.url()],
        Duration::from_secs(2),
    ))
    .await
    .unwrap_err();
    assert!(server.served() >= 1);
    assert!(!err.to_string().contains("certificate"), "{err}");

    let before = server.served();
    let wrong =
        oprf_client::tls::http_client(&tls_config_from_file("pk-wrong", &wrong_pem)).unwrap();
    let err = deadline(health_checks::oprf_public_key_from_services(
        &wrong,
        key_id,
        ShareEpoch::default(),
        &[server.url()],
        Duration::from_secs(2),
    ))
    .await
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("does not match any pinned certificate"),
        "{err}"
    );
    assert_eq!(server.served(), before, "wrong pin completed a handshake");
}
