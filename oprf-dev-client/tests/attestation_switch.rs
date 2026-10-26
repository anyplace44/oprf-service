//! The dev-client's attestation switch, its `attest` command, and errors that name attestation.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_assert_message,
    clippy::let_underscore_must_use,
    reason = "test code"
)]

use std::{
    collections::HashMap,
    future::Future,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use alloy::{primitives::Address, providers::DynProvider};
use ark_ff::UniformRand as _;
use clap::Parser as _;
use oprf_client::{Attestation, Connector};
use oprf_core::oprf::BlindingFactor;
use oprf_types::{OprfKeyId, ShareEpoch, api::OprfRequest, crypto::OprfPublicKey};
use rand::{CryptoRng, Rng, SeedableRng as _};
use taceo_oprf_dev_client::{
    Command, DevClient, DevClientConfig, StressTestItem, attest_command, attestation_mode,
    load_tls_config, send_init_requests, setup_connector,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};
use uuid::Uuid;

const DEADLINE: Duration = Duration::from_secs(10);

async fn deadline<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, f)
        .await
        .expect("test exceeded its deadline")
}

/// A plain-HTTP node whose `/attestation` answers 503 (as a node outside an enclave does);
/// every other request (the WebSocket route) is counted and answered 404.
struct Node {
    port: u16,
    attestation_hits: Arc<AtomicUsize>,
    other_hits: Arc<AtomicUsize>,
}

impl Node {
    async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let attestation_hits = Arc::new(AtomicUsize::new(0));
        let other_hits = Arc::new(AtomicUsize::new(0));
        tokio::spawn({
            let attestation_hits = Arc::clone(&attestation_hits);
            let other_hits = Arc::clone(&other_hits);
            async move {
                while let Ok((mut tcp, _)) = listener.accept().await {
                    let attestation_hits = Arc::clone(&attestation_hits);
                    let other_hits = Arc::clone(&other_hits);
                    tokio::spawn(async move {
                        let mut head = Vec::new();
                        let mut buf = [0u8; 1024];
                        while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 8192 {
                            match tcp.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => head.extend_from_slice(&buf[..n]),
                            }
                        }
                        let head = String::from_utf8_lossy(&head);
                        let path = head.split_whitespace().nth(1).unwrap_or_default();
                        let reply: &[u8] = if path.starts_with("/attestation") {
                            attestation_hits.fetch_add(1, Ordering::SeqCst);
                            b"HTTP/1.1 503 Service Unavailable\r\ncontent-type: text/plain\r\n\
                              content-length: 50\r\nconnection: close\r\n\r\n\
                              attestation unavailable: not running in an enclave"
                        } else {
                            other_hits.fetch_add(1, Ordering::SeqCst);
                            b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        };
                        let _ = tcp.write_all(reply).await;
                        let _ = tcp.shutdown().await;
                    });
                }
            }
        });
        Self {
            port,
            attestation_hits,
            other_hits,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn attestation_hits(&self) -> usize {
        self.attestation_hits.load(Ordering::SeqCst)
    }

    fn other_hits(&self) -> usize {
        self.other_hits.load(Ordering::SeqCst)
    }
}

/// Writes an expected-values file that lists `url` with a (non-zero) PCR0.
fn policy_file(name: &str, url: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("{name}-{}.pcrs", std::process::id()));
    std::fs::write(&path, format!("{url} {}\n", "11".repeat(48))).unwrap();
    path
}

fn http_client() -> reqwest::Client {
    oprf_client::tls::http_client(&load_tls_config(None).unwrap()).unwrap()
}

fn connector() -> Connector {
    setup_connector(&load_tls_config(None).unwrap())
}

fn parse(args: &[&str]) -> DevClientConfig {
    DevClientConfig::try_parse_from(std::iter::once("dev-client").chain(args.iter().copied()))
        .unwrap()
}

fn init_requests() -> HashMap<Uuid, (OprfRequest<String>, String)> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();
    let blinded = oprf_core::oprf::client::blind_query(
        ark_babyjubjub::Fq::rand(&mut rng),
        BlindingFactor::rand(&mut rng),
    );
    let request_id = Uuid::new_v4();
    let req = OprfRequest {
        request_id,
        blinded_query: blinded.blinded_query(),
        auth: "module".to_owned(),
    };
    HashMap::from([(request_id, (req, "module".to_owned()))])
}

#[test]
fn every_call_without_file_is_a_startup_error() {
    let config = parse(&["--attest-every-call", "test"]);
    let err = attestation_mode(&config, &http_client()).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("--attest-every-call"), "{text}");
    assert!(text.contains("--attestation-pcrs"), "{text}");

    let config = parse(&["test"]);
    assert!(matches!(
        attestation_mode(&config, &http_client()).unwrap(),
        Attestation::OnDemand
    ));
}

#[tokio::test]
async fn init_error_names_attestation() {
    let node = Node::spawn().await;
    let nodes = [node.url()];

    // positive control: without the switch the WebSocket route is hit (and fails: 404)
    let err = deadline(send_init_requests(
        &nodes,
        1,
        connector(),
        false,
        init_requests(),
        &Attestation::OnDemand,
    ))
    .await
    .err()
    .expect("the node speaks no OPRF");
    assert_eq!(node.other_hits(), 1, "{err:#}");
    assert_eq!(node.attestation_hits(), 0);
    assert!(!format!("{err:#}").contains("attestation"), "{err:#}");

    let pcrs = policy_file("init-error", &node.url());
    let config = parse(&[
        "--attest-every-call",
        "--attestation-pcrs",
        pcrs.to_str().unwrap(),
        "stress-test-oprf",
    ]);
    let attestation = attestation_mode(&config, &http_client()).unwrap();
    std::fs::remove_file(&pcrs).unwrap();
    assert!(matches!(attestation, Attestation::EveryCall { .. }));

    let err = deadline(send_init_requests(
        &nodes,
        1,
        connector(),
        false,
        init_requests(),
        &attestation,
    ))
    .await
    .err()
    .expect("attestation answers 503");
    let text = format!("{err:#}");
    let ws_url = oprf_client::to_oprf_uri(&node.url(), "module")
        .unwrap()
        .to_string();
    assert!(text.contains("attestation of"), "{text}");
    assert!(text.contains(&ws_url), "{text}");
    assert!(text.contains("503"), "{text}");
    assert_eq!(node.attestation_hits(), 1);
    assert_eq!(
        node.other_hits(),
        1,
        "the WebSocket route was hit exactly once, not again after the failed attestation"
    );
}

/// A dev client whose methods are never reached by the `attest` command.
struct Unused;

#[oprf_types::async_trait::async_trait]
impl DevClient for Unused {
    type Setup = ();
    type RequestAuth = String;

    async fn setup_oprf_test(
        &self,
        _: &DevClientConfig,
        _: DynProvider,
        _: &reqwest::Client,
    ) -> eyre::Result<()> {
        unreachable!("not used by the attest command")
    }

    async fn run_oprf(
        &self,
        _: &DevClientConfig,
        _: (),
        _: Connector,
        _: &Attestation,
    ) -> eyre::Result<ShareEpoch> {
        unreachable!("not used by the attest command")
    }

    async fn run_delegate_oprf(
        &self,
        _: &DevClientConfig,
        _: (),
        _: Option<String>,
        _: &reqwest::Client,
        _: &Attestation,
    ) -> eyre::Result<ShareEpoch> {
        unreachable!("not used by the attest command")
    }

    async fn prepare_stress_test_item<R: Rng + CryptoRng + Send>(
        &self,
        _: &(),
        _: &mut R,
    ) -> eyre::Result<StressTestItem<String>> {
        unreachable!("not used by the attest command")
    }

    fn get_oprf_key(&self, (): &()) -> OprfPublicKey {
        unreachable!("not used by the attest command")
    }

    fn get_oprf_key_id(&self, (): &()) -> OprfKeyId {
        unreachable!("not used by the attest command")
    }
}

#[tokio::test]
async fn attest_runs_with_only_policy_and_tls_settings() {
    let node = Node::spawn().await;
    let pcrs = policy_file("attest-cmd", &node.url());
    // no registry, and nodes nobody listens on: the startup health check would fail on them
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_url = format!("http://127.0.0.1:{}", dead.local_addr().unwrap().port());
    drop(dead);
    let config = parse(&[
        "--nodes",
        &dead_url,
        "--attestation-pcrs",
        pcrs.to_str().unwrap(),
        "attest",
    ]);
    assert!(matches!(config.command, Command::Attest));

    let err = deadline(attest_command(&config, &http_client()))
        .await
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("attestation of"), "{text}");
    assert!(text.contains(&node.url()), "{text}");
    assert!(!text.contains("registry"), "{text}");
    assert!(!text.contains("health"), "{text}");
    assert_eq!(node.attestation_hits(), 1);

    // through `run`: dispatched before the health check, the wallet and the RPC provider
    let start = Instant::now();
    let err = deadline(taceo_oprf_dev_client::run(config, Unused))
        .await
        .unwrap_err();
    let text = format!("{err:#}");
    std::fs::remove_file(&pcrs).unwrap();
    assert!(text.contains("attestation of"), "{text}");
    assert!(!text.contains("health"), "{text}");
    assert_eq!(node.attestation_hits(), 2);
    assert!(start.elapsed() < Duration::from_secs(4), "{text}");
}

#[test]
fn registry_required_for_oprf_commands() {
    let err = parse(&["test"]).registry().unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("--oprf-key-registry-contract"), "{text}");
    assert!(
        text.contains("OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT"),
        "{text}"
    );

    let address = Address::repeat_byte(0x42);
    let config = parse(&["--oprf-key-registry-contract", &address.to_string(), "test"]);
    assert_eq!(config.registry().unwrap(), address);
}
