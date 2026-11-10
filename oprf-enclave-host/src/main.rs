//! Parent-side counterpart of `oprf-enclave-launcher`, serving every enclave of a parent.
//!
//! Reads a JSON config naming each enclave (name, CID, KMS key and ports, ciphertext file,
//! forward table). Each `outbound` line becomes a pontifex vsock-to-TCP proxy that only admits
//! its enclave's CID; each `inbound` line becomes a TCP listener whose connections are relayed to
//! that enclave over vsock.
//!
//! It also serves the bootstrap (KMS ciphertext, key ARN and instance role credentials) and
//! collects the logs of all enclaves on the shared ports 7001 and 7002, telling them apart by
//! the peer's CID; a peer that is not a configured enclave gets nothing.

mod bootstrap;
mod config;
mod imds;
mod logsink;
mod tls;

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use eyre::Context;
use launcher::bootstrap::{BOOTSTRAP_PORT, LOG_PORT};
use launcher::table::Table;
use pontifex::proxy;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

use crate::config::HostConfig;

/// Bounds dialing the enclave for an inbound connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
/// Bounds the TLS handshake of an inbound connection.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const METRICS_OUTBOUND: &str = "taceo.oprf.enclave_host.outbound";
const METRICS_INBOUND: &str = "taceo.oprf.enclave_host.inbound";

#[derive(Parser)]
struct Args {
    /// JSON file naming the enclaves this parent serves; see `config.rs`.
    #[arg(
        long,
        env = "OPRF_ENCLAVE_HOST_CONFIG",
        default_value = "/etc/oprf-enclave-host/config.json"
    )]
    config: PathBuf,
}

fn bind_vsock(port: u32) -> eyre::Result<VsockListener> {
    VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))
        .with_context(|| format!("binding vsock port {port}"))
}

/// Answers each connection on the bootstrap port, one at a time.
async fn serve_bootstrap(listener: VsockListener, config: Arc<HostConfig>) -> eyre::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await.context("bootstrap accept")?;
        bootstrap::handle(peer.cid(), stream, &config).await;
    }
}

/// Prints the enclaves' log lines to stdout.
async fn serve_logs(listener: VsockListener, config: Arc<HostConfig>) -> eyre::Result<()> {
    let mut current = HashMap::new();
    loop {
        let (stream, peer) = listener.accept().await.context("log accept")?;
        let Some(enclave) = config.by_cid(peer.cid()) else {
            tracing::warn!(
                peer_cid = peer.cid(),
                "log connection from foreign CID refused"
            );
            continue;
        };
        replace_log_copy(
            &mut current,
            enclave.cid,
            &enclave.name,
            stream,
            tokio::io::stdout(),
        );
    }
}

/// Copies `stream` to `out` in place of the connection of the same enclave in `current`. Only
/// one launcher per enclave is alive at a time, so an older connection is a stale one from before
/// a restart and would otherwise hold its task until it times out. Other enclaves' copies are
/// left alone.
fn replace_log_copy<R, W>(
    current: &mut HashMap<u32, JoinHandle<()>>,
    cid: u32,
    name: &str,
    stream: R,
    out: W,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    if let Some(previous) = current.remove(&cid) {
        if !previous.is_finished() {
            tracing::info!(
                enclave = name,
                "new log connection replaces the previous one"
            );
        }
        previous.abort();
    }
    let name = name.to_owned();
    current.insert(
        cid,
        tokio::spawn(async move {
            if let Err(err) = logsink::copy_lines(BufReader::new(stream), out, &name).await {
                tracing::debug!(enclave = name, %err, "log connection ended");
            }
        }),
    );
}

/// One pontifex proxy per outbound forward, admitting only `enclave_cid`.
fn proxy_configs(table: &Table, enclave_cid: u32) -> Vec<proxy::Config> {
    table
        .outbound
        .iter()
        .map(|o| {
            let mut config = proxy::Config::new(o.vsock_port, o.host.clone(), o.port);
            config.allowed_cid = Some(enclave_cid);
            config
        })
        .collect()
}

fn record_outbound(vsock_port: u32, event: proxy::Event) {
    let event = match event {
        proxy::Event::RejectedPeer => "rejected_peer",
        proxy::Event::AcceptFailed => "accept_failed",
        proxy::Event::Closed { outcome, .. } => match outcome {
            proxy::Outcome::Completed => "completed",
            proxy::Outcome::ConnectFailed => "connect_failed",
            proxy::Outcome::ConnectTimedOut => "connect_timed_out",
            proxy::Outcome::IdleTimedOut => "idle_timed_out",
            proxy::Outcome::Io => "io",
            _ => "other",
        },
        _ => "other",
    };
    metrics::counter!(METRICS_OUTBOUND, "vsock_port" => vsock_port.to_string(), "event" => event)
        .increment(1);
}

/// Dials the enclave and relays `client` to it; returns the event to count.
async fn relay<C, F, S>(mut client: C, dialing: F) -> &'static str
where
    C: AsyncRead + AsyncWrite + Unpin,
    F: Future<Output = std::io::Result<S>>,
    S: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::time::timeout(CONNECT_TIMEOUT, dialing).await {
        Ok(Ok(mut enclave)) => match tokio::io::copy_bidirectional(&mut client, &mut enclave).await
        {
            Ok(_) => "completed",
            Err(_) => "io",
        },
        Ok(Err(_)) => "connect_failed",
        Err(_) => "connect_timed_out",
    }
}

/// Relays every connection accepted on `listener` to a stream from `dial`. With `tls`, the
/// handshake comes first and the enclave only ever sees the plaintext; a failed handshake is
/// counted and the enclave is not dialed.
async fn serve_inbound<D, F, S>(
    listener: TcpListener,
    dial: D,
    tls: Option<TlsAcceptor>,
) -> Infallible
where
    D: Fn() -> F + Clone + Send + 'static,
    F: Future<Output = std::io::Result<S>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let port = listener
        .local_addr()
        .map_or_else(|_| String::new(), |a| a.port().to_string());
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::warn!(%err, "inbound accept failed");
                metrics::counter!(METRICS_INBOUND, "port" => port.clone(), "event" => "accept_failed")
                    .increment(1);
                continue;
            }
        };
        let dial = dial.clone();
        let tls = tls.clone();
        let port = port.clone();
        tokio::spawn(async move {
            let event = match tls {
                None => relay(tcp, dial()).await,
                Some(acceptor) => {
                    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                        Ok(Ok(stream)) => relay(stream, dial()).await,
                        Ok(Err(_)) | Err(_) => "tls_handshake_failed",
                    }
                }
            };
            if event != "completed" {
                tracing::warn!(%peer, event, "inbound connection failed");
            }
            metrics::counter!(METRICS_INBOUND, "port" => port, "event" => event).increment(1);
        });
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _guard = telemetry_batteries::init()?;
    let args = Args::parse();
    let config = Arc::new(HostConfig::load(&args.config)?);

    let mut tasks = tokio::task::JoinSet::new();
    for enclave in &config.enclaves {
        for proxy_config in proxy_configs(&enclave.table, enclave.cid) {
            let port = proxy_config.port;
            tracing::info!(enclave = %enclave.name, port, host = %proxy_config.destination_host, dest_port = proxy_config.destination_port, "outbound proxy");
            tasks.spawn(async move {
                let Err(err) =
                    proxy::serve(proxy_config, move |event| record_outbound(port, event)).await;
                eyre::Result::<()>::Err(err.into())
            });
        }
        for i in &enclave.table.inbound {
            let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, i.tcp_port))
                .await
                .with_context(|| format!("binding inbound port {}", i.tcp_port))?;
            let addr = VsockAddr::new(enclave.cid, i.vsock_port);
            let tls = match &enclave.inbound_tls {
                Some(t) if t.port == i.tcp_port => Some(
                    tls::acceptor(&t.cert_pem, &t.key_pem)
                        .with_context(|| format!("enclave {}: inbound_tls", enclave.name))?,
                ),
                _ => None,
            };
            tracing::info!(enclave = %enclave.name, port = i.tcp_port, %addr, tls = tls.is_some(), "inbound relay");
            tasks.spawn(async move {
                match serve_inbound(listener, move || VsockStream::connect(addr), tls).await {}
            });
        }
    }
    tasks.spawn(serve_bootstrap(
        bind_vsock(BOOTSTRAP_PORT)?,
        Arc::clone(&config),
    ));
    tasks.spawn(serve_logs(bind_vsock(LOG_PORT)?, config));
    // Every task serves forever; the first one to end failed at startup.
    match tasks.join_next().await {
        Some(result) => result.context("forwarding task panicked")?,
        None => eyre::bail!("no tasks to run"),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[test]
    fn one_proxy_per_outbound_line_restricted_to_the_enclave() {
        let table = Table::parse(
            "outbound db.internal 5432 8001\n\
             outbound rpc.example.com 443 8002\n\
             inbound 4321 4321\n",
        )
        .expect("valid table");
        let configs = proxy_configs(&table, 16);
        let got: Vec<_> = configs
            .iter()
            .map(|c| {
                (
                    c.port,
                    c.destination_host.as_str(),
                    c.destination_port,
                    c.allowed_cid,
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                (8001, "db.internal", 5432, Some(16)),
                (8002, "rpc.example.com", 443, Some(16)),
            ],
            "inbound lines produce no proxy"
        );
    }

    #[tokio::test]
    async fn inbound_connections_are_relayed_both_ways() {
        // Stands in for the enclave's vsock listener.
        let enclave = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind enclave");
        let enclave_addr = enclave.local_addr().expect("enclave addr");
        tokio::spawn(async move {
            let (mut s, _) = enclave.accept().await.expect("accept");
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.expect("read");
            s.write_all(&buf).await.expect("write");
        });

        let front = TcpListener::bind("127.0.0.1:0").await.expect("bind front");
        let front_addr = front.local_addr().expect("front addr");
        tokio::spawn(serve_inbound(
            front,
            move || TcpStream::connect(enclave_addr),
            None,
        ));

        let mut client = TcpStream::connect(front_addr).await.expect("connect");
        client.write_all(b"hello").await.expect("write");
        client.shutdown().await.expect("shutdown");
        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut reply))
            .await
            .expect("relay must propagate EOF")
            .expect("read");
        assert_eq!(reply, b"hello", "bytes go to the enclave and back");
    }

    #[tokio::test]
    async fn log_replacement_is_per_cid() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut current = HashMap::new();
            let conn = |cid, name: &str, current: &mut _| {
                let (tx, rx) = tokio::io::duplex(1024);
                let (out, seen) = tokio::io::duplex(1024);
                replace_log_copy(current, cid, name, rx, out);
                (tx, seen)
            };
            let (mut kg_tx, mut kg_seen) = conn(16, "key-gen", &mut current);
            let (mut old_tx, mut old_seen) = conn(17, "node", &mut current);
            old_tx.write_all(b"one\n").await.expect("write");
            let mut line = [0; 18];
            old_seen.read_exact(&mut line).await.expect("read");
            assert_eq!(&line, b"enclave node: one\n");

            let (mut new_tx, mut new_seen) = conn(17, "node", &mut current);
            // `old_tx` is still open: only the abort closes the old copy's output.
            let mut rest = Vec::new();
            old_seen.read_to_end(&mut rest).await.expect("read");
            assert_eq!(rest, b"", "the stale copy is aborted, not drained");
            new_tx.write_all(b"two\n").await.expect("write");
            let mut line = [0; 18];
            new_seen.read_exact(&mut line).await.expect("read");
            assert_eq!(&line, b"enclave node: two\n");

            // CID 16's copy survived CID 17's replacement.
            kg_tx.write_all(b"kg\n").await.expect("write");
            let mut line = [0; 20];
            kg_seen.read_exact(&mut line).await.expect("read");
            assert_eq!(&line, b"enclave key-gen: kg\n");
            drop(old_tx);
        })
        .await
        .expect("test deadline");
    }

    async fn deadline<T>(f: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), f)
            .await
            .expect("test exceeded 10 s")
    }

    /// An enclave stand-in that echoes one connection and records the bytes it received.
    struct Fixture {
        front: std::net::SocketAddr,
        cert_pem: String,
        dials: Arc<AtomicUsize>,
        received: Arc<Mutex<Vec<u8>>>,
    }

    async fn tls_fixture() -> Fixture {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("cert");
        let cert_pem = ck.cert.pem();
        let acceptor = tls::acceptor(&cert_pem, &ck.signing_key.serialize_pem()).expect("acceptor");
        let enclave = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let enclave_addr = enclave.local_addr().expect("addr");
        let received = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&received);
        tokio::spawn(async move {
            loop {
                let (mut s, _) = enclave.accept().await.expect("accept");
                let mut buf = Vec::new();
                s.read_to_end(&mut buf).await.expect("read");
                seen.lock().expect("lock").extend_from_slice(&buf);
                s.write_all(&buf).await.expect("write");
            }
        });
        let dials = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&dials);
        let front = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let front_addr = front.local_addr().expect("addr");
        tokio::spawn(serve_inbound(
            front,
            move || {
                counter.fetch_add(1, Ordering::SeqCst);
                TcpStream::connect(enclave_addr)
            },
            Some(acceptor),
        ));
        Fixture {
            front: front_addr,
            cert_pem,
            dials,
            received,
        }
    }

    async fn tls_echo(f: &Fixture, payload: &[u8]) -> Vec<u8> {
        let config = oprf_client::tls::pinned_client_config(Some(&f.cert_pem)).expect("config");
        let tcp = TcpStream::connect(f.front).await.expect("connect");
        let name = rustls_pki_types::ServerName::try_from("localhost").expect("name");
        let mut tls = tokio_rustls::TlsConnector::from(config)
            .connect(name, tcp)
            .await
            .expect("handshake");
        tls.write_all(payload).await.expect("write");
        tls.shutdown().await.expect("shutdown");
        let mut reply = Vec::new();
        tls.read_to_end(&mut reply).await.expect("read");
        reply
    }

    #[tokio::test]
    async fn tls_inbound_relays_plaintext_to_enclave() {
        deadline(async {
            let f = tls_fixture().await;
            assert_eq!(tls_echo(&f, b"hello").await, b"hello");
            assert_eq!(
                *f.received.lock().expect("lock"),
                b"hello",
                "the enclave receives plaintext"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn garbage_client_does_not_stop_listener() {
        deadline(async {
            let f = tls_fixture().await;
            let mut bad = TcpStream::connect(f.front).await.expect("connect");
            bad.write_all(b"GET / HTTP/1.0\r\n\r\n")
                .await
                .expect("write");
            let mut sink = Vec::new();
            bad.read_to_end(&mut sink).await.ok();
            assert_eq!(tls_echo(&f, b"after").await, b"after");
            assert_eq!(
                f.dials.load(Ordering::SeqCst),
                1,
                "only the proper client reached the enclave"
            );
        })
        .await;
    }
}
