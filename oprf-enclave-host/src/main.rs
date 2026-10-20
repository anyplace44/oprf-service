//! Parent-side counterpart of `oprf-enclave-launcher`.
//!
//! Reads a forward table provided at run time: the KMS line first, then the
//! forwards of the enclave's config blob. Each `outbound` line becomes a
//! pontifex vsock-to-TCP proxy that only admits the enclave's CID; each
//! `inbound` line becomes a TCP listener whose connections are relayed to the
//! enclave over vsock.
//!
//! It also serves the enclave's bootstrap (KMS ciphertext and instance role
//! credentials) and collects its logs, both from the enclave's CID only.

mod bootstrap;
mod imds;
mod logsink;

use std::convert::Infallible;
use std::future::Future;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use eyre::Context;
use launcher::bootstrap::{BOOTSTRAP_PORT, LOG_PORT};
use launcher::table::Table;
use pontifex::proxy;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

/// Bounds dialing the enclave for an inbound connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const METRICS_OUTBOUND: &str = "taceo.oprf.enclave_host.outbound";
const METRICS_INBOUND: &str = "taceo.oprf.enclave_host.inbound";

#[derive(Parser)]
struct Args {
    /// CID of the enclave: the only peer the outbound proxies admit, and the
    /// target of inbound connections.
    #[arg(long, env = "OPRF_ENCLAVE_HOST_ENCLAVE_CID")]
    enclave_cid: u32,
    /// Forward table, provided at run time: the KMS line first, then the
    /// forwards of the enclave's config blob.
    #[arg(
        long,
        env = "OPRF_ENCLAVE_HOST_FORWARDS",
        default_value = "/etc/enclave/forwards"
    )]
    forwards: PathBuf,
    /// File holding the base64 KMS ciphertext of the enclave's config blob;
    /// re-read for every bootstrap request.
    #[arg(long, env = "OPRF_ENCLAVE_HOST_BOOTSTRAP_CIPHERTEXT")]
    bootstrap_ciphertext: PathBuf,
    /// Instance metadata service the role credentials are fetched from.
    #[arg(
        long,
        env = "OPRF_ENCLAVE_HOST_IMDS_URL",
        default_value = "http://169.254.169.254"
    )]
    imds_url: String,
}

fn bind_vsock(port: u32) -> eyre::Result<VsockListener> {
    VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))
        .with_context(|| format!("binding vsock port {port}"))
}

/// Answers each connection on the bootstrap port, one at a time.
async fn serve_bootstrap(
    listener: VsockListener,
    enclave_cid: u32,
    ciphertext: PathBuf,
    imds_url: String,
) -> eyre::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await.context("bootstrap accept")?;
        bootstrap::handle(peer.cid(), enclave_cid, stream, &ciphertext, &imds_url).await;
    }
}

/// Prints the enclave's log lines to stdout.
async fn serve_logs(listener: VsockListener, enclave_cid: u32) -> eyre::Result<()> {
    let mut current = None;
    loop {
        let (stream, peer) = listener.accept().await.context("log accept")?;
        if peer.cid() != enclave_cid {
            tracing::warn!(
                peer_cid = peer.cid(),
                "log connection from foreign CID refused"
            );
            continue;
        }
        replace_log_copy(&mut current, stream, tokio::io::stdout());
    }
}

/// Copies `stream` to `out` in place of the connection in `current`. Only one
/// launcher is alive at a time, so an older connection is a stale one from
/// before a restart and would otherwise hold its task until it times out.
fn replace_log_copy<R, W>(current: &mut Option<JoinHandle<()>>, stream: R, out: W)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    if let Some(previous) = current.take() {
        if !previous.is_finished() {
            tracing::info!("new log connection replaces the previous one");
        }
        previous.abort();
    }
    *current = Some(tokio::spawn(async move {
        if let Err(err) = logsink::copy_lines(BufReader::new(stream), out).await {
            tracing::debug!(%err, "log connection ended");
        }
    }));
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

/// Relays every connection accepted on `listener` to a stream from `dial`.
async fn serve_inbound<D, F, S>(listener: TcpListener, dial: D) -> Infallible
where
    D: Fn() -> F,
    F: Future<Output = std::io::Result<S>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let port = listener
        .local_addr()
        .map_or_else(|_| String::new(), |a| a.port().to_string());
    loop {
        let (mut tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::warn!(%err, "inbound accept failed");
                metrics::counter!(METRICS_INBOUND, "port" => port.clone(), "event" => "accept_failed")
                    .increment(1);
                continue;
            }
        };
        let dialing = dial();
        let port = port.clone();
        tokio::spawn(async move {
            let event = match tokio::time::timeout(CONNECT_TIMEOUT, dialing).await {
                Ok(Ok(mut enclave)) => {
                    match tokio::io::copy_bidirectional(&mut tcp, &mut enclave).await {
                        Ok(_) => "completed",
                        Err(_) => "io",
                    }
                }
                Ok(Err(_)) => "connect_failed",
                Err(_) => "connect_timed_out",
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
    let forwards = std::fs::read_to_string(&args.forwards)
        .with_context(|| format!("reading {}", args.forwards.display()))?;
    let table = Table::parse(&forwards).map_err(eyre::Report::msg)?;

    let mut tasks = tokio::task::JoinSet::new();
    for config in proxy_configs(&table, args.enclave_cid) {
        let port = config.port;
        tracing::info!(port, host = %config.destination_host, dest_port = config.destination_port, "outbound proxy");
        tasks.spawn(async move {
            let Err(err) = proxy::serve(config, move |event| record_outbound(port, event)).await;
            eyre::Result::<()>::Err(err.into())
        });
    }
    for i in &table.inbound {
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, i.tcp_port))
            .await
            .with_context(|| format!("binding inbound port {}", i.tcp_port))?;
        let addr = VsockAddr::new(args.enclave_cid, i.vsock_port);
        tracing::info!(port = i.tcp_port, %addr, "inbound relay");
        tasks.spawn(async move {
            match serve_inbound(listener, move || VsockStream::connect(addr)).await {}
        });
    }
    tasks.spawn(serve_bootstrap(
        bind_vsock(BOOTSTRAP_PORT)?,
        args.enclave_cid,
        args.bootstrap_ciphertext,
        args.imds_url,
    ));
    tasks.spawn(serve_logs(bind_vsock(LOG_PORT)?, args.enclave_cid));
    // Every task serves forever; the first one to end failed at startup.
    match tasks.join_next().await {
        Some(result) => result.context("forwarding task panicked")?,
        None => eyre::bail!("forward table has no entries"),
    }
}

#[cfg(test)]
mod tests {
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
        tokio::spawn(serve_inbound(front, move || {
            TcpStream::connect(enclave_addr)
        }));

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
    async fn newest_log_connection_replaces_the_previous_one() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut current = None;
            let (mut old_tx, old_rx) = tokio::io::duplex(1024);
            let (old_out, mut old_seen) = tokio::io::duplex(1024);
            replace_log_copy(&mut current, old_rx, old_out);
            old_tx.write_all(b"one\n").await.expect("write");
            let mut line = [0; 13];
            old_seen.read_exact(&mut line).await.expect("read");
            assert_eq!(&line, b"enclave: one\n");

            let (mut new_tx, new_rx) = tokio::io::duplex(1024);
            let (new_out, mut new_seen) = tokio::io::duplex(1024);
            replace_log_copy(&mut current, new_rx, new_out);
            // `old_tx` is still open: only the abort closes the old copy's output.
            let mut rest = Vec::new();
            old_seen.read_to_end(&mut rest).await.expect("read");
            assert_eq!(rest, b"", "the stale copy is aborted, not drained");
            new_tx.write_all(b"two\n").await.expect("write");
            new_seen.read_exact(&mut line).await.expect("read");
            assert_eq!(&line, b"enclave: two\n");
            drop(old_tx);
        })
        .await
        .expect("test deadline");
    }
}
