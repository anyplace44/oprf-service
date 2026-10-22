//! Bootstrap endpoint: hands the enclave its KMS ciphertext and the instance
//! role's credentials, to CID 16 only.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use eyre::Context;
use launcher::bootstrap::Bootstrap;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::imds;

const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const METRICS: &str = "taceo.oprf.enclave_host.bootstrap";

/// Writes `make`'s bootstrap line to `w` if `peer_cid == allowed_cid`. For any
/// other peer nothing is written and `make` is never polled.
pub async fn answer<W: AsyncWrite + Unpin>(
    peer_cid: u32,
    allowed_cid: u32,
    mut w: W,
    make: impl Future<Output = eyre::Result<Bootstrap>>,
) -> eyre::Result<bool> {
    if peer_cid != allowed_cid {
        return Ok(false);
    }
    let line = make.await?.to_line();
    tokio::time::timeout(WRITE_TIMEOUT, async {
        w.write_all(line.as_bytes()).await?;
        w.flush().await
    })
    .await
    .context("bootstrap write timed out")?
    .context("bootstrap write")?;
    Ok(true)
}

/// Base64 ciphertext from `path` (re-read per request, ASCII whitespace trimmed).
pub async fn read_ciphertext(path: &Path) -> eyre::Result<Vec<u8>> {
    let text = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("reading {}", path.display()))?;
    STANDARD
        .decode(text.trim_ascii())
        .with_context(|| format!("decoding base64 in {}", path.display()))
}

/// Where the bootstrap line's parts come from.
pub struct Source {
    /// File holding the base64 ciphertext.
    pub ciphertext: PathBuf,
    /// Instance metadata service for the role credentials.
    pub imds_url: String,
    /// Sent as [`Bootstrap::kms_key_arn`].
    pub kms_key_arn: String,
    /// Sent as [`Bootstrap::kms_vsock_port`].
    pub kms_vsock_port: u32,
}

async fn make(source: &Source) -> eyre::Result<Bootstrap> {
    let ciphertext = read_ciphertext(&source.ciphertext).await?;
    let (access_key_id, secret_access_key, session_token) =
        imds::role_credentials(&source.imds_url).await?;
    Ok(Bootstrap {
        ciphertext,
        access_key_id,
        secret_access_key,
        session_token,
        kms_key_arn: source.kms_key_arn.clone(),
        kms_vsock_port: source.kms_vsock_port,
    })
}

/// Serves one connection and records the outcome.
pub async fn handle<W: AsyncWrite + Unpin>(peer_cid: u32, allowed_cid: u32, w: W, source: &Source) {
    let outcome = match answer(peer_cid, allowed_cid, w, make(source)).await {
        Ok(true) => "served",
        Ok(false) => {
            tracing::warn!(peer_cid, "bootstrap connection from foreign CID refused");
            "rejected_peer"
        }
        Err(err) => {
            tracing::warn!(error = %format!("{err:#}"), "bootstrap failed");
            "error"
        }
    };
    metrics::counter!(METRICS, "outcome" => outcome).increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn sample() -> Bootstrap {
        Bootstrap {
            ciphertext: b"cipher".to_vec(),
            access_key_id: "AK".into(),
            secret_access_key: "SK".into(),
            session_token: "ST".into(),
            kms_key_arn: "arn:aws:kms:eu-central-1:111122223333:alias/test".into(),
            kms_vsock_port: 8000,
        }
    }

    #[tokio::test]
    async fn bootstrap_served_to_enclave_cid() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (host, mut peer) = tokio::io::duplex(4096);
            let served = answer(16, 16, host, async { Ok(sample()) })
                .await
                .expect("answer");
            assert!(served);
            let mut got = String::new();
            peer.read_to_string(&mut got).await.expect("read");
            assert_eq!(got, sample().to_line());
        })
        .await
        .expect("test deadline");
    }

    #[tokio::test]
    async fn bootstrap_refused_to_other_cid() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (host, mut peer) = tokio::io::duplex(4096);
            let served = answer(17, 16, host, async {
                panic!("make must not be polled for a foreign peer");
            })
            .await
            .expect("answer");
            assert!(!served);
            let mut got = Vec::new();
            peer.read_to_end(&mut got).await.expect("read");
            assert_eq!(got, Vec::<u8>::new(), "nothing is written");
        })
        .await
        .expect("test deadline");
    }

    #[tokio::test]
    async fn make_error_writes_nothing() {
        let (host, mut peer) = tokio::io::duplex(4096);
        let res = answer(16, 16, host, async { eyre::bail!("imds down") }).await;
        assert_eq!(res.expect_err("make failed").to_string(), "imds down");
        let mut got = Vec::new();
        peer.read_to_end(&mut got).await.expect("read");
        assert_eq!(got, Vec::<u8>::new());
    }

    #[tokio::test]
    async fn ciphertext_file_is_trimmed_and_decoded() {
        let dir = std::env::temp_dir().join(format!("a6-ct-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("ct");
        std::fs::write(&path, " Y2lwaGVy\n").expect("write");
        assert_eq!(read_ciphertext(&path).await.expect("decode"), b"cipher");
        std::fs::write(&path, "not base64!").expect("write");
        assert!(read_ciphertext(&path).await.is_err(), "error, not panic");
        std::fs::remove_dir_all(&dir).ok();
    }
}
