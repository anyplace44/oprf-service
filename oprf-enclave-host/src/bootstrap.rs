//! Bootstrap endpoint: hands each enclave its own KMS ciphertext, key ARN and the instance
//! role's credentials, keyed by the peer's CID. Any other peer gets nothing.

use std::future::Future;
use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use eyre::Context;
use launcher::bootstrap::Bootstrap;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::config::{Enclave, HostConfig};
use crate::imds;

const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const METRICS: &str = "taceo.oprf.enclave_host.bootstrap";

/// Writes the bootstrap line `make` builds for the enclave whose CID is `peer_cid`. For any
/// other peer nothing is written and `make` is never polled.
pub async fn answer<'a, W: AsyncWrite + Unpin, F: Future<Output = eyre::Result<Bootstrap>>>(
    peer_cid: u32,
    enclaves: &'a [Enclave],
    mut w: W,
    make: impl FnOnce(&'a Enclave) -> F,
) -> eyre::Result<bool> {
    let Some(enclave) = enclaves.iter().find(|e| e.cid == peer_cid) else {
        return Ok(false);
    };
    let line = make(enclave).await?.to_line();
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

/// Role credentials: access key id, secret access key, session token.
pub type Credentials = (String, String, String);

/// `enclave`'s ciphertext (re-read now) and key, with `credentials`.
pub async fn build(enclave: &Enclave, credentials: Credentials) -> eyre::Result<Bootstrap> {
    let ciphertext = read_ciphertext(&enclave.ciphertext).await?;
    let (access_key_id, secret_access_key, session_token) = credentials;
    Ok(Bootstrap {
        ciphertext,
        access_key_id,
        secret_access_key,
        session_token,
        kms_key_arn: enclave.kms_key_arn.clone(),
        kms_vsock_port: enclave.kms_vsock_port,
    })
}

/// Serves one connection and records the outcome.
pub async fn handle<W: AsyncWrite + Unpin>(peer_cid: u32, w: W, config: &HostConfig) {
    let name = config.by_cid(peer_cid).map(|e| e.name.as_str());
    let outcome = match answer(peer_cid, &config.enclaves, w, |e| async {
        build(e, imds::role_credentials(&config.imds_url).await?).await
    })
    .await
    {
        Ok(true) => "served",
        Ok(false) => {
            tracing::warn!(peer_cid, "bootstrap connection from foreign CID refused");
            "rejected_peer"
        }
        Err(err) => {
            tracing::warn!(enclave = name, error = %format!("{err:#}"), "bootstrap failed");
            "error"
        }
    };
    metrics::counter!(METRICS, "outcome" => outcome, "enclave" => name.unwrap_or("unknown").to_owned())
        .increment(1);
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use launcher::table::Table;
    use tokio::io::AsyncReadExt;

    use super::*;

    const ARN_KG: &str = "arn:aws:kms:eu-central-1:111122223333:alias/key-gen";
    const ARN_NODE: &str = "arn:aws:kms:eu-central-1:111122223333:alias/node";

    fn enclave(name: &str, cid: u32, arn: &str, port: u32, ciphertext: PathBuf) -> Enclave {
        Enclave {
            name: name.into(),
            cid,
            kms_key_arn: arn.into(),
            kms_vsock_port: port,
            ciphertext,
            table: Table::default(),
        }
    }

    fn creds() -> Credentials {
        ("AK".into(), "SK".into(), "ST".into())
    }

    /// Ciphertext files: `key-gen` holds base64 of `cipher16`, `node` of `cipher17`.
    fn fixture(tag: &str) -> (PathBuf, Vec<Enclave>) {
        let dir = std::env::temp_dir().join(format!("a5-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("kg"), "Y2lwaGVyMTY=\n").expect("write");
        std::fs::write(dir.join("node"), "Y2lwaGVyMTc=").expect("write");
        let enclaves = vec![
            enclave("key-gen", 16, ARN_KG, 8000, dir.join("kg")),
            enclave("node", 17, ARN_NODE, 8100, dir.join("node")),
        ];
        (dir, enclaves)
    }

    async fn ask(enclaves: &[Enclave], peer: u32) -> (bool, Vec<u8>) {
        let (host, mut peer_end) = tokio::io::duplex(4096);
        let served = answer(peer, enclaves, host, |e| build(e, creds()))
            .await
            .expect("answer");
        let mut got = Vec::new();
        peer_end.read_to_end(&mut got).await.expect("read");
        (served, got)
    }

    #[tokio::test]
    async fn bootstrap_answers_per_cid() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (dir, enclaves) = fixture("per-cid");
            let (served, got) = ask(&enclaves, 16).await;
            assert!(served);
            let b = Bootstrap::from_line(std::str::from_utf8(&got).expect("utf8")).expect("line");
            assert_eq!(b.ciphertext, b"cipher16");
            assert_eq!((b.kms_key_arn.as_str(), b.kms_vsock_port), (ARN_KG, 8000));

            let (served, got) = ask(&enclaves, 17).await;
            assert!(served);
            let b = Bootstrap::from_line(std::str::from_utf8(&got).expect("utf8")).expect("line");
            assert_eq!(b.ciphertext, b"cipher17");
            assert_eq!((b.kms_key_arn.as_str(), b.kms_vsock_port), (ARN_NODE, 8100));
            assert_eq!(b.access_key_id, "AK");

            let (host, mut peer_end) = tokio::io::duplex(4096);
            let served = answer(18, &enclaves, host, |_| async {
                panic!("make must not be polled for an unknown peer");
            })
            .await
            .expect("answer");
            assert!(!served);
            let mut got = Vec::new();
            peer_end.read_to_end(&mut got).await.expect("read");
            assert_eq!(got, Vec::<u8>::new(), "nothing is written");
            std::fs::remove_dir_all(dir).ok();
        })
        .await
        .expect("test deadline");
    }

    #[tokio::test]
    async fn make_error_writes_nothing() {
        let (_dir, enclaves) = fixture("make-err");
        let (host, mut peer) = tokio::io::duplex(4096);
        let res = answer(16, &enclaves, host, |_| async { eyre::bail!("imds down") }).await;
        assert_eq!(res.expect_err("make failed").to_string(), "imds down");
        let mut got = Vec::new();
        peer.read_to_end(&mut got).await.expect("read");
        assert_eq!(got, Vec::<u8>::new());
    }

    #[tokio::test]
    async fn ciphertext_file_is_trimmed_and_decoded() {
        let dir = std::env::temp_dir().join(format!("a5-ct-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("ct");
        std::fs::write(&path, " Y2lwaGVy\n").expect("write");
        assert_eq!(read_ciphertext(&path).await.expect("decode"), b"cipher");
        std::fs::write(&path, "not base64!").expect("write");
        assert!(read_ciphertext(&path).await.is_err(), "error, not panic");
        std::fs::remove_dir_all(&dir).ok();
    }
}
