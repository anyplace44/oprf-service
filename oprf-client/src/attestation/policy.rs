//! The expected-values file and the attestation fetch.

use std::{
    path::Path,
    time::{Duration, SystemTime},
};

use reqwest::Url;

use super::{
    AttestationError, AttestationFailure, VerifiedAttestation,
    document::verify_document_with_anchor,
};

/// Per-request timeout for `GET /attestation` (connect through end of body).
pub const ATTESTATION_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest attestation document accepted; the NSM driver's response buffer is 12288 bytes.
pub const MAX_DOCUMENT_BYTES: usize = 0x4000;
const STATUS_BODY_CHARS: usize = 200;

/// What a node is expected to prove.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Expected {
    /// The node must attest with a PCR0 from this set.
    Pcr0(Vec<[u8; 48]>),
    /// The node is not an enclave; no request is made.
    Unattested,
}

/// A problem with the expected-values file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// The file could not be read.
    #[error("cannot read attestation expected-values file: {0}")]
    Io(#[from] std::io::Error),
    /// A line is malformed.
    #[error("attestation expected-values file, line {line}: {reason}")]
    Line {
        /// 1-based line number.
        line: usize,
        /// What is wrong.
        reason: String,
    },
    /// The file has no entries; an empty allowlist would accept nothing meaningful.
    #[error("attestation expected-values file has no entries")]
    Empty,
    /// One URL is both `unattested` and given a PCR0.
    #[error("attestation expected-values file: {0}")]
    Conflict(String),
}

/// The expected-values file: which nodes must attest, and with which PCR0.
///
/// One entry per line: `<base url> <pcr0 hex, 96 chars>` or `<base url> unattested`.
/// Several PCR0 lines for one URL accumulate. Blank lines and `#` lines are ignored.
#[derive(Debug, Clone)]
pub struct AttestationPolicy {
    entries: Vec<(Url, Expected)>,
    #[cfg(test)]
    anchor: Option<Vec<u8>>,
}

type Key = (&'static str, String, u16);

/// (scheme, host, port) with `ws`→`http`, `wss`→`https` and default ports filled in.
fn key(url: &Url) -> Option<Key> {
    let scheme = match url.scheme() {
        "http" | "ws" => "http",
        "https" | "wss" => "https",
        _ => return None,
    };
    Some((
        scheme,
        url.host_str()?.to_owned(),
        url.port_or_known_default()?,
    ))
}

impl AttestationPolicy {
    /// Parses the contents of an expected-values file.
    ///
    /// # Errors
    /// [`PolicyError`] for a malformed line, a URL that is both `unattested` and given a PCR0,
    /// or a file without entries.
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let mut entries: Vec<(Url, Expected)> = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let raw = raw.trim();
            if raw.is_empty() || raw.starts_with('#') {
                continue;
            }
            let bad = |reason: &str| PolicyError::Line {
                line,
                reason: reason.to_owned(),
            };
            let mut fields = raw.split_whitespace();
            let (Some(url), Some(value), None) = (fields.next(), fields.next(), fields.next())
            else {
                return Err(bad("expected `<url> <pcr0 hex | unattested>`"));
            };
            let url: Url = url.parse().map_err(|e| bad(&format!("invalid URL: {e}")))?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(bad("URL must be http or https with a host"));
            }
            let new = if value == "unattested" {
                None
            } else {
                Some(parse_pcr0(value).map_err(|r| bad(&r))?)
            };
            let k = key(&url);
            match entries.iter_mut().find(|(u, _)| key(u) == k) {
                None => entries.push((
                    url,
                    new.map_or(Expected::Unattested, |p| Expected::Pcr0(vec![p])),
                )),
                Some((existing, current)) => match (current, new) {
                    (Expected::Unattested, None) => {}
                    (Expected::Pcr0(set), Some(p)) => {
                        if !set.contains(&p) {
                            set.push(p);
                        }
                    }
                    _ => {
                        return Err(PolicyError::Conflict(format!(
                            "{existing} is listed both as unattested and with a PCR0 (line {line})"
                        )));
                    }
                },
            }
        }
        if entries.is_empty() {
            return Err(PolicyError::Empty);
        }
        Ok(Self {
            entries,
            #[cfg(test)]
            anchor: None,
        })
    }

    /// Reads and parses an expected-values file.
    ///
    /// # Errors
    /// [`PolicyError::Io`] if the file cannot be read, else as [`Self::parse`].
    pub fn from_file(path: &Path) -> Result<Self, PolicyError> {
        Self::parse(&std::fs::read_to_string(path)?)
    }

    /// What `url` is expected to prove; `None` if it is not listed.
    #[must_use]
    pub fn expected(&self, url: &Url) -> Option<&Expected> {
        let k = key(url)?;
        self.entries
            .iter()
            .find(|(u, _)| key(u).as_ref() == Some(&k))
            .map(|(_, e)| e)
    }

    /// All entries, in file order.
    pub fn entries(&self) -> impl Iterator<Item = (&Url, &Expected)> {
        self.entries.iter().map(|(u, e)| (u, e))
    }

    #[cfg(test)]
    pub(crate) fn with_anchor(mut self, der: Vec<u8>) -> Self {
        self.anchor = Some(der);
        self
    }

    #[cfg(test)]
    fn anchor(&self) -> &[u8] {
        self.anchor
            .as_deref()
            .unwrap_or(super::document::AWS_NITRO_ROOT_G1)
    }

    #[cfg(not(test))]
    #[expect(
        clippy::unused_self,
        reason = "production always uses the bundled root"
    )]
    fn anchor(&self) -> &[u8] {
        super::document::AWS_NITRO_ROOT_G1
    }
}

fn parse_pcr0(value: &str) -> Result<[u8; 48], String> {
    let bytes = hex::decode(value).map_err(|e| format!("PCR0 is not hex: {e}"))?;
    let pcr0: [u8; 48] = bytes
        .try_into()
        .map_err(|b: Vec<u8>| format!("PCR0 is {} bytes, expected 48", b.len()))?;
    if pcr0 == [0; 48] {
        return Err("PCR0 is all zero (a debug-mode enclave)".to_owned());
    }
    Ok(pcr0)
}

/// Attests the node at `url` as `policy` demands.
///
/// Returns `Ok(None)` for an `unattested` entry (no request is made) and the verified
/// facts otherwise.
///
/// # Errors
/// [`AttestationError`] naming `url` if it is not listed, the request fails or times
/// out, or the document does not verify.
pub async fn attest(
    http: &reqwest::Client,
    url: &Url,
    policy: &AttestationPolicy,
) -> Result<Option<VerifiedAttestation>, AttestationError> {
    attest_with(http, url, policy, ATTESTATION_TIMEOUT).await
}

pub(crate) async fn attest_with(
    http: &reqwest::Client,
    url: &Url,
    policy: &AttestationPolicy,
    timeout: Duration,
) -> Result<Option<VerifiedAttestation>, AttestationError> {
    let fail = |failure| AttestationError {
        url: url.to_string(),
        failure,
    };
    let allowed = match policy.expected(url) {
        None => return Err(fail(AttestationFailure::NotListed)),
        Some(Expected::Unattested) => return Ok(None),
        Some(Expected::Pcr0(allowed)) => allowed,
    };
    let nonce: [u8; 32] = rand::random();
    let document = fetch(http, url, &nonce, timeout).await.map_err(fail)?;
    verify_document_with_anchor(
        &document,
        &nonce,
        allowed,
        SystemTime::now(),
        policy.anchor(),
    )
    .map(Some)
    .map_err(fail)
}

async fn fetch(
    http: &reqwest::Client,
    url: &Url,
    nonce: &[u8; 32],
    timeout: Duration,
) -> Result<Vec<u8>, AttestationFailure> {
    let mut target = url.clone();
    let scheme = if target.scheme() == "wss" {
        "https"
    } else if target.scheme() == "ws" {
        "http"
    } else {
        ""
    };
    if !scheme.is_empty() {
        target
            .set_scheme(scheme)
            .map_err(|()| AttestationFailure::Transport("cannot derive HTTP URL".to_owned()))?;
    }
    target.set_username("").ok();
    target.set_password(None).ok();
    target.set_fragment(None);
    target.set_path("/attestation");
    target.set_query(Some(&format!("nonce={}", hex::encode(nonce))));

    let transport = |e: reqwest::Error| transport_failure(&e, timeout);
    let mut response = http
        .get(target)
        .timeout(timeout)
        .send()
        .await
        .map_err(transport)?;
    if response.status() != reqwest::StatusCode::OK {
        let code = response.status().as_u16();
        let (body, _) = read_capped(&mut response, MAX_DOCUMENT_BYTES)
            .await
            .unwrap_or_default();
        let body = String::from_utf8_lossy(&body)
            .chars()
            .take(STATUS_BODY_CHARS)
            .collect();
        return Err(AttestationFailure::Status { code, body });
    }
    let (body, complete) = read_capped(&mut response, MAX_DOCUMENT_BYTES)
        .await
        .map_err(transport)?;
    if !complete {
        return Err(AttestationFailure::TooLarge {
            limit: MAX_DOCUMENT_BYTES,
        });
    }
    Ok(body)
}

/// Reads the body chunk by chunk; `false` if it exceeded `limit` (read is abandoned).
async fn read_capped(
    response: &mut reqwest::Response,
    limit: usize,
) -> Result<(Vec<u8>, bool), reqwest::Error> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        body.extend_from_slice(&chunk);
        if body.len() > limit {
            return Ok((body, false));
        }
    }
    Ok((body, true))
}

fn transport_failure(error: &reqwest::Error, timeout: Duration) -> AttestationFailure {
    if error.is_timeout() {
        let waited = if timeout.subsec_millis() == 0 {
            format!("{} s", timeout.as_secs())
        } else {
            format!("{} ms", timeout.as_millis())
        };
        return AttestationFailure::Transport(format!("timed out after {waited}"));
    }
    let mut message = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    AttestationFailure::Transport(message)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::assertions_on_result_states,
    reason = "test code"
)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::{Arc, Mutex},
        time::{Duration, Instant, UNIX_EPOCH},
    };

    use axum::{Router, extract::Query, http::StatusCode, routing::get};
    use tokio::{io::AsyncWriteExt, net::TcpListener};
    use url::Url;

    use super::*;
    use crate::attestation::test_support::{
        Fields, TEST_PCR0, TEST_PUBLIC_SHA256, chain, sign_with,
    };

    const PCR_A: &str = "aa";
    const PCR_B: &str = "bb";

    fn pcr(byte: &str) -> String {
        byte.repeat(48)
    }

    fn url(s: &str) -> Url {
        s.parse().unwrap()
    }

    async fn deadline<T>(f: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), f)
            .await
            .expect("test exceeded 10 s")
    }

    fn pcrs_of(policy: &AttestationPolicy, u: &str) -> Vec<[u8; 48]> {
        match policy.expected(&url(u)) {
            Some(Expected::Pcr0(v)) => v.clone(),
            other => panic!("expected Pcr0, got {other:?}"),
        }
    }

    #[test]
    fn parses_pcr0_and_unattested_lines() {
        let text = format!(
            "https://a.example {}\nhttp://b.example:8080 unattested\n",
            pcr(PCR_A)
        );
        let p = AttestationPolicy::parse(&text).unwrap();
        assert_eq!(pcrs_of(&p, "https://a.example"), vec![[0xaa; 48]]);
        assert_eq!(
            p.expected(&url("http://b.example:8080")),
            Some(&Expected::Unattested)
        );
        assert_eq!(p.entries().count(), 2);
    }

    #[test]
    fn several_pcr0_lines_for_one_url_accumulate() {
        let text = format!(
            "https://a.example {}\nhttps://a.example:443/x {}\n",
            pcr(PCR_A),
            pcr(PCR_B)
        );
        let p = AttestationPolicy::parse(&text).unwrap();
        assert_eq!(
            pcrs_of(&p, "https://a.example"),
            vec![[0xaa; 48], [0xbb; 48]]
        );
        assert_eq!(p.entries().count(), 1);
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let text = format!(
            "# c\n\n  \n   # indented\nhttps://a.example {}\n",
            pcr(PCR_A)
        );
        assert_eq!(
            AttestationPolicy::parse(&text).unwrap().entries().count(),
            1
        );
    }

    #[test]
    fn rejects_bad_pcr0_length_and_nonhex() {
        let short = format!("# c\nhttps://a.example {}\n", "aa".repeat(47));
        let err = AttestationPolicy::parse(&short).unwrap_err();
        assert!(matches!(err, PolicyError::Line { line: 2, .. }), "{err:?}");
        let nonhex = format!("https://a.example {}\n", "zz".repeat(48));
        let err = AttestationPolicy::parse(&nonhex).unwrap_err();
        assert!(matches!(err, PolicyError::Line { line: 1, .. }), "{err:?}");
        assert!(err.to_string().contains("line 1"));
        assert!(matches!(
            AttestationPolicy::parse("https://a.example\n").unwrap_err(),
            PolicyError::Line { line: 1, .. }
        ));
    }

    #[test]
    fn rejects_all_zero_pcr0() {
        let text = format!("https://a.example {}\n", "00".repeat(48));
        assert!(matches!(
            AttestationPolicy::parse(&text).unwrap_err(),
            PolicyError::Line { line: 1, .. }
        ));
    }

    #[test]
    fn rejects_url_with_both_unattested_and_pcr0() {
        for text in [
            format!(
                "https://a.example unattested\nhttps://a.example {}\n",
                pcr(PCR_A)
            ),
            format!(
                "https://a.example {}\nhttps://a.example unattested\n",
                pcr(PCR_A)
            ),
        ] {
            assert!(matches!(
                AttestationPolicy::parse(&text).unwrap_err(),
                PolicyError::Conflict(_)
            ));
        }
    }

    #[test]
    fn empty_file_is_an_error() {
        for text in ["", "# only a comment\n\n  # another\n"] {
            assert!(matches!(
                AttestationPolicy::parse(text).unwrap_err(),
                PolicyError::Empty
            ));
        }
    }

    #[test]
    fn from_file_reports_io_and_empty() {
        let dir = std::env::temp_dir().join(format!("attest-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pcrs.txt");
        assert!(matches!(
            AttestationPolicy::from_file(&path).unwrap_err(),
            PolicyError::Io(_)
        ));
        std::fs::write(&path, "# nothing\n").unwrap();
        assert!(matches!(
            AttestationPolicy::from_file(&path).unwrap_err(),
            PolicyError::Empty
        ));
        std::fs::write(&path, "https://a.example unattested\n").unwrap();
        assert_eq!(
            AttestationPolicy::from_file(&path)
                .unwrap()
                .entries()
                .count(),
            1
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_non_http_scheme() {
        for u in [
            "ws://a.example",
            "wss://a.example",
            "ftp://a.example",
            "a.example",
        ] {
            let text = format!("{u} unattested\n");
            assert!(
                matches!(
                    AttestationPolicy::parse(&text).unwrap_err(),
                    PolicyError::Line { line: 1, .. }
                ),
                "{u}"
            );
        }
    }

    #[test]
    fn ws_and_wss_urls_match_http_and_https_entries() {
        let p =
            AttestationPolicy::parse("http://a.example unattested\nhttps://b.example unattested\n")
                .unwrap();
        assert!(p.expected(&url("ws://a.example")).is_some());
        assert!(p.expected(&url("ws://a.example:80")).is_some());
        assert!(p.expected(&url("wss://b.example")).is_some());
        assert!(p.expected(&url("https://b.example:443")).is_some());
        assert!(p.expected(&url("wss://a.example")).is_none());
        assert!(p.expected(&url("ws://b.example")).is_none());
        assert!(p.expected(&url("http://a.example:81")).is_none());
        assert!(p.expected(&url("http://c.example")).is_none());
    }

    #[test]
    fn path_and_query_do_not_affect_match() {
        let p = AttestationPolicy::parse("https://a.example unattested\n").unwrap();
        assert!(
            p.expected(&url("https://a.example/api/x/oprf?y=1#z"))
                .is_some()
        );
    }

    async fn serve(app: Router) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        addr
    }

    fn policy_for(addr: SocketAddr, pcr0: &str) -> (AttestationPolicy, Url) {
        let u = url(&format!("http://{addr}"));
        let text = format!("http://{addr} {}\n", pcr0.repeat(48));
        (AttestationPolicy::parse(&text).unwrap(), u)
    }

    #[tokio::test]
    async fn attest_unattested_sends_no_request() {
        // nothing listens on this port
        let u = url("http://127.0.0.1:1");
        let p = AttestationPolicy::parse("http://127.0.0.1:1 unattested\n").unwrap();
        let out = deadline(attest(&reqwest::Client::new(), &u, &p)).await;
        assert_eq!(out.unwrap(), None);
    }

    #[tokio::test]
    async fn attest_not_listed_fails() {
        let p = AttestationPolicy::parse("http://a.example unattested\n").unwrap();
        let u = url("http://other.example");
        let err = deadline(attest(&reqwest::Client::new(), &u, &p))
            .await
            .unwrap_err();
        assert_eq!(err.failure, AttestationFailure::NotListed);
        assert!(
            err.to_string()
                .starts_with("attestation of http://other.example")
        );
    }

    #[tokio::test]
    async fn attest_reports_http_status() {
        let app = Router::new().route(
            "/attestation",
            get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "attestation unavailable") }),
        );
        let addr = serve(app).await;
        let (p, u) = policy_for(addr, "aa");
        let err = deadline(attest(&reqwest::Client::new(), &u, &p))
            .await
            .unwrap_err();
        match err.failure {
            AttestationFailure::Status { code: 503, body } => {
                assert_eq!(body, "attestation unavailable");
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn attest_times_out_on_stalled_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        assert_times_out(addr).await;
    }

    #[tokio::test]
    async fn attest_times_out_on_stalled_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((mut s, _)) = listener.accept().await {
                s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nab")
                    .await
                    .unwrap();
                held.push(s);
            }
        });
        assert_times_out(addr).await;
    }

    async fn assert_times_out(addr: SocketAddr) {
        let (p, u) = policy_for(addr, "aa");
        let started = Instant::now();
        let err = deadline(attest_with(
            &reqwest::Client::new(),
            &u,
            &p,
            Duration::from_millis(500),
        ))
        .await
        .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(2));
        match &err.failure {
            AttestationFailure::Transport(m) => assert!(m.contains("timed out"), "{m}"),
            other => panic!("{other:?}"),
        }
        let shown = err.to_string();
        assert!(shown.contains("attestation of"), "{shown}");
        assert!(shown.contains(&u.to_string()), "{shown}");
    }

    #[tokio::test]
    async fn attest_rejects_oversized_body() {
        let app = Router::new().route(
            "/attestation",
            get(|| async { vec![0u8; MAX_DOCUMENT_BYTES + 4096] }),
        );
        let addr = serve(app).await;
        let (p, u) = policy_for(addr, "aa");
        let err = deadline(attest(&reqwest::Client::new(), &u, &p))
            .await
            .unwrap_err();
        assert_eq!(
            err.failure,
            AttestationFailure::TooLarge {
                limit: MAX_DOCUMENT_BYTES
            }
        );
    }

    #[tokio::test]
    async fn attest_end_to_end_with_test_anchor() {
        let chain = Arc::new(chain());
        let anchor = chain.root_der.clone();
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let seen_in = seen.clone();
        let app = Router::new().route(
            "/attestation",
            get(
                move |Query(q): Query<std::collections::HashMap<String, String>>| {
                    let seen = seen_in.clone();
                    let chain = chain.clone();
                    async move {
                        let nonce_hex = q["nonce"].clone();
                        seen.lock().unwrap().push(nonce_hex.clone());
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis()
                            .try_into()
                            .unwrap();
                        sign_with(
                            &chain,
                            &Fields {
                                nonce: Some(hex::decode(nonce_hex).unwrap()),
                                timestamp_ms: now_ms,
                                ..Fields::default()
                            },
                        )
                    }
                },
            ),
        );
        let addr = serve(app).await;
        let u = url(&format!("http://{addr}"));
        let text = format!("http://{addr} {}\n", hex::encode(TEST_PCR0));
        let p = AttestationPolicy::parse(&text).unwrap().with_anchor(anchor);
        let out = deadline(attest(&reqwest::Client::new(), &u, &p))
            .await
            .unwrap()
            .expect("attested");
        assert_eq!(out.pcr0, TEST_PCR0);
        assert_eq!(out.public_sha256, TEST_PUBLIC_SHA256);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].len(), 64);
        assert!(
            seen[0]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }
}
