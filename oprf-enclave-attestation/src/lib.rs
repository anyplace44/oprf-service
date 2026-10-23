//! Attestation protocol between an app inside a Nitro enclave and the enclave
//! launcher, which owns the NSM device.
//!
//! One exchange per TCP connection: the app sends `<64 lowercase hex nonce>\n`
//! and the launcher answers `ok <base64 COSE document>\n` or `error <message>\n`.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// Where the launcher listens for attestation requests inside the enclave.
pub const LAUNCHER_ADDR: &str = "127.0.0.1:9901";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_LINE: usize = 128;
const MAX_RESPONSE_LINE: usize = 64 * 1024;
const ROUTE_LAUNCHER_TIMEOUT: Duration = Duration::from_secs(10);
const UNAVAILABLE: &str = "attestation unavailable: not running in an enclave";

/// Parses exactly 64 lowercase hex characters into a nonce.
///
/// # Errors
/// Returns a message naming the first problem found.
pub fn parse_nonce_hex(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("nonce must be 64 hex characters, got {}", s.len()));
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err("nonce must be lowercase hex".to_owned()),
    };
    let mut nonce = [0_u8; 32];
    let (pairs, _) = s.as_bytes().as_chunks::<2>();
    for (byte, pair) in nonce.iter_mut().zip(pairs) {
        *byte = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Ok(nonce)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [b >> 4, b & 0x0f])
        .map(|n| char::from(DIGITS[usize::from(n)]))
        .collect()
}

/// The exact `user_data` bytes the launcher puts into the attestation document.
#[must_use]
pub fn user_data(public_sha256: &[u8; 32]) -> Vec<u8> {
    format!("{{\"public_sha256\":\"{}\"}}", hex(public_sha256)).into_bytes()
}

/// Reads one line (without the newline) of at most `max` bytes before `deadline`.
fn read_line(stream: &mut TcpStream, max: usize, deadline: Instant) -> Result<Vec<u8>, String> {
    let mut line = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or("timed out")?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|e| e.to_string())?;
        let n = match stream.read(&mut buf) {
            Ok(0) => return Err("connection closed before end of line".to_owned()),
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err("timed out".to_owned());
            }
            Err(e) => return Err(e.to_string()),
        };
        line.extend_from_slice(&buf[..n]);
        if let Some(end) = line.iter().position(|b| *b == b'\n') {
            line.truncate(end);
            return if end > max {
                Err("line too long".to_owned())
            } else {
                Ok(line)
            };
        }
        if line.len() > max {
            return Err("line too long".to_owned());
        }
    }
}

fn handle(
    mut stream: TcpStream,
    attest: &(impl Fn(&[u8; 32]) -> Result<Vec<u8>, String> + ?Sized),
    log: &(impl Fn(&str) + ?Sized),
) {
    let request = read_line(
        &mut stream,
        MAX_REQUEST_LINE,
        Instant::now() + REQUEST_TIMEOUT,
    )
    .and_then(|line| {
        let line = String::from_utf8(line).map_err(|_| "request is not UTF-8".to_owned())?;
        parse_nonce_hex(&line)
    });
    let reply = match request {
        Err(msg) => {
            log(&format!("attestation request rejected: {msg}"));
            format!("error {}\n", one_line(&msg))
        }
        Ok(nonce) => match attest(&nonce) {
            Ok(doc) => {
                log("attestation served");
                format!("ok {}\n", STANDARD.encode(doc))
            }
            Err(msg) => {
                log(&format!("attestation failed: {msg}"));
                format!("error {}\n", one_line(&msg))
            }
        },
    };
    if stream.set_write_timeout(Some(REQUEST_TIMEOUT)).is_ok() {
        // the peer may be gone; the event is already logged
        drop(stream.write_all(reply.as_bytes()));
    }
}

fn one_line(msg: &str) -> String {
    msg.replace(['\r', '\n'], " ")
}

/// Answers attestation requests on `listener`, one thread per connection.
///
/// Calls `log` exactly once per connection: `attestation served`,
/// `attestation failed: <msg>` or `attestation request rejected: <msg>`.
/// Never returns while the listener accepts.
#[allow(
    clippy::needless_pass_by_value,
    reason = "serve owns the listener for as long as it accepts"
)]
pub fn serve(
    listener: TcpListener,
    attest: impl Fn(&[u8; 32]) -> Result<Vec<u8>, String> + Send + Sync + 'static,
    log: impl Fn(&str) + Send + Sync + 'static,
) {
    let attest = Arc::new(attest);
    let log = Arc::new(log);
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let attest = Arc::clone(&attest);
                let log = Arc::clone(&log);
                thread::spawn(move || handle(stream, &*attest, &*log));
            }
            // e.g. EMFILE: back off instead of spinning
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// Asks the launcher at `addr` for an attestation document bound to `nonce`.
///
/// # Errors
/// Returns a message on connection failure, timeout (`timeout` bounds the whole
/// exchange), an `error` reply from the launcher, or a malformed reply.
pub fn request_document(
    addr: SocketAddr,
    nonce: &[u8; 32],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + timeout;
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|e| format!("connecting to launcher at {addr}: {e}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(format!("{}\n", hex(nonce)).as_bytes())
        .map_err(|e| format!("sending request to launcher: {e}"))?;
    let line = read_line(&mut stream, MAX_RESPONSE_LINE, deadline)
        .map_err(|e| format!("reading launcher response: {e}"))?;
    let line = String::from_utf8(line).map_err(|_| "launcher response is not UTF-8".to_owned())?;
    if let Some(b64) = line.strip_prefix("ok ") {
        STANDARD
            .decode(b64)
            .map_err(|e| format!("launcher response is not base64: {e}"))
    } else if let Some(msg) = line.strip_prefix("error ") {
        Err(msg.to_owned())
    } else {
        Err("malformed launcher response".to_owned())
    }
}

/// Status, content type and body of the `/attestation` route.
#[derive(Debug)]
#[non_exhaustive]
pub struct RouteReply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

fn text(status: u16, body: String) -> RouteReply {
    RouteReply {
        status,
        content_type: "text/plain",
        body: body.into_bytes(),
    }
}

/// Computes the reply of `GET /attestation?nonce=…`. Blocks on the launcher.
#[must_use]
pub fn route_reply(launcher: Option<SocketAddr>, nonce: Option<&str>) -> RouteReply {
    let Some(launcher) = launcher else {
        return text(503, UNAVAILABLE.to_owned());
    };
    let nonce = match nonce
        .ok_or_else(|| "missing nonce".to_owned())
        .and_then(parse_nonce_hex)
    {
        Ok(nonce) => nonce,
        Err(msg) => return text(400, format!("invalid nonce: {msg}")),
    };
    match request_document(launcher, &nonce, ROUTE_LAUNCHER_TIMEOUT) {
        Ok(body) => RouteReply {
            status: 200,
            content_type: "application/cbor",
            body,
        },
        Err(msg) => text(502, format!("attestation failed: {msg}")),
    }
}

/// Router with `GET /attestation`, to be merged into an app's router.
#[cfg(feature = "router")]
pub fn router(launcher: Option<SocketAddr>) -> axum::Router {
    use axum::extract::Query;
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse as _;
    use std::collections::HashMap;

    axum::Router::new().route(
        "/attestation",
        axum::routing::get(
            move |Query(query): Query<HashMap<String, String>>| async move {
                let nonce = query.get("nonce").cloned();
                let reply =
                    tokio::task::spawn_blocking(move || route_reply(launcher, nonce.as_deref()))
                        .await;
                match reply {
                    Ok(reply) => (
                        StatusCode::from_u16(reply.status)
                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                        [(header::CONTENT_TYPE, reply.content_type)],
                        reply.body,
                    )
                        .into_response(),
                    Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            },
        ),
    )
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
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    fn deadline<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(Duration::from_secs(10))
            .expect("test exceeded 10 s")
    }

    fn spawn_server(
        attest: impl Fn(&[u8; 32]) -> Result<Vec<u8>, String> + Send + Sync + 'static,
        log: impl Fn(&str) + Send + Sync + 'static,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || serve(listener, attest, log));
        addr
    }

    fn echo_server() -> SocketAddr {
        spawn_server(|nonce| Ok(nonce.to_vec()), |_| {})
    }

    fn failing_server() -> SocketAddr {
        spawn_server(|_| Err("nsm down".to_owned()), |_| {})
    }

    const NONCE: [u8; 32] = [0x5a; 32];

    #[test]
    fn nonce_hex_round_trip() {
        let hex = "00ff10".repeat(10) + "abcd";
        assert_eq!(hex.len(), 64);
        let nonce = parse_nonce_hex(&hex).unwrap();
        assert_eq!(nonce[0], 0x00);
        assert_eq!(nonce[1], 0xff);
        assert_eq!(nonce[31], 0xcd);
        assert_eq!(super::hex(&nonce), hex);
    }

    #[test]
    fn nonce_rejects_uppercase_short_long_nonhex() {
        for bad in [
            "AB".repeat(32),
            "ab".repeat(31),
            "ab".repeat(33),
            "zz".repeat(32),
            String::new(),
            format!("{}+", "a".repeat(63)),
        ] {
            assert!(parse_nonce_hex(&bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn user_data_is_exact_json() {
        let expected = format!("{{\"public_sha256\":\"{}\"}}", "ab".repeat(32));
        assert_eq!(user_data(&[0xab; 32]), expected.as_bytes());
    }

    #[test]
    fn serve_answers_request_document() {
        deadline(|| {
            let addr = echo_server();
            let doc = request_document(addr, &NONCE, Duration::from_secs(5)).unwrap();
            assert_eq!(doc, NONCE.to_vec());
        });
    }

    #[test]
    fn serve_reports_attest_error() {
        deadline(|| {
            let addr = failing_server();
            let err = request_document(addr, &NONCE, Duration::from_secs(5)).unwrap_err();
            assert!(err.contains("nsm down"), "{err}");
        });
    }

    #[test]
    fn serve_rejects_bad_request_line() {
        deadline(|| {
            let addr = echo_server();
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(b"zz\n").unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).unwrap();
            assert!(reply.starts_with("error "), "{reply}");
            assert!(reply.ends_with('\n'));
        });
    }

    #[test]
    fn serve_survives_a_silent_client() {
        deadline(|| {
            let addr = echo_server();
            let _silent = TcpStream::connect(addr).unwrap();
            let start = Instant::now();
            request_document(addr, &NONCE, Duration::from_secs(5)).unwrap();
            assert!(start.elapsed() < Duration::from_secs(2));
        });
    }

    #[test]
    fn serve_logs_one_event_per_request() {
        deadline(|| {
            let events = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&events);
            let addr = spawn_server(
                |nonce| Ok(nonce.to_vec()),
                move |line| sink.lock().unwrap().push(line.to_owned()),
            );
            request_document(addr, &NONCE, Duration::from_secs(5)).unwrap();
            request_document(addr, &NONCE, Duration::from_secs(5)).unwrap();
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(b"zz\n").unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).unwrap();
            // the log call precedes the close the client waited for
            let events = events.lock().unwrap();
            assert_eq!(events.len(), 3, "{events:?}");
            assert_eq!(
                events.iter().filter(|e| *e == "attestation served").count(),
                2
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|e| e.starts_with("attestation request rejected: "))
                    .count(),
                1
            );
        });
    }

    #[test]
    fn request_document_times_out() {
        deadline(|| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let _held = thread::spawn(move || {
                let conn = listener.accept();
                thread::sleep(Duration::from_secs(3));
                drop(conn);
            });
            let start = Instant::now();
            let result = request_document(addr, &NONCE, Duration::from_millis(200));
            assert!(result.is_err());
            assert!(start.elapsed() < Duration::from_secs(1));
        });
    }

    #[test]
    fn route_reply_statuses() {
        deadline(|| {
            let nonce_hex = "5a".repeat(32);

            let none = route_reply(None, Some(&nonce_hex));
            assert_eq!(none.status, 503);
            assert_eq!(none.content_type, "text/plain");
            assert_eq!(
                none.body,
                b"attestation unavailable: not running in an enclave"
            );
            // launcher presence is checked before the nonce
            assert_eq!(route_reply(None, None).status, 503);

            let ok = echo_server();
            assert_eq!(route_reply(Some(ok), None).status, 400);
            assert_eq!(route_reply(Some(ok), Some("nothex")).status, 400);

            let bad = route_reply(Some(failing_server()), Some(&nonce_hex));
            assert_eq!(bad.status, 502);
            assert_eq!(bad.content_type, "text/plain");
            assert_eq!(bad.body, b"attestation failed: nsm down");

            let good = route_reply(Some(ok), Some(&nonce_hex));
            assert_eq!(good.status, 200);
            assert_eq!(good.content_type, "application/cbor");
            assert_eq!(good.body, NONCE.to_vec());
        });
    }

    #[cfg(feature = "router")]
    #[tokio::test]
    async fn router_serves_attestation() {
        let addr = echo_server();
        let server = axum_test::TestServer::new(router(Some(addr)));
        let nonce_hex = "5a".repeat(32);
        let ok = server
            .get("/attestation")
            .add_query_param("nonce", &nonce_hex)
            .await;
        ok.assert_status_ok();
        assert_eq!(ok.as_bytes().as_ref(), NONCE.as_slice());
        server
            .get("/attestation")
            .await
            .assert_status(axum::http::StatusCode::BAD_REQUEST);
        let off = axum_test::TestServer::new(router(None));
        off.get("/attestation")
            .await
            .assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }
}
