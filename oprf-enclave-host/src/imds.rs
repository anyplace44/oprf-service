//! `IMDSv2` client for the parent instance's role credentials.

use std::time::Duration;

use eyre::Context;
use serde::Deserialize;

const TIMEOUT: Duration = Duration::from_secs(2);
const TOKEN_HEADER: &str = "X-aws-ec2-metadata-token";

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Credentials {
    access_key_id: String,
    secret_access_key: String,
    token: String,
}

/// `(access_key_id, secret_access_key, session_token)` of the instance role.
pub async fn role_credentials(base: &str) -> eyre::Result<(String, String, String)> {
    let base = base.trim_end_matches('/');
    // Plain HTTP to a link-local address: no proxy, bounded time. No roots:
    // the platform verifier would load the system CA store, which the scratch
    // image does not have, and fail the build.
    let client = reqwest::Client::builder()
        .no_proxy()
        .tls_certs_only([])
        .timeout(TIMEOUT)
        .build()
        .context("building IMDS client")?;
    let token = client
        .put(format!("{base}/latest/api/token"))
        .header("X-aws-ec2-metadata-token-ttl-seconds", "60")
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .context("IMDS token request")?
        .text()
        .await
        .context("IMDS token body")?;
    let get = |path: String| {
        client
            .get(format!("{base}{path}"))
            .header(TOKEN_HEADER, token.trim())
            .send()
    };
    let roles = get("/latest/meta-data/iam/security-credentials/".to_owned())
        .await
        .and_then(reqwest::Response::error_for_status)
        .context("IMDS role listing")?
        .text()
        .await
        .context("IMDS role listing body")?;
    let role = roles.lines().next().map(str::trim).unwrap_or_default();
    eyre::ensure!(!role.is_empty(), "instance has no IAM role");
    let creds: Credentials = get(format!("/latest/meta-data/iam/security-credentials/{role}"))
        .await
        .and_then(reqwest::Response::error_for_status)
        .context("IMDS role credentials")?
        .json()
        .await
        .context("IMDS role credentials body")?;
    Ok((creds.access_key_id, creds.secret_access_key, creds.token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn imds_fetches_role_credentials() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let base = format!("http://{}", listener.local_addr().expect("addr"));
            let server =
                tokio::spawn(async move {
                    let mut requests = Vec::new();
                    for body in [
                    "tok123".to_owned(),
                    "my-role\n".to_owned(),
                    r#"{"Code":"Success","AccessKeyId":"AK","SecretAccessKey":"SK","Token":"ST"}"#
                        .to_owned(),
                ] {
                    let (mut s, _) = listener.accept().await.expect("accept");
                    let mut buf = vec![0; 4096];
                    let n = s.read(&mut buf).await.expect("read");
                    requests.push(String::from_utf8_lossy(&buf[..n]).to_lowercase());
                    s.write_all(response(&body).as_bytes()).await.expect("write");
                }
                    requests
                });
            let got = role_credentials(&base).await.expect("credentials");
            assert_eq!(got, ("AK".into(), "SK".into(), "ST".into()));
            let requests = server.await.expect("server");
            assert!(requests[0].starts_with("put /latest/api/token "));
            assert!(requests[0].contains("x-aws-ec2-metadata-token-ttl-seconds: 60"));
            assert!(requests[1].starts_with("get /latest/meta-data/iam/security-credentials/ "));
            assert!(requests[1].contains("x-aws-ec2-metadata-token: tok123"));
            assert!(
                requests[2].starts_with("get /latest/meta-data/iam/security-credentials/my-role ")
            );
            assert!(requests[2].contains("x-aws-ec2-metadata-token: tok123"));
        })
        .await
        .expect("test deadline");
    }
}
