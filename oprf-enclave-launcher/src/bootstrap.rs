//! Wire types shared by the enclave launcher and the parent-side `oprf-enclave-host`.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

use aws_lc_rs::digest;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::table::Table;

/// Parent vsock port the enclave dials to fetch the [`Bootstrap`] line.
pub const BOOTSTRAP_PORT: u32 = 7001;
/// Parent vsock port the enclave streams its log lines to.
pub const LOG_PORT: u32 = 7002;

/// What the parent sends on [`BOOTSTRAP_PORT`]: the encrypted config blob, the credentials to
/// decrypt it with, and the KMS key and parent vsock port to decrypt it through.
#[allow(
    clippy::exhaustive_structs,
    reason = "wire type, constructed by the host crate"
)]
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct Bootstrap {
    /// KMS ciphertext of the [`EnclaveConfig`] JSON.
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    /// AWS access key id.
    pub access_key_id: String,
    /// AWS secret access key.
    pub secret_access_key: String,
    /// AWS session token.
    pub session_token: String,
    /// ARN (alias or key) of the KMS key the ciphertext was encrypted under; also names the
    /// region whose KMS endpoint the enclave dials.
    pub kms_key_arn: String,
    /// Parent vsock port that carries the enclave's KMS traffic.
    pub kms_vsock_port: u32,
}

mod b64 {
    use super::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for Bootstrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bootstrap")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("access_key_id", &self.access_key_id)
            .field("kms_key_arn", &self.kms_key_arn)
            .field("kms_vsock_port", &self.kms_vsock_port)
            .finish_non_exhaustive()
    }
}

impl Bootstrap {
    /// One JSON line, newline included.
    ///
    /// # Panics
    ///
    /// Never; serializing plain strings cannot fail.
    #[must_use]
    pub fn to_line(&self) -> String {
        let mut line = serde_json::to_string(self).expect("strings serialize");
        line.push('\n');
        line
    }

    /// Parses the line written by [`Self::to_line`].
    ///
    /// # Errors
    ///
    /// Malformed JSON, missing or unknown fields, or invalid base64.
    pub fn from_line(line: &str) -> Result<Self, String> {
        serde_json::from_str(line.trim_end()).map_err(|e| format!("bootstrap line: {e}"))
    }
}

/// The blob's public part, the JSON text in [`EnclaveConfig::public_json`].
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::exhaustive_structs,
    reason = "wire type, fields are the wire format"
)]
pub struct PublicConfig {
    /// The app's environment, except its secrets.
    pub environment: BTreeMap<String, String>,
    /// Forward table text, without the KMS line.
    pub forwards: String,
    /// The KMS key the blob was written for; must equal [`Bootstrap::kms_key_arn`].
    pub kms_key_arn: String,
}

/// The decrypted blob: `{"public":"<public JSON text>","secret_environment":{…}}`.
#[derive(PartialEq, Eq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "wire type, fields are the wire format"
)]
pub struct EnclaveConfig {
    /// The parsed public part.
    pub public: PublicConfig,
    /// The public part exactly as it appears in the blob; [`Self::hash_line`] hashes these bytes.
    pub public_json: String,
    /// The app's secret environment.
    pub secret_environment: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Blob {
    public: String,
    secret_environment: BTreeMap<String, String>,
}

impl fmt::Debug for EnclaveConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnclaveConfig")
            .field("public", &self.public)
            .field("secret_keys", &self.secret_environment.keys())
            .finish_non_exhaustive()
    }
}

impl EnclaveConfig {
    /// Parses the blob plaintext.
    ///
    /// # Errors
    ///
    /// Malformed JSON, missing or unknown fields at either level, an environment key that is not
    /// `[A-Za-z_][A-Za-z0-9_]*`, or a key present in both environments. Errors never contain a
    /// secret value.
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        let blob: Blob = serde_json::from_slice(bytes)
            .map_err(|e| format!("enclave config: {}", without_values(&e)))?;
        let public: PublicConfig = serde_json::from_str(&blob.public)
            .map_err(|e| format!("enclave config: public: {e}"))?;
        for key in public
            .environment
            .keys()
            .chain(blob.secret_environment.keys())
        {
            let mut chars = key.chars();
            let first_ok = chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
            if !first_ok || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(format!("enclave config: bad environment key {key:?}"));
            }
        }
        if let Some(key) = blob
            .secret_environment
            .keys()
            .find(|k| public.environment.contains_key(*k))
        {
            return Err(format!(
                "enclave config: {key:?} is in both the public and the secret environment"
            ));
        }
        Ok(Self {
            public,
            public_json: blob.public,
            secret_environment: blob.secret_environment,
        })
    }

    /// Exactly the environment the app runs with: the public and the secret environment.
    #[must_use]
    pub fn app_environment(&self) -> BTreeMap<String, String> {
        self.public
            .environment
            .iter()
            .chain(&self.secret_environment)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// `config public_sha256=<hex> secrets <KEY>=<hex> …`: SHA-256 of the public JSON text, then
    /// one SHA-256 commitment per secret value, keys sorted.
    #[must_use]
    pub fn hash_line(&self) -> String {
        let mut line = format!(
            "config public_sha256={} secrets",
            sha256_hex(self.public_json.as_bytes())
        );
        for (key, value) in &self.secret_environment {
            write!(line, " {key}={}", sha256_hex(value.as_bytes())).expect("String write");
        }
        line
    }
}

/// `serde_json`'s message, unless it may quote a value from the input ("invalid type: string
/// \"…\""): the blob's values include secrets.
fn without_values(e: &serde_json::Error) -> String {
    let msg = e.to_string();
    let names_only = ["missing field", "unknown field"]
        .iter()
        .any(|p| msg.starts_with(p));
    if e.classify() == serde_json::error::Category::Data && !names_only {
        format!(
            "invalid type or value at line {} column {}",
            e.line(),
            e.column()
        )
    } else {
        msg
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest::digest(&digest::SHA256, bytes).as_ref().iter().fold(
        String::with_capacity(64),
        |mut s, b| {
            write!(s, "{b:02x}").expect("String write");
            s
        },
    )
}

/// Refuses a blob written for another key than the one the parent named.
///
/// # Errors
///
/// `config.public.kms_key_arn` differs from `bootstrap_arn`.
pub fn check_key(bootstrap_arn: &str, config: &EnclaveConfig) -> Result<(), String> {
    if config.public.kms_key_arn == bootstrap_arn {
        Ok(())
    } else {
        Err(format!(
            "config was written for KMS key {:?}, the parent named {bootstrap_arn:?}",
            config.public.kms_key_arn
        ))
    }
}

/// The forward-table line for KMS in the ARN's region, over parent vsock port `vsock_port`.
///
/// # Errors
///
/// `arn` is not a KMS key or alias ARN (see [`kms_region`]).
pub fn kms_forward_line(arn: &str, vsock_port: u32) -> Result<String, String> {
    let region = kms_region(arn)?;
    Ok(format!(
        "outbound kms.{region}.amazonaws.com 443 {vsock_port}"
    ))
}

/// The region of a KMS ARN in the `aws` partition.
///
/// # Errors
///
/// `arn` is not `arn:aws:kms:<region>:<12 digits>:alias/<name>` or `…:key/<id>`.
pub fn kms_region(arn: &str) -> Result<&str, String> {
    let bad = || format!("not a KMS key or alias ARN: {arn:?}");
    let parts: Vec<&str> = arn.split(':').collect();
    let ["arn", "aws", "kms", region, account, resource] = parts.as_slice() else {
        return Err(bad());
    };
    let valid_region = !region.is_empty()
        && region
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    let valid_account = account.len() == 12 && account.chars().all(|c| c.is_ascii_digit());
    let valid_resource = resource
        .strip_prefix("alias/")
        .or_else(|| resource.strip_prefix("key/"))
        .is_some_and(|n| !n.is_empty());
    if !valid_region || !valid_account || !valid_resource {
        return Err(bad());
    }
    Ok(region)
}

/// `kms_line` followed by the blob's `forwards`, parsed as one table.
///
/// # Errors
///
/// A malformed table, or `forwards` claiming parent vsock port `kms_vsock_port` or the KMS host.
pub fn combined_table(
    kms_line: &str,
    forwards: &str,
    kms_vsock_port: u32,
) -> Result<Table, String> {
    let table = Table::parse(&format!("{kms_line}\n{forwards}"))?;
    let kms_host = kms_line.split_whitespace().nth(1).unwrap_or_default();
    for o in table.outbound.iter().skip(1) {
        if o.vsock_port == kms_vsock_port {
            return Err(format!(
                "forwards must not use the KMS vsock port {kms_vsock_port}"
            ));
        }
        if o.host.eq_ignore_ascii_case(kms_host) {
            return Err(format!("forwards must not mention the KMS host {kms_host}"));
        }
    }
    Ok(table)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::net::Ipv4Addr;

    use sha2::{Digest as _, Sha256};

    use super::*;

    const ARN: &str = "arn:aws:kms:eu-central-1:111122223333:alias/oprf-nitro-node";
    const KMS_PORT: u32 = 8100;

    /// Public part as Terraform's `jsonencode` writes it: sorted keys, compact, `>` as `\u003e`,
    /// multi-line PEM values.
    const PUBLIC: &str = r#"{"environment":{"RUST_LOG":"taceo=trace,warn","TACEO_OPRF_NODE__BIND_ADDR":"127.0.0.1:10000","TACEO_OPRF_NODE__NODE_URLS":"https://127.0.0.1:10000,http://services.example:10001,http://services.example:10002","TACEO_OPRF_NODE__SERVICE__VERSION_REQ":"\u003e=0.0.0","TACEO_OPRF_NODE__TLS_PINNED_CERTS":"-----BEGIN CERTIFICATE-----\nMIIBfakeCERT\n-----END CERTIFICATE-----\n","TACEO_OPRF_NODE__TLS__CERT_PEM":"-----BEGIN CERTIFICATE-----\nMIIBfakeCERT\n-----END CERTIFICATE-----\n"},"forwards":"outbound db.example 5432 8101\noutbound services.example 10001 8102\noutbound services.example 10002 8103\ninbound 10000 10000","kms_key_arn":"arn:aws:kms:eu-central-1:111122223333:alias/oprf-nitro-node"}"#;

    /// The node blob with [`PUBLIC`] and fake secrets, encoded as Terraform's `jsonencode` does
    /// (`&` as `\u0026`).
    const BLOB: &str = r#"{"public":"{\"environment\":{\"RUST_LOG\":\"taceo=trace,warn\",\"TACEO_OPRF_NODE__BIND_ADDR\":\"127.0.0.1:10000\",\"TACEO_OPRF_NODE__NODE_URLS\":\"https://127.0.0.1:10000,http://services.example:10001,http://services.example:10002\",\"TACEO_OPRF_NODE__SERVICE__VERSION_REQ\":\"\\u003e=0.0.0\",\"TACEO_OPRF_NODE__TLS_PINNED_CERTS\":\"-----BEGIN CERTIFICATE-----\\nMIIBfakeCERT\\n-----END CERTIFICATE-----\\n\",\"TACEO_OPRF_NODE__TLS__CERT_PEM\":\"-----BEGIN CERTIFICATE-----\\nMIIBfakeCERT\\n-----END CERTIFICATE-----\\n\"},\"forwards\":\"outbound db.example 5432 8101\\noutbound services.example 10001 8102\\noutbound services.example 10002 8103\\ninbound 10000 10000\",\"kms_key_arn\":\"arn:aws:kms:eu-central-1:111122223333:alias/oprf-nitro-node\"}","secret_environment":{"TACEO_OPRF_NODE__POSTGRES__CONNECTION_STRING":"postgres://oprf:p%40ss@db.example:5432/oprf?sslmode=verify-full\u0026sslrootcert=/etc/enclave/rds-ca.pem","TACEO_OPRF_NODE__TLS__KEY_PEM":"-----BEGIN EC PRIVATE KEY-----\nMHcfakeKEY\n-----END EC PRIVATE KEY-----\n"}}"#;

    const DB_URL: &str = "postgres://oprf:p%40ss@db.example:5432/oprf?sslmode=verify-full&sslrootcert=/etc/enclave/rds-ca.pem";
    const KEY_PEM: &str =
        "-----BEGIN EC PRIVATE KEY-----\nMHcfakeKEY\n-----END EC PRIVATE KEY-----\n";

    fn sample() -> Bootstrap {
        Bootstrap {
            ciphertext: vec![0, 1, 2, 250, 255],
            access_key_id: "AKIA123".into(),
            secret_access_key: "s3cr3t-value".into(),
            session_token: "t0ken-value".into(),
            kms_key_arn: ARN.into(),
            kms_vsock_port: KMS_PORT,
        }
    }

    /// A blob whose public part is `public` (serialized here) and whose secrets are `secrets`.
    fn blob(public: &serde_json::Value, secrets: &serde_json::Value) -> Vec<u8> {
        serde_json::json!({
            "public": public.to_string(),
            "secret_environment": secrets,
        })
        .to_string()
        .into_bytes()
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .fold(String::new(), |mut s, b| {
                write!(s, "{b:02x}").unwrap();
                s
            })
    }

    #[test]
    fn bootstrap_v2_round_trips() {
        let b = sample();
        let line = b.to_line();
        assert!(line.ends_with('\n'), "one line");
        assert!(
            line.contains(
                r#""kms_key_arn":"arn:aws:kms:eu-central-1:111122223333:alias/oprf-nitro-node""#
            ),
            "{line}"
        );
        assert!(line.contains(r#""kms_vsock_port":8100"#), "{line}");
        assert_eq!(Bootstrap::from_line(&line), Ok(b));
    }

    #[test]
    fn bootstrap_requires_the_key_fields() {
        let line = r#"{"ciphertext":"AA==","access_key_id":"a","secret_access_key":"s","session_token":"t"}"#;
        Bootstrap::from_line(line).unwrap_err();
    }

    #[test]
    fn bootstrap_debug_hides_secrets() {
        let dbg = format!("{:?}", sample());
        assert!(!dbg.contains("s3cr3t-value"), "{dbg}");
        assert!(!dbg.contains("t0ken-value"), "{dbg}");
    }

    #[test]
    fn kms_region_accepts_key_arn() {
        assert_eq!(kms_region(ARN), Ok("eu-central-1"));
        assert_eq!(
            kms_region(
                "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
            ),
            Ok("us-east-2")
        );
        for bad in [
            "arn:aws-cn:kms:cn-north-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
            "arn:aws-us-gov:kms:us-gov-west-1:111122223333:alias/x",
            "arn:aws:kms:us-east-2:111122223333:key/",
            "arn:aws:kms:us-east-2:111122223333:alias/",
            "arn:aws:kms:us-east-2:111122223333:grant/abc",
            "arn:aws:kms:us-east-2:1111:alias/x",
            "arn:aws:kms:us-east-2:11112222333a:alias/x",
            "arn:aws:kms::111122223333:alias/x",
            "nope",
        ] {
            assert!(kms_region(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn kms_line_uses_the_given_port() {
        assert_eq!(
            kms_forward_line(ARN, KMS_PORT),
            Ok("outbound kms.eu-central-1.amazonaws.com 443 8100".to_owned())
        );
        kms_forward_line("nope", KMS_PORT).unwrap_err();
    }

    #[test]
    fn blob_v2_parses_and_merges_environment() {
        let config = EnclaveConfig::from_json(BLOB.as_bytes()).unwrap();
        assert_eq!(config.public_json, PUBLIC, "public text kept byte for byte");
        assert_eq!(config.public.kms_key_arn, ARN);
        assert_eq!(
            config.public.forwards,
            "outbound db.example 5432 8101\noutbound services.example 10001 8102\noutbound services.example 10002 8103\ninbound 10000 10000"
        );
        assert_eq!(
            config.public.environment["TACEO_OPRF_NODE__SERVICE__VERSION_REQ"],
            ">=0.0.0"
        );
        assert_eq!(
            config.secret_environment["TACEO_OPRF_NODE__TLS__KEY_PEM"], KEY_PEM,
            "multi-line secret values survive"
        );
        let env = config.app_environment();
        assert_eq!(env.len(), 8, "6 public + 2 secret");
        assert_eq!(env["TACEO_OPRF_NODE__POSTGRES__CONNECTION_STRING"], DB_URL);
        assert_eq!(
            env["TACEO_OPRF_NODE__TLS__CERT_PEM"],
            "-----BEGIN CERTIFICATE-----\nMIIBfakeCERT\n-----END CERTIFICATE-----\n"
        );
        assert_eq!(env["RUST_LOG"], "taceo=trace,warn");
    }

    #[test]
    fn blob_v2_rejects_overlapping_key() {
        let json = blob(
            &serde_json::json!({"environment": {"A": "1"}, "forwards": "", "kms_key_arn": ARN}),
            &serde_json::json!({"A": "2"}),
        );
        let err = EnclaveConfig::from_json(&json).unwrap_err();
        assert!(err.contains("\"A\""), "{err}");
        assert!(!err.contains('2'), "the secret value is not echoed: {err}");
    }

    #[test]
    fn blob_v2_rejects_unknown_field() {
        let public = serde_json::json!({"environment": {}, "forwards": "", "kms_key_arn": ARN});
        let outer = serde_json::json!({
            "public": public.to_string(),
            "secret_environment": {},
            "x": 1,
        });
        EnclaveConfig::from_json(outer.to_string().as_bytes()).unwrap_err();
        let inner = serde_json::json!({
            "environment": {}, "forwards": "", "kms_key_arn": ARN, "x": 1,
        });
        EnclaveConfig::from_json(&blob(&inner, &serde_json::json!({}))).unwrap_err();
        EnclaveConfig::from_json(&blob(&public, &serde_json::json!({}))).unwrap();
    }

    #[test]
    fn blob_v2_rejects_missing_fields() {
        let full = serde_json::json!({"environment": {}, "forwards": "", "kms_key_arn": ARN});
        for field in ["environment", "forwards", "kms_key_arn"] {
            let mut public = full.clone();
            public.as_object_mut().unwrap().remove(field);
            let res = EnclaveConfig::from_json(&blob(&public, &serde_json::json!({})));
            assert!(res.is_err(), "public without {field} must be rejected");
        }
        let no_secrets = serde_json::json!({"public": full.to_string()});
        EnclaveConfig::from_json(no_secrets.to_string().as_bytes()).unwrap_err();
    }

    #[test]
    fn blob_error_does_not_quote_secret_values() {
        let public = serde_json::json!({"environment": {}, "forwards": "", "kms_key_arn": ARN});
        for secrets in [
            serde_json::json!({"A": 31_415_926}),
            serde_json::json!("s3cr3t-blob"),
        ] {
            let err = EnclaveConfig::from_json(&blob(&public, &secrets)).unwrap_err();
            assert!(
                !err.contains("31415926") && !err.contains("s3cr3t-blob"),
                "{err}"
            );
        }
    }

    #[test]
    fn blob_v2_rejects_public_as_object() {
        let json = serde_json::json!({
            "public": {"environment": {}, "forwards": "", "kms_key_arn": ARN},
            "secret_environment": {},
        });
        EnclaveConfig::from_json(json.to_string().as_bytes()).unwrap_err();
    }

    #[test]
    fn blob_v2_rejects_bad_env_key_in_either_map() {
        let public = |env: serde_json::Value| serde_json::json!({"environment": env, "forwards": "", "kms_key_arn": ARN});
        let none = serde_json::json!({});
        for bad in ["A B", "1A", "", "A=B", "A\nB"] {
            let err =
                EnclaveConfig::from_json(&blob(&public(serde_json::json!({bad: "1"})), &none))
                    .unwrap_err();
            assert!(err.contains("environment key"), "{err}");
            let err = EnclaveConfig::from_json(&blob(
                &public(serde_json::json!({})),
                &serde_json::json!({bad: "secret"}),
            ))
            .unwrap_err();
            assert!(err.contains("environment key"), "{err}");
            assert!(!err.contains("secret\""), "{err}");
        }
        EnclaveConfig::from_json(&blob(
            &public(serde_json::json!({"_A1": "1"})),
            &serde_json::json!({"_B2": "2"}),
        ))
        .unwrap();
    }

    #[test]
    fn hash_line_is_public_sha256_and_sorted_commitments() {
        let config = EnclaveConfig::from_json(BLOB.as_bytes()).unwrap();
        let expected = format!(
            "config public_sha256={} secrets TACEO_OPRF_NODE__POSTGRES__CONNECTION_STRING={} TACEO_OPRF_NODE__TLS__KEY_PEM={}",
            sha256_hex(PUBLIC.as_bytes()),
            sha256_hex(DB_URL.as_bytes()),
            sha256_hex(KEY_PEM.as_bytes()),
        );
        assert_eq!(config.hash_line(), expected);
    }

    #[test]
    fn hash_line_without_secrets() {
        let public = serde_json::json!({"environment": {}, "forwards": "", "kms_key_arn": ARN});
        let config = EnclaveConfig::from_json(&blob(&public, &serde_json::json!({}))).unwrap();
        assert_eq!(
            config.hash_line(),
            format!(
                "config public_sha256={} secrets",
                sha256_hex(public.to_string().as_bytes())
            )
        );
    }

    #[test]
    fn hash_line_never_contains_secret_values() {
        let config = EnclaveConfig::from_json(BLOB.as_bytes()).unwrap();
        for output in [config.hash_line(), format!("{config:?}")] {
            for secret in ["p%40ss", "MHcfakeKEY", "EC PRIVATE KEY"] {
                assert!(!output.contains(secret), "{secret} leaked into {output}");
            }
        }
    }

    #[test]
    fn arn_mismatch_is_detected() {
        let config = EnclaveConfig::from_json(BLOB.as_bytes()).unwrap();
        check_key(ARN, &config).unwrap();
        for other in [
            "arn:aws:kms:eu-central-1:111122223333:alias/oprf-nitro-enclave",
            "arn:aws:kms:eu-central-1:444455556666:alias/oprf-nitro-node",
            "arn:aws:kms:eu-west-1:111122223333:alias/oprf-nitro-node",
        ] {
            let err = check_key(other, &config).unwrap_err();
            assert!(err.contains(other) && err.contains(ARN), "{err}");
        }
    }

    #[test]
    fn combined_keeps_kms_first() {
        let kms = kms_forward_line(ARN, KMS_PORT).unwrap();
        let config = EnclaveConfig::from_json(BLOB.as_bytes()).unwrap();
        let t = combined_table(&kms, &config.public.forwards, KMS_PORT).unwrap();
        assert_eq!(t.outbound[0].host, "kms.eu-central-1.amazonaws.com");
        assert_eq!(t.outbound[0].vsock_port, KMS_PORT);
        assert_eq!(t.outbound[0].ip, Ipv4Addr::new(127, 0, 0, 2));
        assert_eq!(t.outbound.len(), 4);
        assert_eq!(t.inbound.len(), 1);
    }

    #[test]
    fn combined_rejects_kms_port_and_host() {
        let kms = kms_forward_line(ARN, KMS_PORT).unwrap();
        let err = combined_table(&kms, "outbound evil 443 8100", KMS_PORT).unwrap_err();
        assert!(err.contains("8100"), "{err}");
        for host in [
            "kms.eu-central-1.amazonaws.com",
            "KMS.EU-CENTRAL-1.amazonaws.com",
        ] {
            let err =
                combined_table(&kms, &format!("outbound {host} 444 8109"), KMS_PORT).unwrap_err();
            assert!(err.contains("KMS host"), "{err}");
        }
        combined_table(&kms, "outbound db 5432 8000", KMS_PORT).unwrap();
    }
}
