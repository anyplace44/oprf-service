//! Wire types shared by the enclave launcher and the parent-side `oprf-enclave-host`.

use std::collections::BTreeMap;
use std::fmt;

use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::table::Table;

/// Enclave vsock port the parent delivers the [`Bootstrap`] line to.
pub const BOOTSTRAP_PORT: u32 = 7001;
/// Parent vsock port the enclave streams its log lines to.
pub const LOG_PORT: u32 = 7002;
/// Parent vsock port carrying the enclave's KMS traffic.
pub const KMS_VSOCK_PORT: u32 = 8000;

/// What the parent sends on [`BOOTSTRAP_PORT`]: the encrypted config blob and the credentials
/// to decrypt it with.
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

/// The decrypted blob: key-gen's whole environment and the forward table.
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::exhaustive_structs,
    reason = "wire type, fields are the wire format"
)]
pub struct EnclaveConfig {
    /// Exactly the environment key-gen runs with.
    pub environment: BTreeMap<String, String>,
    /// Forward table text, without the KMS line.
    pub forwards: String,
}

impl EnclaveConfig {
    /// Parses the blob plaintext.
    ///
    /// # Errors
    ///
    /// Malformed JSON, unknown fields, or an environment key that is not
    /// `[A-Za-z_][A-Za-z0-9_]*`.
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        let config: Self =
            serde_json::from_slice(bytes).map_err(|e| format!("enclave config: {e}"))?;
        for key in config.environment.keys() {
            let mut chars = key.chars();
            let first_ok = chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
            if !first_ok || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(format!("enclave config: bad environment key {key:?}"));
            }
        }
        Ok(config)
    }
}

/// The forward-table line for KMS in the alias ARN's region.
///
/// # Errors
///
/// `alias_arn` is not `arn:aws:kms:<region>:<account>:alias/<name>`.
pub fn kms_forward_line(alias_arn: &str) -> Result<String, String> {
    let region = kms_region(alias_arn)?;
    Ok(format!(
        "outbound kms.{region}.amazonaws.com 443 {KMS_VSOCK_PORT}"
    ))
}

/// The region of a KMS alias ARN.
///
/// # Errors
///
/// `alias_arn` is not `arn:aws:kms:<region>:<account>:alias/<name>`.
pub fn kms_region(alias_arn: &str) -> Result<&str, String> {
    let bad = || format!("not a KMS alias ARN: {alias_arn:?}");
    let parts: Vec<&str> = alias_arn.split(':').collect();
    let ["arn", "aws", "kms", region, account, resource] = parts.as_slice() else {
        return Err(bad());
    };
    let valid_region = !region.is_empty()
        && region
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    let valid_alias = resource
        .strip_prefix("alias/")
        .is_some_and(|n| !n.is_empty());
    if !valid_region || account.is_empty() || !valid_alias {
        return Err(bad());
    }
    Ok(region)
}

/// The KMS line followed by the blob's forwards, parsed as one table.
///
/// # Errors
///
/// A bad ARN, a malformed table, or a blob table that claims vsock port [`KMS_VSOCK_PORT`] or
/// the KMS host.
pub fn combined_table(alias_arn: &str, config: &EnclaveConfig) -> Result<Table, String> {
    let kms = kms_forward_line(alias_arn)?;
    let table = Table::parse(&format!("{kms}\n{}", config.forwards))?;
    let kms_host = kms.split_whitespace().nth(1).unwrap_or_default();
    if table
        .outbound
        .iter()
        .skip(1)
        .any(|o| o.host.eq_ignore_ascii_case(kms_host))
    {
        return Err(format!("forwards must not mention the KMS host {kms_host}"));
    }
    Ok(table)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const ARN: &str = "arn:aws:kms:eu-central-1:575490177671:alias/oprf-nitro-enclave";

    fn sample() -> Bootstrap {
        Bootstrap {
            ciphertext: vec![0, 1, 2, 250, 255],
            access_key_id: "AKIA123".into(),
            secret_access_key: "s3cr3t-value".into(),
            session_token: "t0ken-value".into(),
        }
    }

    fn config(forwards: &str) -> EnclaveConfig {
        EnclaveConfig {
            environment: BTreeMap::new(),
            forwards: forwards.into(),
        }
    }

    #[test]
    fn bootstrap_round_trips() {
        let b = sample();
        let line = b.to_line();
        assert!(line.ends_with('\n'));
        assert_eq!(Bootstrap::from_line(&line), Ok(b));
    }

    #[test]
    fn bootstrap_debug_hides_secrets() {
        let dbg = format!("{:?}", sample());
        assert!(!dbg.contains("s3cr3t-value"));
        assert!(!dbg.contains("t0ken-value"));
    }

    #[test]
    fn config_rejects_unknown_field() {
        EnclaveConfig::from_json(br#"{"environment":{},"forwards":"","x":1}"#).unwrap_err();
    }

    #[test]
    fn config_rejects_bad_env_key() {
        let json = br#"{"environment":{"A B":"1"},"forwards":""}"#;
        EnclaveConfig::from_json(json).unwrap_err();
        let ok = br#"{"environment":{"_A1":"1"},"forwards":""}"#;
        EnclaveConfig::from_json(ok).unwrap();
    }

    #[test]
    fn kms_line_from_alias_arn() {
        assert_eq!(kms_region(ARN), Ok("eu-central-1"));
        assert_eq!(
            kms_forward_line(ARN),
            Ok("outbound kms.eu-central-1.amazonaws.com 443 8000".to_owned())
        );
        kms_forward_line("arn:aws:kms:eu-central-1:575490177671:key/abc").unwrap_err();
        kms_forward_line("nope").unwrap_err();
    }

    #[test]
    fn combined_keeps_kms_first() {
        let t = combined_table(
            ARN,
            &config("outbound db.example 5432 8001\ninbound 4321 4321"),
        )
        .unwrap();
        assert_eq!(t.outbound[0].host, "kms.eu-central-1.amazonaws.com");
        assert_eq!(t.outbound[0].ip, Ipv4Addr::new(127, 0, 0, 2));
        assert_eq!(t.outbound.len(), 2);
        assert_eq!(t.inbound.len(), 1);
    }

    #[test]
    fn combined_rejects_kms_port() {
        combined_table(ARN, &config("outbound evil 443 8000")).unwrap_err();
    }

    #[test]
    fn combined_rejects_kms_host() {
        let f = "outbound kms.eu-central-1.amazonaws.com 443 8009";
        combined_table(ARN, &config(f)).unwrap_err();
    }

    #[test]
    fn combined_rejects_kms_host_on_other_port() {
        for host in [
            "kms.eu-central-1.amazonaws.com",
            "KMS.EU-CENTRAL-1.amazonaws.com",
        ] {
            let err =
                combined_table(ARN, &config(&format!("outbound {host} 444 8009"))).unwrap_err();
            assert!(err.contains("KMS host"), "{err}");
        }
    }
}
