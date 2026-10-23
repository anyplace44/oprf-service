//! Host configuration: which enclaves this parent serves and how.
//!
//! ```json
//! {"imds_url": "http://169.254.169.254",
//!  "enclaves": [{"name": "key-gen", "cid": 16, "kms_key_arn": "arn:aws:kms:…",
//!                "kms_vsock_port": 8000, "ciphertext": "<path>", "forwards": "<path>",
//!                "inbound_tls": {"port": 10000, "cert": "<path>", "key": "<path>"}}]}
//! ```
//!
//! `inbound_tls` is optional: the host then terminates TLS on that inbound TCP port of the
//! enclave and relays the plaintext.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use eyre::{Context, ensure};
use launcher::bootstrap::{BOOTSTRAP_PORT, LOG_PORT, kms_region};
use launcher::table::Table;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    imds_url: String,
    enclaves: Vec<RawEnclave>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnclave {
    name: String,
    cid: u32,
    kms_key_arn: String,
    kms_vsock_port: u32,
    ciphertext: PathBuf,
    forwards: PathBuf,
    inbound_tls: Option<RawInboundTls>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInboundTls {
    port: u16,
    cert: PathBuf,
    key: PathBuf,
}

/// TLS terminated by the host on one inbound TCP port.
pub struct InboundTls {
    /// The inbound TCP port of the enclave.
    pub port: u16,
    /// PEM certificate chain.
    pub cert_pem: String,
    /// PEM private key.
    pub key_pem: String,
}

impl std::fmt::Debug for InboundTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundTls")
            .field("port", &self.port)
            .field("cert_pem", &self.cert_pem)
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

/// One enclave this parent serves.
#[derive(Debug)]
pub struct Enclave {
    /// Names the enclave in log lines and metrics.
    pub name: String,
    /// Its vsock CID: the only peer its proxies, bootstrap and log connections admit.
    pub cid: u32,
    /// Sent verbatim in the bootstrap message.
    pub kms_key_arn: String,
    /// Sent in the bootstrap message; the parent vsock port of the KMS forward.
    pub kms_vsock_port: u32,
    /// File holding the base64 KMS ciphertext of the enclave's config blob.
    pub ciphertext: PathBuf,
    /// The KMS line first, then the forwards of the enclave's config blob.
    pub table: Table,
    /// TLS to terminate on one of the inbound ports.
    pub inbound_tls: Option<InboundTls>,
}

#[derive(Debug)]
pub struct HostConfig {
    /// Instance metadata service the role credentials are fetched from.
    pub imds_url: String,
    pub enclaves: Vec<Enclave>,
}

impl HostConfig {
    /// Reads the config file and the forward table it names for each enclave.
    ///
    /// # Errors
    ///
    /// An unreadable or malformed file, or any rule of [`Self::parse`] broken.
    pub fn load(path: &Path) -> eyre::Result<Self> {
        let json =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&json, |p| {
            std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))
        })
        .with_context(|| format!("in {}", path.display()))
    }

    /// Parses `json`, reading each forward table through `read`.
    ///
    /// # Errors
    ///
    /// Malformed JSON or tables; an enclave name that is empty or not `[A-Za-z0-9_-]`; a repeated
    /// name or CID; a `kms_key_arn` that is not a KMS ARN; an `inbound_tls` port that is not an inbound TCP port of the enclave; a forward table that does not hold
    /// exactly one outbound line to `kms.<region>.amazonaws.com:443` on `kms_vsock_port`; a
    /// parent vsock port (outbound, bootstrap, logs) or inbound TCP port used twice.
    pub fn parse(
        json: &str,
        mut read: impl FnMut(&Path) -> eyre::Result<String>,
    ) -> eyre::Result<Self> {
        let raw: RawConfig = serde_json::from_str(json).context("parsing host config")?;
        ensure!(!raw.enclaves.is_empty(), "no enclaves configured");
        let mut enclaves: Vec<Enclave> = Vec::new();
        for e in raw.enclaves {
            let name = e.name;
            ensure!(
                !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "enclave name {name:?} must be non-empty and made of [A-Za-z0-9_-]"
            );
            ensure!(
                enclaves.iter().all(|o| o.name != name),
                "enclave name {name:?} used twice"
            );
            ensure!(
                enclaves.iter().all(|o| o.cid != e.cid),
                "enclave {name}: CID {} used twice",
                e.cid
            );
            let text = read(&e.forwards)?;
            let table = Table::parse(&text)
                .map_err(eyre::Report::msg)
                .with_context(|| format!("enclave {name}: forward table"))?;
            check_kms_line(&table, &e.kms_key_arn, e.kms_vsock_port)
                .map_err(|msg| eyre::eyre!("enclave {name}: {msg}"))?;
            let inbound_tls = e
                .inbound_tls
                .map(|t| {
                    ensure!(
                        table.inbound.iter().any(|i| i.tcp_port == t.port),
                        "enclave {name}: inbound_tls port {} is not an inbound TCP port",
                        t.port
                    );
                    Ok(InboundTls {
                        port: t.port,
                        cert_pem: read(&t.cert)?,
                        key_pem: read(&t.key)?,
                    })
                })
                .transpose()?;
            enclaves.push(Enclave {
                name,
                cid: e.cid,
                kms_key_arn: e.kms_key_arn,
                kms_vsock_port: e.kms_vsock_port,
                ciphertext: e.ciphertext,
                table,
                inbound_tls,
            });
        }
        let mut vsock_ports = HashSet::from([BOOTSTRAP_PORT, LOG_PORT]);
        let mut tcp_ports = HashSet::new();
        for e in &enclaves {
            for o in &e.table.outbound {
                ensure!(
                    vsock_ports.insert(o.vsock_port),
                    "enclave {}: parent vsock port {} is already used (outbound of another \
                     enclave, or the bootstrap/log port)",
                    e.name,
                    o.vsock_port
                );
            }
            for i in &e.table.inbound {
                ensure!(
                    tcp_ports.insert(i.tcp_port),
                    "enclave {}: inbound TCP port {} is already used",
                    e.name,
                    i.tcp_port
                );
            }
        }
        Ok(Self {
            imds_url: raw.imds_url,
            enclaves,
        })
    }

    /// The enclave with vsock CID `cid`.
    #[must_use]
    pub fn by_cid(&self, cid: u32) -> Option<&Enclave> {
        self.enclaves.iter().find(|e| e.cid == cid)
    }
}

/// The launcher forwards KMS over `kms_vsock_port` to the KMS host of the ARN's region.
fn check_kms_line(table: &Table, arn: &str, vsock_port: u32) -> Result<(), String> {
    let host = format!("kms.{}.amazonaws.com", kms_region(arn)?);
    let on_host = table
        .outbound
        .iter()
        .filter(|o| o.host.eq_ignore_ascii_case(&host))
        .count();
    let ok = on_host == 1
        && table.outbound.iter().any(|o| {
            o.vsock_port == vsock_port && o.port == 443 && o.host.eq_ignore_ascii_case(&host)
        });
    if ok {
        Ok(())
    } else {
        Err(format!(
            "forward table needs exactly one line `outbound {host} 443 {vsock_port}` and no other \
             line for that host"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KG_ARN: &str = "arn:aws:kms:eu-central-1:111122223333:alias/oprf-nitro-enclave";
    const NODE_ARN: &str = "arn:aws:kms:eu-central-1:111122223333:alias/oprf-nitro-node";
    const KG_TABLE: &str = "outbound kms.eu-central-1.amazonaws.com 443 8000\n\
                            outbound db.internal 5432 8001\ninbound 4321 4321\n";
    const NODE_TABLE: &str = "outbound kms.eu-central-1.amazonaws.com 443 8100\n\
                              outbound db.internal 5432 8101\ninbound 10000 10000\n";

    fn enclave(name: &str, cid: u32, arn: &str, port: u32) -> String {
        format!(
            r#"{{"name":"{name}","cid":{cid},"kms_key_arn":"{arn}","kms_vsock_port":{port},
                "ciphertext":"/c/{name}.b64","forwards":"/f/{name}"}}"#
        )
    }

    fn parse(enclaves: &[String], tables: &[(&str, &str)]) -> eyre::Result<HostConfig> {
        let json = format!(
            r#"{{"imds_url":"http://imds","enclaves":[{}]}}"#,
            enclaves.join(",")
        );
        HostConfig::parse(&json, |p| {
            let key = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            tables
                .iter()
                .find(|(n, _)| *n == key)
                .map(|(_, t)| (*t).to_owned())
                .ok_or_else(|| eyre::eyre!("no table {key}"))
        })
    }

    fn two() -> Vec<String> {
        vec![
            enclave("key-gen", 16, KG_ARN, 8000),
            enclave("node", 17, NODE_ARN, 8100),
        ]
    }

    #[test]
    fn config_loads_two_enclaves() {
        let c = parse(&two(), &[("key-gen", KG_TABLE), ("node", NODE_TABLE)]).expect("valid");
        assert_eq!(c.by_cid(17).expect("node").name, "node");
        assert_eq!(c.by_cid(16).expect("key-gen").kms_key_arn, KG_ARN);
        assert!(c.by_cid(18).is_none());
    }

    #[test]
    fn config_rejects_duplicate_cid() {
        let e = [
            enclave("key-gen", 16, KG_ARN, 8000),
            enclave("node", 16, NODE_ARN, 8100),
        ];
        let err = parse(&e, &[("key-gen", KG_TABLE), ("node", NODE_TABLE)]).expect_err("dup");
        assert!(err.to_string().contains("CID 16 used twice"), "{err:#}");
    }

    #[test]
    fn config_rejects_duplicate_name() {
        let e = [
            enclave("node", 16, KG_ARN, 8000),
            enclave("node", 17, NODE_ARN, 8100),
        ];
        let err = parse(&e, &[("node", KG_TABLE)]).expect_err("dup name");
        assert!(err.to_string().contains("used twice"), "{err:#}");
    }

    fn node_with_tls(port: u16) -> String {
        enclave("node", 17, NODE_ARN, 8100).replace(
            "\"forwards\"",
            &format!(
                r#""inbound_tls":{{"port":{port},"cert":"/t/crt","key":"/t/key"}},"forwards""#
            ),
        )
    }

    #[test]
    fn config_accepts_inbound_tls_on_an_inbound_port() {
        let e = [node_with_tls(10000)];
        let tables = [("node", NODE_TABLE), ("crt", "CERT"), ("key", "KEY")];
        let c = parse(&e, &tables).expect("valid");
        let tls = c.enclaves[0].inbound_tls.as_ref().expect("tls");
        assert_eq!(
            (tls.port, &*tls.cert_pem, &*tls.key_pem),
            (10000, "CERT", "KEY")
        );
        assert!(
            !format!("{tls:?}").contains("KEY"),
            "key is redacted in Debug"
        );
    }

    #[test]
    fn config_rejects_inbound_tls_on_unknown_port() {
        let e = [node_with_tls(4321)];
        let tables = [("node", NODE_TABLE), ("crt", "CERT"), ("key", "KEY")];
        let err = parse(&e, &tables).expect_err("not an inbound port");
        assert!(err.to_string().contains("inbound_tls port 4321"), "{err:#}");
    }

    #[test]
    fn config_rejects_shared_vsock_port() {
        let clash = NODE_TABLE.replace("8101", "8001");
        let err = parse(&two(), &[("key-gen", KG_TABLE), ("node", &clash)]).expect_err("clash");
        assert!(err.to_string().contains("vsock port 8001"), "{err:#}");
        let on_log_port = KG_TABLE.replace("8001", "7002");
        let err = parse(&two(), &[("key-gen", &on_log_port), ("node", NODE_TABLE)])
            .expect_err("log port");
        assert!(err.to_string().contains("vsock port 7002"), "{err:#}");
    }

    #[test]
    fn config_rejects_shared_inbound_port() {
        let clash = NODE_TABLE.replace("10000 10000", "4321 10000");
        let err = parse(&two(), &[("key-gen", KG_TABLE), ("node", &clash)]).expect_err("clash");
        assert!(err.to_string().contains("TCP port 4321"), "{err:#}");
    }

    #[test]
    fn config_rejects_missing_kms_line() {
        for (bad, why) in [
            (
                "outbound db.internal 5432 8001\ninbound 4321 4321\n",
                "absent",
            ),
            (
                "outbound kms.eu-central-1.amazonaws.com 443 8009\ninbound 4321 4321\n",
                "other port",
            ),
            (
                "outbound kms.us-east-1.amazonaws.com 443 8000\ninbound 4321 4321\n",
                "other region",
            ),
            (
                "outbound kms.eu-central-1.amazonaws.com 8443 8000\ninbound 4321 4321\n",
                "other tcp port",
            ),
            (
                "outbound kms.eu-central-1.amazonaws.com 443 8000\n\
                 outbound kms.eu-central-1.amazonaws.com 444 8001\n",
                "second line for the host",
            ),
        ] {
            let err = parse(&two(), &[("key-gen", bad), ("node", NODE_TABLE)]).expect_err(why);
            assert!(
                err.to_string().contains("enclave key-gen"),
                "{why}: {err:#}"
            );
        }
    }

    #[test]
    fn config_rejects_bad_arn_name_and_unknown_field() {
        let e = [enclave(
            "key-gen",
            16,
            "arn:aws-cn:kms:cn-north-1:111122223333:key/x",
            8000,
        )];
        let err = parse(&e, &[("key-gen", KG_TABLE)]).expect_err("cn partition");
        assert!(err.to_string().contains("not a KMS"), "{err:#}");
        let e = [enclave("key gen", 16, KG_ARN, 8000)];
        let err = parse(&e, &[("key gen", KG_TABLE)]).expect_err("space in name");
        assert!(err.to_string().contains("[A-Za-z0-9_-]"), "{err:#}");
        let json = r#"{"imds_url":"x","enclaves":[],"extra":1}"#;
        let err = HostConfig::parse(json, |_| Ok(String::new())).expect_err("unknown field");
        assert!(format!("{err:#}").contains("unknown field"), "{err:#}");
    }
}
