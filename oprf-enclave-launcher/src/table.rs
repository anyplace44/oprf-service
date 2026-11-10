//! Parser for the forward table.
//!
//! ```text
//! # outbound <host> <port> <vsock-port>: enclave TCP -> parent vsock -> <host>:<port>
//! outbound db.internal 5432 8001
//! # inbound <tcp-port> <vsock-port>: parent vsock -> enclave 127.0.0.1:<tcp-port>
//! inbound 4321 4321
//! ```

use std::net::Ipv4Addr;

/// A connection the enclave opens to `host:port`, carried over vsock port `vsock_port` of the parent.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Outbound {
    /// Destination host, dialed by the parent.
    pub host: String,
    /// Destination TCP port.
    pub port: u16,
    /// Parent vsock port the enclave dials.
    pub vsock_port: u32,
    /// Loopback address `host` resolves to inside the enclave.
    pub ip: Ipv4Addr,
}

/// A connection the parent opens to the enclave's vsock port `vsock_port`, delivered to
/// `127.0.0.1:tcp_port` inside the enclave.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Inbound {
    /// Port key-gen listens on inside the enclave; the parent listens on it too.
    pub tcp_port: u16,
    /// Enclave vsock port the parent dials.
    pub vsock_port: u32,
}

/// The parsed forward table.
#[derive(Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Table {
    /// Enclave-to-parent forwards.
    pub outbound: Vec<Outbound>,
    /// Parent-to-enclave forwards.
    pub inbound: Vec<Inbound>,
}

impl Table {
    /// Parses the forward table format shown in the module docs.
    ///
    /// # Errors
    ///
    /// A malformed line, a reused vsock port or listener, or more than 254 hosts; the message
    /// names the line.
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut table = Self::default();
        for (idx, line) in s.lines().enumerate() {
            let fields: Vec<&str> = line
                .split('#')
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .collect();
            let err = |msg: &str| format!("forwards line {}: {msg}: {line:?}", idx + 1);
            match fields.as_slice() {
                [] => {}
                ["outbound", host, port, vsock_port] => {
                    let port = port.parse().map_err(|_| err("bad port"))?;
                    let vsock_port = vsock_port.parse().map_err(|_| err("bad vsock port"))?;
                    let ip = table.ip_for(host).ok_or_else(|| err("too many hosts"))?;
                    if table.outbound.iter().any(|o| o.vsock_port == vsock_port) {
                        return Err(err("vsock port already used"));
                    }
                    if table.outbound.iter().any(|o| o.ip == ip && o.port == port) {
                        return Err(err("host and port already forwarded"));
                    }
                    table.outbound.push(Outbound {
                        host: (*host).to_owned(),
                        port,
                        vsock_port,
                        ip,
                    });
                }
                ["inbound", tcp_port, vsock_port] => {
                    let tcp_port = tcp_port.parse().map_err(|_| err("bad port"))?;
                    let vsock_port = vsock_port.parse().map_err(|_| err("bad vsock port"))?;
                    if table.inbound.iter().any(|i| i.vsock_port == vsock_port) {
                        return Err(err("vsock port already used"));
                    }
                    table.inbound.push(Inbound {
                        tcp_port,
                        vsock_port,
                    });
                }
                _ => {
                    return Err(err(
                        "expected `outbound <host> <port> <vsock-port>` or `inbound <tcp-port> <vsock-port>`",
                    ));
                }
            }
        }
        Ok(table)
    }

    /// The host's existing address, or the next free one from 127.0.0.2.
    fn ip_for(&self, host: &str) -> Option<Ipv4Addr> {
        if let Some(o) = self.outbound.iter().find(|o| o.host == host) {
            return Some(o.ip);
        }
        let used = self.outbound.iter().map(|o| o.ip).max();
        let next = used.map_or(Some(2), |ip| ip.octets()[3].checked_add(1))?;
        Some(Ipv4Addr::new(127, 0, 0, next))
    }

    /// `/etc/hosts` mapping every outbound host to its loopback address.
    #[must_use]
    pub fn hosts(&self) -> String {
        let mut hosts = String::from("127.0.0.1 localhost\n");
        hosts.extend(
            self.outbound
                .iter()
                .enumerate()
                .filter(|(i, o)| self.outbound[..*i].iter().all(|prev| prev.host != o.host))
                .map(|(_, o)| format!("{} {}\n", o.ip, o.host)),
        );
        hosts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(host: &str, port: u16, vsock_port: u32, last_octet: u8) -> Outbound {
        Outbound {
            host: host.to_owned(),
            port,
            vsock_port,
            ip: Ipv4Addr::new(127, 0, 0, last_octet),
        }
    }

    #[test]
    fn parses_forwards_and_gives_each_host_one_loopback_ip() {
        let table = Table::parse(
            "# comment\n\
             outbound db.internal 5432 8001\n\
             \n\
             outbound rpc.example.com 443 8002\n\
             outbound db.internal 6432 8003   # second port, same host\n\
             inbound 4321 4321\n",
        )
        .expect("valid table");
        assert_eq!(
            table,
            Table {
                outbound: vec![
                    out("db.internal", 5432, 8001, 2),
                    out("rpc.example.com", 443, 8002, 3),
                    out("db.internal", 6432, 8003, 2),
                ],
                inbound: vec![Inbound {
                    tcp_port: 4321,
                    vsock_port: 4321
                }],
            },
            "hosts get 127.0.0.2.. in order of first appearance"
        );
    }

    #[test]
    fn hosts_lists_localhost_and_each_host_once() {
        let table = Table::parse(
            "outbound db.internal 5432 8001\n\
             outbound rpc.example.com 443 8002\n\
             outbound db.internal 6432 8003\n",
        )
        .expect("valid table");
        assert_eq!(
            table.hosts(),
            "127.0.0.1 localhost\n127.0.0.2 db.internal\n127.0.0.3 rpc.example.com\n",
            "one line per distinct host"
        );
    }

    #[test]
    fn rejects_malformed_lines_with_line_number() {
        for (input, needle) in [
            ("outbound db.internal 5432\n", "line 1"),
            ("\noutbound db.internal 5432 8001 extra\n", "line 2"),
            ("sideways db.internal 5432 8001\n", "line 1"),
            ("outbound db.internal 70000 8001\n", "line 1"),
            ("inbound 4321\n", "line 1"),
            ("inbound 4321 x\n", "line 1"),
        ] {
            let err = Table::parse(input).expect_err(input);
            assert!(err.contains(needle), "{input:?} -> {err}");
        }
    }

    #[test]
    fn rejects_reused_vsock_port_and_listener() {
        let err = Table::parse("outbound a 1 8001\noutbound b 2 8001\n").expect_err("dup vsock");
        assert!(err.contains("line 2"), "{err}");
        let err = Table::parse("outbound a 1 8001\noutbound a 1 8002\n").expect_err("dup listener");
        assert!(err.contains("line 2"), "{err}");
        let err = Table::parse("inbound 1 9001\ninbound 2 9001\n").expect_err("dup inbound vsock");
        assert!(err.contains("line 2"), "{err}");
    }
}
