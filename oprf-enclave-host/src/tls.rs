//! TLS termination for an inbound port: the certificate lives on the parent, not in the enclave.

use std::sync::Arc;

use eyre::{Context, ensure};
use rustls::ServerConfig;
use rustls::crypto::aws_lc_rs;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

/// Builds an acceptor serving `cert_pem` (leaf first) with `key_pem`, without client
/// authentication.
///
/// # Errors
///
/// No certificate or no private key in the PEMs, or a key that does not match the leaf
/// certificate (`ServerConfig::with_single_cert` checks the public keys, rustls 0.23.46
/// `crypto/signer.rs`, `CertifiedKey::from_der`).
pub fn acceptor(cert_pem: &str, key_pem: &str) -> eyre::Result<TlsAcceptor> {
    let certs = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("parsing TLS certificate PEM")?;
    ensure!(
        !certs.is_empty(),
        "TLS certificate PEM holds no certificate"
    );
    let key =
        PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).context("parsing TLS private key PEM")?;
    let config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .context("selecting TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| eyre::eyre!("TLS certificate and key rejected: {err}"))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use super::*;

    fn pems() -> (String, String) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        (ck.cert.pem(), ck.signing_key.serialize_pem())
    }

    #[test]
    fn acceptor_rejects_mismatched_key() {
        let (cert, key) = pems();
        let (_, other_key) = pems();
        acceptor(&cert, &key).expect("matching pair");
        let err = acceptor(&cert, &other_key).err().expect("mismatch");
        assert!(format!("{err:#}").contains("KeyMismatch"), "{err:#}");
        assert!(acceptor("", &key).is_err(), "no certificate");
        assert!(acceptor(&cert, "").is_err(), "no key");
    }
}
