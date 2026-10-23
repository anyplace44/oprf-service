//! Attestation and KMS `Decrypt` of the config blob.
//!
//! [`RecipientKey::decrypt_envelope`]'s content cipher (CMS AES-CBC) is unauthenticated, so two
//! properties must hold here:
//! - each call generates a fresh [`RecipientKey`] and uses it for exactly one decrypt; a key is
//!   never reused, so it can never serve as a padding oracle;
//! - TLS to KMS is verified, hostname included: the envelope's authenticity rests on that
//!   channel alone.

use std::time::Duration;

use aws_sdk_kms::config::timeout::TimeoutConfig;
use aws_sdk_kms::config::{BehaviorVersion, Credentials, Region, SharedHttpClient};
use aws_sdk_kms::error::{DisplayErrorContext, ProvideErrorMetadata as _};
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{KeyEncryptionMechanism, RecipientInfo};
use aws_smithy_http_client::tls::rustls_provider::CryptoMode;
use aws_smithy_http_client::tls::{Provider, TlsContext, TrustStore};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use taceo_oprf_enclave_launcher::bootstrap::{Bootstrap, kms_region};
use taceo_oprf_enclave_launcher::recipient::RecipientKey;

use crate::nsm;

/// Bounds the whole call, retries included, so a stalled KMS path fails the launcher instead
/// of hanging it.
const DECRYPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Attests a fresh RSA key and has KMS decrypt `bootstrap.ciphertext` to it under `key_arn`
/// (alias or key ARN; the caller takes it from the bootstrap message).
pub(crate) fn decrypt_config(bootstrap: &Bootstrap, key_arn: &str) -> Result<Vec<u8>, String> {
    let region = kms_region(key_arn)?;
    let key = RecipientKey::generate()?;
    let document = nsm::attestation(None, None, Some(key.public_key_der()))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    let envelope = runtime.block_on(kms_decrypt(bootstrap, region, key_arn, document))?;
    key.decrypt_envelope(&envelope)
}

async fn kms_decrypt(
    bootstrap: &Bootstrap,
    region: &str,
    key_arn: &str,
    document: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let credentials = Credentials::new(
        bootstrap.access_key_id.clone(),
        bootstrap.secret_access_key.clone(),
        Some(bootstrap.session_token.clone()),
        None,
        "bootstrap",
    );
    let config = aws_sdk_kms::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(region.to_owned()))
        .credentials_provider(credentials)
        .http_client(http_client()?)
        .timeout_config(
            TimeoutConfig::builder()
                .operation_timeout(DECRYPT_TIMEOUT)
                .build(),
        )
        .build();
    let recipient = RecipientInfo::builder()
        .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
        .attestation_document(Blob::new(document))
        .build();
    let output = aws_sdk_kms::Client::from_conf(config)
        .decrypt()
        .key_id(key_arn)
        .ciphertext_blob(Blob::new(bootstrap.ciphertext.clone()))
        .recipient(recipient)
        .send()
        .await
        .map_err(|e| match e.code() {
            Some(code) => format!("KMS Decrypt: {code}: {}", e.message().unwrap_or_default()),
            None => format!("KMS Decrypt: {}", DisplayErrorContext(&e)),
        })?;
    output
        .ciphertext_for_recipient()
        .map(|b| b.as_ref().to_vec())
        .ok_or_else(|| "KMS Decrypt: response has no CiphertextForRecipient".to_owned())
}

/// Common names of the Amazon Trust Services roots, the only roots KMS endpoints chain to.
const KMS_ROOT_CNS: [&str; 5] = [
    "Amazon Root CA 1",
    "Amazon Root CA 2",
    "Amazon Root CA 3",
    "Amazon Root CA 4",
    "Starfield Services Root Certificate Authority - G2",
];

/// The SDK's rustls client, trusting only the Amazon Trust Services roots, taken from the
/// Mozilla roots compiled in by `webpki-root-certs`. Its default would load the platform store,
/// whose presence in the EIF is a property of the rootfs (and of `SSL_CERT_FILE`); a missing
/// store only shows as a failed handshake.
fn http_client() -> Result<SharedHttpClient, String> {
    let mut roots = TrustStore::empty();
    for der in kms_roots()? {
        // The trust store takes PEM only.
        roots.add_pem_certificate(format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(der)
        ));
    }
    let context = TlsContext::builder()
        .with_trust_store(roots)
        .build()
        .map_err(|e| format!("TLS context: {e}"))?;
    Ok(aws_smithy_http_client::Builder::new()
        .tls_provider(Provider::Rustls(CryptoMode::AwsLc))
        .tls_context(context)
        .build_https())
}

/// One certificate per [`KMS_ROOT_CNS`] entry, matched by subject; an error names any that is
/// missing.
fn kms_roots() -> Result<Vec<&'static [u8]>, String> {
    KMS_ROOT_CNS
        .iter()
        .map(|cn| {
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .find(|der| {
                    webpki::anchor_from_trusted_cert(der)
                        .is_ok_and(|anchor| subject_has_cn(&anchor.subject, cn))
                })
                .map(AsRef::as_ref)
                .ok_or_else(|| format!("TLS root {cn:?} missing from webpki-root-certs"))
        })
        .collect()
}

/// Whether the DER `subject` (a Name's contents) holds the attribute `id-at-commonName = cn`
/// as a `PrintableString` or `UTF8String`.
fn subject_has_cn(subject: &[u8], cn: &str) -> bool {
    let Some(len) = u8::try_from(cn.len()).ok().filter(|&l| l < 0x80) else {
        return false;
    };
    [0x13, 0x0c].into_iter().any(|tag| {
        let mut attr = vec![0x06, 0x03, 0x55, 0x04, 0x03, tag, len];
        attr.extend_from_slice(cn.as_bytes());
        subject.windows(attr.len()).any(|w| w == attr)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kms_roots_are_the_five_amazon_roots() {
        let roots = kms_roots().expect("all roots present");
        assert_eq!(roots.len(), KMS_ROOT_CNS.len(), "one certificate per name");
        for (i, a) in roots.iter().enumerate() {
            assert!(
                roots[i + 1..].iter().all(|b| a != b),
                "names select distinct certificates"
            );
        }
    }

    #[test]
    fn common_name_must_match_exactly() {
        let root = webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .find(|der| {
                webpki::anchor_from_trusted_cert(der)
                    .is_ok_and(|a| subject_has_cn(&a.subject, "Amazon Root CA 1"))
            })
            .expect("Amazon Root CA 1");
        let anchor = webpki::anchor_from_trusted_cert(root).expect("anchor");
        assert!(
            !subject_has_cn(&anchor.subject, "Amazon Root CA"),
            "a prefix is not a match"
        );
        assert!(
            !subject_has_cn(&anchor.subject, "Amazon Root CA 2"),
            "another root's name is not a match"
        );
    }
}
