//! Attestation and KMS `Decrypt` of the config blob.
//!
//! [`RecipientKey::decrypt_envelope`]'s content cipher (CMS AES-CBC) is unauthenticated, so two
//! properties must hold here:
//! - each call generates a fresh [`RecipientKey`] and uses it for exactly one decrypt; a key is
//!   never reused, so it can never serve as a padding oracle;
//! - TLS to KMS is verified, hostname included: the envelope's authenticity rests on that
//!   channel alone.

use std::time::Duration;

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
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

/// Bounds the whole call, retries included, so a stalled KMS path fails the launcher instead
/// of hanging it.
const DECRYPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Attests a fresh RSA key and has KMS decrypt `bootstrap.ciphertext` to it under `alias_arn`.
pub(crate) fn decrypt_config(bootstrap: &Bootstrap, alias_arn: &str) -> Result<Vec<u8>, String> {
    let region = kms_region(alias_arn)?;
    let key = RecipientKey::generate()?;
    let document = attest(key.public_key_der())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    let envelope = runtime.block_on(kms_decrypt(bootstrap, region, alias_arn, document))?;
    key.decrypt_envelope(&envelope)
}

fn attest(public_key: Vec<u8>) -> Result<Vec<u8>, String> {
    let fd = nsm_init();
    if fd < 0 {
        return Err("cannot open /dev/nsm".to_owned());
    }
    let response = nsm_process_request(
        fd,
        Request::Attestation {
            user_data: None,
            nonce: None,
            public_key: Some(public_key.into()),
        },
    );
    nsm_exit(fd);
    match response {
        Response::Attestation { document } => Ok(document),
        other => Err(format!("NSM attestation: {other:?}")),
    }
}

async fn kms_decrypt(
    bootstrap: &Bootstrap,
    region: &str,
    alias_arn: &str,
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
        .key_id(alias_arn)
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

/// The SDK's rustls client, trusting only the Mozilla roots compiled in from
/// `webpki-root-certs`. Its default would load the platform store, whose presence in the EIF
/// is a property of the rootfs (and of `SSL_CERT_FILE`); a missing store only shows as a
/// failed handshake.
fn http_client() -> Result<SharedHttpClient, String> {
    let mut roots = TrustStore::empty();
    for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
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
