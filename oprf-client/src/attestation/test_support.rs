//! Synthetic NSM attestation documents for tests ("test anchor / synthetic document").
//!
//! [`signed_document`] builds a fresh rcgen P-384 chain root → intermediate →
//! leaf (the leaf has no EKU, like AWS's) and a `COSE_Sign1` document signed by
//! the leaf with ES384. It returns `(document, anchor_der)`; pass `anchor_der`
//! to `verify_document_with_anchor` / `verify_signed`.
//!
//! Field-override shape: start from [`Fields::default()`] and change what the
//! test is about, e.g.
//! `signed_document(&Fields { nonce: Some(sent.to_vec()), timestamp_ms: now_ms, ..Fields::default() })`.
//!
//! | Field | Default | Encoded as |
//! |---|---|---|
//! | `nonce` | `Some(TEST_NONCE)` | `nonce` bstr, `None` → CBOR null |
//! | `pcr0` | `TEST_PCR0` | `pcrs[0]` bstr (any length) |
//! | `timestamp_ms` | `TEST_TIMESTAMP_MS` | `timestamp` uint |
//! | `digest` | `"SHA384"` | `digest` text |
//! | `user_data` | `Some(user_data_json(&TEST_PUBLIC_SHA256))` | `user_data` bstr, `None` → CBOR null |
//! | `protected` | `protected_header(-35)` | COSE protected header bstr (raw bytes) |
//!
//! The certificates are valid from 1975 to 4096, so any `timestamp_ms` passes the chain check.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair},
};
use ciborium::Value;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, PKCS_ECDSA_P384_SHA384,
};

pub(crate) const TEST_NONCE: [u8; 32] = [0x07; 32];
pub(crate) const TEST_PCR0: [u8; 48] = [0x11; 48];
pub(crate) const TEST_TIMESTAMP_MS: u64 = 1_700_000_000_000;
pub(crate) const TEST_PUBLIC_SHA256: [u8; 32] = [0x22; 32];
pub(crate) const TEST_MODULE_ID: &str = "i-test-enc0";

#[derive(Debug, Clone)]
pub(crate) struct Fields {
    pub(crate) nonce: Option<Vec<u8>>,
    pub(crate) pcr0: Vec<u8>,
    pub(crate) timestamp_ms: u64,
    pub(crate) digest: String,
    pub(crate) user_data: Option<Vec<u8>>,
    pub(crate) protected: Vec<u8>,
}

impl Default for Fields {
    fn default() -> Self {
        Self {
            nonce: Some(TEST_NONCE.to_vec()),
            pcr0: TEST_PCR0.to_vec(),
            timestamp_ms: TEST_TIMESTAMP_MS,
            digest: "SHA384".to_owned(),
            user_data: Some(user_data_json(&TEST_PUBLIC_SHA256)),
            protected: protected_header(-35),
        }
    }
}

/// `{"public_sha256":"<64 lowercase hex>"}`, as the launcher sends it.
pub(crate) fn user_data_json(public_sha256: &[u8; 32]) -> Vec<u8> {
    format!(r#"{{"public_sha256":"{}"}}"#, hex::encode(public_sha256)).into_bytes()
}

/// The encoded COSE protected header `{1: alg}`.
pub(crate) fn protected_header(alg: i64) -> Vec<u8> {
    encode(&Value::Map(vec![(Value::from(1), Value::from(alg))]))
}

/// `UNIX_EPOCH + ms`.
pub(crate) fn at_ms(ms: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(ms)
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("CBOR encoding");
    out
}

fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
}

pub(crate) fn signed_document(fields: &Fields) -> (Vec<u8>, Vec<u8>) {
    let root = CertifiedIssuer::self_signed(
        ca_params(),
        KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("root key"),
    )
    .expect("root");
    let intermediate = CertifiedIssuer::signed_by(
        ca_params(),
        KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("intermediate key"),
        &root,
    )
    .expect("intermediate");
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("leaf key");
    let leaf = CertificateParams::new(Vec::<String>::new())
        .expect("leaf params")
        .signed_by(&leaf_key, &intermediate)
        .expect("leaf");

    let root_der = root.as_ref().der().to_vec();
    let opt_bytes = |b: &Option<Vec<u8>>| b.clone().map_or(Value::Null, Value::Bytes);
    let payload = encode(&Value::Map(vec![
        ("module_id".into(), TEST_MODULE_ID.into()),
        ("digest".into(), fields.digest.as_str().into()),
        ("timestamp".into(), fields.timestamp_ms.into()),
        (
            "pcrs".into(),
            Value::Map(vec![
                (0.into(), Value::Bytes(fields.pcr0.clone())),
                (1.into(), Value::Bytes(vec![0; 48])),
            ]),
        ),
        ("certificate".into(), Value::Bytes(leaf.der().to_vec())),
        (
            "cabundle".into(),
            Value::Array(vec![
                Value::Bytes(root_der.clone()),
                Value::Bytes(intermediate.as_ref().der().to_vec()),
            ]),
        ),
        ("public_key".into(), Value::Null),
        ("user_data".into(), opt_bytes(&fields.user_data)),
        ("nonce".into(), opt_bytes(&fields.nonce)),
    ]));

    let to_sign = encode(&Value::Array(vec![
        "Signature1".into(),
        Value::Bytes(fields.protected.clone()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.clone()),
    ]));
    let signer =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &leaf_key.serialize_der())
            .expect("leaf key for aws-lc-rs");
    let signature = signer
        .sign(&SystemRandom::new(), &to_sign)
        .expect("ES384 signature");

    let document = encode(&Value::Array(vec![
        Value::Bytes(fields.protected.clone()),
        Value::Map(Vec::new()),
        Value::Bytes(payload),
        Value::Bytes(signature.as_ref().to_vec()),
    ]));
    (document, root_der)
}
