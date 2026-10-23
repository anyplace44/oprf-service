use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ciborium::Value;
use rustls_pki_types::{CertificateDer, UnixTime};
use webpki::{EndEntityCert, KeyUsage, aws_lc_rs::ECDSA_P384_SHA384};

use super::{AttestationFailure, VerifiedAttestation};

/// AWS Nitro Enclaves Root G1 (DER), from AWS's `AWS_NitroEnclaves_Root-G1.zip`.
pub(crate) const AWS_NITRO_ROOT_G1: &[u8] = include_bytes!("aws-nitro-enclaves-root-g1.der");

/// COSE algorithm id of ES384.
const ES384: i64 = -35;
/// `COSE_Sign1` tag.
const COSE_SIGN1_TAG: u64 = 18;
/// Largest accepted `|now − timestamp|`.
const MAX_TIMESTAMP_SKEW_MS: u64 = 300_000;

/// The payload fields of an attestation document whose COSE signature and chain verified.
#[derive(Debug)]
pub(crate) struct Payload {
    pub(crate) module_id: String,
    pub(crate) digest: String,
    pub(crate) timestamp_ms: u64,
    pub(crate) pcr0: Vec<u8>,
    pub(crate) nonce: Option<Vec<u8>>,
    pub(crate) user_data: Option<Vec<u8>>,
}

/// Verifies an NSM attestation document against the bundled AWS Nitro root.
///
/// `nonce` is the nonce sent with the request, `allowed_pcr0` the PCR0 values
/// accepted for this node, `now` the local time the timestamp is checked against.
pub fn verify_document(
    document: &[u8],
    nonce: &[u8; 32],
    allowed_pcr0: &[[u8; 48]],
    now: SystemTime,
) -> Result<VerifiedAttestation, AttestationFailure> {
    verify_document_with_anchor(document, nonce, allowed_pcr0, now, AWS_NITRO_ROOT_G1)
}

pub(crate) fn verify_document_with_anchor(
    document: &[u8],
    nonce: &[u8; 32],
    allowed_pcr0: &[[u8; 48]],
    now: SystemTime,
    anchor_der: &[u8],
) -> Result<VerifiedAttestation, AttestationFailure> {
    let payload = verify_signed(document, anchor_der)?;
    if payload.digest != "SHA384" {
        return Err(AttestationFailure::Digest(payload.digest));
    }
    let pcr0: [u8; 48] = payload
        .pcr0
        .as_slice()
        .try_into()
        .map_err(|_| malformed(format!("PCR0 is {} bytes, expected 48", payload.pcr0.len())))?;
    if pcr0 == [0; 48] {
        return Err(AttestationFailure::DebugMode);
    }
    if payload.nonce.as_deref() != Some(nonce.as_slice()) {
        return Err(AttestationFailure::Nonce);
    }
    let now_ms = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    if payload.timestamp_ms.abs_diff(now_ms) > MAX_TIMESTAMP_SKEW_MS {
        return Err(AttestationFailure::Timestamp {
            document_ms: payload.timestamp_ms,
            now_ms,
        });
    }
    if !allowed_pcr0.contains(&pcr0) {
        return Err(AttestationFailure::Pcr0NotAllowed(hex::encode(pcr0)));
    }
    let public_sha256 = public_sha256(payload.user_data.as_deref())?;
    Ok(VerifiedAttestation {
        pcr0,
        public_sha256,
        timestamp_ms: payload.timestamp_ms,
        module_id: payload.module_id,
    })
}

/// Checks the `COSE_Sign1` structure and ES384 header, the certificate chain to
/// `anchor_der` at the document's timestamp, and the signature.
pub(crate) fn verify_signed(
    document: &[u8],
    anchor_der: &[u8],
) -> Result<Payload, AttestationFailure> {
    let cose = match decode(document, "COSE_Sign1")? {
        Value::Tag(COSE_SIGN1_TAG, inner) => *inner,
        other => other,
    };
    let Value::Array(items) = cose else {
        return Err(malformed("COSE_Sign1 is not an array"));
    };
    let Ok(
        [
            Value::Bytes(protected),
            Value::Map(_),
            Value::Bytes(payload_bytes),
            Value::Bytes(signature),
        ],
    ) = <[Value; 4]>::try_from(items)
    else {
        return Err(malformed(
            "COSE_Sign1 is not [protected bstr, unprotected map, payload bstr, signature bstr]",
        ));
    };
    check_algorithm(&protected)?;
    let fields = PayloadFields::parse(&payload_bytes)?;

    let leaf_der = CertificateDer::from(fields.certificate.as_slice());
    let leaf = EndEntityCert::try_from(&leaf_der)
        .map_err(|e| AttestationFailure::Chain(format!("leaf certificate: {e}")))?;
    let anchor_cert = CertificateDer::from(anchor_der);
    let anchor = webpki::anchor_from_trusted_cert(&anchor_cert)
        .map_err(|e| AttestationFailure::Chain(format!("trust anchor: {e}")))?;
    let intermediates: Vec<CertificateDer<'_>> = fields
        .cabundle
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    leaf.verify_for_usage(
        &[ECDSA_P384_SHA384],
        &[anchor],
        &intermediates,
        UnixTime::since_unix_epoch(Duration::from_millis(fields.payload.timestamp_ms)),
        KeyUsage::client_auth(),
        None,
        None,
    )
    .map_err(|e| AttestationFailure::Chain(e.to_string()))?;

    let signed = encode(&Value::Array(vec![
        Value::Text("Signature1".to_owned()),
        Value::Bytes(protected),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload_bytes),
    ]))?;
    leaf.verify_signature(ECDSA_P384_SHA384, &signed, &es384_to_der(&signature)?)
        .map_err(|_| AttestationFailure::Signature)?;
    Ok(fields.payload)
}

fn malformed(reason: impl Into<String>) -> AttestationFailure {
    AttestationFailure::Malformed(reason.into())
}

fn decode(mut bytes: &[u8], what: &str) -> Result<Value, AttestationFailure> {
    let value: Value =
        ciborium::from_reader(&mut bytes).map_err(|e| malformed(format!("{what}: {e}")))?;
    if bytes.is_empty() {
        Ok(value)
    } else {
        Err(malformed(format!("{what}: trailing bytes")))
    }
}

fn encode(value: &Value) -> Result<Vec<u8>, AttestationFailure> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| malformed(format!("encoding: {e}")))?;
    Ok(out)
}

fn check_algorithm(protected: &[u8]) -> Result<(), AttestationFailure> {
    let Value::Map(header) = decode(protected, "protected header")? else {
        return Err(malformed("protected header is not a map"));
    };
    let alg = header
        .iter()
        .find(|(k, _)| k.as_integer() == Some(1.into()))
        .and_then(|(_, v)| v.as_integer())
        .ok_or_else(|| malformed("protected header has no integer alg (1)"))?;
    let alg = i64::try_from(alg).map_err(|_| malformed("protected header alg out of range"))?;
    if alg == ES384 {
        Ok(())
    } else {
        Err(AttestationFailure::UnsupportedAlgorithm(alg))
    }
}

/// The parsed payload plus the certificates the signature check needs.
struct PayloadFields {
    payload: Payload,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
}

impl PayloadFields {
    fn parse(bytes: &[u8]) -> Result<Self, AttestationFailure> {
        let Value::Map(map) = decode(bytes, "payload")? else {
            return Err(malformed("payload is not a map"));
        };
        let get = |name: &str| {
            map.iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .map(|(_, v)| v)
        };
        let text = |name: &str| {
            get(name)
                .and_then(Value::as_text)
                .map(ToOwned::to_owned)
                .ok_or_else(|| malformed(format!("payload {name} missing or not text")))
        };
        let bstr = |name: &str| {
            get(name)
                .and_then(Value::as_bytes)
                .cloned()
                .ok_or_else(|| malformed(format!("payload {name} missing or not bytes")))
        };
        let optional_bytes = |name: &str| match get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bytes(b)) => Ok(Some(b.clone())),
            Some(_) => Err(malformed(format!("payload {name} is not bytes or null"))),
        };

        let timestamp_ms = get("timestamp")
            .and_then(Value::as_integer)
            .and_then(|t| u64::try_from(t).ok())
            .ok_or_else(|| malformed("payload timestamp missing or not an unsigned integer"))?;
        let pcr0 = get("pcrs")
            .and_then(Value::as_map)
            .and_then(|pcrs| pcrs.iter().find(|(k, _)| k.as_integer() == Some(0.into())))
            .and_then(|(_, v)| v.as_bytes())
            .cloned()
            .ok_or_else(|| malformed("payload pcrs[0] missing or not bytes"))?;
        let cabundle = get("cabundle")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("payload cabundle missing or not an array"))?
            .iter()
            .map(|c| {
                c.as_bytes()
                    .cloned()
                    .ok_or_else(|| malformed("payload cabundle entry is not bytes"))
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            payload: Payload {
                module_id: text("module_id")?,
                digest: text("digest")?,
                timestamp_ms,
                pcr0,
                nonce: optional_bytes("nonce")?,
                user_data: optional_bytes("user_data")?,
            },
            certificate: bstr("certificate")?,
            cabundle,
        })
    }
}

/// Converts a COSE ES384 signature (`r ‖ s`, 48 bytes each) to a DER `ECDSA-Sig-Value`.
fn es384_to_der(signature: &[u8]) -> Result<Vec<u8>, AttestationFailure> {
    if signature.len() != 96 {
        return Err(malformed(format!(
            "ES384 signature is {} bytes, expected 96",
            signature.len()
        )));
    }
    let (r, s) = signature.split_at(48);
    let mut body = Vec::with_capacity(102);
    der_unsigned_integer(&mut body, r);
    der_unsigned_integer(&mut body, s);
    let mut out = Vec::with_capacity(body.len() + 2);
    out.push(0x30);
    push_short_len(&mut out, body.len());
    out.extend(body);
    Ok(out)
}

fn der_unsigned_integer(out: &mut Vec<u8>, bytes: &[u8]) {
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let value = &bytes[start..];
    out.push(0x02);
    if value[0] & 0x80 == 0 {
        push_short_len(out, value.len());
    } else {
        push_short_len(out, value.len() + 1);
        out.push(0);
    }
    out.extend_from_slice(value);
}

/// DER short-form length; every length here is at most 102.
fn push_short_len(out: &mut Vec<u8>, len: usize) {
    out.push(u8::try_from(len).expect("DER length below 128"));
}

/// `public_sha256` from `user_data` JSON (extra fields are allowed).
fn public_sha256(user_data: Option<&[u8]>) -> Result<[u8; 32], AttestationFailure> {
    let user_data = user_data.ok_or_else(|| AttestationFailure::UserData("missing".to_owned()))?;
    let json: serde_json::Value = serde_json::from_slice(user_data)
        .map_err(|e| AttestationFailure::UserData(format!("not JSON: {e}")))?;
    let hex_str = json
        .get("public_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AttestationFailure::UserData("no public_sha256 string".to_owned()))?;
    let mut out = [0; 32];
    hex::decode_to_slice(hex_str, &mut out).map_err(|e| {
        AttestationFailure::UserData(format!("public_sha256 is not 64 hex characters: {e}"))
    })?;
    Ok(out)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    clippy::assertions_on_result_states,
    reason = "test code"
)]
mod tests {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PKCS_ECDSA_P384_SHA384};
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::attestation::test_support::{
        Fields, TEST_MODULE_ID, TEST_NONCE, TEST_PCR0, TEST_PUBLIC_SHA256, TEST_TIMESTAMP_MS,
        at_ms, protected_header, signed_document,
    };

    const VALID: &[u8] = include_bytes!("../../tests/fixtures/nitro/valid-attestation-doc-bytes");
    const DEBUG: &[u8] =
        include_bytes!("../../tests/fixtures/nitro/debug-mode-attestation-doc-bytes");
    const VALID_PCR0: &str = "f4d48b81a460c9916d1e685119074bf24660afd3e34fae9fca0a0d28d9d5599936332687e6f66fc890ac8cf150142d8b";
    const VALID_TIMESTAMP_MS: u64 = 1_665_651_482_136;

    fn flip_byte(document: &[u8], index: usize) -> Vec<u8> {
        let mut out = document.to_vec();
        out[index] ^= 0x01;
        out
    }

    #[test]
    fn bundled_root_is_aws_nitro_g1() {
        assert_eq!(
            hex::encode(Sha256::digest(AWS_NITRO_ROOT_G1)),
            "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
        );
    }

    #[test]
    fn real_production_document_verifies() {
        let payload = verify_signed(VALID, AWS_NITRO_ROOT_G1).unwrap();
        assert_eq!(hex::encode(&payload.pcr0), VALID_PCR0);
        assert_eq!(payload.timestamp_ms, VALID_TIMESTAMP_MS);
    }

    #[test]
    fn real_document_with_flipped_signature_byte_fails() {
        // The signature is the last element of the COSE array.
        let document = flip_byte(VALID, VALID.len() - 1);
        assert_eq!(
            verify_signed(&document, AWS_NITRO_ROOT_G1).unwrap_err(),
            AttestationFailure::Signature
        );
    }

    #[test]
    fn real_document_with_flipped_pcr0_byte_fails() {
        let pcr0 = hex::decode(VALID_PCR0).unwrap();
        let at = VALID.windows(48).position(|w| w == pcr0).unwrap();
        let document = flip_byte(VALID, at + 10);
        assert_eq!(
            verify_signed(&document, AWS_NITRO_ROOT_G1).unwrap_err(),
            AttestationFailure::Signature
        );
    }

    #[test]
    fn real_document_against_foreign_root_fails() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let foreign_root = params.self_signed(&key).unwrap();
        let err = verify_signed(VALID, foreign_root.der()).unwrap_err();
        assert!(
            matches!(err, AttestationFailure::Chain(_)),
            "expected Chain, got {err:?}"
        );
    }

    #[test]
    fn real_debug_document_is_rejected() {
        let err = verify_document(DEBUG, &[0; 32], &[[0; 48]], SystemTime::now()).unwrap_err();
        assert_eq!(err, AttestationFailure::DebugMode);
    }

    fn verify_synthetic(
        fields: &Fields,
        now_ms: u64,
    ) -> Result<VerifiedAttestation, AttestationFailure> {
        let (document, anchor) = signed_document(fields);
        verify_document_with_anchor(&document, &TEST_NONCE, &[TEST_PCR0], at_ms(now_ms), &anchor)
    }

    #[test]
    fn synthetic_document_verifies() {
        let verified = verify_synthetic(&Fields::default(), TEST_TIMESTAMP_MS).unwrap();
        assert_eq!(
            verified,
            VerifiedAttestation {
                pcr0: TEST_PCR0,
                public_sha256: TEST_PUBLIC_SHA256,
                timestamp_ms: TEST_TIMESTAMP_MS,
                module_id: TEST_MODULE_ID.to_owned(),
            }
        );
    }

    #[test]
    fn wrong_nonce_fails() {
        let fields = Fields {
            nonce: Some(vec![0x08; 32]),
            ..Fields::default()
        };
        assert_eq!(
            verify_synthetic(&fields, TEST_TIMESTAMP_MS).unwrap_err(),
            AttestationFailure::Nonce
        );
    }

    #[test]
    fn missing_nonce_fails() {
        let fields = Fields {
            nonce: None,
            ..Fields::default()
        };
        assert_eq!(
            verify_synthetic(&fields, TEST_TIMESTAMP_MS).unwrap_err(),
            AttestationFailure::Nonce
        );
    }

    #[test]
    fn stale_timestamp_fails() {
        let now_ms = TEST_TIMESTAMP_MS + 301_000;
        assert_eq!(
            verify_synthetic(&Fields::default(), now_ms).unwrap_err(),
            AttestationFailure::Timestamp {
                document_ms: TEST_TIMESTAMP_MS,
                now_ms
            }
        );
    }

    #[test]
    fn future_timestamp_fails() {
        let now_ms = TEST_TIMESTAMP_MS - 301_000;
        assert_eq!(
            verify_synthetic(&Fields::default(), now_ms).unwrap_err(),
            AttestationFailure::Timestamp {
                document_ms: TEST_TIMESTAMP_MS,
                now_ms
            }
        );
    }

    #[test]
    fn timestamp_within_bound_passes() {
        let (document, anchor) = signed_document(&Fields::default());
        for now_ms in [TEST_TIMESTAMP_MS - 299_000, TEST_TIMESTAMP_MS + 299_000] {
            let verified = verify_document_with_anchor(
                &document,
                &TEST_NONCE,
                &[TEST_PCR0],
                at_ms(now_ms),
                &anchor,
            );
            assert!(verified.is_ok(), "now {now_ms}: {verified:?}");
        }
    }

    #[test]
    fn pcr0_not_allowed_fails() {
        let (document, anchor) = signed_document(&Fields::default());
        let err = verify_document_with_anchor(
            &document,
            &TEST_NONCE,
            &[[0x12; 48]],
            at_ms(TEST_TIMESTAMP_MS),
            &anchor,
        )
        .unwrap_err();
        assert_eq!(
            err,
            AttestationFailure::Pcr0NotAllowed(hex::encode(TEST_PCR0))
        );
    }

    #[test]
    fn digest_not_sha384_fails() {
        let fields = Fields {
            digest: "SHA256".to_owned(),
            ..Fields::default()
        };
        assert_eq!(
            verify_synthetic(&fields, TEST_TIMESTAMP_MS).unwrap_err(),
            AttestationFailure::Digest("SHA256".to_owned())
        );
    }

    #[test]
    fn user_data_missing_or_malformed_fails() {
        let not_hex = format!(r#"{{"public_sha256":"zz{}"}}"#, "2".repeat(62));
        let cases: [Option<&[u8]>; 6] = [
            None,
            Some(b"hello, world!"),
            Some(br#"{"other":"x"}"#),
            Some(br#"{"public_sha256":"abcd"}"#),
            Some(br#"{"public_sha256":42}"#),
            Some(not_hex.as_bytes()),
        ];
        for user_data in cases {
            let fields = Fields {
                user_data: user_data.map(<[u8]>::to_vec),
                ..Fields::default()
            };
            let err = verify_synthetic(&fields, TEST_TIMESTAMP_MS).unwrap_err();
            assert!(
                matches!(err, AttestationFailure::UserData(_)),
                "{user_data:?}: expected UserData, got {err:?}"
            );
        }
    }

    #[test]
    fn user_data_extra_fields_are_accepted() {
        let json = format!(
            r#"{{"version":1,"public_sha256":"{}","note":"x"}}"#,
            hex::encode(TEST_PUBLIC_SHA256)
        );
        let fields = Fields {
            user_data: Some(json.into_bytes()),
            ..Fields::default()
        };
        let verified = verify_synthetic(&fields, TEST_TIMESTAMP_MS).unwrap();
        assert_eq!(verified.public_sha256, TEST_PUBLIC_SHA256);
    }

    #[test]
    fn es256_header_fails() {
        let fields = Fields {
            protected: protected_header(-7),
            ..Fields::default()
        };
        assert_eq!(
            verify_synthetic(&fields, TEST_TIMESTAMP_MS).unwrap_err(),
            AttestationFailure::UnsupportedAlgorithm(-7)
        );
    }
}
