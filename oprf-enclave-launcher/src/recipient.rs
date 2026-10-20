//! Decryption of KMS's `CiphertextForRecipient`: CMS `EnvelopedData` (BER) encrypted to the
//! enclave's RSA key with RSAES-OAEP (SHA-256), content AES-256-CBC.
//!
//! KMS sends indefinite-length BER, which DER parsers reject, so this module carries a small
//! BER reader that understands exactly what the envelope needs.

use aws_lc_rs::cipher::{AES_256, DecryptionContext, PaddedBlockDecryptingKey, UnboundCipherKey};
use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rsa::{
    KeySize, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, PrivateDecryptingKey,
};

const ENVELOPED_DATA: &str = "1.2.840.113549.1.7.3";
const DATA: &str = "1.2.840.113549.1.7.1";
const RSAES_OAEP: &str = "1.2.840.113549.1.1.7";
const MGF1: &str = "1.2.840.113549.1.1.8";
const SHA1: &str = "1.3.14.3.2.26";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const AES256_CBC: &str = "2.16.840.1.101.3.4.1.42";

const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const INTEGER: u8 = 0x02;
const CONSTRUCTED: u8 = 0x20;
/// Context-specific `[n]`, primitive; OR with [`CONSTRUCTED`] for the constructed form.
const fn ctx(n: u8) -> u8 {
    0x80 | n
}

/// Real envelopes nest 11 deep; anything far beyond that is not one.
const MAX_DEPTH: usize = 32;

/// The parts of an envelope the recipient needs to decrypt it.
#[allow(
    clippy::exhaustive_structs,
    reason = "plain data, fields are the CMS parts"
)]
#[derive(Debug, PartialEq, Eq)]
pub struct Envelope {
    /// The content-encryption key, RSA-OAEP encrypted to the recipient.
    pub encrypted_key: Vec<u8>,
    /// The AES-CBC IV.
    pub iv: [u8; 16],
    /// The AES-256-CBC encrypted content, segments concatenated.
    pub ciphertext: Vec<u8>,
}

/// Parses a CMS `ContentInfo` holding `EnvelopedData` with one RSAES-OAEP (SHA-256)
/// `KeyTransRecipientInfo` and AES-256-CBC content.
///
/// # Errors
///
/// Malformed BER, a different structure, or an unsupported algorithm (named by its dotted OID).
pub fn parse_envelope(ber: &[u8]) -> Result<Envelope, String> {
    let mut top = Reader::new(ber, 0);
    let content_info = top.expect(SEQUENCE)?;
    if !top.is_empty() {
        return Err("cms: trailing data after ContentInfo".to_owned());
    }
    let mut content_info = content_info.reader()?;
    expect_oid(&mut content_info, ENVELOPED_DATA, "content type")?;
    let mut explicit = content_info.expect(ctx(0) | CONSTRUCTED)?.reader()?;
    let mut enveloped = explicit.expect(SEQUENCE)?.reader()?;

    enveloped.expect(INTEGER)?;
    if enveloped.peek_tag() == Some(ctx(0) | CONSTRUCTED) {
        enveloped.next()?; // originatorInfo
    }
    let encrypted_key = recipient_key(&mut enveloped.expect(SET)?.reader()?)?;

    let mut info = enveloped.expect(SEQUENCE)?.reader()?;
    expect_oid(&mut info, DATA, "encrypted content type")?;
    let mut alg = info.expect(SEQUENCE)?.reader()?;
    expect_oid(&mut alg, AES256_CBC, "content encryption algorithm")?;
    let iv = alg
        .expect_any(&[OCTET_STRING, OCTET_STRING | CONSTRUCTED])?
        .octets()?;
    let iv = <[u8; 16]>::try_from(iv.as_slice())
        .map_err(|_| format!("cms: IV is {} bytes, want 16", iv.len()))?;
    let ciphertext = info
        .expect_any(&[ctx(0), ctx(0) | CONSTRUCTED])
        .map_err(|e| format!("{e} (encrypted content missing or detached)"))?
        .octets()?;

    Ok(Envelope {
        encrypted_key,
        iv,
        ciphertext,
    })
}

/// The encrypted key of the one `KeyTransRecipientInfo` in `recipientInfos`.
fn recipient_key(infos: &mut Reader<'_>) -> Result<Vec<u8>, String> {
    let ktri = infos.next()?;
    if ktri.tag != SEQUENCE {
        return Err(format!(
            "cms: recipient info with tag {:#04x}, only KeyTransRecipientInfo is supported",
            ktri.tag
        ));
    }
    if !infos.is_empty() {
        return Err("cms: more than one recipient info".to_owned());
    }
    let mut ktri = ktri.reader()?;
    ktri.expect(INTEGER)?;
    ktri.next()?; // rid
    let mut alg = ktri.expect(SEQUENCE)?.reader()?;
    expect_oid(&mut alg, RSAES_OAEP, "key encryption algorithm")?;
    check_oaep_params(&mut alg)?;
    ktri.expect_any(&[OCTET_STRING, OCTET_STRING | CONSTRUCTED])?
        .octets()
}

/// `RSAES-OAEP-params` must name SHA-256 for both the hash and MGF1; absent fields default to
/// SHA-1 (RFC 4055).
fn check_oaep_params(alg: &mut Reader<'_>) -> Result<(), String> {
    let mut hash = SHA1.to_owned();
    let mut mgf_hash = SHA1.to_owned();
    if !alg.is_empty() {
        let mut params = alg.expect(SEQUENCE)?.reader()?;
        while !params.is_empty() {
            let field = params.next()?;
            let mut inner = field.reader()?;
            match field.tag {
                t if t == ctx(0) | CONSTRUCTED => {
                    hash = inner.expect(SEQUENCE)?.reader()?.expect(OID)?.oid()?;
                }
                t if t == ctx(1) | CONSTRUCTED => {
                    let mut mgf = inner.expect(SEQUENCE)?.reader()?;
                    expect_oid(&mut mgf, MGF1, "OAEP mask generation function")?;
                    mgf_hash = mgf.expect(SEQUENCE)?.reader()?.expect(OID)?.oid()?;
                }
                // pSourceAlgorithm: a non-empty label makes decryption fail on its own.
                t if t == ctx(2) | CONSTRUCTED => {}
                t => return Err(format!("cms: unexpected OAEP parameter tag {t:#04x}")),
            }
        }
    }
    for (what, oid) in [("OAEP hash", hash), ("OAEP MGF1 hash", mgf_hash)] {
        if oid != SHA256 {
            return Err(format!("cms: unsupported {what} {oid}, want {SHA256}"));
        }
    }
    Ok(())
}

fn expect_oid(r: &mut Reader<'_>, want: &str, what: &str) -> Result<(), String> {
    let got = r.expect(OID)?.oid()?;
    if got == want {
        Ok(())
    } else {
        Err(format!("cms: unsupported {what} {got}, want {want}"))
    }
}

/// One BER element. For an indefinite length, `body` is the contents without the
/// end-of-contents octets.
struct Tlv<'a> {
    tag: u8,
    body: &'a [u8],
    depth: usize,
}

impl<'a> Tlv<'a> {
    fn reader(&self) -> Result<Reader<'a>, String> {
        if self.tag & CONSTRUCTED == 0 {
            return Err(format!("cms: element {:#04x} is not constructed", self.tag));
        }
        Ok(Reader::new(self.body, self.depth + 1))
    }

    /// OCTET STRING contents (either tagging), constructed segments concatenated.
    fn octets(&self) -> Result<Vec<u8>, String> {
        if self.tag & CONSTRUCTED == 0 {
            return Ok(self.body.to_vec());
        }
        let mut out = Vec::new();
        let mut segments = self.reader()?;
        while !segments.is_empty() {
            let segment = segments.expect_any(&[OCTET_STRING, OCTET_STRING | CONSTRUCTED])?;
            out.extend_from_slice(&segment.octets()?);
        }
        Ok(out)
    }

    fn oid(&self) -> Result<String, String> {
        let bad = || format!("cms: malformed OID {:02x?}", self.body);
        let mut arcs = Vec::new();
        let mut value: u64 = 0;
        let mut pending = false;
        for &b in self.body {
            if !pending && b == 0x80 {
                return Err(bad()); // non-minimal
            }
            value = value
                .checked_mul(128)
                .ok_or_else(bad)?
                .checked_add(u64::from(b & 0x7f))
                .ok_or_else(bad)?;
            pending = b & 0x80 != 0;
            if !pending {
                arcs.push(value);
                value = 0;
            }
        }
        let Some((&first, rest)) = arcs.split_first() else {
            return Err(bad());
        };
        if pending {
            return Err(bad());
        }
        let (a, b) = match first {
            0..40 => (0, first),
            40..80 => (1, first - 40),
            _ => (2, first - 80),
        };
        let mut dotted = format!("{a}.{b}");
        for arc in rest {
            dotted.push('.');
            dotted.push_str(&arc.to_string());
        }
        Ok(dotted)
    }
}

/// Reads consecutive BER elements from a slice.
struct Reader<'a> {
    rest: &'a [u8],
    depth: usize,
}

impl<'a> Reader<'a> {
    fn new(rest: &'a [u8], depth: usize) -> Self {
        Self { rest, depth }
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    fn expect(&mut self, tag: u8) -> Result<Tlv<'a>, String> {
        self.expect_any(&[tag])
    }

    fn expect_any(&mut self, tags: &[u8]) -> Result<Tlv<'a>, String> {
        match self.peek_tag() {
            Some(t) if tags.contains(&t) => self.next(),
            Some(t) => Err(format!("cms: found tag {t:#04x}, want one of {tags:#04x?}")),
            None => Err(format!("cms: input ends, want one of {tags:#04x?}")),
        }
    }

    fn next(&mut self) -> Result<Tlv<'a>, String> {
        if self.depth > MAX_DEPTH {
            return Err("cms: nesting too deep".to_owned());
        }
        let truncated = || "cms: truncated input".to_owned();
        let (&tag, after_tag) = self.rest.split_first().ok_or_else(truncated)?;
        if tag & 0x1f == 0x1f {
            return Err(format!("cms: multi-byte tag {tag:#04x} unsupported"));
        }
        let (&first, mut after_len) = after_tag.split_first().ok_or_else(truncated)?;
        let body = match first {
            0x80 => {
                if tag & CONSTRUCTED == 0 {
                    return Err(format!("cms: primitive {tag:#04x} with indefinite length"));
                }
                let start = after_len;
                let mut children = Reader::new(after_len, self.depth + 1);
                loop {
                    if children.rest.starts_with(&[0, 0]) {
                        break;
                    }
                    if children.is_empty() {
                        return Err(truncated());
                    }
                    children.next()?;
                }
                let body_len = start.len() - children.rest.len();
                after_len = &children.rest[2..];
                &start[..body_len]
            }
            0x00..=0x7f => {
                let (body, rest) = split(after_len, usize::from(first)).ok_or_else(truncated)?;
                after_len = rest;
                body
            }
            0x81..=0x84 => {
                let (len_bytes, rest) =
                    split(after_len, usize::from(first & 0x7f)).ok_or_else(truncated)?;
                let len = len_bytes
                    .iter()
                    .try_fold(0usize, |acc, &b| {
                        acc.checked_mul(256)?.checked_add(usize::from(b))
                    })
                    .ok_or_else(|| "cms: length overflows".to_owned())?;
                let (body, rest) = split(rest, len).ok_or_else(truncated)?;
                after_len = rest;
                body
            }
            _ => return Err(format!("cms: unsupported length octet {first:#04x}")),
        };
        self.rest = after_len;
        Ok(Tlv {
            tag,
            body,
            depth: self.depth,
        })
    }
}

fn split(s: &[u8], n: usize) -> Option<(&[u8], &[u8])> {
    (n <= s.len()).then(|| s.split_at(n))
}

/// The enclave's RSA key that KMS encrypts `CiphertextForRecipient` to.
#[derive(Debug)]
pub struct RecipientKey(PrivateDecryptingKey);

impl RecipientKey {
    /// A fresh RSA-2048 key.
    ///
    /// # Errors
    ///
    /// Key generation failed.
    pub fn generate() -> Result<Self, String> {
        PrivateDecryptingKey::generate(KeySize::Rsa2048)
            .map(Self)
            .map_err(|e| format!("RSA key generation: {e}"))
    }

    /// Loads a PKCS#8 RSA private key.
    ///
    /// # Errors
    ///
    /// Not a PKCS#8 RSA key of 2048 to 8192 bits.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, String> {
        PrivateDecryptingKey::from_pkcs8(der)
            .map(Self)
            .map_err(|e| format!("RSA key: {e}"))
    }

    /// X.509 `SubjectPublicKeyInfo` DER, what KMS expects as the attestation document's
    /// `public_key`.
    ///
    /// # Panics
    ///
    /// Never; encoding a valid RSA public key cannot fail.
    #[must_use]
    pub fn public_key_der(&self) -> Vec<u8> {
        self.0
            .public_key()
            .as_der()
            .expect("valid RSA public key encodes")
            .as_ref()
            .to_vec()
    }

    /// Parses `ber` with [`parse_envelope`] and returns the decrypted content.
    ///
    /// # Errors
    ///
    /// The envelope does not parse, the content key does not decrypt with this key, or the
    /// content does not decrypt and unpad.
    pub fn decrypt_envelope(&self, ber: &[u8]) -> Result<Vec<u8>, String> {
        let env = parse_envelope(ber)?;
        let oaep = OaepPrivateDecryptingKey::new(self.0.clone())
            .map_err(|e| format!("RSA-OAEP key: {e}"))?;
        let mut cek = vec![0; oaep.min_output_size()];
        let cek = oaep
            .decrypt(&OAEP_SHA256_MGF1SHA256, &env.encrypted_key, &mut cek, None)
            .map_err(|_| "cms: content key does not decrypt with this RSA key".to_owned())?;
        let key = UnboundCipherKey::new(&AES_256, cek)
            .map_err(|_| format!("cms: content key is {} bytes, want 32", cek.len()))?;
        let key =
            PaddedBlockDecryptingKey::cbc_pkcs7(key).map_err(|e| format!("AES-256-CBC: {e}"))?;
        let mut content = env.ciphertext;
        let len = key
            .decrypt(
                &mut content,
                DecryptionContext::Iv128(FixedLength::from(env.iv)),
            )
            .map_err(|_| "cms: content does not decrypt (AES-256-CBC, PKCS#7)".to_owned())?
            .len();
        content.truncate(len);
        Ok(content)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use aws_lc_rs::rsa::PublicEncryptingKey;

    use super::*;

    include!("../tests/fixtures/aws_kms_response.rs");

    const KEY: &[u8] = include_bytes!("../tests/fixtures/recipient-key.pk8");
    const ENVELOPE: &[u8] = include_bytes!("../tests/fixtures/envelope.der");
    const ENVELOPE_BER: &[u8] = include_bytes!("../tests/fixtures/envelope-ber.der");
    const ENVELOPE_AES128: &[u8] = include_bytes!("../tests/fixtures/envelope-aes128.der");
    const PLAINTEXT: &[u8] = include_bytes!("../tests/fixtures/plaintext.json");

    #[test]
    fn parses_aws_kms_response() {
        let env = parse_envelope(INPUT_BER).unwrap();
        assert_eq!(env.encrypted_key, ENCRYPTED_KEY_OUT);
        assert_eq!(env.iv, IV_OUT);
        assert_eq!(env.ciphertext, CIPHERTEXT_OUT);
    }

    #[test]
    fn parses_aws_kms_response_with_context_tag() {
        let env = parse_envelope(INPUT_BER_W_CTX).unwrap();
        assert_eq!(env.encrypted_key, ENCRYPTED_KEY_OUT_W_CTX);
        assert_eq!(env.iv, IV_OUT_W_CTX);
        assert_eq!(env.ciphertext, CIPHERTEXT_OUT_W_CTX);
    }

    #[test]
    fn decrypts_openssl_ber_envelope() {
        assert_eq!(
            ENVELOPE_BER[..2],
            [0x30, 0x80],
            "fixture is indefinite-length"
        );
        let key = RecipientKey::from_pkcs8(KEY).unwrap();
        assert_eq!(key.decrypt_envelope(ENVELOPE_BER).unwrap(), PLAINTEXT);
    }

    #[test]
    fn decrypts_openssl_der_envelope() {
        let key = RecipientKey::from_pkcs8(KEY).unwrap();
        assert_eq!(key.decrypt_envelope(ENVELOPE).unwrap(), PLAINTEXT);
    }

    #[test]
    fn wrong_key_fails() {
        let key = RecipientKey::generate().unwrap();
        key.decrypt_envelope(ENVELOPE).unwrap_err();
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut env = ENVELOPE.to_vec();
        let last = env.len() - 1;
        env[last] ^= 0x01;
        let key = RecipientKey::from_pkcs8(KEY).unwrap();
        key.decrypt_envelope(&env).unwrap_err();
    }

    #[test]
    fn truncated_input_fails() {
        for len in 0..INPUT_BER.len() {
            parse_envelope(&INPUT_BER[..len]).unwrap_err();
        }
    }

    #[test]
    fn deep_nesting_fails() {
        let nested: Vec<u8> = [0x30, 0x80].repeat(100_000);
        let err = parse_envelope(&nested).unwrap_err();
        assert!(err.contains("too deep"), "{err}");
    }

    #[test]
    fn names_unsupported_content_cipher() {
        let key = RecipientKey::from_pkcs8(KEY).unwrap();
        let err = key.decrypt_envelope(ENVELOPE_AES128).unwrap_err();
        assert!(err.contains("2.16.840.1.101.3.4.1.2"), "{err}");
    }

    #[test]
    fn names_unsupported_oaep_hash() {
        const SHA256_OID: [u8; 11] = [
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];
        let mut env = ENVELOPE.to_vec();
        let at = env.windows(11).position(|w| w == SHA256_OID).unwrap();
        env[at + 10] = 0x02; // SHA-384, in the OAEP hashAlgorithm field
        let err = parse_envelope(&env).unwrap_err();
        assert!(err.contains("2.16.840.1.101.3.4.2.2"), "{err}");
    }

    #[test]
    fn public_key_is_spki() {
        const RSA_ENCRYPTION: [u8; 15] = [
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
            0x00,
        ];
        let der = RecipientKey::generate().unwrap().public_key_der();
        assert_eq!(der[..4], [0x30, 0x82, 0x01, 0x22], "outer SEQUENCE");
        assert_eq!(der[4..19], RSA_ENCRYPTION);
        PublicEncryptingKey::from_der(&der).unwrap();
    }
}
