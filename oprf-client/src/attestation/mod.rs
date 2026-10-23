//! Verification of AWS Nitro Enclaves attestation documents served by OPRF nodes.
//!
//! The error and result types compile on every target because [`crate::NodeError`]
//! carries them; the verifier itself is native only.

#[cfg(not(target_arch = "wasm32"))]
mod document;
#[cfg(not(target_arch = "wasm32"))]
mod policy;
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) mod test_support;

#[cfg(not(target_arch = "wasm32"))]
pub use document::verify_document;
#[cfg(not(target_arch = "wasm32"))]
pub use policy::{
    ATTESTATION_TIMEOUT, AttestationPolicy, Expected, MAX_DOCUMENT_BYTES, PolicyError, attest,
};

/// The facts of an attestation document that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    /// PCR0 (enclave image measurement).
    pub pcr0: [u8; 48],
    /// SHA-256 of the enclave's public configuration, from `user_data`.
    pub public_sha256: [u8; 32],
    /// Document timestamp in milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// The NSM module id.
    pub module_id: String,
}

/// The attestation check that failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AttestationFailure {
    /// The attestation request did not complete.
    #[error("attestation transport: {0}")]
    Transport(String),
    /// The node answered the attestation request with a non-success status.
    #[error("attestation request returned HTTP {code}: {body}")]
    Status {
        /// HTTP status code.
        code: u16,
        /// Response body (truncated).
        body: String,
    },
    /// The attestation document exceeded the size limit.
    #[error("attestation document larger than {limit} bytes")]
    TooLarge {
        /// The limit in bytes.
        limit: usize,
    },
    /// The document is not a well-formed `COSE_Sign1` NSM attestation document.
    #[error("malformed attestation document: {0}")]
    Malformed(String),
    /// The COSE protected header names an algorithm other than ES384 (-35).
    #[error("unsupported COSE algorithm {0} (expected ES384, -35)")]
    UnsupportedAlgorithm(i64),
    /// The certificate chain does not lead to the AWS Nitro root at the document's timestamp.
    #[error("certificate chain check failed: {0}")]
    Chain(String),
    /// The COSE signature does not verify with the leaf certificate.
    #[error("signature check failed")]
    Signature,
    /// The document's digest is not SHA384.
    #[error("digest check failed: expected SHA384, got {0}")]
    Digest(String),
    /// PCR0 is all zero: the enclave runs in debug mode.
    #[error("debug-mode check failed: PCR0 is all zero")]
    DebugMode,
    /// The document's nonce is missing or differs from the one sent.
    #[error("nonce check failed: missing or not the one sent")]
    Nonce,
    /// The document's timestamp is more than 5 minutes from now.
    #[error("timestamp check failed: document {document_ms} ms, now {now_ms} ms")]
    Timestamp {
        /// Document timestamp (ms since the Unix epoch).
        document_ms: u64,
        /// Local time (ms since the Unix epoch).
        now_ms: u64,
    },
    /// PCR0 (hex) is not in the allowed set for this node.
    #[error("PCR0 check failed: {0} is not allowed")]
    Pcr0NotAllowed(String),
    /// `user_data` is missing or not JSON with a 64-hex `public_sha256`.
    #[error("user_data check failed: {0}")]
    UserData(String),
    /// The node is not listed in the expected-values file.
    #[error("node not listed in the attestation expected-values file")]
    NotListed,
}

/// An attestation failure together with the node it concerns.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("attestation of {url} failed: {failure}")]
#[non_exhaustive]
pub struct AttestationError {
    /// The node's URL.
    pub url: String,
    /// The check that failed.
    pub failure: AttestationFailure,
}
