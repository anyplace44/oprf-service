//! The NSM attestation request, shared by the KMS recipient attestation and the attestation
//! server.

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

/// Asks `/dev/nsm` for an attestation document binding the given fields.
pub(crate) fn attestation(
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let fd = nsm_init();
    if fd < 0 {
        return Err("cannot open /dev/nsm".to_owned());
    }
    let response = nsm_process_request(
        fd,
        Request::Attestation {
            user_data: user_data.map(Into::into),
            nonce: nonce.map(Into::into),
            public_key: public_key.map(Into::into),
        },
    );
    nsm_exit(fd);
    match response {
        Response::Attestation { document } => Ok(document),
        other => Err(format!("NSM attestation: {other:?}")),
    }
}
