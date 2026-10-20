//! `nit.target` of the oprf-key-gen Nitro Enclave.
//!
//! Streams its own output, and later key-gen's, to the parent's log port;
//! starts the KMS forward for the alias ARN in `/etc/enclave/kms-key-alias`;
//! fetches the bootstrap message from the parent, attests and has KMS decrypt
//! the config blob; writes `/etc/hosts` and starts the blob's forwards; then
//! runs key-gen as 65532:65532 with exactly the blob's environment and exits
//! with its status.

#[cfg(target_os = "linux")]
mod enclave;
#[cfg(target_os = "linux")]
mod kms;
#[cfg_attr(
    all(not(test), not(target_os = "linux")),
    allow(dead_code, reason = "only the Linux runtime uses it outside tests")
)]
mod logpump;
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux runtime uses it outside tests")
)]
mod relay;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    enclave::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
