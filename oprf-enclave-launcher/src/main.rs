//! `nit.target` of the OPRF Nitro Enclaves (key-gen and node).
//!
//! Streams its own output, and later the app's, to the parent's log port;
//! fetches the bootstrap message from the parent, which names the KMS key and
//! the vsock port for KMS; starts the KMS forward, attests and has KMS decrypt
//! the config blob; refuses a blob written for another key; writes
//! `/etc/hosts`, starts the blob's forwards and logs the public config hash;
//! serves attestation documents on loopback; then runs the program named in
//! `/etc/enclave/app` as 65532:65532 with exactly the blob's environment and
//! exits with its status.

#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux runtime uses it outside tests")
)]
mod app;
#[cfg(target_os = "linux")]
mod enclave;
#[cfg(target_os = "linux")]
mod kms;
#[cfg_attr(
    all(not(test), not(target_os = "linux")),
    allow(dead_code, reason = "only the Linux runtime uses it outside tests")
)]
mod logpump;
#[cfg(target_os = "linux")]
mod nsm;
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
