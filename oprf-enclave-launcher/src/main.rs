//! `nit.target` of the oprf-key-gen Nitro Enclave.
//!
//! Brings up loopback, forwards TCP over vsock as listed in
//! `/etc/enclave/forwards`, then runs key-gen as 65532:65532 and exits with
//! its status.

#[cfg(target_os = "linux")]
mod enclave;
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
