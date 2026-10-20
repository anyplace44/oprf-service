//! `nit.target` of the OPRF Nitro Enclaves (key-gen and node).
//!
//! Brings up loopback, forwards TCP over vsock as listed in
//! `/etc/enclave/forwards`, then runs the program named in `/etc/enclave/app`
//! as 65532:65532 and exits with its status.

#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux runtime uses it outside tests")
)]
mod app;
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
