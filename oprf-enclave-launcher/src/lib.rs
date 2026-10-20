//! Forward table shared by the enclave launcher and the parent-side
//! `oprf-enclave-host`, so both ends read the same file.
#![deny(missing_docs)]

pub mod bootstrap;
pub mod recipient;
pub mod table;
