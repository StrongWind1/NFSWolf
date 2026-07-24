//! MOUNT protocol version 3 -- [RFC 1813] appendix I.
//!
//! MOUNT is the sideband service (program 100005) that turns an export path
//! into the root file handle NFSv3 operations start from.  NFSv4 folded this
//! role into the protocol proper and dropped MOUNT entirely.
//!
//! For reconnaissance the interesting procedures are `EXPORT`, which lists
//! every export and the hosts allowed to reach it without requiring any
//! credential, and `DUMP`, which lists who is currently mounted.
//!
//! [RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813

mod client;
mod types;

pub use client::MountClient;
pub use types::*;
