//! Error types owned by this crate.
//!
//! RPC and portmapper errors live in `nfswolf_rpc` and are re-exported from the
//! crate root for compatibility.

mod connect;
mod mount;

pub use connect::ConnectError;
pub use mount::MountError;
