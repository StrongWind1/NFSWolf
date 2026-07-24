//! Errors owned by this crate.
//!
//! Everything else is re-exported from the crate that raises it: RPC and
//! portmapper errors from `nfswolf_rpc`, MOUNT errors from `nfswolf_nfs3`.

mod connect;

pub use connect::ConnectError;
