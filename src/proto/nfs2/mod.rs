//! NFSv2 client  --  RFC 1094.
//!
//! Implements the 18 NFSv2 procedures on top of the generic RPC client in
//! `nfs_proto`.  NFSv2 is the preferred downgrade path when available:
//! - Zero security negotiation (RFC 2623 S2.7)
//! - No auth flavor enforcement  --  AUTH_SYS always accepted
//! - Some servers skip root_squash on the v2 code path
//! - No ACCESS procedure  --  server can't even advise on permissions
//! - Fixed 32-byte file handles (FHSIZE = 32, RFC 1094 S2.3.3)
//!
//! Built via `RpcClient::call(100003, 2, proc, args)`  --  the generic RPC
//! client accepts any program/version/procedure number.

/// NFSv2 wire types live in the protocol crate; re-exported under the name
/// call sites already use.
pub(crate) use nfs_proto::nfs2 as types;

pub(crate) mod client;
