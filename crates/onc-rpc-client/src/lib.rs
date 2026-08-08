//! ONC RPC version 2 -- [RFC 5531], with a runtime-agnostic transport layer.
//!
//! Every NFS version rides on ONC RPC. A call names a (program, version,
//! procedure) triple and carries a credential; the reply either accepts the
//! call and returns results, or rejects it with a reason. This crate provides
//! that machinery once, so the per-version protocol crates only have to
//! describe their own wire types and procedure numbers.
//!
//! The portmapper (program 100000) and rpcbind v3/v4 clients have been
//! extracted to the `onc_rpcbind` crate -- they are a specific RPC
//! service, not part of the RPC machinery itself.
//!
//! # What a security tool needs that a filesystem client does not
//!
//! Two behaviours here differ from a conventional RPC client, deliberately:
//!
//! * **AUTH_SYS is unauthenticated, and this crate leans into that.** The
//!   credential is a plain struct asserting a UID, GID, and group list
//!   (RFC 5531 sec. 14). Nothing signs it. [`RpcClient`] therefore allows its
//!   credential to be replaced on an established connection, so one TCP
//!   session can issue calls under many identities without re-handshaking.
//! * **`PROG_MISMATCH` preserves the server's version range.** A server
//!   rejecting a call reports the lowest and highest versions it supports.
//!   That is a free version-enumeration oracle, so
//!   [`RpcError::ProgMismatch`] carries the range rather than discarding it.
//!
//! # Layout
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`rpc`] | RPC v2 message types and the generic [`RpcClient`] |
//! | [`transport`] | The [`RpcTransport`] seam, a direct implementation, and the tokio backend |
//! | [`auth`] | AUTH_SYS credentials (RFC 5531 sec. 14) |
//!
//! [RFC 5531]: https://www.rfc-editor.org/rfc/rfc5531

pub mod auth;
pub mod rpc;
pub mod transport;

mod error;

pub use auth::{AuthFlavor, AuthSys};
pub use error::RpcError;
pub use rpc::RpcClient;
pub use transport::{DirectTransport, RpcTransport};
