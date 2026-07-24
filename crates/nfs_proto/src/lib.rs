//! Pure-Rust NFS wire protocol stack.
//!
//! This crate is the wire layer NFSWolf is built on: XDR encoding, ONC RPC
//! framing, and the NFSv2, NFSv3, NFSv4, MOUNT, and portmapper protocols.  It
//! deliberately holds no policy -- no connection pooling, no retry logic, no
//! circuit breaking, no credential escalation.  Those decisions belong to the
//! caller, because a security tool needs to make them differently from a
//! filesystem client.
//!
//! # Layout
//!
//! | Module | Protocol | Spec |
//! |--------|----------|------|
//! | [`xdr`] | External Data Representation | [RFC 4506] |
//! | [`rpc`] | ONC RPC version 2 | [RFC 5531] |
//! | [`portmap`] | Portmapper / RPCBIND v2 | [RFC 1057] app. A |
//! | [`mount`] | MOUNT version 3 | [RFC 1813] app. I |
//! | [`nfs2`] | NFS version 2 | [RFC 1094] |
//! | [`nfs3`] | NFS version 3 | [RFC 1813] |
//! | [`nfs4`] | NFS version 4.0 (read-only subset) | [RFC 7530] |
//! | [`transport`] | Async I/O traits and TCP connectors | -- |
//!
//! # Deliberate deviations
//!
//! Two behaviours differ from a conventional NFS client, both because a
//! security tool needs information a filesystem client would discard:
//!
//! * A `PROG_MISMATCH` rejection preserves the server's supported
//!   `(low, high)` version range rather than collapsing into an opaque error,
//!   because that range is a version-enumeration oracle.
//! * [`rpc::RpcClient`] allows its AUTH_SYS credential to be replaced on an
//!   established connection, so one TCP session can issue calls under many
//!   identities without re-handshaking.
//!
//! [RFC 4506]: https://www.rfc-editor.org/rfc/rfc4506
//! [RFC 5531]: https://www.rfc-editor.org/rfc/rfc5531
//! [RFC 1057]: https://www.rfc-editor.org/rfc/rfc1057
//! [RFC 1094]: https://www.rfc-editor.org/rfc/rfc1094
//! [RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813
//! [RFC 7530]: https://www.rfc-editor.org/rfc/rfc7530

// Facade stage of the crate split: the XDR codec now lives in `nfswolf-xdr`
// and the RPC/transport/portmapper layers in `nfswolf-rpc`.  The `xdr`, `rpc`,
// `transport`, and `portmap` modules below re-export them under their previous
// paths so the binary does not churn while the per-version crates are carved
// out.  This facade is removed once that work lands.
pub mod nfs2;
pub mod nfs4;

/// NFSv3 wire types and client -- re-exported from [`nfswolf_nfs3`].
pub use nfswolf_nfs3::wire as nfs3;
/// MOUNT v3 wire types -- re-exported from [`nfswolf_nfs3`].
pub use nfswolf_nfs3::wire::mount;

/// Portmapper / RPCBIND v2 -- re-exported from [`nfswolf_rpc`].
pub use nfswolf_rpc::portmap;
/// ONC RPC v2 -- re-exported from [`nfswolf_rpc`].
pub use nfswolf_rpc::rpc;
/// Async transport traits and the tokio backend -- re-exported from [`nfswolf_rpc`].
pub use nfswolf_rpc::transport;
/// XDR codec -- re-exported from [`nfswolf_xdr`].
pub use nfswolf_xdr as xdr;

mod connect;
mod error;

pub use connect::{Nfs3Connection, Nfs3ConnectionBuilder};
pub use error::ConnectError;
pub use nfswolf_nfs3::{MountClient, MountError, Nfs3Client};
pub use nfswolf_rpc::{PortmapError, PortmapperClient, RpcClient, RpcError};
