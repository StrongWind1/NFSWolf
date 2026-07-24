//! ONC RPC version 2 -- [RFC 5531] (originally [RFC 1057]).
//!
//! Every NFS protocol version rides on ONC RPC.  A call names a
//! (program, version, procedure) triple and carries a credential; the reply
//! either accepts the call and returns results, or rejects it with a reason.
//!
//! Two details in this module matter disproportionately to NFSWolf:
//!
//! * **AUTH_SYS is unauthenticated.**  The credential is a plain struct
//!   asserting a UID, GID, and group list (RFC 5531 sec. 14).  Nothing signs
//!   it, so any client can claim any identity -- this is the basis of the
//!   UID-spraying and privilege-escalation paths.
//! * **`PROG_MISMATCH` leaks the supported version range.**  A server that
//!   rejects a call reports the lowest and highest versions it does support,
//!   which is a free version-enumeration oracle.  Unlike upstream, this crate
//!   preserves that range instead of collapsing it into an opaque error.
//!
//! [RFC 5531]: https://www.rfc-editor.org/rfc/rfc5531
//! [RFC 1057]: https://www.rfc-editor.org/rfc/rfc1057

mod client;
mod types;

pub use client::RpcClient;
pub use types::*;
