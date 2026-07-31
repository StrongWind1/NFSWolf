//! Portmapper v2 ([RFC 1057] appendix A) and rpcbind v3/v4 ([RFC 1833])
//! clients for ONC RPC service discovery.
//!
//! The portmapper (program 100000, port 111) maps a (program, version,
//! protocol) triple onto the TCP or UDP port serving it.  `DUMP` returns the
//! entire mapping table to any caller, which makes it the fastest way to
//! enumerate what RPC services a host runs and on which ports.
//!
//! rpcbind extends the portmapper with versioned protocol bindings.  Version 3
//! adds `GETTIME` (server clock); version 4 adds `GETSTAT` (per-version
//! operational statistics).
//!
//! This crate depends on [`nfswolf_rpc`] for the generic RPC client and
//! transport layer -- the portmapper is program 100000 (a specific RPC
//! service), not part of the RPC machinery itself.
//!
//! [RFC 1057]: https://www.rfc-editor.org/rfc/rfc1057
//! [RFC 1833]: https://www.rfc-editor.org/rfc/rfc1833

mod client;
mod error;
/// Well-known RPC program number table.
pub mod programs;
/// rpcbind v3/v4 types and client ([RFC 1833]).
///
/// [RFC 1833]: https://www.rfc-editor.org/rfc/rfc1833
pub mod rpcbind;
/// Portmapper v2 XDR types ([RFC 1057] appendix A).
///
/// [RFC 1057]: https://www.rfc-editor.org/rfc/rfc1057
pub mod types;

pub use client::PortmapperClient;
pub use error::PortmapError;
pub use programs::{known_programs, program_name};
pub use rpcbind::RpcbindClient;
pub use types::{IPPROTO_TCP, IPPROTO_UDP, PMAP_PORT, PMAP_PROG, PROGRAM, VERSION, call_args, call_result, mapping, pmaplist};
