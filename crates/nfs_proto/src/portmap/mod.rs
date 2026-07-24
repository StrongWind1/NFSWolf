//! Portmapper / RPCBIND version 2 -- [RFC 1057] appendix A.
//!
//! The portmapper (program 100000, port 111) maps a (program, version,
//! protocol) triple onto the TCP or UDP port serving it.  `DUMP` returns the
//! entire mapping table to any caller, which makes it the fastest way to
//! enumerate what RPC services a host runs and on which ports.
//!
//! [RFC 1057]: https://www.rfc-editor.org/rfc/rfc1057

mod client;
mod types;

pub use client::PortmapperClient;
pub use types::*;
