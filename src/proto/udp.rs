//! UDP RPC transport -- re-exports from the RPC crate.
//!
//! The implementation lives in `nfswolf_rpc::transport::udp`.  This module
//! re-exports the public API so existing callers within the binary continue
//! to resolve through `crate::proto::udp::`.

pub(crate) use nfswolf_rpc::transport::udp::{call_rpc_udp, probe_udp_rpc};
