//! UDP RPC transport -- re-exports from the RPC crate.
//!
//! The implementation lives in `onc_rpc_client::transport::udp`.  This module
//! re-exports the public API so existing callers within the binary continue
//! to resolve through `crate::proto::udp::`.

pub(crate) use onc_rpc_client::transport::udp::{call_rpc_udp, probe_udp_rpc};
