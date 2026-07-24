//! Error types for the RPC and portmapper layers.

mod portmap;
mod rpc;

pub use portmap::PortmapError;
pub use rpc::RpcError;
