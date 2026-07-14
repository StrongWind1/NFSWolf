//! NFS protocol layer  --  built on nfs3-rs for NFSv3/MOUNT/portmapper.
//!
//! Uses nfs3_client/nfs3_types crates for all NFSv3 wire protocol.
//! Adds: AUTH_SYS stamp injection, connection pooling, circuit breaker,
//! auto-UID resolution, SOCKS5 transport, privileged port binding.
//! NFSv4 COMPOUND encoder is custom (minimal, ~6 ops).

pub(crate) mod auth;
pub(crate) mod auto_uid;
pub(crate) mod circuit;
pub(crate) mod conn;
pub(crate) mod mount;
pub(crate) mod nfs2;
pub(crate) mod nfs3;
pub(crate) mod nfs4;
pub(crate) mod pool;
pub(crate) mod portmap;
pub(crate) mod rpc_probe;
pub(crate) mod udp;
