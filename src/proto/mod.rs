//! NFS protocol layer  --  built on nfs3-rs for NFSv3/MOUNT/portmapper.
//!
//! Uses nfs3_client/nfs3_types crates for all NFSv3 wire protocol.
//! Adds: AUTH_SYS stamp injection, connection pooling, circuit breaker,
//! auto-UID resolution, SOCKS5 transport, privileged port binding.
//! NFSv4 COMPOUND encoder is custom (minimal, ~6 ops).

pub mod auth;
pub mod auto_uid;
pub mod circuit;
pub mod conn;
pub mod mount;
pub mod nfs2;
pub mod nfs3;
pub mod nfs4;
pub mod pool;
pub mod portmap;
pub mod udp;
