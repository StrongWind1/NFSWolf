//! NFS protocol layer  --  policy on top of the `nfs_proto` wire stack.
//!
//! `nfs_proto` owns the wire format for NFSv2/v3/v4, MOUNT, and the
//! portmapper and holds no policy of its own.  This layer supplies the
//! policy: AUTH_SYS stamp injection, connection pooling, circuit breaking,
//! auto-UID resolution, SOCKS5 transport, and privileged port binding.

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
