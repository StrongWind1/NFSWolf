//! NFS protocol layer  --  policy on top of the protocol crates.
//!
//! The `nfswolf-nfs2`, `nfswolf-nfs3`, and `nfswolf-nfs4` crates own the wire
//! portmapper and holds no policy of its own.  This layer supplies the
//! policy: AUTH_SYS stamp injection, connection pooling, circuit breaking,
//! auto-UID resolution, SOCKS5 transport, and privileged port binding.

pub(crate) mod auth;
pub(crate) mod circuit;
pub(crate) mod conn;
pub(crate) mod mount;
pub(crate) mod nfs2;
pub(crate) mod nfs3;
pub(crate) mod nfs4;
pub(crate) mod nfs_acl;
pub(crate) mod pool;
pub(crate) mod portmap;
pub(crate) mod transport;
pub(crate) mod udp;
