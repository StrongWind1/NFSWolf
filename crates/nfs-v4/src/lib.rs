//! NFS version 4.0 -- [RFC 7530].
//!
//! NFSv4 is a different shape from v2 and v3. Rather than one RPC per
//! operation, the client batches operations into a single `COMPOUND` call that
//! the server executes in order against a "current file handle" the operations
//! mutate as they go, so `PUTROOTFH; LOOKUP "etc"; GETFH` is one round trip.
//! MOUNT is gone: the server exports a single pseudo-filesystem tree reached
//! from `PUTROOTFH`.
//!
//! # Scope
//!
//! This crate implements the stateless, read-only subset -- enough to walk the
//! pseudo-filesystem, read attributes, list directories, query per-directory
//! security flavors, and read file data.
//!
//! The stateful half is not implemented: `OPEN`, `CLOSE`, `LOCK`, delegations,
//! and the v4.1 session machinery of [RFC 8881]. Those need clientid and
//! stateid tracking, `OPEN_CONFIRM`, and lease renewal, which is a
//! substantially larger piece of work than the operations here.
//!
//! [RFC 7530]: https://www.rfc-editor.org/rfc/rfc7530
//! [RFC 8881]: https://www.rfc-editor.org/rfc/rfc8881

pub mod client;
pub mod wire;

pub use client::{Nfs4Client, Nfs4Error};
pub use wire::NfsImplId4;
pub use wire::{ArgOp, AttrRequest, CompoundArgs, CompoundBuilder, CompoundRes, DirEntry4, NFS4_PROC_COMPOUND, NFS4_PROGRAM as PROGRAM, NFS4_VERSION as VERSION, Nfs4Status, ResOp, ResOpData, SecInfoEntry};
pub use wire::{FATTR4_SEC_LABEL, SecLabel4};
