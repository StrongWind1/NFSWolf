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
//! Both stateless operations (LOOKUP, GETATTR, READDIR, anonymous READ) and
//! stateful operations (SETCLIENTID, OPEN, CLOSE, stateid-bearing READ/WRITE,
//! RENEW) are implemented for NFSv4.0. The [`session`] module tracks the
//! (clientid, verifier) pair negotiated via SETCLIENTID + SETCLIENTID_CONFIRM,
//! and the [`state`] module tracks per-file open and lock stateids.
//!
//! The v4.1 session machinery of [RFC 8881] (CREATE_SESSION, SEQUENCE,
//! DESTROY_SESSION) is not yet implemented.
//!
//! [RFC 7530]: https://www.rfc-editor.org/rfc/rfc7530
//! [RFC 8881]: https://www.rfc-editor.org/rfc/rfc8881

pub mod client;
pub mod session;
pub mod state;
pub mod wire;

pub use client::{Nfs4Client, Nfs4Error};
pub use session::Nfs4Session;
pub use state::{LockRange, LockState, OpenState};
pub use wire::NfsImplId4;
pub use wire::{ArgOp, AttrRequest, CompoundArgs, CompoundBuilder, CompoundRes, DirEntry4, Fattr4Decoded, NFS4_PROC_COMPOUND, NFS4_PROGRAM as PROGRAM, NFS4_VERSION as VERSION, Nfs4DirEntry, Nfs4FileInfo, Nfs4FileType, Nfs4Status, ResOp, ResOpData, SecInfoEntry};
pub use wire::{FATTR4_SEC_LABEL, SecLabel4};
// Phase 1: enums and constants.
pub use wire::{CreateMode4, LockType4, NFS4_FHSIZE, NFS4_OPAQUE_LIMIT, NFS4_OTHER_SIZE, NFS4_VERIFIER_SIZE, OpenClaimType4, OpenDelegationType4, OpenType4, StableHow4};
// Phase 2a: compound types.
pub use wire::{ChangeInfo4, LockOwner4, NfsAce4, NfsFtype4, OpenOwner4, Stateid4};
// Phase 2b: discriminated unions and fattr4 container.
pub use wire::{CreateType4, Fattr4, Locker4, OpenClaim4, OpenFlag4};
// Phase 3b: response-only types.
pub use wire::{OpenDelegation4, SpaceLimit4};
