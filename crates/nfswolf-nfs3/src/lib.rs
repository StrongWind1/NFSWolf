//! NFS version 3 -- [RFC 1813], with the MOUNT v3 protocol it depends on.
//!
//! A complete NFSv3 client: all 22 procedures, all wire types, and the MOUNT
//! sideband service that turns an export path into the root file handle
//! everything else starts from.
//!
//! # Layers
//!
//! | Module | What it is |
//! |--------|-----------|
//! | [`wire`] | XDR types transcribed verbatim from the RFC |
//! | [`Nfs3Client`] | One method per procedure, wire types in and out |
//! | [`mount`] | The MOUNT v3 client (RFC 1813 appendix I) |
//! | [`api`] | Domain types -- file handles, attributes, access bits |
//! | [`Nfs3Error`] | Protocol status codes, classified |
//!
//! Pick a layer by what you are doing. Reading a file wants [`api`]. Sending a
//! deliberately malformed request to see how a server reacts wants [`wire`]
//! and the raw client, which will encode whatever you hand it.
//!
//! # Protocol properties worth knowing
//!
//! Two are load-bearing for anything security-related:
//!
//! * **File handles are bearer tokens.** A handle obtained under one
//!   credential keeps working under any other (RFC 1813 sec. 2.6). The server
//!   does not re-check how you got it. Handles can therefore be reused across
//!   identity switches instead of re-resolving paths, and a handle guessed or
//!   constructed rather than looked up is just as valid.
//! * **`ACCESS` is advisory.** The server answers what it believes the caller
//!   may do and is not required to be right (RFC 1813 sec. 3.3.4). It may
//!   permit an operation here and refuse it for real, or the reverse. Confirm
//!   by attempting the operation.
//!
//! [RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813

pub mod api;
pub mod wire;

mod error;
mod error_mount;
pub mod mount;
mod raw;

pub use api::{CreateMode, DirEntry, DirEntryPlus, DirPage, FileAttrs, FileHandle, FileType, FsInfo, FsStat, HexError, Nfs3Fault, NfsTime, ReadChunk, WriteAck, WriteStable, access};
pub use error::Nfs3Error;
pub use error_mount::MountError;
pub use mount::MountClient;
pub use raw::Nfs3Client;
pub use wire::{PROGRAM, VERSION};
