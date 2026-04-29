//! NFSv4 protocol support  --  custom COMPOUND encoder for security analysis.
//!
//! nfs3-rs does not cover NFSv4. libnfs covers it but requires C FFI.
//! We implement a minimal NFSv4 COMPOUND encoder for the ~6 operations
//! nfswolf needs, using nfs3_types XDR primitives for encoding.
//!
//! Operations needed:
//! - PUTROOTFH + LOOKUP + GETATTR + GETFH  --  pseudo-FS mapping (F-5.5)
//! - SECINFO  --  per-directory auth flavor detection
//! - READDIR  --  directory listing when v3 is blocked

// Toolkit API  --  not all items are used in currently-implemented phases.
//! - EXCHANGE_ID + CREATE_SESSION  --  NFSv4.1 session setup
//! - DESTROY_SESSION + DESTROY_CLIENTID  --  stealth session cleanup
//!
//! Even when a server primarily serves NFSv3, the v4 endpoint is often active
//! on the same port (2049) and exposes additional information:
//! - Pseudo-filesystem structure with fsid-based export boundary detection
//! - Per-directory SECINFO (authentication methods)
//! - NFSv4 ACLs (fattr4_acl) not visible through v3 mode bits
//! - Session cleanup (DESTROY_SESSION / DESTROY_CLIENTID) for stealth

pub mod compound;
pub mod types;

/// Linux NFSv4 pseudo-root namespace UUID.
///
/// nfs_analyze uses this UUID to detect the pseudo-root boundary when
/// recursively mapping the NFSv4 pseudo-filesystem. A fsid matching
/// this UUID indicates the pseudo-root, not a real export.
pub const LINUX_PSEUDO_ROOT_UUID: &str = "39c6b5c1-3f24-4f4e-977c-7fe6546b8a25";

/// NFSv4 compound operation codes relevant to security analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Nfs4Op {
    /// Check access permissions.
    Access = 3,
    /// Close a stateful open.
    Close = 4,
    /// Retrieve file attributes.
    Getattr = 9,
    /// Retrieve current file handle.
    Getfh = 10,
    /// Look up a path component.
    Lookup = 15,
    /// Open a file.
    Open = 18,
    /// Set the current file handle.
    Putfh = 22,
    /// Set the current file handle to the server root.
    Putrootfh = 24,
    /// Read file data.
    Read = 25,
    /// Read directory entries.
    Readdir = 26,
    /// Remove a directory entry.
    Remove = 28,
    /// Rename a directory entry.
    Rename = 29,
    /// Query security information for a path component.
    Secinfo = 33,
    /// Set file attributes.
    Setattr = 34,
    /// Write file data.
    Write = 38,
    /// Create a new file or directory.
    Create = 6,
    /// NFSv4.1+: Create session for stateful operations.
    CreateSession = 43,
    /// NFSv4.1+: Destroy session (stealth cleanup).
    DestroySession = 44,
    /// NFSv4.1+: Destroy client ID (stealth cleanup).
    DestroyClientid = 57,
    /// NFSv4.1+: Exchange ID for client registration.
    ExchangeId = 42,
    /// NFSv4.1+: Sequence number for slot-based operation ordering.
    Sequence = 53,
}

/// NFSv4 pseudo-filesystem entry discovered during recursive mapping.
#[derive(Debug, Clone)]
pub struct PseudoFsEntry {
    /// Path in the pseudo-filesystem (e.g., "/exports/home")
    pub path: String,
    /// Filesystem ID  --  changes at export boundaries.
    pub fsid: (u64, u64),
    /// Whether this is the pseudo-root (matches LINUX_PSEUDO_ROOT_UUID).
    pub is_pseudo_root: bool,
    /// Auth methods from SECINFO (e.g., `["krb5", "sys"]`).
    pub auth_methods: Vec<String>,
    /// Whether this entry is a real export (fsid differs from parent).
    pub is_export_boundary: bool,
}
