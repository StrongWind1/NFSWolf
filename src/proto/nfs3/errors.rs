//! NFSv3 error codes  --  maps nfs3_types::nfs3::nfsstat3 to domain errors.
//!
//! The critical distinction for nfswolf is NFS3ERR_STALE (70) vs
//! NFS3ERR_BADHANDLE (10001)  --  this oracle enables targeted handle
//! brute-force (F-2.2, RFC 1813 S2.6).

// Enum variants mirror RFC 1813 SAppendix A status codes; individual docs
// would repeat the error name verbatim.
// Toolkit API  --  not all items are used in currently-implemented phases.
use nfs3_types::nfs3::nfsstat3;
use thiserror::Error;

/// NFSv3 status codes  --  wraps nfs3_types::nfs3::nfsstat3 with Display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Nfs3Error {
    #[error("NFS3ERR_PERM: not owner")]
    Perm,
    #[error("NFS3ERR_NOENT: no such file or directory")]
    NoEnt,
    #[error("NFS3ERR_IO: I/O error")]
    Io,
    #[error("NFS3ERR_NXIO: no such device")]
    Nxio,
    #[error("NFS3ERR_ACCES: permission denied")]
    Acces,
    #[error("NFS3ERR_EXIST: file exists")]
    Exist,
    #[error("NFS3ERR_XDEV: cross-device link")]
    Xdev,
    #[error("NFS3ERR_NODEV: no such device")]
    Nodev,
    #[error("NFS3ERR_NOTDIR: not a directory")]
    NotDir,
    #[error("NFS3ERR_ISDIR: is a directory")]
    IsDir,
    #[error("NFS3ERR_INVAL: invalid argument")]
    Inval,
    #[error("NFS3ERR_FBIG: file too large")]
    Fbig,
    #[error("NFS3ERR_NOSPC: no space left on device")]
    Nospc,
    #[error("NFS3ERR_ROFS: read-only filesystem")]
    Rofs,
    #[error("NFS3ERR_MLINK: too many hard links")]
    Mlink,
    #[error("NFS3ERR_NAMETOOLONG: name too long")]
    NameTooLong,
    #[error("NFS3ERR_NOTEMPTY: directory not empty")]
    NotEmpty,
    #[error("NFS3ERR_DQUOT: disk quota exceeded")]
    Dquot,
    #[error("NFS3ERR_STALE: stale file handle")]
    Stale,
    #[error("NFS3ERR_REMOTE: too many levels of remote")]
    Remote,
    #[error("NFS3ERR_BADHANDLE: illegal NFS file handle")]
    BadHandle,
    #[error("NFS3ERR_NOT_SYNC: update synchronization mismatch")]
    NotSync,
    #[error("NFS3ERR_BAD_COOKIE: stale cookie")]
    BadCookie,
    #[error("NFS3ERR_NOTSUPP: operation not supported")]
    NotSupp,
    #[error("NFS3ERR_TOOSMALL: buffer or request too small")]
    TooSmall,
    #[error("NFS3ERR_SERVERFAULT: server fault")]
    ServerFault,
    #[error("NFS3ERR_BADTYPE: bad type")]
    BadType,
    #[error("NFS3ERR_JUKEBOX: resource temporarily unavailable")]
    Jukebox,
    #[error("Unknown NFS3 error code: {0}")]
    Unknown(u32),
}

impl Nfs3Error {
    /// Convert from nfs3-rs nfsstat3.
    pub const fn from_nfsstat3(stat: nfsstat3) -> Option<Self> {
        match stat {
            nfsstat3::NFS3_OK => None, // not an error
            nfsstat3::NFS3ERR_PERM => Some(Self::Perm),
            nfsstat3::NFS3ERR_NOENT => Some(Self::NoEnt),
            nfsstat3::NFS3ERR_IO => Some(Self::Io),
            nfsstat3::NFS3ERR_NXIO => Some(Self::Nxio),
            nfsstat3::NFS3ERR_ACCES => Some(Self::Acces),
            nfsstat3::NFS3ERR_EXIST => Some(Self::Exist),
            nfsstat3::NFS3ERR_XDEV => Some(Self::Xdev),
            nfsstat3::NFS3ERR_NODEV => Some(Self::Nodev),
            nfsstat3::NFS3ERR_NOTDIR => Some(Self::NotDir),
            nfsstat3::NFS3ERR_ISDIR => Some(Self::IsDir),
            nfsstat3::NFS3ERR_INVAL => Some(Self::Inval),
            nfsstat3::NFS3ERR_FBIG => Some(Self::Fbig),
            nfsstat3::NFS3ERR_NOSPC => Some(Self::Nospc),
            nfsstat3::NFS3ERR_ROFS => Some(Self::Rofs),
            nfsstat3::NFS3ERR_MLINK => Some(Self::Mlink),
            nfsstat3::NFS3ERR_NAMETOOLONG => Some(Self::NameTooLong),
            nfsstat3::NFS3ERR_NOTEMPTY => Some(Self::NotEmpty),
            nfsstat3::NFS3ERR_DQUOT => Some(Self::Dquot),
            nfsstat3::NFS3ERR_STALE => Some(Self::Stale),
            nfsstat3::NFS3ERR_REMOTE => Some(Self::Remote),
            nfsstat3::NFS3ERR_BADHANDLE => Some(Self::BadHandle),
            nfsstat3::NFS3ERR_NOT_SYNC => Some(Self::NotSync),
            nfsstat3::NFS3ERR_BAD_COOKIE => Some(Self::BadCookie),
            nfsstat3::NFS3ERR_NOTSUPP => Some(Self::NotSupp),
            nfsstat3::NFS3ERR_TOOSMALL => Some(Self::TooSmall),
            nfsstat3::NFS3ERR_SERVERFAULT => Some(Self::ServerFault),
            nfsstat3::NFS3ERR_BADTYPE => Some(Self::BadType),
            nfsstat3::NFS3ERR_JUKEBOX => Some(Self::Jukebox),
        }
    }

    /// Is this a transient error (for circuit breaker)?
    /// Permission denials are NOT transient  --  they're expected during UID spraying.
    #[must_use]
    pub const fn is_transient(self) -> bool {
        matches!(self, Self::Io | Self::Jukebox | Self::ServerFault)
    }

    /// Is this a permission error (expected during auto-uid)?
    #[must_use]
    pub const fn is_permission_denied(self) -> bool {
        matches!(self, Self::Perm | Self::Acces)
    }

    /// Handle oracle: BADHANDLE = wrong format, STALE = right format wrong inode/gen.
    #[must_use]
    pub const fn is_handle_oracle_hit(self) -> bool {
        matches!(self, Self::Stale)
    }

    /// Handle oracle: BADHANDLE = wrong format entirely.
    #[must_use]
    pub const fn is_handle_oracle_miss(self) -> bool {
        matches!(self, Self::BadHandle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfs3_ok_maps_to_none() {
        // NFS3_OK is the zero-value success status; it must not become an error.
        assert!(Nfs3Error::from_nfsstat3(nfsstat3::NFS3_OK).is_none());
    }

    #[test]
    fn nfs3_stale_is_oracle_hit() {
        // NFS3ERR_STALE (70) = right handle format, wrong inode/generation.
        // This is the positive signal in the handle-brute-force oracle (F-2.2).
        let e = Nfs3Error::from_nfsstat3(nfsstat3::NFS3ERR_STALE).expect("STALE must be Some");
        assert!(e.is_handle_oracle_hit(), "STALE should be an oracle hit");
        assert!(!e.is_handle_oracle_miss(), "STALE is not an oracle miss");
    }

    #[test]
    fn nfs3_badhandle_is_oracle_miss() {
        // NFS3ERR_BADHANDLE (10001) = wrong format entirely -> bad structure, not just bad inode.
        let e = Nfs3Error::from_nfsstat3(nfsstat3::NFS3ERR_BADHANDLE).expect("BADHANDLE must be Some");
        assert!(e.is_handle_oracle_miss(), "BADHANDLE should be an oracle miss");
        assert!(!e.is_handle_oracle_hit(), "BADHANDLE is not an oracle hit");
    }

    #[test]
    fn nfs3_perm_is_not_transient() {
        // Permission denials must never trip the circuit breaker  --  they're expected
        // during UID spraying (DESIGN.md S3).
        let e = Nfs3Error::from_nfsstat3(nfsstat3::NFS3ERR_PERM).expect("PERM must be Some");
        assert!(!e.is_transient(), "PERM is not a transient error");
        assert!(e.is_permission_denied());
    }

    #[test]
    fn nfs3_acces_is_not_transient() {
        let e = Nfs3Error::from_nfsstat3(nfsstat3::NFS3ERR_ACCES).expect("ACCES must be Some");
        assert!(!e.is_transient(), "ACCES is not a transient error");
        assert!(e.is_permission_denied());
    }

    #[test]
    fn nfs3_io_is_transient() {
        // I/O errors indicate a server problem and should trip the breaker.
        let e = Nfs3Error::from_nfsstat3(nfsstat3::NFS3ERR_IO).expect("IO must be Some");
        assert!(e.is_transient(), "NFS3ERR_IO must be transient");
        assert!(!e.is_permission_denied());
    }

    #[test]
    fn nfs3_jukebox_is_transient() {
        // JUKEBOX = "resource temporarily unavailable"  --  a retry hint from the server.
        let e = Nfs3Error::from_nfsstat3(nfsstat3::NFS3ERR_JUKEBOX).expect("JUKEBOX must be Some");
        assert!(e.is_transient(), "NFS3ERR_JUKEBOX must be transient");
    }

    #[test]
    fn nfs3_serverfault_is_transient() {
        let e = Nfs3Error::from_nfsstat3(nfsstat3::NFS3ERR_SERVERFAULT).expect("SERVERFAULT must be Some");
        assert!(e.is_transient());
    }

    #[test]
    fn nfs3_noent_is_neither_transient_nor_perm() {
        let e = Nfs3Error::from_nfsstat3(nfsstat3::NFS3ERR_NOENT).expect("NOENT must be Some");
        assert!(!e.is_transient());
        assert!(!e.is_permission_denied());
        assert!(!e.is_handle_oracle_hit());
        assert!(!e.is_handle_oracle_miss());
    }
}
