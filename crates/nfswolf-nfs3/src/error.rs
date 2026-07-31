//! NFSv3 status codes, classified.
//!
//! The critical distinction for nfswolf is NFS3ERR_STALE (70) vs
//! NFS3ERR_BADHANDLE (10001)  --  this oracle enables targeted handle
//! brute-force (F-2.2, RFC 1813 S2.6).

// Toolkit API  --  not all items are used in currently-implemented phases.
use core::fmt;

use crate::wire::nfsstat3;

/// An NFSv3 protocol status other than `NFS3_OK`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nfs3Error {
    /// `NFS3ERR_PERM` (1) -- caller is not the owner.
    ///
    /// Like [`Acces`](Self::Acces), a decision rather than a failure.
    Perm,
    /// `NFS3ERR_NOENT` -- no such file or directory.
    NoEnt,
    /// `NFS3ERR_IO` -- I/O error.
    Io,
    /// `NFS3ERR_NXIO` -- no such device.
    Nxio,
    /// `NFS3ERR_ACCES` (13) -- permission denied.
    ///
    /// Expected, not exceptional, when probing identities: it means the
    /// server processed the call and refused it. Never treat this as a
    /// transport fault.
    Acces,
    /// `NFS3ERR_EXIST` -- file exists.
    Exist,
    /// `NFS3ERR_XDEV` -- cross-device link.
    Xdev,
    /// `NFS3ERR_NODEV` -- no such device.
    Nodev,
    /// `NFS3ERR_NOTDIR` -- not a directory.
    NotDir,
    /// `NFS3ERR_ISDIR` -- is a directory.
    IsDir,
    /// `NFS3ERR_INVAL` -- invalid argument.
    Inval,
    /// `NFS3ERR_FBIG` -- file too large.
    Fbig,
    /// `NFS3ERR_NOSPC` -- no space left on device.
    Nospc,
    /// `NFS3ERR_ROFS` -- read-only filesystem.
    Rofs,
    /// `NFS3ERR_MLINK` -- too many hard links.
    Mlink,
    /// `NFS3ERR_NAMETOOLONG` -- name too long.
    NameTooLong,
    /// `NFS3ERR_NOTEMPTY` -- directory not empty.
    NotEmpty,
    /// `NFS3ERR_DQUOT` -- disk quota exceeded.
    Dquot,
    /// `NFS3ERR_STALE` (70) -- the handle is well-formed but names
    /// nothing that currently exists.
    ///
    /// Half of the handle oracle: the server understood the handle's
    /// layout and looked it up, so the format is right and only the
    /// inode or generation number is wrong. Contrast
    /// [`BadHandle`](Self::BadHandle).
    Stale,
    /// `NFS3ERR_REMOTE` -- too many levels of remote.
    Remote,
    /// `NFS3ERR_BADHANDLE` (10001) -- the handle is not well-formed.
    ///
    /// The other half of the oracle: the server rejected the handle's
    /// structure outright, so the format itself is wrong and varying the
    /// inode within it will not help.
    BadHandle,
    /// `NFS3ERR_NOT_SYNC` -- update synchronization mismatch.
    NotSync,
    /// `NFS3ERR_BAD_COOKIE` -- stale cookie.
    BadCookie,
    /// `NFS3ERR_NOTSUPP` -- operation not supported.
    NotSupp,
    /// `NFS3ERR_TOOSMALL` -- buffer or request too small.
    TooSmall,
    /// `NFS3ERR_SERVERFAULT` -- server fault.
    ServerFault,
    /// `NFS3ERR_BADTYPE` -- bad type.
    BadType,
    /// `NFS3ERR_JUKEBOX` (10008) -- the request is queued behind slow
    /// media and should be retried.
    Jukebox,
    /// Unknown NFS3 error code.
    Unknown(u32),
}

impl fmt::Display for Nfs3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Perm => f.write_str("NFS3ERR_PERM: not owner"),
            Self::NoEnt => f.write_str("NFS3ERR_NOENT: no such file or directory"),
            Self::Io => f.write_str("NFS3ERR_IO: I/O error"),
            Self::Nxio => f.write_str("NFS3ERR_NXIO: no such device"),
            Self::Acces => f.write_str("NFS3ERR_ACCES: permission denied"),
            Self::Exist => f.write_str("NFS3ERR_EXIST: file exists"),
            Self::Xdev => f.write_str("NFS3ERR_XDEV: cross-device link"),
            Self::Nodev => f.write_str("NFS3ERR_NODEV: no such device"),
            Self::NotDir => f.write_str("NFS3ERR_NOTDIR: not a directory"),
            Self::IsDir => f.write_str("NFS3ERR_ISDIR: is a directory"),
            Self::Inval => f.write_str("NFS3ERR_INVAL: invalid argument"),
            Self::Fbig => f.write_str("NFS3ERR_FBIG: file too large"),
            Self::Nospc => f.write_str("NFS3ERR_NOSPC: no space left on device"),
            Self::Rofs => f.write_str("NFS3ERR_ROFS: read-only filesystem"),
            Self::Mlink => f.write_str("NFS3ERR_MLINK: too many hard links"),
            Self::NameTooLong => f.write_str("NFS3ERR_NAMETOOLONG: name too long"),
            Self::NotEmpty => f.write_str("NFS3ERR_NOTEMPTY: directory not empty"),
            Self::Dquot => f.write_str("NFS3ERR_DQUOT: disk quota exceeded"),
            Self::Stale => f.write_str("NFS3ERR_STALE: stale file handle"),
            Self::Remote => f.write_str("NFS3ERR_REMOTE: too many levels of remote"),
            Self::BadHandle => f.write_str("NFS3ERR_BADHANDLE: illegal NFS file handle"),
            Self::NotSync => f.write_str("NFS3ERR_NOT_SYNC: update synchronization mismatch"),
            Self::BadCookie => f.write_str("NFS3ERR_BAD_COOKIE: stale cookie"),
            Self::NotSupp => f.write_str("NFS3ERR_NOTSUPP: operation not supported"),
            Self::TooSmall => f.write_str("NFS3ERR_TOOSMALL: buffer or request too small"),
            Self::ServerFault => f.write_str("NFS3ERR_SERVERFAULT: server fault"),
            Self::BadType => f.write_str("NFS3ERR_BADTYPE: bad type"),
            Self::Jukebox => f.write_str("NFS3ERR_JUKEBOX: resource temporarily unavailable"),
            Self::Unknown(code) => write!(f, "Unknown NFS3 error code: {code}"),
        }
    }
}

impl std::error::Error for Nfs3Error {}

impl Nfs3Error {
    /// Convert from the wire `nfsstat3` status code.
    #[must_use]
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
