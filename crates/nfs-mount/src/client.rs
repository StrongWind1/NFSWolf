//! Unified MOUNT client -- versions 1 and 3 behind one type.
//!
//! MOUNT v1 (RFC 1094 Appendix A) returns a bare 32-byte handle on MNT.
//! MOUNT v3 (RFC 1813 Appendix I) returns a variable-length handle plus
//! the authentication flavors the export accepts.
//!
//! [`MountClient`] wraps either version and provides both version-specific
//! methods (v1_mnt, v3_mnt) and version-neutral methods (null, export, umnt).

use onc_rpc_client::RpcTransport;
use onc_xdr::{Pack, Unpack, Void};

use crate::error::MountError;
use crate::wire::{FhStatus, MOUNT_V1, MOUNT_V3, MOUNT_V3_PROC, PROGRAM, dirpath, exports, mountlist, mountres3, mountres3_ok};

// --- Version selector ---

/// Which MOUNT version the client speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MountVersion {
    /// MOUNT v1 (RFC 1094 Appendix A).
    V1,
    /// MOUNT v3 (RFC 1813 Appendix I).
    V3,
}

impl MountVersion {
    /// The version number used in RPC headers.
    #[must_use]
    pub const fn version_number(self) -> u32 {
        match self {
            Self::V1 => MOUNT_V1,
            Self::V3 => MOUNT_V3,
        }
    }
}

// --- MountedHandle ---

/// A file handle obtained from a successful MNT call.
///
/// Carries the auth flavors the server accepts for this export (v3 only;
/// v1 has no flavor negotiation, so the list will contain just `AUTH_SYS = 1`
/// as a reasonable default).
#[derive(Debug, Clone)]
pub struct MountedHandle {
    /// Raw handle bytes (32 for v1, up to 64 for v3).
    pub bytes: Vec<u8>,
    /// Authentication flavors the server advertised for this export.
    ///
    /// Raw u32 values from the MNT response. Known values:
    /// `AUTH_NONE=0`, `AUTH_SYS=1`, `AUTH_SHORT=2`, `RPCSEC_GSS=6`.
    pub auth_flavors: Vec<u32>,
}

/// AUTH_SYS flavor constant (RFC 5531 sec. 14).
const AUTH_SYS: u32 = 1;

impl MountedHandle {
    /// Whether the export accepts AUTH_SYS.
    #[must_use]
    pub fn accepts_auth_sys(&self) -> bool {
        self.auth_flavors.contains(&AUTH_SYS)
    }

    /// Whether AUTH_SYS is the only flavor the export accepts.
    #[must_use]
    pub fn is_auth_sys_only(&self) -> bool {
        self.auth_flavors.len() == 1 && self.auth_flavors.first().copied() == Some(AUTH_SYS)
    }
}

// --- Unified client ---

/// Client for the MOUNT service (program 100005).
///
/// Generic over the transport so it carries no connection policy.
/// Supports both v1 (RFC 1094 Appendix A) and v3 (RFC 1813 Appendix I).
#[derive(Debug)]
pub struct MountClient<T> {
    transport: T,
    version: MountVersion,
}

impl<T: RpcTransport> MountClient<T> {
    /// Create a client for the given version.
    pub const fn new(transport: T, version: MountVersion) -> Self {
        Self { transport, version }
    }

    /// Create a MOUNT v1 client.
    pub const fn v1(transport: T) -> Self {
        Self::new(transport, MountVersion::V1)
    }

    /// Create a MOUNT v3 client.
    pub const fn v3(transport: T) -> Self {
        Self::new(transport, MountVersion::V3)
    }

    /// Borrow the underlying transport.
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Which protocol version this client speaks.
    pub const fn version(&self) -> MountVersion {
        self.version
    }

    // --- Version-neutral procedures ---

    /// `MOUNTPROC_NULL` / `MOUNTPROC3_NULL` -- no-op connectivity check.
    pub async fn null(&self) -> Result<(), T::Error> {
        let _: Void = self.raw_call(0, &Void).await?;
        Ok(())
    }

    /// `MOUNTPROC_EXPORT` / `MOUNTPROC3_EXPORT` -- list all exports.
    ///
    /// The wire format is identical between v1 and v3.
    pub async fn export(&self) -> Result<exports<'static, 'static>, T::Error> {
        self.raw_call(5, &Void).await
    }

    /// `MOUNTPROC_UMNT` / `MOUNTPROC3_UMNT` -- unmount an export.
    pub async fn umnt(&self, path: dirpath<'_>) -> Result<(), T::Error> {
        let _: Void = self.raw_call(3, &path).await?;
        Ok(())
    }

    // --- Version-specific MNT ---

    /// Mount via MOUNT v3 MNT (RFC 1813 Appendix I sec. 4.2).
    ///
    /// Returns the variable-length handle and auth flavor list.
    pub async fn v3_mnt(&self, path: dirpath<'_>) -> Result<mountres3_ok<'static>, MountError<T::Error>> {
        let result = self.transport.call::<dirpath<'_>, mountres3<'_>>(PROGRAM, MOUNT_V3, MOUNT_V3_PROC::MOUNTPROC3_MNT as u32, &path).await.map_err(MountError::Rpc)?;
        match result {
            mountres3::Ok(ok) => Ok(ok),
            mountres3::Err(err) => Err(MountError::Status(err)),
        }
    }

    /// Mount via MOUNT v1 MNT (RFC 1094 Appendix A).
    ///
    /// Returns the fixed 32-byte handle.
    pub async fn v1_mnt(&self, path: dirpath<'_>) -> Result<FhStatus, T::Error> {
        self.transport.call::<dirpath<'_>, FhStatus>(PROGRAM, MOUNT_V1, 1, &path).await
    }

    /// Mount an export using the client's configured version.
    ///
    /// Returns a [`MountedHandle`] that carries the handle bytes and auth
    /// flavors regardless of which version was used.
    pub async fn mnt(&self, path: dirpath<'_>) -> Result<MountedHandle, MountError<T::Error>> {
        match self.version {
            MountVersion::V1 => {
                let fhs = self.v1_mnt(path).await.map_err(MountError::Rpc)?;
                if fhs.status != 0 {
                    // Map v1 errno to the closest mountstat3 value for uniform error handling.
                    let stat = v1_status_to_mountstat3(fhs.status);
                    return Err(MountError::Status(stat));
                }
                Ok(MountedHandle {
                    bytes: fhs.fhandle.to_vec(),
                    // v1 has no flavor negotiation; AUTH_SYS is the only
                    // reasonable assumption (RFC 2623 sec. 2.7).
                    auth_flavors: vec![AUTH_SYS],
                })
            },
            MountVersion::V3 => {
                let ok = self.v3_mnt(path).await?;
                Ok(MountedHandle { bytes: ok.fhandle.0.into_owned(), auth_flavors: ok.auth_flavors })
            },
        }
    }

    // --- Version-neutral additional procedures ---

    /// `MNTPROC_DUMP` / `MNTPROC3_DUMP` -- list currently mounted clients.
    ///
    /// The wire format (mountlist) is identical between v1 and v3.
    pub async fn dump(&self) -> Result<mountlist<'static, 'static>, T::Error> {
        self.raw_call(2, &Void).await
    }

    /// `MNTPROC_UMNTALL` / `MNTPROC3_UMNTALL` -- remove all mount entries for this client.
    ///
    /// The wire format (void -> void) is identical between v1 and v3.
    pub async fn umntall(&self) -> Result<(), T::Error> {
        let _: Void = self.raw_call(4, &Void).await?;
        Ok(())
    }

    /// Issue one MOUNT procedure call against the configured version.
    async fn raw_call<C, R>(&self, proc: u32, args: &C) -> Result<R, T::Error>
    where
        C: Pack + Send + Sync,
        R: Unpack,
    {
        self.transport.call::<C, R>(PROGRAM, self.version.version_number(), proc, args).await
    }
}

/// Map a MOUNT v1 error status (UNIX errno) to the closest mountstat3 value.
///
/// MOUNT v1 returns raw UNIX errno values, not the typed mountstat3 enum.
/// This mapping covers the common cases so callers get a uniform error type.
const fn v1_status_to_mountstat3(errno: u32) -> crate::wire::mountstat3 {
    use crate::wire::mountstat3;
    match errno {
        1 => mountstat3::MNT3ERR_PERM,
        2 => mountstat3::MNT3ERR_NOENT,
        5 => mountstat3::MNT3ERR_IO,
        13 => mountstat3::MNT3ERR_ACCES,
        20 => mountstat3::MNT3ERR_NOTDIR,
        22 => mountstat3::MNT3ERR_INVAL,
        // Catch-all for unexpected errno values.
        _ => mountstat3::MNT3ERR_SERVERFAULT,
    }
}
