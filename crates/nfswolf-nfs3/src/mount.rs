//! MOUNT protocol procedure calls -- [RFC 1813] appendix I sec. 4.
//!
//! [RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813

use crate::wire::mount::{MOUNT_PROGRAM, PROGRAM, VERSION, dirpath, exports, mountlist, mountres3, mountres3_ok};
use nfswolf_rpc::rpc::opaque_auth;
use nfswolf_xdr::{Pack, Unpack, Void};

use crate::MountError;
use nfswolf_rpc::RpcError;
use nfswolf_rpc::rpc::RpcClient;
use nfswolf_rpc::transport::io::{AsyncRead, AsyncWrite};

/// Client for the MOUNT service (program 100005, version 3).
#[derive(Debug)]
pub struct MountClient<IO> {
    rpc: RpcClient<IO>,
}

impl<IO> MountClient<IO>
where
    IO: AsyncRead + AsyncWrite + Send,
{
    /// Create a new mount client using AUTH_NONE.
    pub fn new(io: IO) -> Self {
        Self { rpc: RpcClient::new(io) }
    }

    /// Create a new mount client with a custom credential and verifier.
    pub fn new_with_auth(io: IO, credential: opaque_auth<'static>, verifier: opaque_auth<'static>) -> Self {
        Self { rpc: RpcClient::new_with_auth(io, credential, verifier) }
    }

    /// `MNTPROC3_NULL` -- do nothing (RFC 1813 appendix I sec. 4.1).
    pub async fn null(&mut self) -> Result<(), RpcError> {
        let _ = self.call::<Void, Void>(MOUNT_PROGRAM::MOUNTPROC3_NULL, Void).await?;
        Ok(())
    }

    /// `MNTPROC3_MNT` -- mount an export and obtain its root file handle
    /// (RFC 1813 appendix I sec. 4.2).
    ///
    /// The reply also lists the authentication flavors the server will accept
    /// for this export, which is how a Kerberos-only export is distinguished
    /// from an AUTH_SYS one without attempting an operation.
    pub async fn mnt(&mut self, dirpath_: dirpath<'_>) -> Result<mountres3_ok<'static>, MountError> {
        let result = self.call::<dirpath<'_>, mountres3<'_>>(MOUNT_PROGRAM::MOUNTPROC3_MNT, dirpath_).await?;

        match result {
            mountres3::Ok(ok) => Ok(ok),
            mountres3::Err(err) => Err(MountError::Denied(err)),
        }
    }

    /// `MNTPROC3_DUMP` -- list the clients currently holding mounts
    /// (RFC 1813 appendix I sec. 4.3).
    ///
    /// The server keeps this list on the honour system -- clients are expected
    /// to call `UMNT` on unmount and frequently do not -- so entries are a
    /// record of who has mounted, not of who still has it mounted.
    pub async fn dump(&mut self) -> Result<mountlist<'static, 'static>, RpcError> {
        self.call::<Void, mountlist<'_, '_>>(MOUNT_PROGRAM::MOUNTPROC3_DUMP, Void).await
    }

    /// `MNTPROC3_UMNT` -- remove this client's entry for one export
    /// (RFC 1813 appendix I sec. 4.4).
    pub async fn umnt(&mut self, dirpath_: dirpath<'_>) -> Result<(), RpcError> {
        let _ = self.call::<dirpath<'_>, Void>(MOUNT_PROGRAM::MOUNTPROC3_UMNT, dirpath_).await?;
        Ok(())
    }

    /// `MNTPROC3_UMNTALL` -- remove all of this client's mount entries
    /// (RFC 1813 appendix I sec. 4.5).
    pub async fn umntall(&mut self) -> Result<(), RpcError> {
        let _ = self.call::<Void, Void>(MOUNT_PROGRAM::MOUNTPROC3_UMNTALL, Void).await?;
        Ok(())
    }

    /// `MNTPROC3_EXPORT` -- list every export and the hosts allowed to mount
    /// it (RFC 1813 appendix I sec. 4.6).
    ///
    /// The procedure takes no credential and the spec sets no access control
    /// on it, so any host that can reach the port learns the full export table
    /// along with each export's host restrictions.
    pub async fn export(&mut self) -> Result<exports<'static, 'static>, RpcError> {
        self.call::<Void, exports<'_, '_>>(MOUNT_PROGRAM::MOUNTPROC3_EXPORT, Void).await
    }

    /// Issue one MOUNT procedure call against program 100005, version 3.
    async fn call<C, R>(&mut self, proc: MOUNT_PROGRAM, args: C) -> Result<R, RpcError>
    where
        R: Unpack,
        C: Pack + Send + Sync,
    {
        self.rpc.call::<C, R>(PROGRAM, VERSION, proc as u32, &args).await
    }
}
