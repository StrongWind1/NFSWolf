//! NFSv3 procedure calls -- [RFC 1813] sec. 3.3.
//!
//! One method per procedure, each a thin wrapper that names the right
//! procedure number and lets the caller supply the already-built argument
//! struct.  Deliberately no retry, caching, or handle management: those are
//! policy decisions the caller owns.
//!
//! [RFC 1813]: https://www.rfc-editor.org/rfc/rfc1813

use crate::wire::{
    ACCESS3args, ACCESS3res, COMMIT3args, COMMIT3res, CREATE3args, CREATE3res, FSINFO3args, FSINFO3res, FSSTAT3args, FSSTAT3res, GETATTR3args, GETATTR3res, LINK3args, LINK3res, LOOKUP3args, LOOKUP3res, MKDIR3args, MKDIR3res, MKNOD3args, MKNOD3res, NFS_PROGRAM, PATHCONF3args, PATHCONF3res, PROGRAM,
    READ3args, READ3res, READDIR3args, READDIR3res, READDIRPLUS3args, READDIRPLUS3res, READLINK3args, READLINK3res, REMOVE3args, REMOVE3res, RENAME3args, RENAME3res, RMDIR3args, RMDIR3res, SETATTR3args, SETATTR3res, SYMLINK3args, SYMLINK3res, VERSION, WRITE3args, WRITE3res,
};
use nfswolf_rpc::rpc::opaque_auth;
use nfswolf_xdr::{Pack, Unpack, Void};

use nfswolf_rpc::RpcError;
use nfswolf_rpc::rpc::RpcClient;
use nfswolf_rpc::transport::io::{AsyncRead, AsyncWrite};

/// Client for the `NFSv3` service (program 100003, version 3).
#[derive(Debug)]
pub struct Nfs3Client<IO> {
    rpc: RpcClient<IO>,
}

impl<IO> Nfs3Client<IO>
where
    IO: AsyncRead + AsyncWrite + Send,
{
    /// Create a new `NFSv3` client using AUTH_NONE.
    pub fn new(io: IO) -> Self {
        Self { rpc: RpcClient::new(io) }
    }

    /// Create a new `NFSv3` client with a custom credential and verifier.
    pub fn new_with_auth(io: IO, credential: opaque_auth<'static>, verifier: opaque_auth<'static>) -> Self {
        Self { rpc: RpcClient::new_with_auth(io, credential, verifier) }
    }

    /// Replace the credential used for subsequent RPC calls on this connection.
    ///
    /// AUTH_SYS carries the claimed identity in every call rather than
    /// establishing it at handshake time, so the identity can be changed
    /// mid-session.  That makes it possible to sweep a UID range over one TCP
    /// connection instead of reconnecting for each candidate.
    pub fn set_credential(&mut self, credential: opaque_auth<'static>) {
        self.rpc.credential = credential;
    }

    /// `NULL` -- do nothing (RFC 1813 sec. 3.3.0).
    ///
    /// Costs the server nothing and touches no filesystem state, which makes
    /// it the standard liveness probe for an RPC service.
    pub async fn null(&mut self) -> Result<(), RpcError> {
        let _ = self.call::<Void, Void>(NFS_PROGRAM::NFSPROC3_NULL, &Void).await?;
        Ok(())
    }

    /// `GETATTR` -- retrieve file attributes (RFC 1813 sec. 3.3.1).
    pub async fn getattr(&mut self, args: &GETATTR3args) -> Result<GETATTR3res, RpcError> {
        self.call::<GETATTR3args, GETATTR3res>(NFS_PROGRAM::NFSPROC3_GETATTR, args).await
    }

    /// `SETATTR` -- set file attributes (RFC 1813 sec. 3.3.2).
    pub async fn setattr(&mut self, args: &SETATTR3args) -> Result<SETATTR3res, RpcError> {
        self.call::<SETATTR3args, SETATTR3res>(NFS_PROGRAM::NFSPROC3_SETATTR, args).await
    }

    /// `LOOKUP` -- resolve one path component to a file handle
    /// (RFC 1813 sec. 3.3.3).
    pub async fn lookup(&mut self, args: &LOOKUP3args<'_>) -> Result<LOOKUP3res, RpcError> {
        self.call::<LOOKUP3args<'_>, LOOKUP3res>(NFS_PROGRAM::NFSPROC3_LOOKUP, args).await
    }

    /// `ACCESS` -- ask which operations the caller may perform
    /// (RFC 1813 sec. 3.3.4).
    ///
    /// The answer is advisory.  The server may permit an operation here and
    /// still refuse it, or vice versa, so a positive result must be confirmed
    /// by attempting the real operation.
    pub async fn access(&mut self, args: &ACCESS3args) -> Result<ACCESS3res, RpcError> {
        self.call::<ACCESS3args, ACCESS3res>(NFS_PROGRAM::NFSPROC3_ACCESS, args).await
    }

    /// `READLINK` -- read a symbolic link's target (RFC 1813 sec. 3.3.5).
    pub async fn readlink(&mut self, args: &READLINK3args) -> Result<READLINK3res<'static>, RpcError> {
        self.call::<READLINK3args, READLINK3res<'_>>(NFS_PROGRAM::NFSPROC3_READLINK, args).await
    }

    /// `READ` -- read from a file (RFC 1813 sec. 3.3.6).
    pub async fn read(&mut self, args: &READ3args) -> Result<READ3res<'static>, RpcError> {
        self.call::<READ3args, READ3res<'_>>(NFS_PROGRAM::NFSPROC3_READ, args).await
    }

    /// `WRITE` -- write to a file (RFC 1813 sec. 3.3.7).
    pub async fn write(&mut self, args: &WRITE3args<'_>) -> Result<WRITE3res, RpcError> {
        self.call::<WRITE3args<'_>, WRITE3res>(NFS_PROGRAM::NFSPROC3_WRITE, args).await
    }

    /// `CREATE` -- create a regular file (RFC 1813 sec. 3.3.8).
    pub async fn create(&mut self, args: &CREATE3args<'_>) -> Result<CREATE3res, RpcError> {
        self.call::<CREATE3args<'_>, CREATE3res>(NFS_PROGRAM::NFSPROC3_CREATE, args).await
    }

    /// `MKDIR` -- create a directory (RFC 1813 sec. 3.3.9).
    pub async fn mkdir(&mut self, args: &MKDIR3args<'_>) -> Result<MKDIR3res, RpcError> {
        self.call::<MKDIR3args<'_>, MKDIR3res>(NFS_PROGRAM::NFSPROC3_MKDIR, args).await
    }

    /// `SYMLINK` -- create a symbolic link (RFC 1813 sec. 3.3.10).
    pub async fn symlink(&mut self, args: &SYMLINK3args<'_>) -> Result<SYMLINK3res, RpcError> {
        self.call::<SYMLINK3args<'_>, SYMLINK3res>(NFS_PROGRAM::NFSPROC3_SYMLINK, args).await
    }

    /// `MKNOD` -- create a device, socket, or FIFO (RFC 1813 sec. 3.3.11).
    pub async fn mknod(&mut self, args: &MKNOD3args<'_>) -> Result<MKNOD3res, RpcError> {
        self.call::<MKNOD3args<'_>, MKNOD3res>(NFS_PROGRAM::NFSPROC3_MKNOD, args).await
    }

    /// `REMOVE` -- remove a non-directory entry (RFC 1813 sec. 3.3.12).
    pub async fn remove(&mut self, args: &REMOVE3args<'_>) -> Result<REMOVE3res, RpcError> {
        self.call::<REMOVE3args<'_>, REMOVE3res>(NFS_PROGRAM::NFSPROC3_REMOVE, args).await
    }

    /// `RMDIR` -- remove a directory (RFC 1813 sec. 3.3.13).
    pub async fn rmdir(&mut self, args: &RMDIR3args<'_>) -> Result<RMDIR3res, RpcError> {
        self.call::<RMDIR3args<'_>, RMDIR3res>(NFS_PROGRAM::NFSPROC3_RMDIR, args).await
    }

    /// `RENAME` -- rename a directory entry (RFC 1813 sec. 3.3.14).
    pub async fn rename(&mut self, args: &RENAME3args<'_, '_>) -> Result<RENAME3res, RpcError> {
        self.call::<RENAME3args<'_, '_>, RENAME3res>(NFS_PROGRAM::NFSPROC3_RENAME, args).await
    }

    /// `LINK` -- create a hard link (RFC 1813 sec. 3.3.15).
    pub async fn link(&mut self, args: &LINK3args<'_>) -> Result<LINK3res, RpcError> {
        self.call::<LINK3args<'_>, LINK3res>(NFS_PROGRAM::NFSPROC3_LINK, args).await
    }

    /// `READDIR` -- list a directory, names and file IDs only
    /// (RFC 1813 sec. 3.3.16).
    pub async fn readdir(&mut self, args: &READDIR3args) -> Result<READDIR3res<'static>, RpcError> {
        self.call::<READDIR3args, READDIR3res<'_>>(NFS_PROGRAM::NFSPROC3_READDIR, args).await
    }

    /// `READDIRPLUS` -- list a directory with attributes and file handles
    /// (RFC 1813 sec. 3.3.17).
    ///
    /// Returns in one call what `READDIR` plus a `LOOKUP` and `GETATTR` per
    /// entry would, so it walks a tree far faster -- but servers may refuse it
    /// while still permitting plain `READDIR`.
    pub async fn readdirplus(&mut self, args: &READDIRPLUS3args) -> Result<READDIRPLUS3res<'static>, RpcError> {
        self.call::<READDIRPLUS3args, READDIRPLUS3res<'_>>(NFS_PROGRAM::NFSPROC3_READDIRPLUS, args).await
    }

    /// `FSSTAT` -- dynamic filesystem statistics, such as free space
    /// (RFC 1813 sec. 3.3.18).
    pub async fn fsstat(&mut self, args: &FSSTAT3args) -> Result<FSSTAT3res, RpcError> {
        self.call::<FSSTAT3args, FSSTAT3res>(NFS_PROGRAM::NFSPROC3_FSSTAT, args).await
    }

    /// `FSINFO` -- static filesystem limits, such as maximum read and write
    /// sizes (RFC 1813 sec. 3.3.19).
    pub async fn fsinfo(&mut self, args: &FSINFO3args) -> Result<FSINFO3res, RpcError> {
        self.call::<FSINFO3args, FSINFO3res>(NFS_PROGRAM::NFSPROC3_FSINFO, args).await
    }

    /// `PATHCONF` -- POSIX pathname limits for a filesystem object
    /// (RFC 1813 sec. 3.3.20).
    pub async fn pathconf(&mut self, args: &PATHCONF3args) -> Result<PATHCONF3res, RpcError> {
        self.call::<PATHCONF3args, PATHCONF3res>(NFS_PROGRAM::NFSPROC3_PATHCONF, args).await
    }

    /// `COMMIT` -- flush previously written unstable data to stable storage
    /// (RFC 1813 sec. 3.3.21).
    pub async fn commit(&mut self, args: &COMMIT3args) -> Result<COMMIT3res, RpcError> {
        self.call::<COMMIT3args, COMMIT3res>(NFS_PROGRAM::NFSPROC3_COMMIT, args).await
    }

    /// Issue one NFSv3 procedure call against program 100003, version 3.
    async fn call<C, R>(&mut self, proc: NFS_PROGRAM, args: &C) -> Result<R, RpcError>
    where
        R: Unpack,
        C: Pack + Send + Sync,
    {
        self.rpc.call::<C, R>(PROGRAM, VERSION, proc as u32, args).await
    }
}
