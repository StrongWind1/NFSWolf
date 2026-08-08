//! Wire-level NFSv2 client -- [RFC 1094].
//!
//! [`Nfs2RawClient`] mirrors [`Nfs2Client`](crate::Nfs2Client) but operates
//! entirely at the wire layer: arguments go in as `wire::*` structs, results
//! come back as `wire::*` structs, and no status code is checked or converted.
//! This is the client a security tool needs when it wants to send deliberately
//! malformed requests, study raw error responses, or exercise procedure numbers
//! that the domain-level client does not expose.
//!
//! NFSv2 has no security negotiation at all (RFC 2623 sec. 2.7), making it the
//! version most worth sending deliberate garbage at.
//!
//! [RFC 1094]: https://www.rfc-editor.org/rfc/rfc1094

use onc_rpc_client::RpcTransport;
use onc_xdr::{Pack, Unpack, Void};

use crate::wire;
use crate::wire::{NFS_PROGRAM, NFS_VERSION, proc};

/// Wire-level client for the NFSv2 service (program 100003, version 2).
///
/// Every method takes and returns the raw XDR wire types from [`wire`]. No
/// status codes are checked, no domain conversions are applied. The caller
/// gets exactly what the server sent.
///
/// Generic over the transport, like every client in this workspace, so it
/// carries no connection policy of its own.
#[derive(Debug)]
pub struct Nfs2RawClient<T>(T);

impl<T: RpcTransport> Nfs2RawClient<T> {
    /// Wrap a transport.
    pub const fn new(transport: T) -> Self {
        Self(transport)
    }

    /// Borrow the underlying transport.
    pub const fn transport(&self) -> &T {
        &self.0
    }

    /// Consume the client and return the transport.
    pub fn into_transport(self) -> T {
        self.0
    }

    // --- 18 NFSv2 procedures (RFC 1094 S2.2) ---

    /// `NFSPROC_NULL` (proc 0) -- no-op (RFC 1094 S2.2.1).
    pub async fn null(&self) -> Result<(), T::Error> {
        let Void = self.call_raw::<Void, Void>(proc::NFSPROC_NULL, &Void).await?;
        Ok(())
    }

    /// `NFSPROC_GETATTR` (proc 1) -- get file attributes (RFC 1094 S2.2.2).
    pub async fn getattr(&self, fh: &wire::Nfs2FileHandle) -> Result<wire::AttrStatRes, T::Error> {
        self.call_raw(proc::NFSPROC_GETATTR, fh).await
    }

    /// `NFSPROC_SETATTR` (proc 2) -- set file attributes (RFC 1094 S2.2.3).
    pub async fn setattr(&self, args: &wire::sattrargs) -> Result<wire::AttrStatRes, T::Error> {
        self.call_raw(proc::NFSPROC_SETATTR, args).await
    }

    /// `NFSPROC_ROOT` (proc 3) -- obsolete (RFC 1094 S2.2.4).
    ///
    /// Sends void, expects void. Present for completeness; most servers ignore
    /// this procedure entirely.
    pub async fn root(&self) -> Result<(), T::Error> {
        let Void = self.call_raw::<Void, Void>(proc::NFSPROC_ROOT, &Void).await?;
        Ok(())
    }

    /// `NFSPROC_LOOKUP` (proc 4) -- look up filename in directory (RFC 1094 S2.2.5).
    pub async fn lookup(&self, args: &wire::DirOpArgs) -> Result<wire::DirOpRes, T::Error> {
        self.call_raw(proc::NFSPROC_LOOKUP, args).await
    }

    /// `NFSPROC_READLINK` (proc 5) -- read symbolic link (RFC 1094 S2.2.6).
    pub async fn readlink(&self, fh: &wire::Nfs2FileHandle) -> Result<wire::readlinkres, T::Error> {
        self.call_raw(proc::NFSPROC_READLINK, fh).await
    }

    /// `NFSPROC_READ` (proc 6) -- read from file (RFC 1094 S2.2.7).
    pub async fn read(&self, args: &wire::ReadArgs) -> Result<wire::ReadRes, T::Error> {
        self.call_raw(proc::NFSPROC_READ, args).await
    }

    /// `NFSPROC_WRITECACHE` (proc 7) -- reserved, unused (RFC 1094 S2.2.8).
    pub async fn writecache(&self) -> Result<(), T::Error> {
        let Void = self.call_raw::<Void, Void>(proc::NFSPROC_WRITECACHE, &Void).await?;
        Ok(())
    }

    /// `NFSPROC_WRITE` (proc 8) -- write to file (RFC 1094 S2.2.9).
    pub async fn write(&self, args: &wire::WriteArgs) -> Result<wire::AttrStatRes, T::Error> {
        self.call_raw(proc::NFSPROC_WRITE, args).await
    }

    /// `NFSPROC_CREATE` (proc 9) -- create a file (RFC 1094 S2.2.10).
    pub async fn create(&self, args: &wire::createargs) -> Result<wire::DirOpRes, T::Error> {
        self.call_raw(proc::NFSPROC_CREATE, args).await
    }

    /// `NFSPROC_REMOVE` (proc 10) -- remove a file (RFC 1094 S2.2.11).
    pub async fn remove(&self, args: &wire::DirOpArgs) -> Result<wire::Nfs2Stat, T::Error> {
        self.call_raw(proc::NFSPROC_REMOVE, args).await
    }

    /// `NFSPROC_RENAME` (proc 11) -- rename a file (RFC 1094 S2.2.12).
    pub async fn rename(&self, args: &wire::renameargs) -> Result<wire::Nfs2Stat, T::Error> {
        self.call_raw(proc::NFSPROC_RENAME, args).await
    }

    /// `NFSPROC_LINK` (proc 12) -- create hard link (RFC 1094 S2.2.13).
    pub async fn link(&self, args: &wire::linkargs) -> Result<wire::Nfs2Stat, T::Error> {
        self.call_raw(proc::NFSPROC_LINK, args).await
    }

    /// `NFSPROC_SYMLINK` (proc 13) -- create symbolic link (RFC 1094 S2.2.14).
    pub async fn symlink(&self, args: &wire::symlinkargs) -> Result<wire::Nfs2Stat, T::Error> {
        self.call_raw(proc::NFSPROC_SYMLINK, args).await
    }

    /// `NFSPROC_MKDIR` (proc 14) -- create directory (RFC 1094 S2.2.15).
    pub async fn mkdir(&self, args: &wire::createargs) -> Result<wire::DirOpRes, T::Error> {
        self.call_raw(proc::NFSPROC_MKDIR, args).await
    }

    /// `NFSPROC_RMDIR` (proc 15) -- remove directory (RFC 1094 S2.2.16).
    pub async fn rmdir(&self, args: &wire::DirOpArgs) -> Result<wire::Nfs2Stat, T::Error> {
        self.call_raw(proc::NFSPROC_RMDIR, args).await
    }

    /// `NFSPROC_READDIR` (proc 16) -- read directory entries (RFC 1094 S2.2.17).
    pub async fn readdir(&self, args: &wire::ReaddirArgs) -> Result<wire::readdirres, T::Error> {
        self.call_raw(proc::NFSPROC_READDIR, args).await
    }

    /// `NFSPROC_STATFS` (proc 17) -- get filesystem stats (RFC 1094 S2.2.18).
    pub async fn statfs(&self, fh: &wire::Nfs2FileHandle) -> Result<wire::StatFsRes, T::Error> {
        self.call_raw(proc::NFSPROC_STATFS, fh).await
    }

    // --- Generic escape hatch ---

    /// Send any procedure number with arbitrary XDR-encodable arguments.
    ///
    /// The caller picks the procedure number, builds whatever bytes they want,
    /// and decodes the response into whatever type they want. This is the
    /// escape hatch for fuzzing, probing undocumented procedures, or replaying
    /// captured traffic.
    pub async fn call_raw<C: Pack + Send + Sync, R: Unpack>(&self, proc_num: u32, args: &C) -> Result<R, T::Error> {
        self.0.call::<C, R>(NFS_PROGRAM, NFS_VERSION, proc_num, args).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify program and version constants are correct for NFSv2 (RFC 1094).
    #[test]
    fn program_and_version_constants() {
        assert_eq!(NFS_PROGRAM, 100_003);
        assert_eq!(NFS_VERSION, 2);
    }

    // Verify all 18 procedure numbers are distinct and contiguous 0..=17.
    #[test]
    fn all_18_procedure_numbers_are_contiguous() {
        let procs = [
            proc::NFSPROC_NULL,
            proc::NFSPROC_GETATTR,
            proc::NFSPROC_SETATTR,
            proc::NFSPROC_ROOT,
            proc::NFSPROC_LOOKUP,
            proc::NFSPROC_READLINK,
            proc::NFSPROC_READ,
            proc::NFSPROC_WRITECACHE,
            proc::NFSPROC_WRITE,
            proc::NFSPROC_CREATE,
            proc::NFSPROC_REMOVE,
            proc::NFSPROC_RENAME,
            proc::NFSPROC_LINK,
            proc::NFSPROC_SYMLINK,
            proc::NFSPROC_MKDIR,
            proc::NFSPROC_RMDIR,
            proc::NFSPROC_READDIR,
            proc::NFSPROC_STATFS,
        ];
        for (i, &p) in procs.iter().enumerate() {
            assert_eq!(p, u32::try_from(i).unwrap(), "procedure {i} must equal {i}");
        }
    }
}
