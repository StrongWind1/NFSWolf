//! NFSv2 backend for the unified shell.

use std::net::SocketAddr;
use std::sync::Arc;

use nfswolf_nfs2::Nfs2Client;
use nfswolf_nfs2::wire::{FHSIZE, FType, Nfs2FileAttr, Nfs2FileHandle, Nfs2SetAttr};
use nfswolf_rpc::rpc::opaque_auth;
use nfswolf_rpc::transport::direct::DirectTransport;
use nfswolf_rpc::transport::tokio::TokioIo;

use crate::proto::auth::{AuthSys, Credential, next_stamp};
use crate::proto::mount::NfsMountClient;

use super::ops::{ShellDeviceType, ShellEntry, ShellFileInfo, ShellFileType, ShellHandle, ShellOps};

type V2Transport = DirectTransport<TokioIo<tokio::net::TcpStream>>;

/// NFSv2 backend wrapping a `Nfs2Client` over a single TCP connection.
///
/// Unlike `V3Ops`, whose `PooledTransport` allows mid-session credential swaps,
/// `DirectTransport` fixes the credential at construction time. Identity changes
/// therefore reconnect: new TCP socket, new `AuthSys`, and a fresh MOUNT v1 MNT
/// to verify that the new identity has export access.
pub(crate) struct V2Ops {
    client: Arc<Nfs2Client<V2Transport>>,
    uid: u32,
    gid: u32,
    hostname: String,
    /// Portmapper address (host:111) used for MOUNT port discovery on reconnect.
    addr: SocketAddr,
    /// Export path for re-mounting on identity change.
    export_path: String,
    /// NFS daemon port for the data connection.
    nfs_port: u16,
}

impl V2Ops {
    pub(crate) fn new(client: Arc<Nfs2Client<V2Transport>>, uid: u32, gid: u32, hostname: String, addr: SocketAddr, export_path: String, nfs_port: u16) -> Self {
        Self { client, uid, gid, hostname, addr, export_path, nfs_port }
    }

    /// Probe NFSPROC_ROOT (proc 3) -- obsolete MOUNT bypass check.
    pub(crate) async fn probe_root(&self) -> anyhow::Result<Option<ShellHandle>> {
        match self.client.root().await {
            Ok(Some(fh)) => Ok(Some(from_v2_fh(&fh))),
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("{e}")),
        }
    }
}

fn to_v2_fh(h: &ShellHandle) -> Nfs2FileHandle {
    let mut arr = [0u8; FHSIZE];
    let len = h.0.len().min(FHSIZE);
    #[expect(clippy::indexing_slicing, reason = "len <= FHSIZE = arr.len()")]
    {
        arr[..len].copy_from_slice(&h.0[..len]);
    }
    Nfs2FileHandle(arr)
}

fn from_v2_fh(fh: &Nfs2FileHandle) -> ShellHandle {
    ShellHandle(fh.0.to_vec())
}

fn v2_info(a: &Nfs2FileAttr) -> ShellFileInfo {
    ShellFileInfo {
        file_type: match a.ftype {
            FType::Regular => ShellFileType::Regular,
            FType::Directory => ShellFileType::Directory,
            FType::Block => ShellFileType::Block,
            FType::Character => ShellFileType::Character,
            FType::Symlink => ShellFileType::Symlink,
            FType::Socket => ShellFileType::Socket,
            FType::Fifo => ShellFileType::Fifo,
            FType::NonFile | FType::Bad => ShellFileType::Unknown,
        },
        mode: a.mode,
        nlink: a.nlink,
        uid: a.uid,
        gid: a.gid,
        size: u64::from(a.size),
        fileid: u64::from(a.fileid),
        atime_secs: a.atime.seconds,
        mtime_secs: a.mtime.seconds,
        ctime_secs: a.ctime.seconds,
        // NFSv2 reports disk usage in 512-byte blocks (RFC 1094 S2.3.5).
        used: u64::from(a.blocks) * 512,
        // Old Linux dev_t encoding: major = bits 15:8, minor = bits 7:0.
        rdev: ((a.rdev >> 8) & 0xFF, a.rdev & 0xFF),
        fsid: u64::from(a.fsid),
    }
}

impl ShellOps for V2Ops {
    async fn lookup(&self, dir: &ShellHandle, name: &str) -> anyhow::Result<(ShellHandle, ShellFileInfo)> {
        let (fh, attrs) = self.client.lookup(&to_v2_fh(dir), name).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok((from_v2_fh(&fh), v2_info(&attrs)))
    }

    async fn lookup_path(&self, start: &ShellHandle, path: &str) -> anyhow::Result<(ShellHandle, ShellFileInfo)> {
        let (fh, attrs) = self.client.lookup_path(&to_v2_fh(start), path).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok((from_v2_fh(&fh), v2_info(&attrs)))
    }

    async fn getattr(&self, fh: &ShellHandle) -> anyhow::Result<ShellFileInfo> {
        let attrs = self.client.getattr(&to_v2_fh(fh)).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(v2_info(&attrs))
    }

    async fn list_dir(&self, dir: &ShellHandle) -> anyhow::Result<Vec<ShellEntry>> {
        let v2dir = to_v2_fh(dir);
        let mut all_entries = Vec::new();
        let mut cookie = 0u32;
        loop {
            let entries = self.client.readdir(&v2dir, cookie, 4096).await.map_err(|e| anyhow::anyhow!("{e}"))?;
            if entries.is_empty() {
                break;
            }
            cookie = entries.last().map_or(0, |e| e.cookie);
            all_entries.extend(entries);
            if all_entries.len() > 100_000 {
                break;
            }
        }
        let mut result = Vec::with_capacity(all_entries.len());
        for e in &all_entries {
            let (info, handle) = match self.client.lookup(&v2dir, &e.name).await {
                Ok((fh, attrs)) => (Some(v2_info(&attrs)), Some(from_v2_fh(&fh))),
                Err(_) => (None, None),
            };
            result.push(ShellEntry { name: e.name.clone(), info, handle });
        }
        Ok(result)
    }

    async fn read_file(&self, fh: &ShellHandle) -> anyhow::Result<Vec<u8>> {
        self.client.read_file(&to_v2_fh(fh)).await.map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn read_chunk(&self, fh: &ShellHandle, offset: u64, count: u32) -> anyhow::Result<Vec<u8>> {
        let off32 = u32::try_from(offset).unwrap_or(u32::MAX);
        let (_, data) = self.client.read(&to_v2_fh(fh), off32, count.min(8192)).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(data)
    }

    async fn write_chunk(&self, fh: &ShellHandle, offset: u64, data: &[u8]) -> anyhow::Result<u32> {
        let off32 = u32::try_from(offset).unwrap_or(u32::MAX);
        // NFSv2 WRITE returns attrs we don't use; errors propagate via ?.
        let _ = self.client.write(&to_v2_fh(fh), off32, data.to_vec()).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(u32::try_from(data.len()).unwrap_or(u32::MAX))
    }

    async fn create_file(&self, dir: &ShellHandle, name: &str, mode: u32) -> anyhow::Result<ShellHandle> {
        let attrs = v2_sattr_mode(mode);
        let (fh, _) = self.client.create(&to_v2_fh(dir), name, &attrs).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(from_v2_fh(&fh))
    }

    async fn mkdir(&self, dir: &ShellHandle, name: &str, mode: u32) -> anyhow::Result<ShellHandle> {
        let attrs = v2_sattr_mode(mode);
        let (fh, _) = self.client.mkdir(&to_v2_fh(dir), name, &attrs).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(from_v2_fh(&fh))
    }

    async fn remove(&self, dir: &ShellHandle, name: &str) -> anyhow::Result<()> {
        self.client.remove(&to_v2_fh(dir), name).await.map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn rmdir(&self, dir: &ShellHandle, name: &str) -> anyhow::Result<()> {
        self.client.rmdir(&to_v2_fh(dir), name).await.map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn rename(&self, from_dir: &ShellHandle, from: &str, to_dir: &ShellHandle, to: &str) -> anyhow::Result<()> {
        self.client.rename(&to_v2_fh(from_dir), from, &to_v2_fh(to_dir), to).await.map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn symlink(&self, dir: &ShellHandle, name: &str, target: &str) -> anyhow::Result<()> {
        let attrs = v2_sattr_mode(0o777);
        self.client.symlink(&to_v2_fh(dir), name, target, &attrs).await.map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn hard_link(&self, fh: &ShellHandle, dir: &ShellHandle, name: &str) -> anyhow::Result<()> {
        self.client.link(&to_v2_fh(fh), &to_v2_fh(dir), name).await.map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn mknod(&self, _dir: &ShellHandle, _name: &str, _dev_type: ShellDeviceType, _major: u32, _minor: u32, _mode: u32) -> anyhow::Result<ShellHandle> {
        anyhow::bail!("MKNOD is not supported in NFSv2")
    }

    async fn readlink(&self, fh: &ShellHandle) -> anyhow::Result<String> {
        self.client.readlink(&to_v2_fh(fh)).await.map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn set_mode(&self, fh: &ShellHandle, mode: u32) -> anyhow::Result<()> {
        // NFSv2 SETATTR returns attrs we don't use; errors propagate via ?.
        let _ = self.client.setattr(&to_v2_fh(fh), &v2_sattr_mode(mode)).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(())
    }

    async fn set_owner(&self, fh: &ShellHandle, uid: Option<u32>, gid: Option<u32>) -> anyhow::Result<()> {
        // NFSv2 SETATTR returns attrs we don't use; errors propagate via ?.
        let _ = self.client.setattr(&to_v2_fh(fh), &v2_sattr_owner(uid, gid)).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(())
    }

    fn uid(&self) -> u32 {
        self.uid
    }
    fn gid(&self) -> u32 {
        self.gid
    }
    fn machinename(&self) -> &str {
        &self.hostname
    }

    fn change_identity(&mut self, uid: u32, gid: u32, hostname: &str) -> anyhow::Result<()> {
        // DirectTransport fixes the credential at construction time, so changing
        // identity requires tearing down the old TCP session and building a new
        // one. Bridge into async via block_in_place (we are always called from
        // within a tokio runtime).
        let hostname = hostname.to_owned();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                // Re-mount the export with the new identity to verify access.
                // The returned handle is a bearer token identical to the one the
                // shell already holds, so we discard it.
                let mount_client = NfsMountClient::new().with_credential(Credential::Sys(AuthSys::new(uid, gid, &hostname)));
                drop(mount_client.mount_v1(self.addr, &self.export_path).await.map_err(|e| anyhow::anyhow!("MNT v1 failed for uid={uid} gid={gid}: {e}"))?);

                // Create a fresh NFS connection with the new AUTH_SYS credential.
                let nfs_addr = SocketAddr::new(self.addr.ip(), self.nfs_port);
                let stream = tokio::net::TcpStream::connect(nfs_addr).await.map_err(|e| anyhow::anyhow!("connect to NFSv2 at {nfs_addr}: {e}"))?;
                let io = TokioIo::new(stream);
                let cred = AuthSys::with_groups(uid, gid, &[gid], &hostname);
                let auth = cred.to_opaque_auth(next_stamp());
                let transport = DirectTransport::with_auth(io, auth, opaque_auth::default());

                self.client = Arc::new(Nfs2Client::new(transport));
                self.uid = uid;
                self.gid = gid;
                self.hostname = hostname;
                Ok(())
            })
        })
    }

    fn version_name(&self) -> &'static str {
        "NFSv2"
    }
    fn supports_mknod(&self) -> bool {
        false
    }

    fn supports_identity_change(&self) -> bool {
        true
    }

    fn make_completer(&self) -> Box<dyn crate::shell::complete::RemoteCompleter> {
        Box::new(V2RemoteCompleter { client: Arc::clone(&self.client) })
    }

    async fn probe_root(&self) -> anyhow::Result<Option<ShellHandle>> {
        self.probe_root().await
    }
}

fn v2_sattr_mode(mode: u32) -> Nfs2SetAttr {
    use nfswolf_nfs2::wire::{SATTR_UNCHANGED, Timeval};
    let unchanged_time = Timeval { seconds: SATTR_UNCHANGED, useconds: SATTR_UNCHANGED };
    Nfs2SetAttr { mode, uid: SATTR_UNCHANGED, gid: SATTR_UNCHANGED, size: SATTR_UNCHANGED, atime: unchanged_time, mtime: unchanged_time }
}

fn v2_sattr_owner(uid: Option<u32>, gid: Option<u32>) -> Nfs2SetAttr {
    use nfswolf_nfs2::wire::{SATTR_UNCHANGED, Timeval};
    let unchanged_time = Timeval { seconds: SATTR_UNCHANGED, useconds: SATTR_UNCHANGED };
    Nfs2SetAttr { mode: SATTR_UNCHANGED, uid: uid.unwrap_or(SATTR_UNCHANGED), gid: gid.unwrap_or(SATTR_UNCHANGED), size: SATTR_UNCHANGED, atime: unchanged_time, mtime: unchanged_time }
}

// --- Remote completion for tab-complete in the v2 shell ----------------------

/// Paginated READDIR collecting all entry names, filtering `.` and `..`.
async fn v2_readdir_all_names<T: nfswolf_rpc::RpcTransport>(client: &Nfs2Client<T>, dir: &Nfs2FileHandle) -> Vec<String> {
    let mut names = Vec::new();
    let mut cookie = 0u32;
    loop {
        let Ok(entries) = client.readdir(dir, cookie, 4096).await else { break };
        if entries.is_empty() {
            break;
        }
        cookie = entries.last().map_or(0, |e| e.cookie);
        for e in &entries {
            if e.name != "." && e.name != ".." {
                names.push(e.name.clone());
            }
        }
        if names.len() > 100_000 {
            break;
        }
    }
    names
}

struct V2RemoteCompleter<T: nfswolf_rpc::RpcTransport + Send + Sync + 'static> {
    client: Arc<Nfs2Client<T>>,
}

impl<T: nfswolf_rpc::RpcTransport + Send + Sync + 'static> crate::shell::complete::RemoteCompleter for V2RemoteCompleter<T> {
    fn list_dir_entries(&self, handle: &[u8]) -> Vec<String> {
        let client = Arc::clone(&self.client);
        let fh = Nfs2FileHandle::from_bytes(handle);
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(async move { v2_readdir_all_names(&client, &fh).await }))
    }

    fn resolve_path(&self, start: &[u8], path: &str) -> Option<Vec<u8>> {
        let client = Arc::clone(&self.client);
        let fh = Nfs2FileHandle::from_bytes(start);
        let path = path.to_owned();
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(async move { client.lookup_path(&fh, &path).await.ok().map(|(fh, _)| fh.0.to_vec()) }))
    }
}
