//! NFSv2 backend for the unified shell.

use std::sync::Arc;

use nfs_v2::wire::{FHSIZE, FType, Nfs2FileAttr, Nfs2FileHandle, Nfs2SetAttr};

use crate::proto::auth::{AuthSys, Credential};
use crate::proto::nfs2::{Nfs2Client, PooledNfs2 as _};

use super::ops::{CredCache, ShellDeviceType, ShellEntry, ShellFileInfo, ShellFileType, ShellHandle, ShellOps, try_with_escalation};

/// NFSv2 backend wrapping a `Nfs2Client` over `PooledTransport`.
pub(crate) struct V2Ops {
    client: Arc<Nfs2Client>,
    cred_cache: CredCache,
}

impl V2Ops {
    pub(crate) fn new(client: Arc<Nfs2Client>) -> Self {
        Self { client, cred_cache: CredCache::new() }
    }

    fn make_v2(&self, uid: u32, gid: u32) -> Nfs2Client {
        self.client.with_credential(Credential::Sys(AuthSys::with_groups(uid, gid, &[gid], self.client.machinename())), uid, gid)
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
            FType::NonFile | FType::Bad | _ => ShellFileType::Unknown,
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
        try_with_escalation(
            (self.client.uid(), self.client.gid()),
            &self.cred_cache,
            dir,
            getattr_owner_v2(&self.client, &v2dir),
            is_v2_acces,
            |uid, gid| {
                let c = self.make_v2(uid, gid);
                let fh = v2dir;
                async move { list_dir_v2(&c, &fh).await }
            },
            "NFS2ERR_ACCES: cannot list directory (exhausted credential ladder)",
        )
        .await
    }

    async fn read_file(&self, fh: &ShellHandle) -> anyhow::Result<Vec<u8>> {
        let v2fh = to_v2_fh(fh);
        try_with_escalation(
            (self.client.uid(), self.client.gid()),
            &self.cred_cache,
            fh,
            getattr_owner_v2(&self.client, &v2fh),
            is_v2_acces,
            |uid, gid| {
                let c = self.make_v2(uid, gid);
                let fh = v2fh;
                async move { read_file_v2(&c, &fh).await }
            },
            "NFS2ERR_ACCES: permission denied reading file",
        )
        .await
    }

    async fn read_chunk(&self, fh: &ShellHandle, offset: u64, count: u32) -> anyhow::Result<Vec<u8>> {
        let v2fh = to_v2_fh(fh);
        try_with_escalation(
            (self.client.uid(), self.client.gid()),
            &self.cred_cache,
            fh,
            getattr_owner_v2(&self.client, &v2fh),
            is_v2_acces,
            |uid, gid| {
                let c = self.make_v2(uid, gid);
                let fh = v2fh;
                async move { read_chunk_v2(&c, &fh, offset, count).await }
            },
            "NFS2ERR_ACCES: permission denied reading file chunk",
        )
        .await
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
        self.client.uid()
    }
    fn gid(&self) -> u32 {
        self.client.gid()
    }
    fn machinename(&self) -> &str {
        self.client.machinename()
    }

    fn change_identity(&mut self, uid: u32, gid: u32, hostname: &str) -> anyhow::Result<()> {
        let cred = Credential::Sys(AuthSys::with_groups(uid, gid, &[gid], hostname));
        self.client = Arc::new(self.client.with_credential(cred, uid, gid));
        self.cred_cache.flush();
        Ok(())
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

    fn commands(&self) -> &'static [&'static str] {
        crate::shell::V2_SHELL_COMMANDS
    }

    fn make_completer(&self) -> Box<dyn crate::shell::complete::RemoteCompleter> {
        Box::new(V2RemoteCompleter { client: Arc::clone(&self.client) })
    }

    async fn probe_root(&self) -> anyhow::Result<Option<ShellHandle>> {
        self.probe_root().await
    }
}

fn v2_sattr_mode(mode: u32) -> Nfs2SetAttr {
    use nfs_v2::wire::{SATTR_UNCHANGED, Timeval};
    let unchanged_time = Timeval { seconds: SATTR_UNCHANGED, useconds: SATTR_UNCHANGED };
    Nfs2SetAttr { mode, uid: SATTR_UNCHANGED, gid: SATTR_UNCHANGED, size: SATTR_UNCHANGED, atime: unchanged_time, mtime: unchanged_time }
}

fn v2_sattr_owner(uid: Option<u32>, gid: Option<u32>) -> Nfs2SetAttr {
    use nfs_v2::wire::{SATTR_UNCHANGED, Timeval};
    let unchanged_time = Timeval { seconds: SATTR_UNCHANGED, useconds: SATTR_UNCHANGED };
    Nfs2SetAttr { mode: SATTR_UNCHANGED, uid: uid.unwrap_or(SATTR_UNCHANGED), gid: gid.unwrap_or(SATTR_UNCHANGED), size: SATTR_UNCHANGED, atime: unchanged_time, mtime: unchanged_time }
}

// --- Free helper functions for credential-escalated operations ---------------

fn is_v2_acces(e: &anyhow::Error) -> bool {
    let msg = format!("{e:#}");
    msg.contains("ACCES") || msg.contains("PERM")
}

async fn getattr_owner_v2(client: &Nfs2Client, fh: &Nfs2FileHandle) -> Option<((u32, u32), u32)> {
    let attrs = client.getattr(fh).await.ok()?;
    Some(((attrs.uid, attrs.gid), attrs.mode))
}

async fn list_dir_v2(client: &Nfs2Client, dir: &Nfs2FileHandle) -> anyhow::Result<Vec<ShellEntry>> {
    let mut all_entries = Vec::new();
    let mut cookie = 0u32;
    loop {
        let entries = client.readdir(dir, cookie, 4096).await.map_err(|e| anyhow::anyhow!("{e}"))?;
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
        let (info, handle) = match client.lookup(dir, &e.name).await {
            Ok((fh, attrs)) => (Some(v2_info(&attrs)), Some(from_v2_fh(&fh))),
            Err(_) => (None, None),
        };
        result.push(ShellEntry { name: e.name.clone(), info, handle });
    }
    Ok(result)
}

async fn read_file_v2(client: &Nfs2Client, fh: &Nfs2FileHandle) -> anyhow::Result<Vec<u8>> {
    client.read_file(fh).await.map_err(|e| anyhow::anyhow!("{e}"))
}

async fn read_chunk_v2(client: &Nfs2Client, fh: &Nfs2FileHandle, offset: u64, count: u32) -> anyhow::Result<Vec<u8>> {
    let off32 = u32::try_from(offset).unwrap_or(u32::MAX);
    let (_, data) = client.read(fh, off32, count.min(8192)).await.map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(data)
}

// --- Remote completion for tab-complete in the v2 shell ----------------------

/// Paginated READDIR collecting all entry names, filtering `.` and `..`.
async fn v2_readdir_all_names(client: &Nfs2Client, dir: &Nfs2FileHandle) -> Vec<String> {
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

struct V2RemoteCompleter {
    client: Arc<Nfs2Client>,
}

impl crate::shell::complete::RemoteCompleter for V2RemoteCompleter {
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
