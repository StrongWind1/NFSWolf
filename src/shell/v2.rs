//! NFSv2 backend for the unified shell.

use nfswolf_nfs2::Nfs2Client;
use nfswolf_nfs2::wire::{FHSIZE, FType, Nfs2FileAttr, Nfs2FileHandle, Nfs2SetAttr};
use nfswolf_rpc::transport::direct::DirectTransport;
use nfswolf_rpc::transport::tokio::TokioIo;

use super::ops::{ShellEntry, ShellFileInfo, ShellFileType, ShellHandle, ShellOps};

type V2Transport = DirectTransport<TokioIo<tokio::net::TcpStream>>;

/// NFSv2 backend wrapping a `Nfs2Client` over a single TCP connection.
pub(crate) struct V2Ops {
    client: Nfs2Client<V2Transport>,
    uid: u32,
    gid: u32,
    hostname: String,
}

impl V2Ops {
    pub(crate) fn new(client: Nfs2Client<V2Transport>, uid: u32, gid: u32, hostname: String) -> Self {
        Self { client, uid, gid, hostname }
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
            FType::NonFile => ShellFileType::Unknown,
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
            let info = match self.client.lookup(&v2dir, &e.name).await {
                Ok((_, attrs)) => Some(v2_info(&attrs)),
                Err(_) => None,
            };
            result.push(ShellEntry { name: e.name.clone(), info });
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

    async fn readlink(&self, fh: &ShellHandle) -> anyhow::Result<String> {
        self.client.readlink(&to_v2_fh(fh)).await.map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn set_mode(&self, fh: &ShellHandle, mode: u32) -> anyhow::Result<()> {
        let _ = self.client.setattr(&to_v2_fh(fh), &v2_sattr_mode(mode)).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(())
    }

    async fn set_owner(&self, fh: &ShellHandle, uid: Option<u32>, gid: Option<u32>) -> anyhow::Result<()> {
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

    fn change_identity(&mut self, _uid: u32, _gid: u32, _hostname: &str) -> anyhow::Result<()> {
        anyhow::bail!("identity changes require reconnection on NFSv2 (DirectTransport credential is fixed at connect time)")
    }

    fn version_name(&self) -> &'static str {
        "NFSv2"
    }
    fn supports_mknod(&self) -> bool {
        false
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
