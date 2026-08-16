//! NFSv3 backend for the unified shell.

use std::sync::Arc;

use nfs_v3::Nfs3Fault;
use nfs_v3::wire::{MKNOD3args, Nfs3Option, Nfs3Result, devicedata3, diropargs3, filename3, mknoddata3, sattr3, set_atime, set_mtime, specdata3, stable_how};
use onc_xdr::Opaque;

use crate::proto::auth::{AuthSys, Credential};
use crate::proto::nfs3::types::{DirEntryPlus, FileAttrs, FileHandle, FileType};
use crate::proto::nfs3::{Nfs3Client, PooledNfs3 as _};

use super::ops::{CredCache, ShellDeviceType, ShellEntry, ShellFileInfo, ShellFileType, ShellFsStat, ShellHandle, ShellOps, ShellSetAttr, ShellTimeSpec, try_with_escalation};

/// NFSv3 backend wrapping a pooled `Nfs3Client` with credential escalation.
pub(crate) struct V3Ops {
    pub nfs3: Arc<Nfs3Client>,
    cred_cache: CredCache,
}

impl V3Ops {
    pub(crate) fn new(nfs3: Arc<Nfs3Client>) -> Self {
        Self { nfs3, cred_cache: CredCache::new() }
    }

    fn make_v3(&self, uid: u32, gid: u32) -> Nfs3Client {
        self.nfs3.with_credential(Credential::Sys(AuthSys::with_groups(uid, gid, &[gid], self.nfs3.machinename())), uid, gid)
    }
}

fn to_v3_fh(h: &ShellHandle) -> FileHandle {
    FileHandle::from_bytes(&h.0)
}

fn from_v3_fh(fh: &FileHandle) -> ShellHandle {
    ShellHandle(fh.as_bytes().to_vec())
}

fn v3_info(a: &FileAttrs) -> ShellFileInfo {
    ShellFileInfo {
        file_type: match a.file_type {
            FileType::Regular => ShellFileType::Regular,
            FileType::Directory => ShellFileType::Directory,
            FileType::Block => ShellFileType::Block,
            FileType::Character => ShellFileType::Character,
            FileType::Symlink => ShellFileType::Symlink,
            FileType::Socket => ShellFileType::Socket,
            FileType::Fifo => ShellFileType::Fifo,
            _ => ShellFileType::Unknown,
        },
        mode: a.mode,
        nlink: a.nlink,
        uid: a.uid,
        gid: a.gid,
        size: a.size,
        fileid: a.fileid,
        atime_secs: u64::from(a.atime.seconds),
        atime_nsecs: a.atime.nseconds,
        mtime_secs: u64::from(a.mtime.seconds),
        mtime_nsecs: a.mtime.nseconds,
        ctime_secs: u64::from(a.ctime.seconds),
        ctime_nsecs: a.ctime.nseconds,
        used: a.used,
        rdev: a.rdev,
        fsid: a.fsid,
    }
}

fn is_nfs_acces(e: &anyhow::Error) -> bool {
    if let Some(fault) = e.downcast_ref::<Nfs3Fault<anyhow::Error>>() {
        return fault.is_permission_denied();
    }
    let msg = format!("{e:#}");
    msg.contains("NFS3ERR_ACCES") || msg.contains("NFS3ERR_PERM")
}

#[expect(clippy::needless_pass_by_value, reason = "map_err requires FnOnce(E) -> F")]
fn fault_to_anyhow<E: std::fmt::Display>(e: Nfs3Fault<E>) -> anyhow::Error {
    use crate::shell::ops::ShellError;
    match e.status() {
        Some(nfs_err) => {
            let se: ShellError = nfs_err.into();
            anyhow::Error::new(se).context(format!("{e}"))
        },
        None => anyhow::anyhow!("{e}"),
    }
}

impl ShellOps for V3Ops {
    async fn lookup(&self, dir: &ShellHandle, name: &str) -> anyhow::Result<(ShellHandle, ShellFileInfo)> {
        let (fh, attrs_opt) = self.nfs3.resolve(&to_v3_fh(dir), name).await.map_err(fault_to_anyhow)?;
        let attrs = match attrs_opt {
            Some(a) => a,
            None => self.nfs3.attrs(&fh).await.map_err(fault_to_anyhow)?,
        };
        Ok((from_v3_fh(&fh), v3_info(&attrs)))
    }

    async fn lookup_path(&self, start: &ShellHandle, path: &str) -> anyhow::Result<(ShellHandle, ShellFileInfo)> {
        let (fh, attrs_opt) = self.nfs3.walk(&to_v3_fh(start), path).await.map_err(fault_to_anyhow)?;
        let attrs = match attrs_opt {
            Some(a) => a,
            None => self.nfs3.attrs(&fh).await.map_err(fault_to_anyhow)?,
        };
        Ok((from_v3_fh(&fh), v3_info(&attrs)))
    }

    async fn getattr(&self, fh: &ShellHandle) -> anyhow::Result<ShellFileInfo> {
        let attrs = self.nfs3.attrs(&to_v3_fh(fh)).await.map_err(fault_to_anyhow)?;
        Ok(v3_info(&attrs))
    }

    async fn list_dir(&self, dir: &ShellHandle) -> anyhow::Result<Vec<ShellEntry>> {
        let fh3 = to_v3_fh(dir);
        let nfs3 = &self.nfs3;
        let entries = try_with_escalation(
            (nfs3.uid(), nfs3.gid()),
            &self.cred_cache,
            dir,
            getattr_owner(nfs3, &fh3),
            is_nfs_acces,
            |uid, gid| {
                let c = self.make_v3(uid, gid);
                let fh = fh3.clone();
                async move { list_dir_v3(&c, &fh).await }
            },
            "NFS3ERR_ACCES: cannot list directory (exhausted credential ladder)",
        )
        .await?;
        Ok(to_shell_entries(entries))
    }

    async fn read_file(&self, fh: &ShellHandle) -> anyhow::Result<Vec<u8>> {
        let fh3 = to_v3_fh(fh);
        let nfs3 = &self.nfs3;
        try_with_escalation(
            (nfs3.uid(), nfs3.gid()),
            &self.cred_cache,
            fh,
            getattr_owner(nfs3, &fh3),
            is_nfs_acces,
            |uid, gid| {
                let c = self.make_v3(uid, gid);
                let fh = fh3.clone();
                async move { read_all_v3(&c, &fh).await }
            },
            "NFS3ERR_ACCES: permission denied reading file",
        )
        .await
    }

    async fn read_chunk(&self, fh: &ShellHandle, offset: u64, count: u32) -> anyhow::Result<Vec<u8>> {
        let fh3 = to_v3_fh(fh);
        let nfs3 = &self.nfs3;
        try_with_escalation(
            (nfs3.uid(), nfs3.gid()),
            &self.cred_cache,
            fh,
            getattr_owner(nfs3, &fh3),
            is_nfs_acces,
            |uid, gid| {
                let c = self.make_v3(uid, gid);
                let fh = fh3.clone();
                async move { read_chunk_v3(&c, &fh, offset, count).await }
            },
            "NFS3ERR_ACCES: permission denied reading file chunk",
        )
        .await
    }

    async fn write_chunk(&self, fh: &ShellHandle, offset: u64, data: &[u8]) -> anyhow::Result<u32> {
        let ack = self.nfs3.write_at(&to_v3_fh(fh), offset, data, stable_how::FILE_SYNC).await.map_err(fault_to_anyhow)?;
        Ok(ack.count)
    }

    async fn create_file(&self, dir: &ShellHandle, name: &str, mode: u32) -> anyhow::Result<ShellHandle> {
        if let Some(fh) = self.nfs3.create_file(&to_v3_fh(dir), name, sattr3_with_mode(mode)).await.map_err(fault_to_anyhow)? {
            return Ok(from_v3_fh(&fh));
        }
        let (fh, _) = self.nfs3.resolve(&to_v3_fh(dir), name).await.map_err(fault_to_anyhow)?;
        Ok(from_v3_fh(&fh))
    }

    async fn mkdir(&self, dir: &ShellHandle, name: &str, mode: u32) -> anyhow::Result<ShellHandle> {
        if let Some(fh) = self.nfs3.create_dir(&to_v3_fh(dir), name, sattr3_with_mode(mode)).await.map_err(fault_to_anyhow)? {
            return Ok(from_v3_fh(&fh));
        }
        let (fh, _) = self.nfs3.resolve(&to_v3_fh(dir), name).await.map_err(fault_to_anyhow)?;
        Ok(from_v3_fh(&fh))
    }

    async fn remove(&self, dir: &ShellHandle, name: &str) -> anyhow::Result<()> {
        self.nfs3.unlink(&to_v3_fh(dir), name).await.map_err(fault_to_anyhow)
    }

    async fn rmdir(&self, dir: &ShellHandle, name: &str) -> anyhow::Result<()> {
        self.nfs3.remove_dir(&to_v3_fh(dir), name).await.map_err(fault_to_anyhow)
    }

    async fn rename(&self, from_dir: &ShellHandle, from: &str, to_dir: &ShellHandle, to: &str) -> anyhow::Result<()> {
        self.nfs3.rename_entry(&to_v3_fh(from_dir), from, &to_v3_fh(to_dir), to).await.map_err(fault_to_anyhow)
    }

    async fn symlink(&self, dir: &ShellHandle, name: &str, target: &str) -> anyhow::Result<()> {
        self.nfs3.create_symlink(&to_v3_fh(dir), name, target, sattr3_with_mode(0o777)).await.map_err(fault_to_anyhow)
    }

    async fn hard_link(&self, fh: &ShellHandle, dir: &ShellHandle, name: &str) -> anyhow::Result<()> {
        self.nfs3.hard_link(&to_v3_fh(fh), &to_v3_fh(dir), name).await.map_err(fault_to_anyhow)
    }

    async fn mknod(&self, dir: &ShellHandle, name: &str, dev_type: ShellDeviceType, major: u32, minor: u32, mode: u32) -> anyhow::Result<ShellHandle> {
        let devdata = devicedata3 { dev_attributes: sattr3_with_mode(mode), spec: specdata3 { specdata1: major, specdata2: minor } };
        let what = match dev_type {
            ShellDeviceType::Char => mknoddata3::NF3CHR(devdata),
            ShellDeviceType::Block => mknoddata3::NF3BLK(devdata),
        };
        let args = MKNOD3args { where_: diropargs3 { dir: to_v3_fh(dir).to_nfs_fh3(), name: filename3(Opaque::owned(name.as_bytes().to_vec())) }, what };
        match self.nfs3.mknod(&args).await {
            Ok(Nfs3Result::Ok(ok)) => {
                if let Nfs3Option::Some(fh) = ok.obj {
                    Ok(ShellHandle(fh.data.into_owned()))
                } else {
                    // Server didn't return a handle; look it up.
                    let (fh, _) = self.nfs3.resolve(&to_v3_fh(dir), name).await.map_err(fault_to_anyhow)?;
                    Ok(from_v3_fh(&fh))
                }
            },
            Ok(Nfs3Result::Err((status, _))) => {
                let err = nfs_v3::Nfs3Error::from_nfsstat3(status).unwrap_or(nfs_v3::Nfs3Error::ServerFault);
                Err(anyhow::anyhow!("{err}"))
            },
            Ok(_) | Err(_) => Err(anyhow::anyhow!("unexpected server response")),
        }
    }

    async fn readlink(&self, fh: &ShellHandle) -> anyhow::Result<String> {
        self.nfs3.read_link(&to_v3_fh(fh)).await.map_err(fault_to_anyhow)
    }

    async fn set_mode(&self, fh: &ShellHandle, mode: u32) -> anyhow::Result<()> {
        self.nfs3.set_attrs(&to_v3_fh(fh), sattr3_with_mode(mode)).await.map_err(fault_to_anyhow)
    }

    async fn set_owner(&self, fh: &ShellHandle, uid: Option<u32>, gid: Option<u32>) -> anyhow::Result<()> {
        let attrs = sattr3 { mode: Nfs3Option::None, uid: uid.map_or(Nfs3Option::None, Nfs3Option::Some), gid: gid.map_or(Nfs3Option::None, Nfs3Option::Some), size: Nfs3Option::None, atime: set_atime::DONT_CHANGE, mtime: set_mtime::DONT_CHANGE };
        self.nfs3.set_attrs(&to_v3_fh(fh), attrs).await.map_err(fault_to_anyhow)
    }

    fn uid(&self) -> u32 {
        self.nfs3.uid()
    }
    fn gid(&self) -> u32 {
        self.nfs3.gid()
    }
    fn machinename(&self) -> &str {
        self.nfs3.machinename()
    }

    fn change_identity(&mut self, uid: u32, gid: u32, hostname: &str) -> anyhow::Result<()> {
        let cred = Credential::Sys(AuthSys::new(uid, gid, hostname));
        self.nfs3 = Arc::new(self.nfs3.with_credential(cred, uid, gid));
        self.cred_cache.flush();
        Ok(())
    }

    fn version_name(&self) -> &'static str {
        "NFSv3"
    }
    fn supports_mknod(&self) -> bool {
        true
    }

    fn supports_identity_change(&self) -> bool {
        true
    }

    fn commands(&self) -> &'static [&'static str] {
        crate::shell::V3V4_SHELL_COMMANDS
    }

    fn make_completer(&self) -> Box<dyn crate::shell::complete::RemoteCompleter> {
        Box::new(Nfs3RemoteCompleter { nfs3: Arc::clone(&self.nfs3) })
    }

    async fn write_verifier(&self, fh: &ShellHandle) -> anyhow::Result<Option<[u8; 8]>> {
        let verf = self.nfs3.commit_verifier(&to_v3_fh(fh)).await.map_err(fault_to_anyhow)?;
        Ok(Some(verf))
    }

    // -- FUSE-required operations --

    async fn access(&self, fh: &ShellHandle, mask: u32) -> anyhow::Result<u32> {
        let granted = self.nfs3.check_access(&to_v3_fh(fh), mask).await.map_err(fault_to_anyhow)?;
        Ok(granted)
    }

    async fn setattr(&self, fh: &ShellHandle, attrs: ShellSetAttr) -> anyhow::Result<ShellFileInfo> {
        let sa = shell_setattr_to_sattr3(&attrs);
        self.nfs3.set_attrs(&to_v3_fh(fh), sa).await.map_err(fault_to_anyhow)?;
        // SETATTR3res carries only wcc data, not full fattr3 -- fetch fresh attrs.
        let a = self.nfs3.attrs(&to_v3_fh(fh)).await.map_err(fault_to_anyhow)?;
        Ok(v3_info(&a))
    }

    async fn statfs(&self, fh: &ShellHandle) -> anyhow::Result<ShellFsStat> {
        let fs = self.nfs3.stat_fs(&to_v3_fh(fh)).await.map_err(fault_to_anyhow)?;
        Ok(ShellFsStat { total_bytes: fs.total_bytes, free_bytes: fs.free_bytes, avail_bytes: fs.avail_bytes, total_files: fs.total_files, free_files: fs.free_files, block_size: 4096 })
    }

    async fn commit(&self, fh: &ShellHandle) -> anyhow::Result<()> {
        self.nfs3.commit_range(&to_v3_fh(fh), 0, 0).await.map_err(fault_to_anyhow)
    }

    fn with_credential(&self, uid: u32, gid: u32, hostname: &str) -> Self {
        let cred = Credential::Sys(AuthSys::with_groups(uid, gid, &[gid], hostname));
        Self::new(Arc::new(self.nfs3.with_credential(cred, uid, gid)))
    }
}

// --- Remote completion for tab-complete in the v3 shell ----------------------

struct Nfs3RemoteCompleter {
    pub nfs3: Arc<Nfs3Client>,
}

impl crate::shell::complete::RemoteCompleter for Nfs3RemoteCompleter {
    fn list_dir_entries(&self, handle: &[u8]) -> Vec<String> {
        let nfs3 = Arc::clone(&self.nfs3);
        let fh = FileHandle::from_bytes(handle);
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                match list_dir_v3(&nfs3, &fh).await {
                    Ok(entries) => entries.into_iter().filter(|e| e.name != "." && e.name != "..").map(|e| e.name).collect(),
                    Err(_) => Vec::new(),
                }
            })
        })
    }

    fn resolve_path(&self, start: &[u8], path: &str) -> Option<Vec<u8>> {
        let nfs3 = Arc::clone(&self.nfs3);
        let fh = FileHandle::from_bytes(start);
        let path = path.to_owned();
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(async move { nfs3.walk(&fh, &path).await.ok().map(|(fh, _)| fh.as_bytes().to_vec()) }))
    }
}

fn to_shell_entries(entries: Vec<DirEntryPlus>) -> Vec<ShellEntry> {
    entries.into_iter().map(|e| ShellEntry { name: e.name, info: e.attrs.as_ref().map(v3_info), handle: e.handle.as_ref().map(from_v3_fh) }).collect()
}

fn sattr3_with_mode(mode: u32) -> sattr3 {
    sattr3 { mode: Nfs3Option::Some(mode), uid: Nfs3Option::None, gid: Nfs3Option::None, size: Nfs3Option::None, atime: set_atime::DONT_CHANGE, mtime: set_mtime::DONT_CHANGE }
}

const MAX_DIR_ENTRIES: usize = 1_000_000;

async fn list_dir_v3(nfs3: &Nfs3Client, dir_fh: &FileHandle) -> anyhow::Result<Vec<DirEntryPlus>> {
    let mut out = nfs3.list_dir(dir_fh, MAX_DIR_ENTRIES).await.map_err(|e| anyhow::anyhow!("READDIRPLUS: {e}"))?;
    if out.len() >= MAX_DIR_ENTRIES {
        tracing::warn!(entries = out.len(), "READDIRPLUS hit entry cap; listing truncated");
    }
    for entry in &mut out {
        if entry.attrs.is_some() || entry.name == "." || entry.name == ".." {
            continue;
        }
        if let Ok((_, Some(attrs))) = nfs3.resolve(dir_fh, &entry.name).await {
            entry.attrs = Some(attrs);
        }
    }
    Ok(out)
}

async fn read_chunk_v3(nfs3: &Nfs3Client, fh: &FileHandle, offset: u64, count: u32) -> anyhow::Result<Vec<u8>> {
    let chunk = nfs3.read_at(fh, offset, count).await.map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(chunk.data)
}

async fn read_all_v3(nfs3: &Nfs3Client, fh: &FileHandle) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut offset = 0u64;
    loop {
        let chunk = nfs3.read_at(fh, offset, super::ops::CHUNK_SIZE).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        if chunk.data.is_empty() {
            break;
        }
        buf.extend_from_slice(&chunk.data);
        if buf.len() as u64 > super::ops::READ_ALL_MAX {
            anyhow::bail!("file exceeds 256 MiB read cap");
        }
        offset += chunk.data.len() as u64;
        if chunk.eof {
            break;
        }
    }
    Ok(buf)
}

/// Convert a `ShellSetAttr` to the NFSv3 `sattr3` wire type.
fn shell_setattr_to_sattr3(attrs: &ShellSetAttr) -> sattr3 {
    use nfs_v3::wire::nfstime3;
    let atime = match attrs.atime {
        Some(ShellTimeSpec::Now) => set_atime::SET_TO_SERVER_TIME,
        Some(ShellTimeSpec::At(s, ns)) => set_atime::SET_TO_CLIENT_TIME(nfstime3 { seconds: u32::try_from(s).unwrap_or(0), nseconds: ns }),
        None => set_atime::DONT_CHANGE,
    };
    let mtime = match attrs.mtime {
        Some(ShellTimeSpec::Now) => set_mtime::SET_TO_SERVER_TIME,
        Some(ShellTimeSpec::At(s, ns)) => set_mtime::SET_TO_CLIENT_TIME(nfstime3 { seconds: u32::try_from(s).unwrap_or(0), nseconds: ns }),
        None => set_mtime::DONT_CHANGE,
    };
    sattr3 { mode: attrs.mode.map_or(Nfs3Option::None, Nfs3Option::Some), uid: attrs.uid.map_or(Nfs3Option::None, Nfs3Option::Some), gid: attrs.gid.map_or(Nfs3Option::None, Nfs3Option::Some), size: attrs.size.map_or(Nfs3Option::None, Nfs3Option::Some), atime, mtime }
}

async fn getattr_owner(nfs3: &Nfs3Client, fh: &FileHandle) -> Option<((u32, u32), u32)> {
    let attrs = nfs3.attrs(fh).await.ok()?;
    Some(((attrs.uid, attrs.gid), attrs.mode))
}
