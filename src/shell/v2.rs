//! NFSv2 backend for the unified shell.

use std::sync::Arc;

use nfs_v2::wire::{FHSIZE, FType, Nfs2FileAttr, Nfs2FileHandle, Nfs2SetAttr};

use crate::proto::auth::{AuthSys, Credential};
use crate::proto::nfs2::{Nfs2Client, PooledNfs2 as _};

use super::ops::{CredCache, IoSizes, ReadReply, ShellDeviceType, ShellEntry, ShellFileInfo, ShellFileType, ShellFsStat, ShellHandle, ShellOps, ShellSetAttr, ShellTimeSpec, try_with_escalation};

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
        atime_secs: u64::from(a.atime.seconds),
        atime_nsecs: a.atime.useconds.saturating_mul(1000),
        mtime_secs: u64::from(a.mtime.seconds),
        mtime_nsecs: a.mtime.useconds.saturating_mul(1000),
        ctime_secs: u64::from(a.ctime.seconds),
        ctime_nsecs: a.ctime.useconds.saturating_mul(1000),
        // NFSv2 reports disk usage in 512-byte blocks (RFC 1094 S2.3.5).
        used: u64::from(a.blocks) * 512,
        // Old Linux dev_t encoding: major = bits 15:8, minor = bits 7:0.
        rdev: ((a.rdev >> 8) & 0xFF, a.rdev & 0xFF),
        fsid: u64::from(a.fsid),
    }
}

#[expect(clippy::needless_pass_by_value, reason = "map_err requires FnOnce(E) -> F")]
fn v2err_to_anyhow<E: std::fmt::Display>(e: nfs_v2::Nfs2Error<E>) -> anyhow::Error {
    use crate::shell::ops::ShellError;
    match e.status() {
        Some(stat) => {
            let se: ShellError = stat.into();
            anyhow::Error::new(se).context(format!("{e}"))
        },
        None => anyhow::anyhow!("{e}"),
    }
}

impl ShellOps for V2Ops {
    async fn lookup(&self, dir: &ShellHandle, name: &str) -> anyhow::Result<(ShellHandle, ShellFileInfo)> {
        let (fh, attrs) = self.client.lookup(&to_v2_fh(dir), name).await.map_err(v2err_to_anyhow)?;
        Ok((from_v2_fh(&fh), v2_info(&attrs)))
    }

    async fn lookup_path(&self, start: &ShellHandle, path: &str) -> anyhow::Result<(ShellHandle, ShellFileInfo)> {
        let (fh, attrs) = self.client.lookup_path(&to_v2_fh(start), path).await.map_err(v2err_to_anyhow)?;
        Ok((from_v2_fh(&fh), v2_info(&attrs)))
    }

    async fn getattr(&self, fh: &ShellHandle) -> anyhow::Result<ShellFileInfo> {
        let attrs = self.client.getattr(&to_v2_fh(fh)).await.map_err(v2err_to_anyhow)?;
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

    async fn read_at(&self, fh: &ShellHandle, offset: u64, count: u32) -> anyhow::Result<ReadReply> {
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
                async move { read_at_v2(&c, &fh, offset, count).await }
            },
            "NFS2ERR_ACCES: permission denied reading file chunk",
        )
        .await
    }

    async fn write_chunk(&self, fh: &ShellHandle, offset: u64, data: &[u8]) -> anyhow::Result<u32> {
        // NFSv2 WRITE carries at most NFS_MAXDATA bytes and has no short
        // write: it writes all of them or fails (RFC 1094 sec. 2.2.9).
        let data = data.get(..data.len().min(NFS2_MAXDATA as usize)).unwrap_or(data);
        // NFSv2 WRITE returns attrs we don't use; errors propagate via ?.
        let _ = self.client.write(&to_v2_fh(fh), v2_offset(offset)?, data.to_vec()).await.map_err(v2err_to_anyhow)?;
        Ok(u32::try_from(data.len()).unwrap_or(u32::MAX))
    }

    async fn io_sizes(&self, _fh: &ShellHandle) -> IoSizes {
        IoSizes { read: NFS2_MAXDATA, write: NFS2_MAXDATA }
    }

    async fn create_file(&self, dir: &ShellHandle, name: &str, mode: u32) -> anyhow::Result<ShellHandle> {
        // Size 0 truncates a file that already exists: CREATE applies the
        // attributes to it (RFC 1094 sec. 2.2.10).
        let attrs = Nfs2SetAttr { size: 0, ..v2_sattr_mode(mode) };
        let (fh, _) = self.client.create(&to_v2_fh(dir), name, &attrs).await.map_err(v2err_to_anyhow)?;
        Ok(from_v2_fh(&fh))
    }

    async fn mkdir(&self, dir: &ShellHandle, name: &str, mode: u32) -> anyhow::Result<ShellHandle> {
        let attrs = v2_sattr_mode(mode);
        let (fh, _) = self.client.mkdir(&to_v2_fh(dir), name, &attrs).await.map_err(v2err_to_anyhow)?;
        Ok(from_v2_fh(&fh))
    }

    async fn remove(&self, dir: &ShellHandle, name: &str) -> anyhow::Result<()> {
        self.client.remove(&to_v2_fh(dir), name).await.map_err(v2err_to_anyhow)
    }

    async fn rmdir(&self, dir: &ShellHandle, name: &str) -> anyhow::Result<()> {
        self.client.rmdir(&to_v2_fh(dir), name).await.map_err(v2err_to_anyhow)
    }

    async fn rename(&self, from_dir: &ShellHandle, from: &str, to_dir: &ShellHandle, to: &str) -> anyhow::Result<()> {
        self.client.rename(&to_v2_fh(from_dir), from, &to_v2_fh(to_dir), to).await.map_err(v2err_to_anyhow)
    }

    async fn symlink(&self, dir: &ShellHandle, name: &str, target: &str) -> anyhow::Result<()> {
        let attrs = v2_sattr_mode(0o777);
        self.client.symlink(&to_v2_fh(dir), name, target, &attrs).await.map_err(v2err_to_anyhow)
    }

    async fn hard_link(&self, fh: &ShellHandle, dir: &ShellHandle, name: &str) -> anyhow::Result<()> {
        self.client.link(&to_v2_fh(fh), &to_v2_fh(dir), name).await.map_err(v2err_to_anyhow)
    }

    async fn mknod(&self, _dir: &ShellHandle, _name: &str, _dev_type: ShellDeviceType, _major: u32, _minor: u32, _mode: u32) -> anyhow::Result<ShellHandle> {
        anyhow::bail!("MKNOD is not supported in NFSv2")
    }

    async fn readlink(&self, fh: &ShellHandle) -> anyhow::Result<String> {
        self.client.readlink(&to_v2_fh(fh)).await.map_err(v2err_to_anyhow)
    }

    async fn set_mode(&self, fh: &ShellHandle, mode: u32) -> anyhow::Result<()> {
        // NFSv2 SETATTR returns attrs we don't use; errors propagate via ?.
        let _ = self.client.setattr(&to_v2_fh(fh), &v2_sattr_mode(mode)).await.map_err(v2err_to_anyhow)?;
        Ok(())
    }

    async fn set_owner(&self, fh: &ShellHandle, uid: Option<u32>, gid: Option<u32>) -> anyhow::Result<()> {
        // NFSv2 SETATTR returns attrs we don't use; errors propagate via ?.
        let _ = self.client.setattr(&to_v2_fh(fh), &v2_sattr_owner(uid, gid)).await.map_err(v2err_to_anyhow)?;
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

    // -- FUSE-required operations (v2 has no ACCESS or COMMIT) --

    async fn setattr(&self, fh: &ShellHandle, attrs: ShellSetAttr) -> anyhow::Result<ShellFileInfo> {
        let sa = shell_setattr_to_v2(&attrs);
        let _ = self.client.setattr(&to_v2_fh(fh), &sa).await.map_err(v2err_to_anyhow)?;
        // Fetch fresh attrs after the change.
        let a = self.client.getattr(&to_v2_fh(fh)).await.map_err(v2err_to_anyhow)?;
        Ok(v2_info(&a))
    }

    async fn statfs(&self, fh: &ShellHandle) -> anyhow::Result<ShellFsStat> {
        let fs = self.client.statfs(&to_v2_fh(fh)).await.map_err(v2err_to_anyhow)?;
        let bsize = u64::from(fs.bsize);
        Ok(ShellFsStat { total_bytes: u64::from(fs.blocks).saturating_mul(bsize), free_bytes: u64::from(fs.bfree).saturating_mul(bsize), avail_bytes: u64::from(fs.bavail).saturating_mul(bsize), total_files: 0, free_files: 0, block_size: fs.bsize })
    }

    fn with_credential(&self, uid: u32, gid: u32, hostname: &str) -> Self {
        let cred = Credential::Sys(AuthSys::with_groups(uid, gid, &[gid], hostname));
        Self::new(Arc::new(self.client.with_credential(cred, uid, gid)))
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

/// Convert a `ShellSetAttr` to the NFSv2 `Nfs2SetAttr` wire type.
///
/// Fields set to `None` use the `SATTR_UNCHANGED` sentinel (RFC 1094 S2.3.6).
/// NFSv2 has no "set to server time" -- `ShellTimeSpec::Now` sets the time to
/// the epoch as an approximation; callers should avoid `Now` on v2.
fn shell_setattr_to_v2(attrs: &ShellSetAttr) -> Nfs2SetAttr {
    use nfs_v2::wire::{SATTR_UNCHANGED, Timeval};
    let unchanged_time = Timeval { seconds: SATTR_UNCHANGED, useconds: SATTR_UNCHANGED };
    let atime = match attrs.atime {
        Some(ShellTimeSpec::At(s, ns)) => Timeval { seconds: u32::try_from(s).unwrap_or(0), useconds: ns / 1000 },
        Some(ShellTimeSpec::Now) => {
            // NFSv2 has no SET_TO_SERVER_TIME; use 0 as a best-effort marker.
            Timeval { seconds: 0, useconds: 0 }
        },
        None => unchanged_time,
    };
    let mtime = match attrs.mtime {
        Some(ShellTimeSpec::At(s, ns)) => Timeval { seconds: u32::try_from(s).unwrap_or(0), useconds: ns / 1000 },
        Some(ShellTimeSpec::Now) => Timeval { seconds: 0, useconds: 0 },
        None => unchanged_time,
    };
    Nfs2SetAttr { mode: attrs.mode.unwrap_or(SATTR_UNCHANGED), uid: attrs.uid.unwrap_or(SATTR_UNCHANGED), gid: attrs.gid.unwrap_or(SATTR_UNCHANGED), size: attrs.size.map_or(SATTR_UNCHANGED, |s| u32::try_from(s).unwrap_or(SATTR_UNCHANGED)), atime, mtime }
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
        let entries = client.readdir(dir, cookie, 4096).await.map_err(v2err_to_anyhow)?;
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

/// Largest READ or WRITE payload in NFSv2 (`NFS_MAXDATA`, RFC 1094 sec. 2.3).
const NFS2_MAXDATA: u32 = 8192;

/// An NFSv2 file offset: the protocol's offsets are 32-bit.
fn v2_offset(offset: u64) -> anyhow::Result<u32> {
    u32::try_from(offset).map_err(|_| anyhow::anyhow!("offset {offset} is beyond NFSv2's 32-bit file offsets"))
}

async fn read_at_v2(client: &Nfs2Client, fh: &Nfs2FileHandle, offset: u64, count: u32) -> anyhow::Result<ReadReply> {
    let (attrs, data) = client.read(fh, v2_offset(offset)?, count.min(NFS2_MAXDATA)).await.map_err(v2err_to_anyhow)?;
    // NFSv2 READ has no end-of-file flag, but it returns the file's current
    // attributes (RFC 1094 sec. 2.2.7), and reaching their size is the end.
    let eof = offset.saturating_add(data.len() as u64) >= u64::from(attrs.size);
    Ok(ReadReply { data, eof })
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

/// NFSv2 transfers over real RPC and TCP.
///
/// No NFSv2 server is at hand -- modern Linux kernels build knfsd without it --
/// so this runs a minimal one in-process: READ, WRITE and GETATTR on one file,
/// with a fixed delay on every call standing in for the round trip. The client
/// side is the real stack: `V2Ops`, `Nfs2Client`, `PooledTransport`, the pool,
/// and the RPC client.
#[cfg(test)]
mod wire_tests {
    #![expect(clippy::pedantic, reason = "unit test -- lints are suppressed per project policy")]

    use std::io::Cursor;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use nfs_v2::wire::{FHSIZE, FType, Nfs2FileAttr, Nfs2Stat, ReadArgs, Timeval};
    use onc_rpc_client::rpc::{msg_body, rpc_msg};
    use onc_xdr::{Opaque, Pack as _, Unpack as _};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Semaphore;

    use super::V2Ops;
    use crate::proto::auth::{AuthSys, Credential};
    use crate::proto::circuit::CircuitBreaker;
    use crate::proto::conn::ReconnectStrategy;
    use crate::proto::pool::{ConnectionPool, PoolKey};
    use crate::proto::transport::PooledTransport;
    use crate::shell::ops::ShellHandle;
    use crate::shell::transfer;
    use crate::util::stealth::StealthConfig;

    /// Delay on every call: a LAN-scale round trip.
    const LATENCY: Duration = Duration::from_millis(1);

    fn attrs(size: usize) -> Nfs2FileAttr {
        let t = Timeval { seconds: 0, useconds: 0 };
        Nfs2FileAttr { ftype: FType::Regular, mode: 0o644, nlink: 1, uid: 0, gid: 0, size: u32::try_from(size).unwrap(), blocksize: 4096, rdev: 0, blocks: 0, fsid: 1, fileid: 2, atime: t, mtime: t, ctime: t }
    }

    /// Answer one NFSv2 call against `file`; returns the result body.
    fn handle(proc: u32, args: &mut Cursor<Vec<u8>>, file: &Mutex<Vec<u8>>) -> Vec<u8> {
        let mut out = Vec::new();
        let mut file = file.lock().unwrap();
        match proc {
            // READ (RFC 1094 sec. 2.2.7): status, attributes, data.
            6 => {
                let (a, _) = ReadArgs::unpack(args).unwrap();
                let start = (a.offset as usize).min(file.len());
                let end = start.saturating_add(a.count as usize).min(file.len());
                let _ = Nfs2Stat::Ok.pack(&mut out).unwrap();
                let _ = attrs(file.len()).pack(&mut out).unwrap();
                let _ = Opaque::borrowed(&file[start..end]).pack(&mut out).unwrap();
            },
            // WRITE (RFC 1094 sec. 2.2.9): handle, three offsets, data.
            8 => {
                let mut fh = [0u8; FHSIZE];
                std::io::Read::read_exact(args, &mut fh).unwrap();
                let (_begin, _) = u32::unpack(args).unwrap();
                let (offset, _) = u32::unpack(args).unwrap();
                let (_total, _) = u32::unpack(args).unwrap();
                let (data, _) = Opaque::unpack(args).unwrap();
                let (start, data) = (offset as usize, data.as_ref());
                if file.len() < start + data.len() {
                    file.resize(start + data.len(), 0);
                }
                file[start..start + data.len()].copy_from_slice(data);
                let _ = Nfs2Stat::Ok.pack(&mut out).unwrap();
                let _ = attrs(file.len()).pack(&mut out).unwrap();
            },
            _ => {
                let _ = Nfs2Stat::Ok.pack(&mut out).unwrap();
                let _ = attrs(file.len()).pack(&mut out).unwrap();
            },
        }
        out
    }

    /// The fake server's file, and how many calls it has had in progress at
    /// once -- the proof, independent of timing, that requests overlap.
    #[derive(Default)]
    struct Server {
        file: Mutex<Vec<u8>>,
        in_flight: AtomicUsize,
        peak: AtomicUsize,
    }

    async fn serve(mut sock: TcpStream, server: Arc<Server>) {
        loop {
            let mut header = [0u8; 4];
            if sock.read_exact(&mut header).await.is_err() {
                return;
            }
            let mut body = vec![0u8; (u32::from_be_bytes(header) & 0x7FFF_FFFF) as usize];
            if sock.read_exact(&mut body).await.is_err() {
                return;
            }
            let mut call = Cursor::new(body);
            let (msg, _) = rpc_msg::unpack(&mut call).unwrap();
            let msg_body::CALL(body) = msg.body else { return };
            let now = server.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            let _ = server.peak.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(LATENCY).await;
            let result = handle(body.proc, &mut call, &server.file);
            let _ = server.in_flight.fetch_sub(1, Ordering::SeqCst);
            // Record mark, then REPLY, MSG_ACCEPTED, AUTH_NULL verifier,
            // SUCCESS, then the result -- in one write, as a real server
            // sends it, so Nagle's algorithm cannot hold the tail back.
            let words = [0, msg.xid, 1, 0, 0, 0, 0];
            let mut reply: Vec<u8> = words.iter().flat_map(|w: &u32| w.to_be_bytes()).collect();
            reply.extend_from_slice(&result);
            let mark = u32::try_from(reply.len() - 4).unwrap() | 0x8000_0000;
            reply[..4].copy_from_slice(&mark.to_be_bytes());
            if sock.write_all(&reply).await.is_err() {
                return;
            }
        }
    }

    async fn start(contents: Vec<u8>) -> (SocketAddr, Arc<Server>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = Arc::new(Server { file: Mutex::new(contents), ..Server::default() });
        let shared = Arc::clone(&server);
        drop(tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                sock.set_nodelay(true).unwrap();
                drop(tokio::spawn(serve(sock, Arc::clone(&shared))));
            }
        }));
        (addr, server)
    }

    /// The shell's own NFSv2 backend, bound to `addr` without MOUNT.
    fn ops(addr: SocketAddr) -> V2Ops {
        let pool = Arc::new(ConnectionPool::for_parallel_transfers(transfer::MAX_PIPELINE_DEPTH, None));
        let key = PoolKey { host: addr, export: "/".to_owned(), uid: 0, gid: 0 };
        let transport = PooledTransport::new_direct(pool, key, Arc::new(CircuitBreaker::default_config()), StealthConfig::new(0, 0), Credential::Sys(AuthSys::new(0, 0, "test")), ReconnectStrategy::Persistent, addr.port());
        V2Ops::new(Arc::new(nfs_v2::Nfs2Client::new(transport)))
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 31 + i / 251) % 256) as u8).collect()
    }

    async fn download(ops: &V2Ops, size: u64, budget: &Semaphore) -> (Vec<u8>, Duration) {
        let fh = ShellHandle(vec![0; FHSIZE]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(transfer::SINK_QUEUE);
        let started = Instant::now();
        let fetch = async move {
            let fetched = transfer::download(ops, &fh, size, &tx, None, budget).await;
            drop(tx);
            fetched
        };
        let collect = async move {
            let mut buf = Vec::new();
            while let Some(d) = rx.recv().await {
                buf.extend_from_slice(&d);
            }
            buf
        };
        let (fetched, data) = tokio::join!(fetch, collect);
        let _ = fetched.expect("download");
        (data, started.elapsed())
    }

    async fn upload(ops: &V2Ops, data: &[u8], budget: &Semaphore) -> Duration {
        let started = Instant::now();
        let _ = transfer::upload(ops, &ShellHandle(vec![0; FHSIZE]), data, 0, None, budget).await.expect("upload");
        started.elapsed()
    }

    /// 1 MiB is 128 NFSv2 READs. One at a time -- what the shell did before --
    /// costs 128 round trips; the pipelined transfer keeps 16 in flight.
    ///
    /// The server's count of overlapping calls is the assertion that cannot
    /// flake; the timings are a loose sanity check, measured with the pool
    /// already warm so connection setup is not counted against either side.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn nfs2_download_over_rpc_is_pipelined() {
        let want = pattern(1 << 20);
        let (addr, server) = start(want.clone()).await;
        let ops = ops(addr);
        let (warm, _) = download(&ops, want.len() as u64, &transfer::single_file_budget()).await;
        assert_eq!(warm, want);
        assert_eq!(server.peak.load(Ordering::SeqCst), transfer::MAX_PIPELINE_DEPTH, "READs must overlap on the wire");

        let (sequential_data, sequential) = download(&ops, want.len() as u64, &Semaphore::new(1)).await;
        let (pipelined_data, pipelined) = download(&ops, want.len() as u64, &transfer::single_file_budget()).await;
        eprintln!("NFSv2 1 MiB get over RPC, {LATENCY:?} per call: one at a time {sequential:?}, pipelined {pipelined:?}");
        assert_eq!(sequential_data, want);
        assert_eq!(pipelined_data, want);
        assert!(pipelined * 2 < sequential, "pipelined {pipelined:?} vs one at a time {sequential:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn nfs2_upload_over_rpc_is_pipelined() {
        let data = pattern(1 << 20);
        let (addr, server) = start(Vec::new()).await;
        let ops = ops(addr);
        let _ = upload(&ops, &data, &transfer::single_file_budget()).await;
        assert_eq!(*server.file.lock().unwrap(), data);
        assert_eq!(server.peak.load(Ordering::SeqCst), transfer::MAX_PIPELINE_DEPTH, "WRITEs must overlap on the wire");

        server.file.lock().unwrap().clear();
        let sequential = upload(&ops, &data, &Semaphore::new(1)).await;
        assert_eq!(*server.file.lock().unwrap(), data);
        server.file.lock().unwrap().clear();
        let pipelined = upload(&ops, &data, &transfer::single_file_budget()).await;
        eprintln!("NFSv2 1 MiB put over RPC, {LATENCY:?} per call: one at a time {sequential:?}, pipelined {pipelined:?}");
        assert_eq!(*server.file.lock().unwrap(), data);
        assert!(pipelined * 2 < sequential, "pipelined {pipelined:?} vs one at a time {sequential:?}");
    }
}
