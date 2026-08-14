//! NFSv4 backend for the unified shell.
//!
//! Implements `ShellOps` over a pooled `Nfs4Client`, giving the v4 shell all
//! 52 commands. Stateless operations (LOOKUP, GETATTR, READDIR, anonymous READ)
//! work without OPEN. Write operations lazily establish a session
//! (SETCLIENTID + SETCLIENTID_CONFIRM) and use OPEN + WRITE + CLOSE per
//! RFC 7530 S16.2.5.

use std::sync::Arc;

use nfs_v4::client::Nfs4Error;
use nfs_v4::wire::{ArgOp, AttrRequest, CreateMode4, CreateType4, Fattr4, OpenClaim4, OpenFlag4, ResOpData, Stateid4};
use nfs_v4::{Nfs4FileInfo, Nfs4FileType, Nfs4Session};
use onc_xdr::Pack;

use crate::proto::auth::{AuthSys, Credential};
use crate::proto::nfs4::{Nfs4Client, PooledNfs4 as _};

use super::ops::{CredCache, ShellDeviceType, ShellEntry, ShellFileInfo, ShellFileType, ShellFsStat, ShellHandle, ShellOps, ShellSetAttr, try_with_escalation};

/// NFSv4 backend wrapping a pooled `Nfs4Client` with lazy session establishment.
///
/// Read operations use the anonymous stateid (no OPEN required). Write
/// operations lazily create an `Nfs4Session` on first use, then go through the
/// OPEN + WRITE + CLOSE lifecycle mandated by RFC 7530.
pub(crate) struct V4Ops {
    client: Arc<Nfs4Client>,
    /// Lazily initialized session for stateful operations (OPEN/WRITE/CLOSE).
    session: tokio::sync::Mutex<Option<Nfs4Session>>,
    cred_cache: CredCache,
}

impl V4Ops {
    pub(crate) fn new(client: Arc<Nfs4Client>) -> Self {
        Self { client, session: tokio::sync::Mutex::new(None), cred_cache: CredCache::new() }
    }

    fn make_v4(&self, uid: u32, gid: u32) -> Nfs4Client {
        self.client.with_credential(Credential::Sys(AuthSys::with_groups(uid, gid, &[gid], self.client.machinename())), uid, gid)
    }

    /// Ensure a session exists, creating one on first call.
    async fn ensure_session(&self) -> anyhow::Result<()> {
        let mut guard = self.session.lock().await;
        if guard.is_none() {
            let sess = self.client.establish("nfswolf", "0.0.0.0.0.0").await.map_err(v4_err)?;
            *guard = Some(sess);
        }
        Ok(())
    }
}

// --- Conversion helpers -----------------------------------------------------

fn v4_info(info: &Nfs4FileInfo) -> ShellFileInfo {
    ShellFileInfo {
        file_type: match info.ftype {
            Some(Nfs4FileType::Regular) => ShellFileType::Regular,
            Some(Nfs4FileType::Directory) => ShellFileType::Directory,
            Some(Nfs4FileType::Symlink) => ShellFileType::Symlink,
            Some(Nfs4FileType::BlockDev) => ShellFileType::Block,
            Some(Nfs4FileType::CharDev) => ShellFileType::Character,
            Some(Nfs4FileType::Socket) => ShellFileType::Socket,
            Some(Nfs4FileType::Fifo) => ShellFileType::Fifo,
            _ => ShellFileType::Unknown,
        },
        mode: info.mode.unwrap_or(0),
        nlink: info.numlinks.unwrap_or(1),
        uid: parse_v4_owner_id(info.owner.as_deref()),
        gid: parse_v4_owner_id(info.owner_group.as_deref()),
        size: info.size.unwrap_or(0),
        fileid: info.fileid.unwrap_or(0),
        atime_secs: info.time_access.map_or(0, |(s, _)| u64::try_from(s).unwrap_or(0)),
        atime_nsecs: info.time_access.map_or(0, |(_, ns)| ns),
        mtime_secs: info.time_modify.map_or(0, |(s, _)| u64::try_from(s).unwrap_or(0)),
        mtime_nsecs: info.time_modify.map_or(0, |(_, ns)| ns),
        ctime_secs: info.time_metadata.map_or(0, |(s, _)| u64::try_from(s).unwrap_or(0)),
        ctime_nsecs: info.time_metadata.map_or(0, |(_, ns)| ns),
        used: info.size.unwrap_or(0),
        rdev: (0, 0),
        fsid: info.fsid.map_or(0, |(maj, _)| maj),
    }
}

/// Parse an NFSv4 owner/owner_group string to a numeric uid/gid.
///
/// NFSv4 uses string identities ("user@domain" or bare numeric strings).
/// Try parsing as a bare number first, then extract the user part before '@'.
/// Falls back to 65534 (nobody) on failure.
fn parse_v4_owner_id(owner: Option<&str>) -> u32 {
    owner.and_then(|s| s.parse::<u32>().ok().or_else(|| s.split('@').next().and_then(|u| u.parse().ok()))).unwrap_or(65534)
}

/// Convert an `Nfs4Error` to `anyhow::Error`, attaching `ShellError` for FUSE errno mapping.
#[expect(clippy::needless_pass_by_value, reason = "map_err requires FnOnce(E) -> F")]
fn v4_err<E: std::fmt::Display>(e: Nfs4Error<E>) -> anyhow::Error {
    use crate::shell::ops::ShellError;
    match &e {
        Nfs4Error::Status(status) => {
            let se: ShellError = (*status).into();
            anyhow::Error::new(se).context(format!("{e}"))
        },
        _ => anyhow::anyhow!("{e}"),
    }
}

/// Convert a raw transport error to `anyhow::Error`.
///
/// Used for `compound()` which returns `Result<CompoundRes, T::Error>` directly,
/// unlike the high-level methods which wrap in `Nfs4Error`.
fn rpc_err<E: std::fmt::Display>(e: E) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

/// Build an `Fattr4` containing only the POSIX mode bits.
///
/// Attribute 33 = word 1 bit 1 (RFC 7530 S5.8.2.8). The value is a u32
/// XDR-encoded into `attrvals`.
fn fattr4_with_mode(mode: u32) -> Fattr4 {
    // Word 0: nothing. Word 1: bit 1 = mode (attr 33).
    let bitmap = AttrRequest { words: vec![0, 1 << 1] };
    let mut attrvals = Vec::with_capacity(4);
    // Pack ignores the Result for a Vec writer (infallible).
    drop(mode.pack(&mut attrvals));
    Fattr4 { bitmap, attrvals }
}

/// Encode an XDR string (u32 length + utf8 + padding) into a buffer.
fn xdr_encode_string(buf: &mut Vec<u8>, s: &str) {
    let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
    drop(len.pack(buf));
    buf.extend_from_slice(s.as_bytes());
    let pad = (4 - (s.len() % 4)) % 4;
    buf.extend(std::iter::repeat_n(0u8, pad));
}

/// Build an `Fattr4` containing owner and/or owner_group strings.
///
/// NFSv4 SETATTR uses string identities for owner (attr 36, word 1 bit 4)
/// and owner_group (attr 37, word 1 bit 5). Numeric uid/gid are sent as
/// their decimal string representation -- knfsd accepts this form.
fn fattr4_with_owner(uid: Option<u32>, gid: Option<u32>) -> Fattr4 {
    let mut w1: u32 = 0;
    let mut attrvals = Vec::new();
    // Attributes must be encoded in bitmap order: owner (bit 4) before
    // owner_group (bit 5).
    if let Some(u) = uid {
        w1 |= 1 << 4;
        xdr_encode_string(&mut attrvals, &u.to_string());
    }
    if let Some(g) = gid {
        w1 |= 1 << 5;
        xdr_encode_string(&mut attrvals, &g.to_string());
    }
    Fattr4 { bitmap: AttrRequest { words: vec![0, w1] }, attrvals }
}

/// Pre-encode an `Fattr4` into raw bytes suitable for `OpenFlag4::Create`.
fn pack_fattr4(fattr: &Fattr4) -> Vec<u8> {
    let mut buf = Vec::with_capacity(fattr.packed_size());
    drop(fattr.pack(&mut buf));
    buf
}

/// Build an `Fattr4` from a `ShellSetAttr` for SETATTR.
///
/// Encodes mode (attr 33), owner (attr 36), owner_group (attr 37), and size
/// (attr 4) in bitmap order. Timestamps are not supported by this helper --
/// NFSv4 time_access_set and time_modify_set have a complex union encoding
/// that the decoder doesn't handle yet.
fn shell_setattr_to_fattr4(attrs: &ShellSetAttr) -> Fattr4 {
    let mut w0: u32 = 0;
    let mut w1: u32 = 0;
    let mut attrvals = Vec::new();

    // Attributes must be encoded in strict bitmap order (word 0 first, then word 1).
    // Word 0: size (attr 4, bit 4).
    if let Some(size) = attrs.size {
        w0 |= 1 << 4;
        drop(size.pack(&mut attrvals));
    }

    // Word 1: mode (attr 33, bit 1), owner (attr 36, bit 4), owner_group (attr 37, bit 5).
    if let Some(mode) = attrs.mode {
        w1 |= 1 << 1;
        drop(mode.pack(&mut attrvals));
    }
    if let Some(uid) = attrs.uid {
        w1 |= 1 << 4;
        xdr_encode_string(&mut attrvals, &uid.to_string());
    }
    if let Some(gid) = attrs.gid {
        w1 |= 1 << 5;
        xdr_encode_string(&mut attrvals, &gid.to_string());
    }

    Fattr4 { bitmap: AttrRequest { words: vec![w0, w1] }, attrvals }
}

// --- ShellOps implementation ------------------------------------------------

impl ShellOps for V4Ops {
    // -- Navigation --

    async fn lookup(&self, dir: &ShellHandle, name: &str) -> anyhow::Result<(ShellHandle, ShellFileInfo)> {
        let (fh, info) = self.client.lookup(dir.as_bytes(), name).await.map_err(v4_err)?;
        Ok((ShellHandle(fh), v4_info(&info)))
    }

    async fn lookup_path(&self, start: &ShellHandle, path: &str) -> anyhow::Result<(ShellHandle, ShellFileInfo)> {
        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if components.is_empty() {
            let info = self.client.getattr(start.as_bytes()).await.map_err(v4_err)?;
            return Ok((start.clone(), v4_info(&info)));
        }
        // Walk component-by-component to handle ".." properly and get the
        // final attributes. A single COMPOUND with chained LOOKUPs would be
        // faster for pure-forward paths but cannot handle "..".
        let mut cur = start.clone();
        let last_idx = components.len() - 1;
        for (i, comp) in components.iter().enumerate() {
            match *comp {
                "." => {},
                ".." => {
                    // NFSv4 LOOKUPP to navigate to parent.
                    let ops = vec![ArgOp::Putfh(cur.0.clone()), ArgOp::Lookupp, ArgOp::Getfh, ArgOp::Getattr(AttrRequest::shell_attrs())];
                    let res = self.client.compound(ops).await.map_err(rpc_err)?;
                    if res.status != 0 {
                        anyhow::bail!("LOOKUPP failed: NFSv4 status={}", res.status);
                    }
                    let fh = match res.results.get(2).map(|op| &op.data) {
                        Some(ResOpData::Fh(fh)) => fh.clone(),
                        _ => anyhow::bail!("LOOKUPP: GETFH result missing"),
                    };
                    if i == last_idx {
                        let info = match res.results.get(3).map(|op| &op.data) {
                            Some(ResOpData::Getattr(a)) => v4_info(&Nfs4FileInfo::from(a.clone())),
                            _ => v4_info(&Nfs4FileInfo::default()),
                        };
                        return Ok((ShellHandle(fh), info));
                    }
                    cur = ShellHandle(fh);
                },
                name => {
                    let (fh, info) = self.client.lookup(cur.as_bytes(), name).await.map_err(v4_err)?;
                    if i == last_idx {
                        return Ok((ShellHandle(fh), v4_info(&info)));
                    }
                    cur = ShellHandle(fh);
                },
            }
        }
        // All components were "." -- return start with fresh attrs.
        let info = self.client.getattr(cur.as_bytes()).await.map_err(v4_err)?;
        Ok((cur, v4_info(&info)))
    }

    async fn getattr(&self, fh: &ShellHandle) -> anyhow::Result<ShellFileInfo> {
        let info = self.client.getattr(fh.as_bytes()).await.map_err(v4_err)?;
        Ok(v4_info(&info))
    }

    // -- Directory listing --

    async fn list_dir(&self, dir: &ShellHandle) -> anyhow::Result<Vec<ShellEntry>> {
        let base = &self.client;
        let d = dir.clone();
        try_with_escalation(
            (base.uid(), base.gid()),
            &self.cred_cache,
            dir,
            getattr_owner_v4(base, dir.as_bytes()),
            is_v4_acces,
            |uid, gid| {
                let rd = self.make_v4(uid, gid);
                let b = Arc::clone(base);
                let fh = d.clone();
                async move { list_dir_v4(&b, &rd, &fh).await }
            },
            "NFS4ERR_ACCESS: cannot list directory (exhausted credential ladder)",
        )
        .await
    }

    // -- File I/O --

    async fn read_file(&self, fh: &ShellHandle) -> anyhow::Result<Vec<u8>> {
        let handle_bytes = fh.as_bytes().to_vec();
        try_with_escalation(
            (self.client.uid(), self.client.gid()),
            &self.cred_cache,
            fh,
            getattr_owner_v4(&self.client, fh.as_bytes()),
            is_v4_acces,
            |uid, gid| {
                let c = self.make_v4(uid, gid);
                let h = handle_bytes.clone();
                async move { read_all_v4(&c, &h).await }
            },
            "NFS4ERR_ACCESS: permission denied reading file",
        )
        .await
    }

    async fn read_chunk(&self, fh: &ShellHandle, offset: u64, count: u32) -> anyhow::Result<Vec<u8>> {
        let handle_bytes = fh.as_bytes().to_vec();
        try_with_escalation(
            (self.client.uid(), self.client.gid()),
            &self.cred_cache,
            fh,
            getattr_owner_v4(&self.client, fh.as_bytes()),
            is_v4_acces,
            |uid, gid| {
                let c = self.make_v4(uid, gid);
                let h = handle_bytes.clone();
                async move { read_chunk_v4(&c, &h, offset, count).await }
            },
            "NFS4ERR_ACCESS: permission denied reading file chunk",
        )
        .await
    }

    async fn write_chunk(&self, fh: &ShellHandle, offset: u64, data: &[u8]) -> anyhow::Result<u32> {
        // Try anonymous-stateid write first (knfsd allows this for AUTH_SYS
        // with no_root_squash). Falls back to READ_BYPASS stateid if rejected.
        let ops = vec![ArgOp::Putfh(fh.0.clone()), ArgOp::Write { stateid: Stateid4::ANONYMOUS.to_bytes(), offset, stable: 2, data: data.to_vec() }];
        let res = self.client.compound(ops).await.map_err(rpc_err)?;
        if res.status != 0 {
            // Anonymous write failed (NFS4ERR_OPENMODE etc.) -- fall back to
            // the bypass stateid. In NFSv4.0 we cannot OPEN by file handle
            // (CLAIM_FH is v4.1 only), so this is our best effort.
            return self.write_chunk_via_open(fh, offset, data).await;
        }
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::WriteRes { count, .. }) => Ok(*count),
            _ => anyhow::bail!("WRITE result missing"),
        }
    }

    // -- Mutations --

    async fn create_file(&self, dir: &ShellHandle, name: &str, mode: u32) -> anyhow::Result<ShellHandle> {
        self.ensure_session().await?;
        let guard = self.session.lock().await;
        let Some(session) = guard.as_ref() else {
            anyhow::bail!("session establishment failed unexpectedly");
        };
        let attrs = fattr4_with_mode(mode);
        let attrs_bytes = pack_fattr4(&attrs);
        let seqid = session.next_seqid();
        let ops = vec![ArgOp::Putfh(dir.0.clone()), ArgOp::Open { seqid, share_access: 3, share_deny: 0, owner: session.open_owner().clone(), openhow: OpenFlag4::Create { mode: CreateMode4::Unchecked, attrs: attrs_bytes }, claim: OpenClaim4::Null(name.to_owned()) }, ArgOp::Getfh];
        let res = self.client.compound(ops).await.map_err(rpc_err)?;
        if res.status != 0 {
            anyhow::bail!("OPEN(CREATE) failed: NFSv4 status={}", res.status);
        }
        // Extract open stateid for CLOSE.
        let (stateid, rflags) = match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Open { stateid, rflags, .. }) => (*stateid, *rflags),
            _ => anyhow::bail!("OPEN result missing"),
        };
        let fh = match res.results.get(2).map(|op| &op.data) {
            Some(ResOpData::Fh(fh)) => fh.clone(),
            _ => anyhow::bail!("GETFH result missing after OPEN"),
        };
        // OPEN_CONFIRM if requested (bit 1 of rflags).
        let final_stateid = if rflags & 0x0002 != 0 {
            let confirm_seqid = session.next_seqid();
            let cres = self.client.compound(vec![ArgOp::Putfh(fh.clone()), ArgOp::OpenConfirm { stateid: stateid.to_bytes(), seqid: confirm_seqid }]).await.map_err(rpc_err)?;
            if cres.status != 0 {
                anyhow::bail!("OPEN_CONFIRM failed: NFSv4 status={}", cres.status);
            }
            match cres.results.get(1).map(|op| &op.data) {
                Some(ResOpData::Stateid(sid)) => *sid,
                _ => stateid,
            }
        } else {
            stateid
        };
        // CLOSE the open state -- we only needed it to create the file.
        let close_seqid = session.next_seqid();
        // Best-effort CLOSE; ignore errors (file was already created).
        drop(self.client.compound(vec![ArgOp::Putfh(fh.clone()), ArgOp::Close { seqid: close_seqid, stateid: final_stateid.to_bytes() }]).await);
        Ok(ShellHandle(fh))
    }

    async fn mkdir(&self, dir: &ShellHandle, name: &str, mode: u32) -> anyhow::Result<ShellHandle> {
        let (fh, _) = self.client.mkdir(dir.as_bytes(), name).await.map_err(v4_err)?;
        // Set the requested mode -- CREATE with empty attrs leaves the server's default.
        drop(self.client.setattr(&fh, Stateid4::ANONYMOUS, fattr4_with_mode(mode)).await);
        Ok(ShellHandle(fh))
    }

    async fn remove(&self, dir: &ShellHandle, name: &str) -> anyhow::Result<()> {
        let _cinfo = self.client.remove(dir.as_bytes(), name).await.map_err(v4_err)?;
        Ok(())
    }

    async fn rmdir(&self, dir: &ShellHandle, name: &str) -> anyhow::Result<()> {
        // NFSv4 uses REMOVE for both files and directories (RFC 7530 S16.26).
        let _cinfo = self.client.remove(dir.as_bytes(), name).await.map_err(v4_err)?;
        Ok(())
    }

    async fn rename(&self, from_dir: &ShellHandle, from: &str, to_dir: &ShellHandle, to: &str) -> anyhow::Result<()> {
        let _cinfo = self.client.rename(from_dir.as_bytes(), from, to_dir.as_bytes(), to).await.map_err(v4_err)?;
        Ok(())
    }

    async fn symlink(&self, dir: &ShellHandle, name: &str, target: &str) -> anyhow::Result<()> {
        let _new = self.client.symlink(dir.as_bytes(), name, target).await.map_err(v4_err)?;
        Ok(())
    }

    async fn hard_link(&self, fh: &ShellHandle, dir: &ShellHandle, name: &str) -> anyhow::Result<()> {
        let _cinfo = self.client.link(fh.as_bytes(), dir.as_bytes(), name).await.map_err(v4_err)?;
        Ok(())
    }

    async fn mknod(&self, dir: &ShellHandle, name: &str, dev_type: ShellDeviceType, major: u32, minor: u32, mode: u32) -> anyhow::Result<ShellHandle> {
        let objtype = match dev_type {
            ShellDeviceType::Char => CreateType4::Chr { specdata1: major, specdata2: minor },
            ShellDeviceType::Block => CreateType4::Blk { specdata1: major, specdata2: minor },
        };
        let ops = vec![ArgOp::Putfh(dir.0.clone()), ArgOp::Create { objtype, objname: name.to_owned(), createattrs: fattr4_with_mode(mode) }, ArgOp::Getfh];
        let res = self.client.compound(ops).await.map_err(rpc_err)?;
        if res.status != 0 {
            anyhow::bail!("CREATE(device) failed: NFSv4 status={}", res.status);
        }
        match res.results.get(2).map(|op| &op.data) {
            Some(ResOpData::Fh(fh)) => Ok(ShellHandle(fh.clone())),
            _ => anyhow::bail!("GETFH result missing after CREATE"),
        }
    }

    async fn readlink(&self, fh: &ShellHandle) -> anyhow::Result<String> {
        self.client.readlink(fh.as_bytes()).await.map_err(v4_err)
    }

    async fn set_mode(&self, fh: &ShellHandle, mode: u32) -> anyhow::Result<()> {
        let _attrsset = self.client.setattr(fh.as_bytes(), Stateid4::ANONYMOUS, fattr4_with_mode(mode)).await.map_err(v4_err)?;
        Ok(())
    }

    async fn set_owner(&self, fh: &ShellHandle, uid: Option<u32>, gid: Option<u32>) -> anyhow::Result<()> {
        let _attrsset = self.client.setattr(fh.as_bytes(), Stateid4::ANONYMOUS, fattr4_with_owner(uid, gid)).await.map_err(v4_err)?;
        Ok(())
    }

    // -- Identity --

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
        let cred = Credential::Sys(AuthSys::new(uid, gid, hostname));
        self.client = Arc::new(self.client.with_credential(cred, uid, gid));
        *self.session.get_mut() = None;
        self.cred_cache.flush();
        Ok(())
    }

    // -- Capabilities --

    fn version_name(&self) -> &'static str {
        "NFSv4"
    }
    fn supports_mknod(&self) -> bool {
        true
    }

    fn supports_identity_change(&self) -> bool {
        true
    }

    fn commands(&self) -> &'static [&'static str] {
        crate::shell::V4_SHELL_COMMANDS
    }

    fn make_completer(&self) -> Box<dyn crate::shell::complete::RemoteCompleter> {
        Box::new(V4RemoteCompleter { client: Arc::clone(&self.client) })
    }

    async fn write_verifier(&self, fh: &ShellHandle) -> anyhow::Result<Option<[u8; 8]>> {
        let verf = self.client.commit(fh.as_bytes(), 0, 0).await.map_err(v4_err)?;
        Ok(Some(verf))
    }

    // -- FUSE-required operations --

    async fn access(&self, fh: &ShellHandle, mask: u32) -> anyhow::Result<u32> {
        let (_supported, granted) = self.client.access(fh.as_bytes(), mask).await.map_err(v4_err)?;
        Ok(granted)
    }

    async fn setattr(&self, fh: &ShellHandle, attrs: ShellSetAttr) -> anyhow::Result<ShellFileInfo> {
        let fattr = shell_setattr_to_fattr4(&attrs);
        let _attrsset = self.client.setattr(fh.as_bytes(), Stateid4::ANONYMOUS, fattr).await.map_err(v4_err)?;
        // Fetch fresh attrs after the change.
        let info = self.client.getattr(fh.as_bytes()).await.map_err(v4_err)?;
        Ok(v4_info(&info))
    }

    async fn statfs(&self, fh: &ShellHandle) -> anyhow::Result<ShellFsStat> {
        // Request space attributes via GETATTR with bits 10-12 of word 1
        // (space_avail=42, space_free=43, space_total=44).
        let space_bitmap = AttrRequest { words: vec![0, (1 << 10) | (1 << 11) | (1 << 12)] };
        let ops = vec![ArgOp::Putfh(fh.0.clone()), ArgOp::Getattr(space_bitmap)];
        let res = self.client.compound(ops).await.map_err(rpc_err)?;
        if res.status != 0 {
            anyhow::bail!("GETATTR(space) failed: NFSv4 status={}", res.status);
        }
        let (avail, free, total) = match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::Getattr(a)) => (a.space_avail.unwrap_or(0), a.space_free.unwrap_or(0), a.space_total.unwrap_or(0)),
            _ => (0, 0, 0),
        };
        Ok(ShellFsStat { total_bytes: total, free_bytes: free, avail_bytes: avail, total_files: 0, free_files: 0, block_size: 4096 })
    }

    async fn commit(&self, fh: &ShellHandle) -> anyhow::Result<()> {
        let _verf = self.client.commit(fh.as_bytes(), 0, 0).await.map_err(v4_err)?;
        Ok(())
    }

    fn with_credential(&self, uid: u32, gid: u32, hostname: &str) -> Self {
        let cred = Credential::Sys(AuthSys::with_groups(uid, gid, &[gid], hostname));
        Self::new(Arc::new(self.client.with_credential(cred, uid, gid)))
    }
}

impl V4Ops {
    /// Fallback write path using the bypass stateid when anonymous-stateid
    /// writes are rejected (NFS4ERR_OPENMODE).
    async fn write_chunk_via_open(&self, fh: &ShellHandle, offset: u64, data: &[u8]) -> anyhow::Result<u32> {
        // NFSv4.0 cannot OPEN by file handle (CLAIM_FH is v4.1 only). Try the
        // read-bypass stateid (seqid=0xFFFFFFFF, other=0xFF) which bypasses
        // share reservations on some servers.
        let ops = vec![ArgOp::Putfh(fh.0.clone()), ArgOp::Write { stateid: Stateid4::READ_BYPASS.to_bytes(), offset, stable: 2, data: data.to_vec() }];
        let res = self.client.compound(ops).await.map_err(rpc_err)?;
        if res.status != 0 {
            anyhow::bail!("WRITE failed: NFSv4 status={} (server requires OPEN but file handle parent is unknown)", res.status);
        }
        match res.results.get(1).map(|op| &op.data) {
            Some(ResOpData::WriteRes { count, .. }) => Ok(*count),
            _ => anyhow::bail!("WRITE result missing"),
        }
    }
}

// --- Free helper functions for credential-escalated operations ---------------

fn is_v4_acces(e: &anyhow::Error) -> bool {
    let msg = format!("{e:#}");
    msg.contains("NFS4ERR_ACCESS") || msg.contains("NFS4ERR_PERM")
}

async fn getattr_owner_v4(client: &Nfs4Client, fh: &[u8]) -> Option<((u32, u32), u32)> {
    let info = client.getattr(fh).await.ok()?;
    let uid = parse_v4_owner_id(info.owner.as_deref());
    let gid = parse_v4_owner_id(info.owner_group.as_deref());
    let mode = info.mode.unwrap_or(0);
    Some(((uid, gid), mode))
}

async fn list_dir_v4(base_client: &Nfs4Client, rd_client: &Nfs4Client, dir: &ShellHandle) -> anyhow::Result<Vec<ShellEntry>> {
    let entries = rd_client.readdir_plus(dir.as_bytes()).await.map_err(v4_err)?;

    let dot_info = base_client.getattr(dir.as_bytes()).await.ok().map(|i| v4_info(&i));
    let mut result = vec![ShellEntry { name: ".".to_owned(), info: dot_info, handle: Some(dir.clone()) }];

    let dotdot_res = base_client.compound(vec![ArgOp::Putfh(dir.0.clone()), ArgOp::Lookupp, ArgOp::Getfh, ArgOp::Getattr(AttrRequest::shell_attrs())]).await;
    if let Ok(res) = dotdot_res
        && res.status == 0
    {
        let fh = res.results.get(2).and_then(|op| match &op.data {
            ResOpData::Fh(f) => Some(f.clone()),
            _ => None,
        });
        let info = res.results.get(3).and_then(|op| match &op.data {
            ResOpData::Getattr(a) => Some(v4_info(&Nfs4FileInfo::from(a.clone()))),
            _ => None,
        });
        result.push(ShellEntry { name: "..".to_owned(), info, handle: fh.map(ShellHandle) });
    }

    for e in entries {
        result.push(ShellEntry { name: e.name, info: e.info.as_ref().map(v4_info), handle: e.fh.map(ShellHandle) });
    }
    Ok(result)
}

async fn read_all_v4(client: &Nfs4Client, fh: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut offset = 0u64;
    loop {
        let (data, eof) = client.read_chunk(fh, offset, super::ops::CHUNK_SIZE).await.map_err(v4_err)?;
        if data.is_empty() {
            break;
        }
        buf.extend_from_slice(&data);
        if buf.len() as u64 > super::ops::READ_ALL_MAX {
            anyhow::bail!("file exceeds 256 MiB read cap");
        }
        offset += data.len() as u64;
        if eof {
            break;
        }
    }
    Ok(buf)
}

async fn read_chunk_v4(client: &Nfs4Client, fh: &[u8], offset: u64, count: u32) -> anyhow::Result<Vec<u8>> {
    let (data, _eof) = client.read_chunk(fh, offset, count).await.map_err(v4_err)?;
    Ok(data)
}

// --- Remote completion for tab-complete in the v4 shell ----------------------

struct V4RemoteCompleter {
    client: Arc<Nfs4Client>,
}

impl crate::shell::complete::RemoteCompleter for V4RemoteCompleter {
    fn list_dir_entries(&self, handle: &[u8]) -> Vec<String> {
        let client = Arc::clone(&self.client);
        let fh = handle.to_vec();
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(async move { client.list_dir(&fh).await.unwrap_or_default() }))
    }

    fn resolve_path(&self, start: &[u8], path: &str) -> Option<Vec<u8>> {
        let client = Arc::clone(&self.client);
        let fh = start.to_vec();
        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(async move { client.lookup_from_fh(&fh, &components).await.ok() }))
    }
}
