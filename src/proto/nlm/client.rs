//! NLM4 client  --  Network Lock Manager (RFC 1813 / ONC NLM4).
//!
//! NLM is used for advisory file locking over NFS. nfswolf uses it to:
//! - Test whether NLM is exposed (fingerprinting, F-1.3)
//! - Acquire/release locks to probe denial-of-service surfaces
//! - Cancel pending lock requests
//!
//! NLM is a separate RPC program (100021) running alongside NFS.
//! Protocol reference: NLM version 4 (64-bit offsets, used with NFSv3).

// NLM wire-type fields are protocol values; individual docs would repeat names.
// Toolkit API  --  not all items are used in currently-implemented phases.
// NLM XDR Pack/Unpack slices file handles at fixed offsets matching the NLM wire format.
use std::io::{Read, Write};

use anyhow::Context as _;
use nfs3_types::xdr_codec::{Pack, Unpack};

use crate::proto::conn::NfsConnection;
use crate::proto::nfs3::types::FileHandle;

/// NLM RPC program number.
pub const NLM_PROGRAM: u32 = 100_021;

/// NLM version 4  --  required for 64-bit offsets used with NFSv3.
pub const NLM_VERSION: u32 = 4;

// --- NLM4 procedure numbers ---

/// NLM4_TEST (proc 1): non-blocking lock test.
const NLM4_TEST: u32 = 1;
/// NLM4_LOCK (proc 2): acquire a lock.
const NLM4_LOCK: u32 = 2;
/// NLM4_CANCEL (proc 3): cancel a pending lock request.
const NLM4_CANCEL: u32 = 3;
/// NLM4_UNLOCK (proc 4): release a lock.
const NLM4_UNLOCK: u32 = 4;

// --- XDR helpers ---

/// Write 1, 2, or 3 zero-padding bytes to reach a 4-byte XDR boundary.
fn write_xdr_pad(out: &mut impl Write, pad: usize) -> nfs3_types::xdr_codec::Result<()> {
    match pad {
        1 => out.write_all(&[0u8]).map_err(nfs3_types::xdr_codec::Error::Io),
        2 => out.write_all(&[0u8; 2]).map_err(nfs3_types::xdr_codec::Error::Io),
        3 => out.write_all(&[0u8; 3]).map_err(nfs3_types::xdr_codec::Error::Io),
        _ => Ok(()),
    }
}

fn pack_xdr_string(s: &str, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
    let bytes = s.as_bytes();
    let len = u32::try_from(bytes.len()).map_err(|_| nfs3_types::xdr_codec::Error::ObjectTooLarge(bytes.len()))?;
    let mut n = len.pack(out)?;
    out.write_all(bytes).map_err(nfs3_types::xdr_codec::Error::Io)?;
    n += bytes.len();
    let pad = (4 - (bytes.len() % 4)) % 4;
    write_xdr_pad(out, pad)?;
    n += pad;
    Ok(n)
}

const fn xdr_string_size(s: &str) -> usize {
    let len = s.len();
    4 + len + (4 - (len % 4)) % 4
}

fn pack_opaque(data: &[u8], out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
    let len = u32::try_from(data.len()).map_err(|_| nfs3_types::xdr_codec::Error::ObjectTooLarge(data.len()))?;
    let mut n = len.pack(out)?;
    out.write_all(data).map_err(nfs3_types::xdr_codec::Error::Io)?;
    n += data.len();
    let pad = (4 - (data.len() % 4)) % 4;
    write_xdr_pad(out, pad)?;
    n += pad;
    Ok(n)
}

const fn opaque_packed_size(data: &[u8]) -> usize {
    let len = data.len();
    4 + len + (4 - (len % 4)) % 4
}

// --- NlmLock ---

/// Describes a lock region for NLM operations.
///
/// Wire format per the NLM4 XDR spec:
/// `caller (string) || fh (opaque<>) || owner (opaque<>) || svid (u32) || offset (u64) || length (u64)`
#[derive(Debug, Clone)]
pub struct NlmLock {
    /// Caller identity string  --  typically the local hostname.
    pub caller: String,
    /// NFS file handle for the file to lock.
    pub fh: FileHandle,
    /// Lock owner identifier (arbitrary bytes, uniquely identifies the locker).
    pub owner: Vec<u8>,
    /// Process ID of the locking process (used for deadlock detection).
    pub svid: u32,
    /// Byte offset of the lock region.
    pub offset: u64,
    /// Byte length of the lock region (0 = lock to EOF).
    pub length: u64,
}

impl Pack for NlmLock {
    fn packed_size(&self) -> usize {
        xdr_string_size(&self.caller) + opaque_packed_size(self.fh.as_bytes()) + opaque_packed_size(&self.owner) + 4 + 8 + 8
    }

    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        let mut n = pack_xdr_string(&self.caller, out)?;
        n += pack_opaque(self.fh.as_bytes(), out)?;
        n += pack_opaque(&self.owner, out)?;
        n += self.svid.pack(out)?;
        n += self.offset.pack(out)?;
        n += self.length.pack(out)?;
        Ok(n)
    }
}

// --- NlmArgs (TEST, LOCK, CANCEL) ---

/// Arguments for NLM4_TEST, NLM4_LOCK, and NLM4_CANCEL.
///
/// Wire format: `cookie (opaque<>) || block (bool) || exclusive (bool) || lock || reclaim (bool) || state (i32)`
struct NlmArgs {
    /// Opaque cookie for matching async responses (unused in synchronous mode).
    cookie: Vec<u8>,
    /// If true, block waiting for the lock rather than failing immediately.
    block: bool,
    /// If true, request an exclusive (write) lock; false = shared (read).
    exclusive: bool,
    /// The lock descriptor.
    lock: NlmLock,
    /// True only when reclaiming locks after a server reboot.
    reclaim: bool,
    /// NSM state counter  --  used to detect server reboots.
    state: i32,
}

impl Pack for NlmArgs {
    fn packed_size(&self) -> usize {
        opaque_packed_size(&self.cookie) + 4 + 4 + self.lock.packed_size() + 4 + 4
    }

    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        let mut n = pack_opaque(&self.cookie, out)?;
        n += u32::from(self.block).pack(out)?;
        n += u32::from(self.exclusive).pack(out)?;
        n += self.lock.pack(out)?;
        n += u32::from(self.reclaim).pack(out)?;
        // i32 state field sent as 4 raw bytes big-endian per XDR (ONC SM spec).
        let state_bytes = self.state.to_be_bytes();
        out.write_all(&state_bytes).map_err(nfs3_types::xdr_codec::Error::Io)?;
        n += 4;
        Ok(n)
    }
}

// --- NlmUnlockArgs ---

/// Arguments for NLM4_UNLOCK.
///
/// Wire format: `cookie (opaque<>) || lock`
struct NlmUnlockArgs {
    /// Opaque cookie for matching async responses.
    cookie: Vec<u8>,
    /// The lock to release.
    lock: NlmLock,
}

impl Pack for NlmUnlockArgs {
    fn packed_size(&self) -> usize {
        opaque_packed_size(&self.cookie) + self.lock.packed_size()
    }

    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        let mut n = pack_opaque(&self.cookie, out)?;
        n += self.lock.pack(out)?;
        Ok(n)
    }
}

// --- NlmStatus ---

/// Result status from any NLM operation.
///
/// Values per the NLM4 XDR spec:
/// 0=Granted, 1=Denied, 2=Denied_NoLocks, 3=Blocked, 4=Denied_GracePeriod
#[derive(Debug, Clone, Copy)]
pub struct NlmStatus {
    /// Raw NLM status code.
    pub stat: u32,
}

impl NlmStatus {
    /// True if the lock was granted or released successfully.
    #[must_use]
    pub const fn is_granted(self) -> bool {
        self.stat == 0
    }
}

impl Unpack for NlmStatus {
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (stat, n) = u32::unpack(input)?;
        Ok((Self { stat }, n))
    }
}

/// Full NLM response: `cookie (opaque<>) + stat (u32)`.
///
/// All NLM4 responses (TEST, LOCK, UNLOCK, CANCEL) begin with an opaque cookie
/// followed by a u32 status.  NLM4_TEST may include additional holder data on
/// denial, but we only need the status so we stop after stat.
/// Previous code decoded only a bare u32, missing the leading cookie entirely.
struct NlmRes(NlmStatus);

impl Unpack for NlmRes {
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        // Skip the opaque<> cookie: 4-byte length + data + XDR padding.
        let (cookie_len, mut n) = u32::unpack(input)?;
        let len = cookie_len as usize;
        if len > 0 {
            let mut buf = vec![0u8; len];
            input.read_exact(&mut buf).map_err(nfs3_types::xdr_codec::Error::Io)?;
            n += len;
            let pad = (4 - (len % 4)) % 4;
            if pad > 0 {
                let mut pad_buf = [0u8; 3];
                if let Some(slice) = pad_buf.get_mut(..pad) {
                    input.read_exact(slice).map_err(nfs3_types::xdr_codec::Error::Io)?;
                }
                n += pad;
            }
        }
        // Read the stat field.
        let (status, sn) = NlmStatus::unpack(input)?;
        n += sn;
        Ok((Self(status), n))
    }
}

// --- NlmClient ---

/// NLM4 client over a direct `NfsConnection`.
///
/// The connection is owned here (not pool-backed) because NLM typically runs
/// on a separate port and its lock state is per-connection.
pub struct NlmClient {
    /// Underlying transport connection to the NLM daemon.
    conn: NfsConnection,
}

impl std::fmt::Debug for NlmClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NlmClient").field("conn", &self.conn).finish()
    }
}

impl NlmClient {
    /// Wrap an existing connection as an NLM client.
    #[must_use]
    pub const fn new(conn: NfsConnection) -> Self {
        Self { conn }
    }

    /// NLM4_TEST (proc 1)  --  test whether a lock can be acquired without blocking.
    ///
    /// Returns the NLM status: 0=would succeed, 1=already locked, etc.
    pub async fn test(&mut self, fh: &FileHandle, offset: u64, length: u64, exclusive: bool) -> anyhow::Result<NlmStatus> {
        let args = NlmArgs { cookie: Vec::new(), block: false, exclusive, lock: Self::make_lock(fh, offset, length), reclaim: false, state: 0 };
        let res = self.conn.call_raw::<NlmArgs, NlmRes>(NLM_PROGRAM, NLM_VERSION, NLM4_TEST, &args).await.context("NLM4_TEST")?;
        Ok(res.0)
    }

    /// NLM4_LOCK (proc 2)  --  acquire a lock on a byte range.
    ///
    /// `exclusive=true` requests a write lock; `false` requests a read lock.
    pub async fn lock(&mut self, fh: &FileHandle, offset: u64, length: u64, exclusive: bool) -> anyhow::Result<NlmStatus> {
        let args = NlmArgs { cookie: Vec::new(), block: false, exclusive, lock: Self::make_lock(fh, offset, length), reclaim: false, state: 0 };
        let res = self.conn.call_raw::<NlmArgs, NlmRes>(NLM_PROGRAM, NLM_VERSION, NLM4_LOCK, &args).await.context("NLM4_LOCK")?;
        Ok(res.0)
    }

    /// NLM4_UNLOCK (proc 4)  --  release a lock previously acquired with `lock()`.
    pub async fn unlock(&mut self, fh: &FileHandle, offset: u64, length: u64) -> anyhow::Result<NlmStatus> {
        let args = NlmUnlockArgs { cookie: Vec::new(), lock: Self::make_lock(fh, offset, length) };
        let res = self.conn.call_raw::<NlmUnlockArgs, NlmRes>(NLM_PROGRAM, NLM_VERSION, NLM4_UNLOCK, &args).await.context("NLM4_UNLOCK")?;
        Ok(res.0)
    }

    /// NLM4_CANCEL (proc 3)  --  cancel a pending (blocked) lock request.
    pub async fn cancel(&mut self, fh: &FileHandle, offset: u64, length: u64) -> anyhow::Result<NlmStatus> {
        let args = NlmArgs { cookie: Vec::new(), block: false, exclusive: false, lock: Self::make_lock(fh, offset, length), reclaim: false, state: 0 };
        let res = self.conn.call_raw::<NlmArgs, NlmRes>(NLM_PROGRAM, NLM_VERSION, NLM4_CANCEL, &args).await.context("NLM4_CANCEL")?;
        Ok(res.0)
    }

    /// Build an NlmLock descriptor using "nfswolf" as the caller identity.
    fn make_lock(fh: &FileHandle, offset: u64, length: u64) -> NlmLock {
        NlmLock { caller: "nfswolf".to_owned(), fh: fh.clone(), owner: b"nfswolf-owner".to_vec(), svid: 1, offset, length }
    }
}
