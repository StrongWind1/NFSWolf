//! NSM (Network Status Monitor / statd) client  --  ONC SM protocol.
//!
//! NSM runs alongside NLM to provide crash/reboot notification.
//! nfswolf uses it to detect whether statd is exposed (fingerprinting, F-1.3)
//! and to read the server's reboot counter, which is security-relevant:
//! a counter mismatch can indicate a reboot was hidden from lock clients.
//!
//! Program: 100024 (SM_PROG), Version: 1 (SM_VERS).
//! Reference: ONC SM specification, as implemented by Linux statd.

// NSM wire-type fields are protocol values; individual docs would repeat names.
// Toolkit API  --  not all items are used in currently-implemented phases.
// NSM XDR Pack/Unpack uses slice padding at fixed offsets matching the ONC SM wire format.
use std::io::{Read, Write};
use std::net::SocketAddr;

use anyhow::Context as _;
use nfs3_types::xdr_codec::{Pack, Unpack};

use crate::proto::conn::NfsConnection;

/// NSM RPC program number.
pub const NSM_PROGRAM: u32 = 100_024;

/// NSM version 1 (SM_VERS).
pub const NSM_VERSION: u32 = 1;

// --- NSM procedure numbers ---

/// SM_STAT (proc 1): check whether `hostname` is being monitored.
const SM_STAT: u32 = 1;
/// SM_MON (proc 2): register to monitor `hostname` for crash/reboot.
const SM_MON: u32 = 2;
/// SM_UNMON (proc 3): deregister monitoring for `hostname`.
const SM_UNMON: u32 = 3;

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

fn pack_opaque_fixed(data: &[u8], out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
    // NSM priv_data is a fixed 16-byte field (sm_priv in the ONC SM spec).
    const PRIV_SIZE: usize = 16;
    let mut buf = [0u8; PRIV_SIZE];
    let copy = data.len().min(PRIV_SIZE);
    if let (Some(dst), Some(src)) = (buf.get_mut(..copy), data.get(..copy)) {
        dst.copy_from_slice(src);
    }
    out.write_all(&buf).map_err(nfs3_types::xdr_codec::Error::Io)?;
    Ok(PRIV_SIZE)
}

// --- NSM wire types ---

/// Arguments for SM_STAT  --  identify the host to query.
///
/// Wire format: `mon_name (string)`
struct SmStatArgs {
    mon_name: String,
}

impl Pack for SmStatArgs {
    fn packed_size(&self) -> usize {
        xdr_string_size(&self.mon_name)
    }

    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        pack_xdr_string(&self.mon_name, out)
    }
}

/// Arguments for SM_MON  --  register a monitor callback.
///
/// Wire format: `mon_name (string) || my_name (string) || my_prog (u32) || my_vers (u32) || my_proc (u32) || priv (opaque[16])`
struct SmMonArgs {
    /// Host to monitor.
    mon_name: String,
    /// Our hostname (callback target).
    my_name: String,
    /// Our RPC program number (callback destination).
    my_prog: u32,
    /// Our RPC version.
    my_vers: u32,
    /// Our RPC procedure.
    my_proc: u32,
    /// Private data returned in callback (up to 16 bytes).
    priv_data: Vec<u8>,
}

impl Pack for SmMonArgs {
    fn packed_size(&self) -> usize {
        xdr_string_size(&self.mon_name) + xdr_string_size(&self.my_name) + 4 + 4 + 4 + 16
    }

    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        let mut n = pack_xdr_string(&self.mon_name, out)?;
        n += pack_xdr_string(&self.my_name, out)?;
        n += self.my_prog.pack(out)?;
        n += self.my_vers.pack(out)?;
        n += self.my_proc.pack(out)?;
        n += pack_opaque_fixed(&self.priv_data, out)?;
        Ok(n)
    }
}

/// Arguments for SM_UNMON.
///
/// Wire format: same as SM_MON but priv is omitted: `mon_name (string) || my_name (string) || my_prog || my_vers || my_proc`
struct SmUnmonArgs {
    /// Host to stop monitoring.
    mon_name: String,
    /// Our hostname.
    my_name: String,
}

impl Pack for SmUnmonArgs {
    fn packed_size(&self) -> usize {
        xdr_string_size(&self.mon_name) + xdr_string_size(&self.my_name) + 4 + 4 + 4
    }

    fn pack(&self, out: &mut impl Write) -> nfs3_types::xdr_codec::Result<usize> {
        let mut n = pack_xdr_string(&self.mon_name, out)?;
        n += pack_xdr_string(&self.my_name, out)?;
        // Program/version/proc = 0  --  we don't need callbacks.
        n += 0_u32.pack(out)?;
        n += 0_u32.pack(out)?;
        n += 0_u32.pack(out)?;
        Ok(n)
    }
}

// --- NsmStatRes ---

/// Result of SM_STAT and SM_MON.
///
/// Wire format: `res_stat (u32) || state (i32)`
/// - `res_stat`: 0 = host not monitored, 1 = host is monitored.
/// - `state`: monotonically increasing reboot counter; incremented on each crash+recovery.
///   An odd value means the server is currently in the process of rebooting.
#[derive(Debug, Clone, Copy)]
pub struct NsmStatRes {
    /// 0 = never monitored, 1 = currently monitored.
    pub stat: u32,
    /// Reboot counter  --  odd means a reboot is in progress.
    pub state: i32,
}

impl Unpack for NsmStatRes {
    fn unpack(input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        let (stat, n0) = u32::unpack(input)?;
        let (state_raw, n1) = u32::unpack(input)?;
        // NSM state is defined as i32 on the wire (ONC SM spec); reinterpret the bits.
        let state = state_raw.cast_signed();
        Ok((Self { stat, state }, n0 + n1))
    }
}

/// Void response  --  used for SM_UNMON which returns nothing useful.
struct VoidRes;

impl Unpack for VoidRes {
    fn unpack(_input: &mut impl Read) -> nfs3_types::xdr_codec::Result<(Self, usize)> {
        Ok((Self, 0))
    }
}

// --- NsmClient ---

/// NSM (statd) client over a direct `NfsConnection`.
///
/// Used to probe the reboot counter and check whether monitoring is active.
pub struct NsmClient {
    /// Underlying transport connection to statd.
    conn: NfsConnection,
}

impl std::fmt::Debug for NsmClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NsmClient").field("conn", &self.conn).finish()
    }
}

impl NsmClient {
    /// Wrap an existing connection as an NSM client.
    #[must_use]
    pub const fn new(conn: NfsConnection) -> Self {
        Self { conn }
    }

    /// SM_STAT (proc 1)  --  check whether `hostname` is being monitored.
    ///
    /// Also returns the current reboot `state` counter, which is the security-
    /// relevant value: a hidden reboot leaves NLM lock state stale.
    pub async fn stat(&mut self, hostname: &str) -> anyhow::Result<NsmStatRes> {
        let args = SmStatArgs { mon_name: hostname.to_owned() };
        self.conn.call_raw::<SmStatArgs, NsmStatRes>(NSM_PROGRAM, NSM_VERSION, SM_STAT, &args).await.context("NSM SM_STAT")
    }

    /// SM_MON (proc 2)  --  register nfswolf as a monitor for `hostname`.
    ///
    /// `priv_data` is up to 16 bytes returned in the callback; pass an empty slice
    /// unless a specific marker is needed for testing.
    pub async fn monitor(&mut self, hostname: &str, priv_data: &[u8]) -> anyhow::Result<NsmStatRes> {
        let args = SmMonArgs {
            mon_name: hostname.to_owned(),
            my_name: "nfswolf".to_owned(),
            // Program 0 = no-op callback  --  we only want the state counter.
            my_prog: 0,
            my_vers: 0,
            my_proc: 0,
            priv_data: priv_data.to_vec(),
        };
        self.conn.call_raw::<SmMonArgs, NsmStatRes>(NSM_PROGRAM, NSM_VERSION, SM_MON, &args).await.context("NSM SM_MON")
    }

    /// SM_UNMON (proc 3)  --  deregister nfswolf's monitor entry for `hostname`.
    pub async fn unmonitor(&mut self, hostname: &str) -> anyhow::Result<()> {
        let args = SmUnmonArgs { mon_name: hostname.to_owned(), my_name: "nfswolf".to_owned() };
        self.conn.call_raw::<SmUnmonArgs, VoidRes>(NSM_PROGRAM, NSM_VERSION, SM_UNMON, &args).await.context("NSM SM_UNMON").map(|_| ())
    }

    /// SM_STAT probe using a fresh raw TCP connection (no NfsConnection / MOUNT needed).
    ///
    /// Connects directly to the NSM port `nsm_addr` and calls SM_STAT to check
    /// whether `hostname` is being monitored and to read the reboot counter.
    /// Returns `None` if the server does not respond (NSM not reachable).
    pub async fn probe_stat(nsm_addr: SocketAddr, hostname: &str) -> Option<NsmStatRes> {
        use nfs3_client::net::Connector as _;
        use nfs3_client::rpc::RpcClient;
        use nfs3_client::tokio::TokioConnector;

        let null_auth = nfs3_types::rpc::opaque_auth::default();
        let io = TokioConnector.connect(nsm_addr).await.ok()?;
        let mut rpc = RpcClient::new_with_auth(io, null_auth.clone(), null_auth);
        let args = SmStatArgs { mon_name: hostname.to_owned() };
        rpc.call::<SmStatArgs, NsmStatRes>(NSM_PROGRAM, NSM_VERSION, SM_STAT, &args).await.ok()
    }
}
