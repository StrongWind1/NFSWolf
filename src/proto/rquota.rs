//! RQUOTA client (program 100011) -- UID existence oracle via quota queries.
//!
//! GETQUOTA returns disk usage for a specific UID on a specific export path.
//! A non-zero `curblocks` or `curfiles` confirms the UID exists and has disk
//! activity. The `bsize` field leaks the filesystem block size (ext4=4096,
//! XFS=512, ZFS=1024), narrowing escape strategy before running NFS.
//!
//! Wire format: no RFC; de facto standard from Sun rquota.x.
//! v1: GETQUOTA(path, uid), v2: GETQUOTA(path, id, type) where type=0=user, type=1=group.

use std::net::SocketAddr;

use anyhow::Context as _;
use onc_rpc_client::rpc::RpcClient;
use onc_rpc_client::transport::tokio::TokioIo;
use onc_xdr::{Opaque, Pack, Unpack};
use tokio::net::TcpStream;

use crate::util::stealth::StealthConfig;

const RQUOTA_PROGRAM: u32 = 100_011;
const RQUOTA_V1: u32 = 1;
const RQUOTAPROC_GETQUOTA: u32 = 1;

// --- XDR types ---

/// GETQUOTA v1 args: export path + UID.
struct GetquotaArgs {
    path: Opaque<'static>,
    uid: u32,
}

impl Pack for GetquotaArgs {
    fn pack(&self, out: &mut impl std::io::Write) -> onc_xdr::Result<usize> {
        let mut n = self.path.pack(out)?;
        n += self.uid.pack(out)?;
        Ok(n)
    }

    fn packed_size(&self) -> usize {
        self.path.packed_size() + 4
    }
}

/// GETQUOTA result status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuotaStatus {
    Ok,
    NoQuota,
    PermDenied,
    Unknown(u32),
}

impl QuotaStatus {
    fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Ok,
            2 => Self::NoQuota,
            3 => Self::PermDenied,
            other => Self::Unknown(other),
        }
    }
}

/// Quota data returned on Q_OK.
#[derive(Debug, Clone)]
#[expect(dead_code, reason = "wire-protocol fields decoded for future use by credential ladder integration")]
pub(crate) struct QuotaData {
    pub bsize: u32,
    pub active: bool,
    pub bhardlimit: u32,
    pub bsoftlimit: u32,
    pub curblocks: u32,
    pub fhardlimit: u32,
    pub fsoftlimit: u32,
    pub curfiles: u32,
    pub btimeleft: u32,
    pub ftimeleft: u32,
}

/// GETQUOTA result after XDR decoding.
#[derive(Debug)]
pub(crate) struct GetquotaResult {
    #[expect(dead_code, reason = "status exposed for callers that need to distinguish NoQuota from PermDenied")]
    pub status: QuotaStatus,
    pub quota: Option<QuotaData>,
}

/// Raw reply for manual decoding.
struct GetquotaRawReply {
    data: Vec<u8>,
}

impl Unpack for GetquotaRawReply {
    fn unpack(input: &mut impl std::io::Read) -> onc_xdr::Result<(Self, usize)> {
        let mut data = Vec::new();
        let n = input.read_to_end(&mut data)?;
        Ok((Self { data }, n))
    }
}

/// Read a big-endian u32 from `raw` at `pos`, advancing `pos` by 4.
fn read_u32(raw: &[u8], pos: &mut usize) -> anyhow::Result<u32> {
    let end = *pos + 4;
    let slice = raw.get(*pos..end).context("RQUOTA reply truncated")?;
    let bytes: [u8; 4] = slice.try_into().context("RQUOTA reply truncated")?;
    *pos = end;
    Ok(u32::from_be_bytes(bytes))
}

impl GetquotaResult {
    fn decode(raw: &[u8]) -> anyhow::Result<Self> {
        let mut pos = 0;
        let status_val = read_u32(raw, &mut pos)?;
        let status = QuotaStatus::from_u32(status_val);

        if status != QuotaStatus::Ok {
            return Ok(Self { status, quota: None });
        }

        // Q_OK: rquota struct follows (10 x u32 = 40 bytes).
        let bsize = read_u32(raw, &mut pos)?;
        let active_val = read_u32(raw, &mut pos)?;
        let bhardlimit = read_u32(raw, &mut pos)?;
        let bsoftlimit = read_u32(raw, &mut pos)?;
        let curblocks = read_u32(raw, &mut pos)?;
        let fhardlimit = read_u32(raw, &mut pos)?;
        let fsoftlimit = read_u32(raw, &mut pos)?;
        let curfiles = read_u32(raw, &mut pos)?;
        let btimeleft = read_u32(raw, &mut pos)?;
        let ftimeleft = read_u32(raw, &mut pos)?;

        Ok(Self { status, quota: Some(QuotaData { bsize, active: active_val != 0, bhardlimit, bsoftlimit, curblocks, fhardlimit, fsoftlimit, curfiles, btimeleft, ftimeleft }) })
    }
}

// --- Client ---

/// Query disk quota for a UID on a specific export path.
///
/// Connects to `addr` (rquotad port, resolved via portmapper) with AUTH_SYS
/// uid=0 and issues a GETQUOTA v1 call.
pub(crate) async fn getquota(addr: SocketAddr, export_path: &str, uid: u32, proxy: Option<&str>, stealth: &StealthConfig) -> anyhow::Result<GetquotaResult> {
    stealth.wait().await;

    let stream = if let Some(p) = proxy {
        let proxy_addr = crate::proto::conn::parse_proxy_addr(p)?;
        crate::proto::conn::socks5_connect(proxy_addr, addr).await.context("RQUOTA SOCKS5 connect")?
    } else {
        TcpStream::connect(addr).await.context("RQUOTA TCP connect")?
    };

    let auth = crate::proto::auth::AuthSys::new(0, 0, "localhost").to_opaque_auth(crate::proto::auth::next_stamp());
    let mut rpc = RpcClient::new_with_auth(TokioIo::new(stream), auth, onc_rpc_client::rpc::opaque_auth::default());

    let args = GetquotaArgs { path: Opaque::owned(export_path.as_bytes().to_vec()), uid };

    let raw: GetquotaRawReply = rpc.call(RQUOTA_PROGRAM, RQUOTA_V1, RQUOTAPROC_GETQUOTA, &args).await.context("GETQUOTA RPC")?;

    GetquotaResult::decode(&raw.data)
}
