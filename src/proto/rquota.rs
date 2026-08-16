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
use onc_xdr::{Opaque, Pack};

use crate::proto::sideband::{RawReply, read_u32};
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

impl GetquotaResult {
    fn decode(raw: &[u8]) -> anyhow::Result<Self> {
        let mut pos = 0;
        let status = QuotaStatus::from_u32(read_u32(raw, &mut pos)?);

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
pub(crate) async fn getquota(addr: SocketAddr, export_path: &str, uid: u32, proxy: Option<&str>, stealth: &StealthConfig) -> anyhow::Result<GetquotaResult> {
    let mut rpc = crate::proto::sideband::connect_sideband(addr, proxy, stealth).await?;
    let args = GetquotaArgs { path: Opaque::owned(export_path.as_bytes().to_vec()), uid };
    let raw: RawReply = rpc.call(RQUOTA_PROGRAM, RQUOTA_V1, RQUOTAPROC_GETQUOTA, &args).await.context("GETQUOTA RPC")?;
    GetquotaResult::decode(&raw.data)
}
