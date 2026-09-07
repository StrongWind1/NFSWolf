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
const RQUOTA_V2: u32 = 2;
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
    #[cfg_attr(not(test), expect(dead_code, reason = "read in tests and by future callers"))]
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

/// GETQUOTA v2 args: export path + id + type (0=user, 1=group).
struct GetquotaArgsV2 {
    path: Opaque<'static>,
    id: u32,
    id_type: u32,
}

impl Pack for GetquotaArgsV2 {
    fn pack(&self, out: &mut impl std::io::Write) -> onc_xdr::Result<usize> {
        let mut n = self.path.pack(out)?;
        n += self.id.pack(out)?;
        n += self.id_type.pack(out)?;
        Ok(n)
    }

    fn packed_size(&self) -> usize {
        self.path.packed_size() + 4 + 4
    }
}

// --- Client ---

/// Query disk quota for a UID on a specific export path (RQUOTA v1).
pub(crate) async fn getquota(addr: SocketAddr, export_path: &str, uid: u32, proxy: Option<&str>, stealth: &StealthConfig) -> anyhow::Result<GetquotaResult> {
    let mut rpc = crate::proto::sideband::connect_sideband(addr, proxy, stealth).await?;
    let args = GetquotaArgs { path: Opaque::owned(export_path.as_bytes().to_vec()), uid };
    let raw: RawReply = rpc.call(RQUOTA_PROGRAM, RQUOTA_V1, RQUOTAPROC_GETQUOTA, &args).await.context("GETQUOTA RPC")?;
    GetquotaResult::decode(&raw.data)
}

/// Query user (type=0) or group (type=1) quota via RQUOTA v2.
pub(crate) async fn getquota_v2(addr: SocketAddr, export_path: &str, id: u32, id_type: u32, proxy: Option<&str>, stealth: &StealthConfig) -> anyhow::Result<GetquotaResult> {
    let mut rpc = crate::proto::sideband::connect_sideband(addr, proxy, stealth).await?;
    let args = GetquotaArgsV2 { path: Opaque::owned(export_path.as_bytes().to_vec()), id, id_type };
    let raw: RawReply = rpc.call(RQUOTA_PROGRAM, RQUOTA_V2, RQUOTAPROC_GETQUOTA, &args).await.context("GETQUOTA v2 RPC")?;
    GetquotaResult::decode(&raw.data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_status_from_u32() {
        assert_eq!(QuotaStatus::from_u32(1), QuotaStatus::Ok);
        assert_eq!(QuotaStatus::from_u32(2), QuotaStatus::NoQuota);
        assert_eq!(QuotaStatus::from_u32(3), QuotaStatus::PermDenied);
        assert_eq!(QuotaStatus::from_u32(99), QuotaStatus::Unknown(99));
    }

    fn build_ok_reply() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes()); // Q_OK
        buf.extend_from_slice(&4096u32.to_be_bytes()); // bsize
        buf.extend_from_slice(&1u32.to_be_bytes()); // active
        buf.extend_from_slice(&100_000u32.to_be_bytes()); // bhardlimit
        buf.extend_from_slice(&50_000u32.to_be_bytes()); // bsoftlimit
        buf.extend_from_slice(&25_000u32.to_be_bytes()); // curblocks
        buf.extend_from_slice(&10_000u32.to_be_bytes()); // fhardlimit
        buf.extend_from_slice(&5_000u32.to_be_bytes()); // fsoftlimit
        buf.extend_from_slice(&1_234u32.to_be_bytes()); // curfiles
        buf.extend_from_slice(&0u32.to_be_bytes()); // btimeleft
        buf.extend_from_slice(&0u32.to_be_bytes()); // ftimeleft
        buf
    }

    #[test]
    fn decode_ok_reply() {
        let data = build_ok_reply();
        let result = GetquotaResult::decode(&data).unwrap();
        assert_eq!(result.status, QuotaStatus::Ok);
        let q = result.quota.unwrap();
        assert_eq!(q.bsize, 4096);
        assert!(q.active);
        assert_eq!(q.bhardlimit, 100_000);
        assert_eq!(q.curblocks, 25_000);
        assert_eq!(q.curfiles, 1_234);
    }

    #[test]
    fn decode_noquota() {
        let data = 2u32.to_be_bytes().to_vec();
        let result = GetquotaResult::decode(&data).unwrap();
        assert_eq!(result.status, QuotaStatus::NoQuota);
        assert!(result.quota.is_none());
    }

    #[test]
    fn decode_truncated_rejects() {
        assert!(GetquotaResult::decode(&[0, 0]).is_err());
    }

    #[test]
    fn decode_ok_truncated_body_rejects() {
        // Q_OK but only 4 bytes of rquota (need 40)
        let mut data = 1u32.to_be_bytes().to_vec();
        data.extend_from_slice(&4096u32.to_be_bytes());
        assert!(GetquotaResult::decode(&data).is_err());
    }
}
