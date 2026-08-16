//! NFS_ACL client (program 100227) -- POSIX ACL retrieval over RPC.
//!
//! The NFS_ACL sideband protocol exposes POSIX ACL entries that grant
//! access beyond what standard mode bits reveal. Linux knfsd hosts it
//! on the same port as NFS (2049); Solaris may use a separate port
//! resolved via portmapper.
//!
//! Wire format: Solaris `nfsacl_prot.x` (de facto standard, no RFC).
//! Verified against Linux `fs/nfsd/nfs3acl.c` and `fs/nfs_common/nfsacl.c`.

use std::net::SocketAddr;

use anyhow::Context as _;
use onc_xdr::{Opaque, Pack};

use crate::proto::sideband::{RawReply, read_u32};
use crate::util::stealth::StealthConfig;

const NFS_ACL_PROGRAM: u32 = 100_227;
const NFS_ACL_V3: u32 = 3;
const ACLPROC3_GETACL: u32 = 1;

// --- Mask bits (include/uapi/linux/nfsacl.h) ---

const NFS_ACL_MASK: u32 = 0x0001;
const NFS_DFACL_MASK: u32 = 0x0004;

// --- ACL entry type constants (include/uapi/linux/posix_acl.h) ---

pub(crate) const ACL_USER: u32 = 0x02;
pub(crate) const ACL_GROUP: u32 = 0x08;

/// Wire value OR'd into a_type for default ACL entries.
const NFS_ACL_DEFAULT_FLAG: u32 = 0x1000;

// --- XDR types ---

struct Getacl3Args {
    fh: Opaque<'static>,
    mask: u32,
}

impl Pack for Getacl3Args {
    fn pack(&self, out: &mut impl std::io::Write) -> onc_xdr::Result<usize> {
        let mut n = self.fh.pack(out)?;
        n += self.mask.pack(out)?;
        Ok(n)
    }

    fn packed_size(&self) -> usize {
        self.fh.packed_size() + 4
    }
}

/// A single POSIX ACL entry on the wire (12 bytes).
#[derive(Debug, Clone)]
pub(crate) struct AclEntry {
    pub tag: u32,
    pub id: u32,
    pub perm: u32,
}

impl AclEntry {
    pub(crate) fn type_name(&self) -> &'static str {
        match self.tag {
            0x01 => "USER_OBJ",
            ACL_USER => "USER",
            0x04 => "GROUP_OBJ",
            ACL_GROUP => "GROUP",
            0x10 => "MASK",
            0x20 => "OTHER",
            _ => "UNKNOWN",
        }
    }

    pub(crate) fn perm_string(&self) -> String {
        let r = if self.perm & 4 != 0 { 'r' } else { '-' };
        let w = if self.perm & 2 != 0 { 'w' } else { '-' };
        let x = if self.perm & 1 != 0 { 'x' } else { '-' };
        format!("{r}{w}{x}")
    }
}

/// GETACL3 result after manual XDR decoding.
#[derive(Debug)]
pub(crate) struct Getacl3Result {
    pub status: u32,
    pub access_acl: Vec<AclEntry>,
    pub default_acl: Vec<AclEntry>,
}

impl Getacl3Result {
    fn decode(raw: &[u8]) -> anyhow::Result<Self> {
        let mut pos = 0;
        let status = read_u32(raw, &mut pos)?;
        if status != 0 {
            return Ok(Self { status, access_acl: Vec::new(), default_acl: Vec::new() });
        }

        // post_op_attr: 4-byte bool, then 84 bytes of fattr3 if true.
        let attr_follows = read_u32(raw, &mut pos)?;
        if attr_follows != 0 {
            pos += 84; // fattr3 = 21 x u32
        }

        let _mask = read_u32(raw, &mut pos)?;

        // Solaris wire format: separate `aclcnt` field THEN XDR array
        // (which has its own length prefix). Both carry the same value.
        let _aclcnt = read_u32(raw, &mut pos)?;
        let access_acl = Self::decode_acl_array(raw, &mut pos)?;

        let _dfaclcnt = read_u32(raw, &mut pos)?;
        let default_acl = Self::decode_acl_array(raw, &mut pos)?;

        Ok(Self { status, access_acl, default_acl })
    }

    fn decode_acl_array(raw: &[u8], pos: &mut usize) -> anyhow::Result<Vec<AclEntry>> {
        let count = read_u32(raw, pos)? as usize;
        if count > 1024 {
            anyhow::bail!("ACL count {count} exceeds NFS_ACL_MAX_ENTRIES (1024)");
        }

        let needed = count * 12;
        anyhow::ensure!(raw.len() >= *pos + needed, "GETACL3 reply truncated in ACL array");

        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let raw_type = read_u32(raw, pos)?;
            let a_id = read_u32(raw, pos)?;
            let a_perm = read_u32(raw, pos)?;
            let tag = raw_type & !NFS_ACL_DEFAULT_FLAG;
            entries.push(AclEntry { tag, id: a_id, perm: a_perm });
        }
        Ok(entries)
    }
}

// --- Client ---

/// Retrieve POSIX ACLs for a file handle via the NFS_ACL sideband protocol.
pub(crate) async fn getacl3(addr: SocketAddr, fh_bytes: &[u8], proxy: Option<&str>, stealth: &StealthConfig) -> anyhow::Result<Getacl3Result> {
    let mut rpc = crate::proto::sideband::connect_sideband(addr, proxy, stealth).await?;
    let args = Getacl3Args { fh: Opaque::owned(fh_bytes.to_vec()), mask: NFS_ACL_MASK | NFS_DFACL_MASK };
    let raw: RawReply = rpc.call(NFS_ACL_PROGRAM, NFS_ACL_V3, ACLPROC3_GETACL, &args).await.context("GETACL3 RPC")?;
    Getacl3Result::decode(&raw.data)
}
