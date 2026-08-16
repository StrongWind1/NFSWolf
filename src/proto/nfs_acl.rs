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

#[cfg(test)]
mod tests {
    use super::*;

    fn build_golden_reply() -> Vec<u8> {
        let mut buf = Vec::new();
        // status = NFS3_OK
        buf.extend_from_slice(&0u32.to_be_bytes());
        // post_op_attr: follows = false
        buf.extend_from_slice(&0u32.to_be_bytes());
        // mask = NFS_ACL | NFS_DFACL (0x0005)
        buf.extend_from_slice(&5u32.to_be_bytes());
        // Solaris wire format: separate aclcnt before the XDR array
        buf.extend_from_slice(&3u32.to_be_bytes()); // aclcnt
        buf.extend_from_slice(&3u32.to_be_bytes()); // XDR array count
        // access ACL: 3 entries
        // USER_OBJ(0x01) uid=0 perm=rwx(7)
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&7u32.to_be_bytes());
        // USER(0x02) uid=1001 perm=rw-(6)
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(&1001u32.to_be_bytes());
        buf.extend_from_slice(&6u32.to_be_bytes());
        // GROUP(0x08) gid=42 perm=r-x(5)
        buf.extend_from_slice(&8u32.to_be_bytes());
        buf.extend_from_slice(&42u32.to_be_bytes());
        buf.extend_from_slice(&5u32.to_be_bytes());
        // Solaris wire format: separate dfaclcnt + XDR array count
        buf.extend_from_slice(&0u32.to_be_bytes()); // dfaclcnt
        buf.extend_from_slice(&0u32.to_be_bytes()); // XDR array count
        buf
    }

    #[test]
    fn decode_golden_reply() {
        let data = build_golden_reply();
        let result = Getacl3Result::decode(&data).unwrap();
        assert_eq!(result.status, 0);
        assert_eq!(result.access_acl.len(), 3);
        assert_eq!(result.default_acl.len(), 0);
        assert_eq!(result.access_acl[0].tag, 0x01);
        assert_eq!(result.access_acl[1].tag, ACL_USER);
        assert_eq!(result.access_acl[1].id, 1001);
        assert_eq!(result.access_acl[1].perm, 6);
        assert_eq!(result.access_acl[2].tag, ACL_GROUP);
        assert_eq!(result.access_acl[2].id, 42);
    }

    #[test]
    fn decode_error_status() {
        let data = 13u32.to_be_bytes().to_vec();
        let result = Getacl3Result::decode(&data).unwrap();
        assert_eq!(result.status, 13);
        assert!(result.access_acl.is_empty());
    }

    #[test]
    fn decode_truncated_rejects() {
        assert!(Getacl3Result::decode(&[0, 0]).is_err());
    }

    #[test]
    fn acl_entry_type_names() {
        assert_eq!(AclEntry { tag: 0x01, id: 0, perm: 7 }.type_name(), "USER_OBJ");
        assert_eq!(AclEntry { tag: ACL_USER, id: 0, perm: 0 }.type_name(), "USER");
        assert_eq!(AclEntry { tag: ACL_GROUP, id: 0, perm: 0 }.type_name(), "GROUP");
        assert_eq!(AclEntry { tag: 0x10, id: 0, perm: 0 }.type_name(), "MASK");
        assert_eq!(AclEntry { tag: 0x20, id: 0, perm: 0 }.type_name(), "OTHER");
        assert_eq!(AclEntry { tag: 0xFF, id: 0, perm: 0 }.type_name(), "UNKNOWN");
    }

    #[test]
    fn perm_string_formatting() {
        assert_eq!(AclEntry { tag: 0, id: 0, perm: 7 }.perm_string(), "rwx");
        assert_eq!(AclEntry { tag: 0, id: 0, perm: 5 }.perm_string(), "r-x");
        assert_eq!(AclEntry { tag: 0, id: 0, perm: 0 }.perm_string(), "---");
        assert_eq!(AclEntry { tag: 0, id: 0, perm: 6 }.perm_string(), "rw-");
    }
}
