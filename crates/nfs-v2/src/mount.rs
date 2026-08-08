//! MOUNT version 1 -- RFC 1094 Appendix A.
//!
//! MOUNT v1 is the mount protocol for NFSv2. It predates auth flavor
//! negotiation: the MNT response is a bare `fhstatus` union (status + 32-byte
//! handle), unlike MOUNT v3 which also returns the auth flavors the export
//! accepts. EXPORT is wire-identical to v3 EXPORT (a linked list of `exports`
//! nodes), just carried over version 1.
//!
//! The export types are defined locally rather than imported from `nfswolf-nfs3`
//! because there are no edges between the version crates.

#![expect(non_camel_case_types, reason = "identifiers are transcribed verbatim from RFC 1094's XDR definitions; renaming them to Rust conventions would break the correspondence a reader needs when checking this module against the spec")]
#![expect(missing_copy_implementations, reason = "Copy is derived on the wire types whose callers benefit from it; demanding it exhaustively cascades through every containing struct without improving the API")]
#![expect(single_use_lifetimes, reason = "newtype wrappers over borrowed wire data genuinely need the parameter; the lint counts the declaration and the single use and misreads it as removable")]

use std::io::{Read, Write};

use onc_rpc_client::RpcTransport;
use onc_xdr::{List, Opaque, Pack, Unpack, XdrCodec};

use crate::wire::Nfs2FileHandle;

/// MOUNT v1 program number (shared with v3, RFC 1094 Appendix A / RFC 1813).
pub const PROGRAM: u32 = 100_005;

/// MOUNT version 1.
pub const VERSION: u32 = 1;

/// MOUNT v1 procedure numbers (RFC 1094 Appendix A).
pub mod proc {
    /// Do nothing -- connectivity check.
    pub const MOUNTPROC_NULL: u32 = 0;
    /// Mount an export and obtain a 32-byte file handle.
    pub const MOUNTPROC_MNT: u32 = 1;
    /// Dump the mount table.
    pub const MOUNTPROC_DUMP: u32 = 2;
    /// Unmount a single export.
    pub const MOUNTPROC_UMNT: u32 = 3;
    /// Unmount all exports for this client.
    pub const MOUNTPROC_UMNTALL: u32 = 4;
    /// List all exports and their access control lists.
    pub const MOUNTPROC_EXPORT: u32 = 5;
}

// --- Wire types ---

/// Directory path argument for MNT/UMNT (RFC 1094 Appendix A: `dirpath`).
///
/// XDR string, encoded as a length-prefixed opaque.
#[derive(Debug, XdrCodec)]
pub struct dirpath<'a>(pub Opaque<'a>);

/// Export name in the EXPORT response (RFC 1094 Appendix A: `name`).
#[derive(Debug, XdrCodec)]
pub struct name<'a>(pub Opaque<'a>);

/// One node of the EXPORT linked list (RFC 1094 Appendix A: `exports`).
///
/// ```text
/// struct exports {
///     dirpath  ex_dir;
///     groups   ex_groups;
///     exports  ex_next;       /* optional linked-list pointer */
/// };
/// ```
///
/// The linked-list pointer is handled by `List<T>`.
#[derive(Debug, XdrCodec)]
pub struct export_node<'a, 'b> {
    /// Exported directory path.
    pub ex_dir: dirpath<'a>,
    /// Hosts allowed to mount this export.
    pub ex_groups: List<name<'b>>,
}

/// EXPORT response: linked list of `export_node`.
pub type exports<'a, 'b> = List<export_node<'a, 'b>>;

/// MOUNT v1 MNT response (RFC 1094 Appendix A).
///
/// ```text
/// union fhstatus switch (unsigned status) {
///     case 0: fhandle directory;   /* opaque[FHSIZE=32] */
///     default: void;
/// };
/// ```
///
/// Hand-implemented because FHSIZE=32 is a fixed-length opaque (no length
/// prefix), and the status is not a standard NFS3 discriminant.
#[derive(Debug)]
pub struct FhStatus {
    /// Zero on success, a UNIX errno on failure.
    pub status: u32,
    /// The root file handle for the export (only valid when `status == 0`).
    pub fhandle: Nfs2FileHandle,
}

impl Unpack for FhStatus {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (status, n1) = u32::unpack(input)?;
        let (fhandle, n2) = if status == 0 {
            let (fh, n) = Nfs2FileHandle::unpack(input)?;
            (fh, n)
        } else {
            (Nfs2FileHandle([0u8; 32]), 0)
        };
        Ok((Self { status, fhandle }, n1 + n2))
    }
}

/// We only need Pack for the response type if the server needs to send it.
/// Include it for completeness and symmetry with other wire types.
impl Pack for FhStatus {
    fn packed_size(&self) -> usize {
        4 + if self.status == 0 { 32 } else { 0 }
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        let mut n = self.status.pack(out)?;
        if self.status == 0 {
            n += self.fhandle.pack(out)?;
        }
        Ok(n)
    }
}

// --- Client ---

/// Client for the MOUNT v1 service (program 100005, version 1).
///
/// Generic over the transport, so it carries no connection policy.
/// RFC 1094 Appendix A defines 6 procedures (NULL through EXPORT);
/// only the two that nfswolf needs are exposed here.
#[derive(Debug)]
pub struct MountV1Client<T> {
    transport: T,
}

impl<T: RpcTransport> MountV1Client<T> {
    /// Wrap a transport.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Borrow the underlying transport.
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// `MOUNTPROC_NULL` (proc 0) -- no-op connectivity check.
    pub async fn null(&self) -> Result<(), T::Error> {
        let _: onc_xdr::Void = self.raw_call(proc::MOUNTPROC_NULL, &onc_xdr::Void).await?;
        Ok(())
    }

    /// `MOUNTPROC_MNT` (proc 1) -- mount an export and obtain a 32-byte handle
    /// (RFC 1094 Appendix A).
    ///
    /// Unlike MOUNT v3 MNT, the v1 response has no auth flavor list -- the
    /// protocol predates flavor negotiation. A successful response is a bare
    /// `fhstatus { status=0, fhandle[32] }`.
    pub async fn mnt(&self, path: dirpath<'_>) -> Result<FhStatus, T::Error> {
        self.raw_call(proc::MOUNTPROC_MNT, &path).await
    }

    /// `MOUNTPROC_UMNT` (proc 3) -- unmount an export.
    pub async fn umnt(&self, path: dirpath<'_>) -> Result<(), T::Error> {
        let _: onc_xdr::Void = self.raw_call(proc::MOUNTPROC_UMNT, &path).await?;
        Ok(())
    }

    /// `MOUNTPROC_EXPORT` (proc 5) -- list all exports and their ACLs
    /// (RFC 1094 Appendix A).
    ///
    /// The wire format is identical to MOUNT v3 EXPORT; only the version
    /// number in the RPC header differs. MOUNT v1 EXPORT returns the NFSv2
    /// export list; MOUNT v3 EXPORT returns the NFSv3 list. They are usually
    /// the same but can differ.
    pub async fn export(&self) -> Result<exports<'static, 'static>, T::Error> {
        self.raw_call(proc::MOUNTPROC_EXPORT, &onc_xdr::Void).await
    }

    /// Issue one MOUNT procedure call against program 100005, version 1.
    async fn raw_call<C, R>(&self, proc: u32, args: &C) -> Result<R, T::Error>
    where
        C: Pack + Send + Sync,
        R: Unpack,
    {
        self.transport.call::<C, R>(PROGRAM, VERSION, proc, args).await
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::pedantic, reason = "unit test  --  lints are suppressed per project policy")]
    use super::*;
    use std::io::Cursor;

    // --- RFC 1094 Appendix A: program / version constants ---

    #[test]
    fn mount_v1_program_number() {
        // RFC 1094 Appendix A: MOUNT program number is 100005.
        assert_eq!(PROGRAM, 100_005);
    }

    #[test]
    fn mount_v1_version_is_1() {
        assert_eq!(VERSION, 1);
    }

    // --- RFC 1094 Appendix A: procedure constants ---

    #[test]
    fn mount_v1_procedure_constants() {
        // RFC 1094 Appendix A: 6 MOUNT v1 procedures, numbered 0-5.
        use proc::*;
        assert_eq!(MOUNTPROC_NULL, 0);
        assert_eq!(MOUNTPROC_MNT, 1);
        assert_eq!(MOUNTPROC_DUMP, 2);
        assert_eq!(MOUNTPROC_UMNT, 3);
        assert_eq!(MOUNTPROC_UMNTALL, 4);
        assert_eq!(MOUNTPROC_EXPORT, 5);
    }

    // --- dirpath XDR encoding ---

    #[test]
    fn dirpath_pack_unpack_round_trip() {
        // dirpath is an XDR variable-length opaque (string).
        let dp = dirpath(Opaque::borrowed(b"/export"));
        let mut buf = Vec::new();
        _ = dp.pack(&mut buf).unwrap();
        // 4 (length) + 7 ("/export") + 1 (pad to 4-byte boundary) = 12 bytes.
        assert_eq!(buf.len(), 12);
        let (decoded, n) = dirpath::unpack(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(n, 12);
        assert_eq!(decoded.0.as_ref(), b"/export");
    }

    // --- FhStatus XDR union encoding ---

    #[test]
    fn fhstatus_ok_carries_exactly_32_byte_handle() {
        // RFC 1094 Appendix A: fhstatus success = status(4) + fhandle(32) = 36 bytes.
        let fhs = FhStatus { status: 0, fhandle: Nfs2FileHandle::from_bytes(&[0x42; 32]) };
        let mut buf = Vec::new();
        let n = fhs.pack(&mut buf).unwrap();
        assert_eq!(n, 36, "status(4) + fhandle(32) = 36");
        assert_eq!(buf.len(), 36);
        // Unpack and verify round-trip.
        let (decoded, un) = FhStatus::unpack(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(un, 36);
        assert_eq!(decoded.status, 0);
        assert_eq!(decoded.fhandle, Nfs2FileHandle::from_bytes(&[0x42; 32]));
    }

    #[test]
    fn fhstatus_error_carries_only_4_bytes() {
        // RFC 1094 Appendix A: fhstatus error = status(4) only, no handle follows.
        let fhs = FhStatus { status: 13, fhandle: Nfs2FileHandle([0u8; 32]) }; // 13 = EACCES
        let mut buf = Vec::new();
        let n = fhs.pack(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf.len(), 4);
        let (decoded, un) = FhStatus::unpack(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(un, 4);
        assert_eq!(decoded.status, 13);
        assert_eq!(decoded.fhandle, Nfs2FileHandle([0u8; 32]));
    }

    // --- export_node round-trip ---

    #[test]
    fn export_node_round_trip_with_path_and_groups() {
        // RFC 1094 Appendix A: export_node = dirpath + groups linked list.
        let node = export_node { ex_dir: dirpath(Opaque::borrowed(b"/data")), ex_groups: List(vec![name(Opaque::borrowed(b"host1")), name(Opaque::borrowed(b"host2"))]) };
        let mut buf = Vec::new();
        _ = node.pack(&mut buf).unwrap();
        let (decoded, _) = export_node::unpack(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(decoded.ex_dir.0.as_ref(), b"/data");
        assert_eq!(decoded.ex_groups.0.len(), 2);
        assert_eq!(decoded.ex_groups.0[0].0.as_ref(), b"host1");
        assert_eq!(decoded.ex_groups.0[1].0.as_ref(), b"host2");
    }

    // --- Golden vector tests: hand-constructed byte sequences verified against RFC 1094 XDR ---

    /// Golden vector: FhStatus success with a real 32-byte handle (fsid_type=4
    /// from lab testing).
    ///
    /// Wire layout (RFC 1094 Appendix A):
    ///   status(4)=0 | fhandle(32) -- fixed-length opaque, no length prefix
    /// Total: 36 bytes.
    #[test]
    fn golden_fhstatus_ok() {
        #[rustfmt::skip]
        let golden: &[u8] = &[
            // status = 0 (success)
            0x00, 0x00, 0x00, 0x00,
            // fhandle: real lab handle (fsid_type=4, fixed 32 bytes, no length prefix)
            0x01, 0x00, 0x04, 0x00, 0x29, 0x00, 0x12, 0x00,
            0xE6, 0x8D, 0x6A, 0x0C, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(golden.len(), 36);

        let expected_handle = Nfs2FileHandle::from_bytes(&[0x01, 0x00, 0x04, 0x00, 0x29, 0x00, 0x12, 0x00, 0xE6, 0x8D, 0x6A, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Unpack the golden vector and verify each field.
        let (decoded, consumed) = FhStatus::unpack(&mut Cursor::new(golden)).expect("unpack golden FhStatus ok");
        assert_eq!(consumed, 36);
        assert_eq!(decoded.status, 0, "status must be success");
        assert_eq!(decoded.fhandle, expected_handle, "handle bytes must match lab capture");

        // Pack the Rust struct and verify it reproduces the golden vector exactly.
        let mut packed = Vec::new();
        let n = decoded.pack(&mut packed).unwrap();
        assert_eq!(n, 36);
        assert_eq!(packed, golden, "pack must reproduce the golden vector byte-for-byte");
    }
}
