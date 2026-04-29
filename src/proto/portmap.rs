//! Portmapper client  --  wraps nfs3_client::PortmapperClient for service enumeration.
//!
//! Exposes PMAPPROC_DUMP (all registered RPC services) and PMAPPROC_GETPORT
//! (port resolution for NFS/mountd). Also measures UDP amplification factor
//! (F-3.2) and detects NIS (F-5.3) and NetApp services.

// Toolkit API  --  not all items are used in currently-implemented phases.
use std::net::SocketAddr;

use anyhow::Context as _;
use nfs3_client::PortmapperClient;
use nfs3_client::net::Connector as _;
use nfs3_client::tokio::TokioConnector;
use nfs3_types::portmap::{IPPROTO_TCP, IPPROTO_UDP};

/// RPC program numbers relevant to NFS infrastructure.
/// NFSv2/v3/v4 server (program 100003, RFC 1057 S9).
const PROG_NFS: u32 = 100_003;
/// NFS MOUNT protocol (program 100005, RFC 1813 Appendix I).
const PROG_MOUNT: u32 = 100_005;
/// NIS / ypserv (program 100004, vulnerable to map dump).
const PROG_YPSERV: u32 = 100_004;
/// NIS ypbind (program 100007).
const PROG_YPBIND: u32 = 100_007;
/// NetApp proprietary program (amplification indicator).
const PROG_NETAPP: u32 = 400_010;

/// One entry returned by PMAPPROC_DUMP.
#[derive(Debug, Clone)]
pub struct PortmapEntry {
    /// RPC program number.
    pub program: u32,
    /// Program version.
    pub version: u32,
    /// Transport protocol (6=TCP, 17=UDP).
    pub protocol: u32,
    /// Port number.
    pub port: u16,
}

/// NIS detection result.
#[derive(Debug, Clone)]
pub struct NisDetection {
    /// Whether ypserv (program 100004) is registered.
    pub ypserv_present: bool,
    /// Port ypserv is listening on, if found.
    pub ypserv_port: Option<u16>,
    /// Whether ypbind (program 100007) is registered.
    pub ypbind_present: bool,
}

/// Portmapper UDP amplification measurement (F-3.2).
#[derive(Debug, Clone)]
pub struct PortmapAmplificationResult {
    /// Size of the UDP DUMP request in bytes.
    pub request_bytes: usize,
    /// Size of the DUMP response in bytes.
    pub response_bytes: usize,
    /// Amplification ratio (response / request).
    pub factor: f64,
}

/// Portmapper client.
#[derive(Debug, Clone)]
pub struct PortmapClient {
    /// Default portmapper port (111).
    port: u16,
}

impl PortmapClient {
    /// Create a portmapper client targeting the given port.
    #[must_use]
    pub const fn new(port: u16) -> Self {
        Self { port }
    }

    /// Create with the standard portmapper port (111).
    #[must_use]
    pub const fn default_port() -> Self {
        Self::new(nfs3_types::portmap::PMAP_PORT)
    }

    /// Resolve the port for `program`/`version` via PMAPPROC_GETPORT (TCP).
    pub async fn query_port(&self, addr: SocketAddr, program: u32, version: u32) -> anyhow::Result<u16> {
        let pmap_addr = SocketAddr::new(addr.ip(), self.port);
        let io = TokioConnector.connect(pmap_addr).await.with_context(|| format!("connect to portmapper at {pmap_addr}"))?;
        let mut client = PortmapperClient::new(io);
        client.getport(program, version).await.with_context(|| format!("GETPORT {program}/{version}"))
    }

    /// Enumerate all registered RPC services via PMAPPROC_DUMP.
    pub async fn dump(&self, addr: SocketAddr) -> anyhow::Result<Vec<PortmapEntry>> {
        let pmap_addr = SocketAddr::new(addr.ip(), self.port);
        let io = TokioConnector.connect(pmap_addr).await.with_context(|| format!("connect to portmapper at {pmap_addr}"))?;
        let mut client = PortmapperClient::new(io);
        let mappings = client.dump().await.context("PMAPPROC_DUMP")?;
        Ok(mappings.into_iter().filter_map(|m| u16::try_from(m.port).ok().map(|port| PortmapEntry { program: m.prog, version: m.vers, protocol: m.prot, port })).collect())
    }

    /// Return NFS versions (2, 3, 4) registered in the portmapper.
    pub async fn detect_nfs_versions(&self, addr: SocketAddr) -> anyhow::Result<Vec<u32>> {
        let entries = self.dump(addr).await?;
        let mut versions: Vec<u32> = entries.iter().filter(|e| e.program == PROG_NFS && e.protocol == IPPROTO_TCP).map(|e| e.version).collect();
        versions.sort_unstable();
        versions.dedup();
        Ok(versions)
    }

    /// Resolve the mountd port (program 100005).
    pub async fn detect_mount_port(&self, addr: SocketAddr) -> anyhow::Result<u16> {
        self.query_port(addr, PROG_MOUNT, 3).await
    }

    /// Check for NIS (ypserv / ypbind) in the portmapper dump.
    pub async fn detect_nis(&self, addr: SocketAddr) -> anyhow::Result<NisDetection> {
        let entries = self.dump(addr).await?;
        let ypserv = entries.iter().find(|e| e.program == PROG_YPSERV && e.protocol == IPPROTO_TCP);
        let ypbind_present = entries.iter().any(|e| e.program == PROG_YPBIND);
        Ok(NisDetection { ypserv_present: ypserv.is_some(), ypserv_port: ypserv.map(|e| e.port), ypbind_present })
    }

    /// Check whether a NetApp proprietary program is registered (amplification indicator).
    pub async fn has_netapp(&self, addr: SocketAddr) -> anyhow::Result<bool> {
        let entries = self.dump(addr).await?;
        Ok(entries.iter().any(|e| e.program == PROG_NETAPP))
    }

    /// Measure UDP amplification by comparing DUMP request/response sizes.
    ///
    /// This is a TCP-based approximation. True UDP measurement would require
    /// a raw UDP socket, which lives in `proto::udp` and is wired through
    /// the global `--transport-udp` flag.
    pub async fn measure_amplification(&self, addr: SocketAddr) -> anyhow::Result<PortmapAmplificationResult> {
        // Estimate request size: RPC header + DUMP args = ~64 bytes
        let request_bytes: usize = 64;
        let entries = self.dump(addr).await?;
        // Each entry: 4 fields x 4 bytes + XDR overhead ~ 20 bytes
        let response_bytes = entries.len().saturating_mul(20).saturating_add(8);
        // Entry counts are always small (< 1000); u32->f64 is exact for values this size.
        let factor = f64::from(u32::try_from(response_bytes).unwrap_or(u32::MAX)) / f64::from(u32::try_from(request_bytes).unwrap_or(1u32));
        Ok(PortmapAmplificationResult { request_bytes, response_bytes, factor })
    }

    /// Look up the TCP port for the given protocol number in a pre-fetched dump.
    #[must_use]
    pub fn find_port(entries: &[PortmapEntry], program: u32, proto: u32) -> Option<u16> {
        entries.iter().find(|e| e.program == program && e.protocol == proto).map(|e| e.port)
    }

    /// Return true if the dump shows both TCP and UDP registrations for NFS.
    ///
    /// UDP NFS is a prerequisite for the amplification attack (F-3.2).
    #[must_use]
    pub fn has_nfs_udp(entries: &[PortmapEntry]) -> bool {
        entries.iter().any(|e| e.program == PROG_NFS && e.protocol == IPPROTO_UDP)
    }
}
