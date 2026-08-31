//! Portmapper client  --  wraps onc_rpcbind::PortmapperClient for service enumeration.
//!
//! Exposes PMAPPROC_DUMP (all registered RPC services) and PMAPPROC_GETPORT
//! (port resolution for NFS/mountd). Also measures UDP amplification factor
//! (F-3.2) and detects NIS (F-5.3) and NetApp services.

// Toolkit API  --  not all items are used in currently-implemented phases.
use std::io::Cursor;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context as _;
use onc_rpc_client::transport::net::Connector as _;
use onc_rpc_client::transport::tokio::{TokioConnector, TokioIo};
use onc_rpcbind::{self as portmap, IPPROTO_TCP, PortmapperClient};
use onc_xdr::{Opaque, Pack, Unpack};

use crate::proto::mount::MountResult;
use crate::proto::nfs3::types::FileHandle;

/// RPC program numbers relevant to NFS infrastructure.
/// NFSv2/v3/v4 server (program 100003, RFC 1057 S9).
const PROG_NFS: u32 = 100_003;
/// NIS / ypserv (program 100004, vulnerable to map dump).
const PROG_YPSERV: u32 = 100_004;
/// NIS ypbind (program 100007).
const PROG_YPBIND: u32 = 100_007;
/// One entry returned by PMAPPROC_DUMP.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct PortmapEntry {
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
pub(crate) struct NisDetection {
    /// Whether ypserv (program 100004) is registered.
    pub ypserv_present: bool,
    /// Port ypserv is listening on, if found.
    pub ypserv_port: Option<u16>,
    /// Whether ypbind (program 100007) is registered.
    pub ypbind_present: bool,
}

/// Portmapper UDP amplification measurement (F-3.2).
#[derive(Debug, Clone)]
pub(crate) struct PortmapAmplificationResult {
    /// Size of the UDP DUMP request in bytes.
    pub request_bytes: usize,
    /// Size of the DUMP response in bytes.
    pub response_bytes: usize,
    /// Amplification ratio (response / request).
    pub factor: f64,
}

/// Portmapper client.
#[derive(Debug, Clone)]
pub(crate) struct PortmapClient {
    /// Default portmapper port (111).
    port: u16,
    /// Optional SOCKS5 proxy for all TCP connections.
    proxy: Option<String>,
}

impl PortmapClient {
    /// Create a portmapper client targeting the given port.
    #[must_use]
    pub(crate) const fn new(port: u16) -> Self {
        Self { port, proxy: None }
    }

    /// Create with the standard portmapper port (111).
    #[must_use]
    pub(crate) const fn default_port() -> Self {
        Self::new(portmap::PMAP_PORT)
    }

    /// Attach a SOCKS5 proxy to this client.
    #[must_use]
    pub(crate) fn with_proxy(mut self, proxy: String) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Open a TCP connection to `addr`, tunnelling through the proxy if configured.
    async fn connect_tcp(&self, addr: SocketAddr) -> anyhow::Result<crate::proto::conn::NfsIo> {
        if let Some(ref p) = self.proxy {
            let proxy_addr = crate::proto::conn::parse_proxy_addr(p)?;
            let stream = crate::proto::conn::socks5_connect(proxy_addr, addr).await.with_context(|| format!("SOCKS5 connect to {addr} via {p}"))?;
            Ok(TokioIo::new(stream))
        } else {
            TokioConnector.connect(addr).await.with_context(|| format!("connect to {addr}"))
        }
    }

    /// Resolve the port for `program`/`version` via PMAPPROC_GETPORT (TCP).
    pub(crate) async fn query_port(&self, addr: SocketAddr, program: u32, version: u32) -> anyhow::Result<u16> {
        let pmap_addr = SocketAddr::new(addr.ip(), self.port);
        let io = self.connect_tcp(pmap_addr).await.with_context(|| format!("connect to portmapper at {pmap_addr}"))?;
        let mut client = PortmapperClient::new(io);
        client.getport(program, version, IPPROTO_TCP).await.with_context(|| format!("GETPORT {program}/{version}"))
    }

    /// Enumerate all registered RPC services via PMAPPROC_DUMP.
    pub(crate) async fn dump(&self, addr: SocketAddr) -> anyhow::Result<Vec<PortmapEntry>> {
        let pmap_addr = SocketAddr::new(addr.ip(), self.port);
        let io = self.connect_tcp(pmap_addr).await.with_context(|| format!("connect to portmapper at {pmap_addr}"))?;
        let mut client = PortmapperClient::new(io);
        let mappings = client.dump().await.context("PMAPPROC_DUMP")?;
        Ok(mappings.into_iter().filter_map(|m| u16::try_from(m.port).ok().map(|port| PortmapEntry { program: m.prog, version: m.vers, protocol: m.prot, port })).collect())
    }

    /// Return NFS versions (2, 3, 4) registered in the portmapper.
    pub(crate) async fn detect_nfs_versions(&self, addr: SocketAddr) -> anyhow::Result<Vec<u32>> {
        let entries = self.dump(addr).await?;
        let mut versions: Vec<u32> = entries.iter().filter(|e| e.program == PROG_NFS && e.protocol == IPPROTO_TCP).map(|e| e.version).collect();
        versions.sort_unstable();
        versions.dedup();
        Ok(versions)
    }

    /// Check for NIS (ypserv / ypbind) in the portmapper dump.
    pub(crate) async fn detect_nis(&self, addr: SocketAddr) -> anyhow::Result<NisDetection> {
        let entries = self.dump(addr).await?;
        let ypserv = entries.iter().find(|e| e.program == PROG_YPSERV && e.protocol == IPPROTO_TCP);
        let ypbind_present = entries.iter().any(|e| e.program == PROG_YPBIND);
        Ok(NisDetection { ypserv_present: ypserv.is_some(), ypserv_port: ypserv.map(|e| e.port), ypbind_present })
    }

    /// Measure UDP amplification by comparing DUMP request/response sizes.
    ///
    /// This is a TCP-based approximation. True UDP measurement would require
    /// a raw UDP socket, which lives in `proto::udp` and is wired through
    /// the `--scan-udp` flag.
    pub(crate) async fn measure_amplification(&self, addr: SocketAddr) -> anyhow::Result<PortmapAmplificationResult> {
        // Estimate request size: RPC header + DUMP args = ~64 bytes
        let request_bytes: usize = 64;
        let entries = self.dump(addr).await?;
        // Each entry: 4 fields x 4 bytes + XDR overhead ~ 20 bytes
        let response_bytes = entries.len().saturating_mul(20).saturating_add(8);
        // Entry counts are always small (< 1000); u32->f64 is exact for values this size.
        let factor = f64::from(u32::try_from(response_bytes).unwrap_or(u32::MAX)) / f64::from(u32::try_from(request_bytes).unwrap_or(1u32));
        Ok(PortmapAmplificationResult { request_bytes, response_bytes, factor })
    }

    /// Enumerate all registered RPC services via PMAPPROC_DUMP over UDP.
    ///
    /// Fallback for environments where TCP/111 is firewalled but UDP/111 is open
    /// (RFC 1057 S10: portmapper MUST be available on both transports).
    pub(crate) async fn dump_udp(&self, addr: SocketAddr, probe_timeout: Duration) -> anyhow::Result<Vec<PortmapEntry>> {
        use onc_xdr::Void;

        let pmap_addr = SocketAddr::new(addr.ip(), self.port);
        let list: portmap::pmaplist = crate::proto::udp::call_rpc_udp(pmap_addr, portmap::PROGRAM, portmap::VERSION, 4, &Void, probe_timeout).await.context("PMAPPROC_DUMP over UDP")?;
        Ok(list.0.into_iter().filter_map(|m| u16::try_from(m.port).ok().map(|port| PortmapEntry { program: m.prog, version: m.vers, protocol: m.prot, port })).collect())
    }

    /// Relay a MOUNT v3 MNT request through PMAPPROC_CALLIT (RFC 1057 Appendix A, proc 5).
    ///
    /// The portmapper forwards the RPC to mountd on localhost, so mountd sees
    /// the request from 127.0.0.1. On systems where localhost passes the export
    /// ACL this bypasses IP-based restrictions. Modern rpcbind may restrict
    /// CALLIT forwarding.
    pub(crate) async fn callit_mount(&self, addr: SocketAddr, export: &str) -> anyhow::Result<MountResult> {
        let pmap_addr = SocketAddr::new(addr.ip(), self.port);
        let io = self.connect_tcp(pmap_addr).await.context("connect to portmapper for CALLIT")?;
        let mut pm = PortmapperClient::new(io);

        let mut mnt_args = Vec::new();
        let _ = Opaque::borrowed(export.as_bytes()).pack(&mut mnt_args).context("pack MNT dirpath")?;

        let result = pm.callit(100_005, 3, 1, &mnt_args).await.context("PMAPPROC_CALLIT MOUNT v3 MNT")?;
        decode_mnt3_response(result.res.as_ref()).with_context(|| format!("decode CALLIT MNT v3 response for {export}"))
    }

    /// Relay a MOUNT v1 MNT request through PMAPPROC_CALLIT.
    ///
    /// Returns a fixed 32-byte NFSv2 handle (RFC 1094 Appendix A).
    pub(crate) async fn callit_mount_v1(&self, addr: SocketAddr, export: &str) -> anyhow::Result<MountResult> {
        let pmap_addr = SocketAddr::new(addr.ip(), self.port);
        let io = self.connect_tcp(pmap_addr).await.context("connect to portmapper for CALLIT v1")?;
        let mut pm = PortmapperClient::new(io);

        let mut mnt_args = Vec::new();
        let _ = Opaque::borrowed(export.as_bytes()).pack(&mut mnt_args).context("pack MNT v1 dirpath")?;

        let result = pm.callit(100_005, 1, 1, &mnt_args).await.context("PMAPPROC_CALLIT MOUNT v1 MNT")?;
        decode_mnt1_response(result.res.as_ref()).with_context(|| format!("decode CALLIT MNT v1 response for {export}"))
    }

    /// Resolve the port for `program`/`version` via PMAPPROC_GETPORT over UDP.
    pub(crate) async fn query_port_udp(&self, addr: SocketAddr, program: u32, version: u32, probe_timeout: Duration) -> anyhow::Result<u16> {
        let pmap_addr = SocketAddr::new(addr.ip(), self.port);
        let query = portmap::mapping { prog: program, vers: version, prot: IPPROTO_TCP, port: 0 };
        let port: u32 = crate::proto::udp::call_rpc_udp(pmap_addr, portmap::PROGRAM, portmap::VERSION, 3, &query, probe_timeout).await.context("PMAPPROC_GETPORT over UDP")?;
        u16::try_from(port).with_context(|| format!("port {port} out of u16 range"))
    }
}

// --- CALLIT response decoders ---

/// Decode a MOUNT v3 MNT response from raw XDR bytes (RFC 1813 Appendix I).
///
/// Wire layout: u32 status, then if status == 0: opaque<> fhandle + u32 count + count x u32 flavors.
fn decode_mnt3_response(data: &[u8]) -> anyhow::Result<MountResult> {
    let mut cur = Cursor::new(data);
    let (status, _) = u32::unpack(&mut cur).context("read MNT3 status")?;
    anyhow::ensure!(status == 0, "MNT3 returned status {status}");

    let (fh_opaque, _) = Opaque::<'_>::unpack(&mut cur).context("read MNT3 fhandle")?;
    let handle = FileHandle::from_bytes(fh_opaque.as_ref());

    let (count, _) = u32::unpack(&mut cur).context("read auth flavor count")?;
    let mut auth_flavors = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (f, _) = u32::unpack(&mut cur).context("read auth flavor")?;
        auth_flavors.push(f);
    }
    let parsed = auth_flavors.iter().map(|&f| crate::proto::auth::AuthFlavor::from_u32(f)).collect();
    Ok(MountResult { handle, auth_flavors, _parsed_flavors: parsed })
}

/// Decode a MOUNT v1 MNT response from raw XDR bytes (RFC 1094 Appendix A).
///
/// Wire layout: u32 status, then if status == 0: 32 bytes of file handle (fixed size).
fn decode_mnt1_response(data: &[u8]) -> anyhow::Result<MountResult> {
    let mut cur = Cursor::new(data);
    let (status, _) = u32::unpack(&mut cur).context("read MNT1 status")?;
    anyhow::ensure!(status == 0, "MNT1 returned status {status}");
    let fh_bytes = data.get(4..36).context("MNT1 response too short for 32-byte handle")?;
    let handle = FileHandle::from_bytes(fh_bytes);
    Ok(MountResult { handle, auth_flavors: vec![1], _parsed_flavors: vec![crate::proto::auth::AuthFlavor::Sys] })
}
