//! Parallel NFS network scanner.
//!
//! Discovers NFS services across network ranges using async I/O.
//! Architecture: tokio::spawn fan-out with Semaphore-based concurrency limit.
//! Per-host: TCP probe -> portmapper DUMP -> mount export list -> mount each export.

// Toolkit API  --  not all items are used in currently-implemented phases.
use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use ipnet::IpNet;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::engine::file_handle::FileHandleAnalyzer;
use crate::proto::mount::NfsMountClient;
use crate::proto::nfs3::types::FileHandle;
use crate::proto::nfs4::compound::probe_nfs4;
use crate::proto::portmap::PortmapClient;
use crate::proto::udp::call_rpc_udp;
use crate::util::stealth::StealthConfig;

/// Scan result for a single host.
#[derive(Debug, Clone)]
pub struct HostResult {
    /// Remote address (IP + portmapper port).
    pub addr: SocketAddr,
    /// True if TCP connect to port 2049 succeeded.
    pub nfs_port_open: bool,
    /// True if TCP connect to port 111 (portmapper) succeeded.
    pub portmap_open: bool,
    /// NFS versions registered in the portmapper (e.g., `[2, 3, 4]`).
    pub nfs_versions: Vec<u32>,
    /// Discovered exports.
    pub exports: Vec<ExportInfo>,
    /// OS/filesystem fingerprint from the first mountable export handle.
    pub os_guess: Option<String>,
    /// Connected clients from MNTPROC_DUMP.
    pub connected_clients: Vec<String>,
    /// True if the server responded to an NFSv4 COMPOUND (PUTROOTFH) probe.
    ///
    /// This is a live confirmation distinct from `nfs_versions.contains(&4)`:
    /// it catches NFSv4-only servers where portmapper is filtered but port 2049 is open.
    pub nfs4_reachable: bool,
}

/// Information about a single NFS export.
#[derive(Debug, Clone)]
pub struct ExportInfo {
    /// Export path on the server.
    pub path: String,
    /// Access control entries (hostnames, subnets, wildcards).
    pub allowed_hosts: Vec<String>,
    /// Auth flavors advertised by MNTPROC_MNT (0=none, 1=sys, 6=gss/krb5).
    pub auth_flavors: Vec<u32>,
    /// Root file handle bytes, if successfully mounted.
    pub file_handle: Option<Vec<u8>>,
}

/// Scanner configuration.
#[derive(Debug)]
pub struct ScanConfig {
    /// Maximum number of hosts to scan simultaneously.
    pub concurrency: usize,
    /// Timeout for each TCP connection probe.
    pub timeout: Duration,
    /// Fast mode: skip portmapper, only probe NFS port.
    pub fast_mode: bool,
    /// Enumerate RPC services via portmapper DUMP.
    pub enumerate_rpc: bool,
    /// Check portmapper UDP amplification factor.
    pub check_amplification: bool,
    /// Report NFSv2 alongside v3/v4 as a downgrade risk.
    pub check_downgrade: bool,
    /// Detect NIS (ypserv/ypbind) co-hosted with NFS.
    pub check_nis: bool,
    /// Detect portmapper firewall bypass (port 111 filtered, 2049 open).
    pub check_portmap_bypass: bool,
    /// Use UDP instead of TCP for portmapper DUMP/GETPORT queries.
    /// Needed when TCP/111 is firewalled but UDP/111 is open.
    pub transport_udp: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self { concurrency: 256, timeout: Duration::from_secs(5), fast_mode: false, enumerate_rpc: true, check_amplification: false, check_downgrade: false, check_nis: false, check_portmap_bypass: false, transport_udp: false }
    }
}

/// Parallel NFS scanner.
///
/// Spawns one tokio task per host, bounded by a `Semaphore`.
/// Each task probes ports, enumerates RPC services, and mounts exports.
#[derive(Debug)]
pub struct Scanner {
    portmap: PortmapClient,
    mount_client: NfsMountClient,
    config: ScanConfig,
    _stealth: StealthConfig,
}

impl Scanner {
    /// Create a new scanner with the given configuration.
    #[must_use]
    pub const fn new(config: ScanConfig, stealth: StealthConfig) -> Self {
        Self { portmap: PortmapClient::default_port(), mount_client: NfsMountClient::new(), config, _stealth: stealth }
    }

    /// Scan a list of IP addresses and return one `HostResult` per host.
    ///
    /// Hosts that don't respond to either port 111 or 2049 are still
    /// included with `nfs_port_open = false` so the caller can count them.
    pub async fn scan_range(&self, targets: Vec<IpAddr>) -> Vec<HostResult> {
        let sem = Arc::new(Semaphore::new(self.config.concurrency));
        let mut handles = Vec::with_capacity(targets.len());

        for ip in targets {
            let permit = Arc::clone(&sem);
            let portmap = self.portmap.clone();
            let mount = self.mount_client.clone();
            let job = ScanJob { timeout: self.config.timeout, fast: self.config.fast_mode, enumerate_rpc: self.config.enumerate_rpc, check_nis: self.config.check_nis, check_downgrade: self.config.check_downgrade, transport_udp: self.config.transport_udp };

            let handle = tokio::spawn(async move {
                let _permit = permit.acquire_owned().await;
                scan_host(ip, portmap, mount, job).await
            });
            handles.push(handle);
        }

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            if let Ok(r) = handle.await {
                results.push(r);
            }
        }
        results
    }

    /// Parse target specifications into a flat list of IP addresses.
    ///
    /// Accepted formats:
    /// - Bare IP: `192.168.1.1`
    /// - CIDR range: `192.168.0.0/24`
    /// - Hostname: `nfsserver.example.com` (DNS-resolved)
    /// - File path: `/path/to/targets.txt` (one spec per line)
    pub fn parse_targets(specs: &[String]) -> anyhow::Result<Vec<IpAddr>> {
        let mut ips = Vec::new();
        for spec in specs {
            if std::path::Path::new(spec.as_str()).exists() {
                let content = std::fs::read_to_string(spec).with_context(|| format!("read targets file {spec}"))?;
                let file_specs: Vec<String> = content.lines().map(str::to_owned).collect();
                ips.extend(Self::parse_targets(&file_specs)?);
            } else if let Ok(net) = spec.parse::<IpNet>() {
                ips.extend(net.hosts());
            } else if let Ok(ip) = spec.parse::<IpAddr>() {
                ips.push(ip);
            } else {
                // Assume hostname -- resolve via stdlib getaddrinfo (no crate needed).
                match format!("{spec}:0").to_socket_addrs() {
                    Ok(addrs) => ips.extend(addrs.map(|a| a.ip())),
                    Err(e) => tracing::warn!("DNS lookup failed for {spec}: {e}"),
                }
            }
        }
        Ok(ips)
    }
}

/// Per-host scan parameters extracted from `ScanConfig` for task spawn.
///
/// Bundles the boolean flags so `scan_host` stays within the argument-count limit.
struct ScanJob {
    timeout: Duration,
    fast: bool,
    enumerate_rpc: bool,
    check_nis: bool,
    check_downgrade: bool,
    transport_udp: bool,
}

/// Probe a single host and return its `HostResult`.
async fn scan_host(ip: IpAddr, portmap: PortmapClient, mount: NfsMountClient, job: ScanJob) -> HostResult {
    let probe_timeout = job.timeout;
    let fast = job.fast;
    let enumerate_rpc = job.enumerate_rpc;
    let check_nis = job.check_nis;
    let check_downgrade = job.check_downgrade;
    let addr = SocketAddr::new(ip, 111);
    let nfs_addr = SocketAddr::new(ip, 2049);

    let portmap_open = is_port_open(addr, probe_timeout).await;
    let nfs_port_open = is_port_open(nfs_addr, probe_timeout).await;

    if !nfs_port_open && !portmap_open {
        return HostResult { addr, nfs_port_open, portmap_open, nfs_versions: vec![], exports: vec![], os_guess: None, connected_clients: vec![], nfs4_reachable: false };
    }

    let nfs_versions = if !fast && (enumerate_rpc || check_downgrade) {
        if job.transport_udp {
            // UDP portmapper: bypass TCP/111 firewalls by querying PMAPPROC_DUMP over UDP.
            detect_nfs_versions_udp(addr, probe_timeout).await
        } else if portmap_open {
            portmap.detect_nfs_versions(addr).await.unwrap_or_default()
        } else if nfs_port_open {
            vec![3] // portmapper closed, NFS port open -- assume v3
        } else {
            vec![]
        }
    } else if nfs_port_open {
        vec![3] // fast mode or no rpc enum -- assume v3
    } else {
        vec![]
    };

    if nfs_versions.is_empty() && !nfs_port_open {
        return HostResult { addr, nfs_port_open, portmap_open, nfs_versions, exports: vec![], os_guess: None, connected_clients: vec![], nfs4_reachable: false };
    }

    // Enumerate exports
    let export_entries = mount.list_exports(addr).await.unwrap_or_default();

    let mut exports = Vec::new();
    let mut os_guess: Option<String> = None;

    for entry in export_entries {
        let mount_result = mount.mount(addr, &entry.path).await;
        let (auth_flavors, file_handle) = match mount_result {
            Ok(mr) => {
                if os_guess.is_none() {
                    let fh = FileHandle::from_bytes(&mr.handle.0);
                    os_guess = Some(format!("{:?}/{:?}", FileHandleAnalyzer::fingerprint_os(&fh), FileHandleAnalyzer::fingerprint_fs(&fh)));
                }
                (mr.auth_flavors, Some(mr.handle.0.clone()))
            },
            Err(_) => (vec![], None),
        };
        exports.push(ExportInfo { path: entry.path, allowed_hosts: entry.allowed_hosts, auth_flavors, file_handle });
    }

    // Connected clients from MNTPROC_DUMP
    let connected_clients = if fast { vec![] } else { mount.dump_clients(addr).await.unwrap_or_default().into_iter().map(|c| c.hostname).collect() };

    // NIS detection (optional)
    if check_nis
        && portmap_open
        && let Ok(nis) = portmap.detect_nis(addr).await
        && nis.ypserv_present
    {
        tracing::info!(%ip, port = ?nis.ypserv_port, "NIS ypserv detected");
    }

    // NFSv4 direct probe: confirm the server actually responds to NFSv4 COMPOUND.
    // This catches NFSv4-only servers where portmapper is filtered but port 2049 is open.
    let nfs4_reachable = if nfs_port_open { probe_nfs4(ip, probe_timeout).await } else { false };

    HostResult { addr, nfs_port_open, portmap_open, nfs_versions, exports, os_guess, connected_clients, nfs4_reachable }
}

/// Non-blocking TCP probe: returns true if the port accepts connections within timeout.
async fn is_port_open(addr: SocketAddr, probe_timeout: Duration) -> bool {
    timeout(probe_timeout, TcpStream::connect(addr)).await.is_ok_and(|r| r.is_ok())
}

/// Detect registered NFS versions via the portmapper DUMP procedure over UDP.
///
/// Used when `--transport-udp` is set and TCP/111 may be firewalled.
/// Sends PMAPPROC_DUMP (proc 4) over UDP, parses the mapping list, and
/// returns all NFS (program 100003) TCP-registered versions.
async fn detect_nfs_versions_udp(addr: SocketAddr, probe_timeout: Duration) -> Vec<u32> {
    use nfs3_types::portmap::{IPPROTO_TCP, pmaplist};
    use nfs3_types::xdr_codec::Void;

    // portmapper: program 100000, version 2, PMAPPROC_DUMP = proc 4.
    const PMAP_PROGRAM: u32 = 100_000;
    const PMAP_VERSION: u32 = 2;
    const PMAPPROC_DUMP: u32 = 4;
    const NFS_PROGRAM: u32 = 100_003;

    let Ok(list) = call_rpc_udp::<Void, pmaplist>(addr, PMAP_PROGRAM, PMAP_VERSION, PMAPPROC_DUMP, &Void, probe_timeout).await else {
        return vec![];
    };

    let mut versions: Vec<u32> = list.into_inner().into_iter().filter(|m| m.prog == NFS_PROGRAM && m.prot == IPPROTO_TCP).map(|m| m.vers).collect();
    versions.sort_unstable();
    versions.dedup();
    versions
}
