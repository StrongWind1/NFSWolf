//! Parallel NFS network scanner.
//!
//! Discovers NFS services across network ranges using async I/O.
//! Architecture: JoinSet fan-out gated by a Semaphore. The permit is acquired
//! before each task spawns, so live task count (and memory) is bounded by the
//! concurrency cap rather than the target-list size. StealthConfig is honored
//! before every outbound probe (critical rule 10), not once per host.
//! Per-host probe sequence:
//!   1. TCP (+ UDP) probe port 111
//!   2. Portmapper DUMP (+ GETPORT fallback)
//!   3. NFS + mountd port set assembly and dedup
//!   4. TCP (+ UDP) reachability probes on all discovered ports
//!   5. Version probes (NULL v2/v3, COMPOUND v4) with TCP connection reuse
//!   6. Host skip logic (no version = omit)
//!   7. MOUNT v1/v3 EXPORT + DUMP queries
//!   8. NFSv4 READDIR on pseudo-root
//!   9. Assemble HostResult

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use ipnet::IpNet;
use onc_rpc_client::RpcClient;
use onc_rpc_client::RpcError;
use onc_rpc_client::transport::tokio::TokioIo;
use onc_xdr::Void;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::engine::scan_types::{HostResult, MountPortInfo, NfsPortInfo, PortReachability, TargetSpec, V4ExportEntry, VersionRange};
use crate::proto::mount::NfsMountClient;
use crate::proto::nfs4::compound::Nfs4DirectClient;
use crate::proto::nfs4::types::{ArgOp, CompoundArgs, CompoundRes};
use crate::proto::portmap::PortmapClient;
use crate::util::stealth::StealthConfig;

/// Output from `scan_range` -- results plus metadata about the scan.
#[derive(Debug)]
pub(crate) struct ScanOutput {
    /// Hosts with confirmed NFS (passed skip logic).
    pub results: Vec<HostResult>,
    /// Total number of targets submitted.
    pub total: usize,
    /// True if the scan was interrupted by Ctrl+C (SIGINT).
    pub interrupted: bool,
}

/// Scanner configuration.
#[derive(Debug)]
pub(crate) struct ScanConfig {
    /// Maximum number of hosts to scan simultaneously.
    pub concurrency: usize,
    /// Timeout for each TCP connection probe / RPC call.
    pub timeout: Duration,
    /// Probe all ports over UDP in addition to TCP (`--scan-udp`).
    pub scan_udp: bool,
    /// Additional NFS ports to probe (`--nfs-port`).
    pub nfs_ports: Vec<u16>,
    /// Override mountd port (`--mount-port`).
    pub mount_port: Option<u16>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self { concurrency: 256, timeout: Duration::from_secs(3), scan_udp: false, nfs_ports: vec![], mount_port: None }
    }
}

/// Parallel NFS scanner.
///
/// Spawns one tokio task per host, bounded by a `Semaphore`.
#[derive(Debug)]
pub(crate) struct Scanner {
    config: ScanConfig,
    stealth: StealthConfig,
    proxy: Option<String>,
}

impl Scanner {
    /// Create a new scanner with the given configuration.
    #[must_use]
    pub(crate) const fn new(config: ScanConfig, stealth: StealthConfig) -> Self {
        Self { config, stealth, proxy: None }
    }

    /// Attach a SOCKS5 proxy so ALL connections are tunnelled.
    #[must_use]
    pub(crate) fn with_proxy(mut self, proxy: String) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Scan a list of targets and return results for hosts with confirmed NFS.
    ///
    /// Hosts where no NFS version probe succeeds are omitted.
    /// On SIGINT (Ctrl+C): cancels in-flight workers, returns partial results
    /// collected so far with `interrupted = true`.
    pub(crate) async fn scan_range(&self, targets: Vec<TargetSpec>) -> ScanOutput {
        let total = targets.len();
        let sem = Arc::new(Semaphore::new(self.config.concurrency));
        let nfs_found = Arc::new(AtomicU32::new(0));

        let pb = indicatif::ProgressBar::new(u64::try_from(total).unwrap_or(u64::MAX));
        pb.set_style(indicatif::ProgressStyle::default_bar().template("[*] Scanning  {bar:40.cyan/blue}  {pos}/{len}  ({msg})  [{elapsed_precise} / ~{eta_precise}]").unwrap_or_else(|_| indicatif::ProgressStyle::default_bar()));
        pb.set_message("0 with NFS");

        // Shared result collector -- workers push as they complete.
        let results = Arc::new(tokio::sync::Mutex::new(Vec::<HostResult>::new()));

        // Drive the targets through a JoinSet whose live size is bounded by the
        // semaphore: the permit is acquired BEFORE each task is spawned, so at
        // most `concurrency` tasks (and their ScanJob clones) exist at once and
        // the spawn loop backpressures. Memory therefore scales with the
        // concurrency cap, not the target-list size -- a /8 sweep no longer
        // allocates millions of pending tasks and JoinHandles up front.
        let drive = async {
            let mut join_set: JoinSet<()> = JoinSet::new();
            for target in targets {
                // Block here until a slot frees up -- this is the backpressure.
                let Ok(permit) = Arc::clone(&sem).acquire_owned().await else { break };
                // Reap already-finished tasks so the set stays ~concurrency-sized.
                while join_set.try_join_next().is_some() {}

                let nfs_found = Arc::clone(&nfs_found);
                let results = Arc::clone(&results);
                let pb = pb.clone();
                let job = ScanJob { timeout: self.config.timeout, scan_udp: self.config.scan_udp, nfs_ports: self.config.nfs_ports.clone(), mount_port: self.config.mount_port, proxy: self.proxy.clone(), stealth: self.stealth.clone() };

                drop(join_set.spawn(async move {
                    let _permit = permit;
                    let result = scan_host(target, job).await;
                    if let Some(r) = result
                        && r.has_nfs()
                    {
                        _ = nfs_found.fetch_add(1, Ordering::Relaxed);
                        results.lock().await.push(r);
                    }
                    pb.set_message(format!("{} with NFS", nfs_found.load(Ordering::Relaxed)));
                    pb.inc(1);
                }));
            }
            // Drain the remainder; a panicked host yields JoinError, which is
            // isolated and ignored here (per-host panic isolation preserved).
            while join_set.join_next().await.is_some() {}
        };

        // Run the driver OR bail on Ctrl+C (SIGINT) -- whichever comes first.
        // On interrupt the `drive` future is dropped, which drops the JoinSet it
        // owns and aborts every still-running probe; results gathered so far are
        // already in the shared collector below.
        let interrupted = tokio::select! {
            () = drive => false,
            _ = tokio::signal::ctrl_c() => true,
        };

        pb.finish_and_clear();
        // All tasks are either complete or aborted -- safe to lock.
        let collected = std::mem::take(&mut *results.lock().await);

        ScanOutput { results: collected, total, interrupted }
    }

    /// Parse target specifications into a flat list of `TargetSpec`.
    ///
    /// Preserves hostnames and deduplicates by IP (first-seen hostname wins).
    pub(crate) fn parse_targets(specs: &[String]) -> anyhow::Result<Vec<TargetSpec>> {
        let mut targets = Vec::new();

        for spec in specs {
            // Check if it's a file path.
            let path = std::path::Path::new(spec.as_str());
            if path.is_file() && (path.extension().is_some_and(|e| e.eq_ignore_ascii_case("txt")) || !spec.contains('/')) {
                let content = std::fs::read_to_string(spec).with_context(|| format!("read targets file {spec}"))?;
                let file_specs: Vec<String> = content.lines().filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#')).map(str::to_owned).collect();
                targets.extend(Self::parse_targets(&file_specs)?);
                continue;
            }

            if let Ok(net) = spec.parse::<IpNet>() {
                for ip in net.hosts() {
                    targets.push(TargetSpec { ip, hostname: None });
                }
            } else if let Ok(ip) = spec.parse::<IpAddr>() {
                targets.push(TargetSpec { ip, hostname: None });
            } else {
                // Assume hostname.
                match format!("{spec}:0").to_socket_addrs() {
                    Ok(addrs) => {
                        for a in addrs {
                            targets.push(TargetSpec { ip: a.ip(), hostname: Some(spec.clone()) });
                        }
                    },
                    Err(e) => tracing::warn!("DNS lookup failed for {spec}: {e}"),
                }
            }
        }

        // IP deduplication: first-seen hostname wins.
        let mut seen = HashSet::new();
        targets.retain(|t| seen.insert(t.ip));
        Ok(targets)
    }
}

/// Per-host scan parameters.
struct ScanJob {
    timeout: Duration,
    scan_udp: bool,
    nfs_ports: Vec<u16>,
    mount_port: Option<u16>,
    proxy: Option<String>,
    stealth: StealthConfig,
}

/// Probe a single host. Returns `None` if no NFS version is confirmed.
#[expect(clippy::cognitive_complexity, reason = "scanner dispatch coordinates multiple protocol probes")]
async fn scan_host(target: TargetSpec, job: ScanJob) -> Option<HostResult> {
    let start = Instant::now();
    let ip = target.ip;
    let probe_timeout = job.timeout;

    // --- Stage 1: TCP/UDP probe port 111 ---
    // Honor StealthConfig before every outbound probe (critical rule 10),
    // mirroring Nfs3Client which waits before each of its 22 procedures so the
    // scan emits paced traffic rather than one burst per host. `wait()` is a
    // no-op when no delay/jitter is configured, so the non-stealth path is free.
    let portmap_addr = SocketAddr::new(ip, 111);
    job.stealth.wait().await;
    let portmap_tcp = is_port_open(portmap_addr, probe_timeout, job.proxy.as_deref()).await;
    let portmap_udp = if job.scan_udp {
        job.stealth.wait().await;
        crate::proto::udp::probe_udp_rpc(portmap_addr, 100_000, 2, probe_timeout).await
    } else {
        false
    };
    let portmap_reachability = PortReachability::from_probes(portmap_tcp, portmap_udp);

    // --- Stage 2: Portmapper DUMP + GETPORT fallback ---
    let portmap = PortmapClient::default_port();
    let portmap = if let Some(ref p) = job.proxy { portmap.with_proxy(p.clone()) } else { portmap };

    // Try TCP DUMP first; fall back to UDP DUMP if TCP is unreachable but UDP is.
    let dump_entries = if portmap_reachability.has_tcp() {
        job.stealth.wait().await;
        timeout(probe_timeout, portmap.dump(portmap_addr)).await.ok().and_then(Result::ok).unwrap_or_default()
    } else if portmap_udp {
        job.stealth.wait().await;
        portmap.dump_udp(portmap_addr, probe_timeout).await.unwrap_or_default()
    } else {
        vec![]
    };

    // Extract NFS and MOUNT entries from dump.
    let nfs_from_dump: Vec<(u32, u32, u16)> = dump_entries.iter().filter(|e| e.program == 100_003 && e.port > 0).map(|e| (e.version, e.protocol, e.port)).collect();
    let mount_from_dump: Vec<(u32, u32, u16)> = dump_entries.iter().filter(|e| e.program == 100_005 && e.port > 0).map(|e| (e.version, e.protocol, e.port)).collect();

    // If dump returned nothing and portmapper is reachable, try individual GETPORT queries.
    let portmap_reachable = portmap_reachability.has_tcp() || portmap_udp;
    let (nfs_from_getport, mount_from_getport) = if nfs_from_dump.is_empty() && portmap_reachable {
        let mut nfs_gp = Vec::new();
        let mut mount_gp = Vec::new();
        for v in [2u32, 3, 4] {
            job.stealth.wait().await;
            let result = if portmap_reachability.has_tcp() { timeout(probe_timeout, portmap.query_port(portmap_addr, 100_003, v)).await.ok().and_then(Result::ok) } else { portmap.query_port_udp(portmap_addr, 100_003, v, probe_timeout).await.ok() };
            if let Some(port) = result
                && port > 0
            {
                nfs_gp.push((v, 6u32, port));
            }
        }
        for v in [1u32, 3] {
            job.stealth.wait().await;
            let result = if portmap_reachability.has_tcp() { timeout(probe_timeout, portmap.query_port(portmap_addr, 100_005, v)).await.ok().and_then(Result::ok) } else { portmap.query_port_udp(portmap_addr, 100_005, v, probe_timeout).await.ok() };
            if let Some(port) = result
                && port > 0
            {
                mount_gp.push((v, 6u32, port));
            }
        }
        (nfs_gp, mount_gp)
    } else {
        (vec![], vec![])
    };

    // --- Stage 3: NFS + mountd port set assembly + dedup ---
    let mut nfs_port_set: HashSet<u16> = HashSet::new();
    for &(_, _, port) in nfs_from_dump.iter().chain(nfs_from_getport.iter()) {
        _ = nfs_port_set.insert(port);
    }
    for &port in &job.nfs_ports {
        _ = nfs_port_set.insert(port);
    }
    // If no NFS port from portmapper, add 2049 as fallback.
    if nfs_from_dump.is_empty() && nfs_from_getport.is_empty() {
        _ = nfs_port_set.insert(2049);
    }

    // Mountd port discovery.
    let mut mountd_ports: HashSet<u16> = HashSet::new();
    for &(_, _, port) in mount_from_dump.iter().chain(mount_from_getport.iter()) {
        _ = mountd_ports.insert(port);
    }

    // Build the MOUNT client. When TCP/111 is down but we discovered the
    // mountd port via UDP DUMP/GETPORT, pin the client to that port so
    // EXPORT and DUMP calls connect directly instead of trying GETPORT
    // through the unreachable TCP portmapper.
    let explicit_mount_port = job.mount_port.or_else(|| if portmap_reachability.has_tcp() { None } else { mountd_ports.iter().next().copied() });
    let mount_client = match explicit_mount_port {
        Some(port) => {
            let mc = NfsMountClient::with_port(port);
            if let Some(ref p) = job.proxy { mc.with_proxy(p.clone()) } else { mc }
        },
        None => {
            if let Some(ref p) = job.proxy {
                NfsMountClient::new().with_proxy(p.clone())
            } else {
                NfsMountClient::new()
            }
        },
    };

    if mountd_ports.is_empty() {
        if let Some(mp) = job.mount_port {
            _ = mountd_ports.insert(mp);
        } else {
            // Probe fallback ports 2049, 20048 with MOUNT NULL.
            for &port in &[2049u16, 20048] {
                let probe_addr = SocketAddr::new(ip, port);
                job.stealth.wait().await;
                if is_port_open(probe_addr, probe_timeout, job.proxy.as_deref()).await {
                    let mc = if let Some(ref p) = job.proxy { NfsMountClient::with_port(port).with_proxy(p.clone()) } else { NfsMountClient::with_port(port) };
                    job.stealth.wait().await;
                    if timeout(probe_timeout, mc.list_exports(SocketAddr::new(ip, 111))).await.is_ok_and(|r| r.is_ok()) {
                        _ = mountd_ports.insert(port);
                        break;
                    }
                }
            }
        }
    }

    // --- Stage 4: Reachability probes on NFS ports ---
    let mut nfs_ports_info: Vec<NfsPortInfo> = Vec::new();
    for &port in &nfs_port_set {
        let addr = SocketAddr::new(ip, port);
        job.stealth.wait().await;
        let tcp = is_port_open(addr, probe_timeout, job.proxy.as_deref()).await;
        let udp = if job.scan_udp {
            job.stealth.wait().await;
            crate::proto::udp::probe_udp_rpc(addr, 100_003, 3, probe_timeout).await
        } else {
            false
        };
        if tcp || udp {
            nfs_ports_info.push(NfsPortInfo { port, tcp, udp, v2: false, v3: false, v4: false });
        }
    }

    // --- Stage 5: Version probes ---
    let mut hint: Option<VersionRange> = None;

    for port_info in &mut nfs_ports_info {
        if !port_info.tcp {
            continue;
        }
        let addr = SocketAddr::new(ip, port_info.port);
        job.stealth.wait().await;
        let (v2, v3, v4, tcp_hint) = probe_nfs_versions_tcp(addr, probe_timeout, job.proxy.as_deref()).await;
        port_info.v2 = v2;
        port_info.v3 = v3;
        port_info.v4 = v4;
        if hint.is_none() {
            hint = tcp_hint;
        }
    }

    // UDP version probes.
    if job.scan_udp {
        for port_info in &mut nfs_ports_info {
            if !port_info.udp {
                continue;
            }
            let addr = SocketAddr::new(ip, port_info.port);
            if !port_info.v2 {
                job.stealth.wait().await;
                match onc_rpc_client::transport::udp::call_rpc_udp::<Void, Void>(addr, 100_003, 2, 0, &Void, probe_timeout).await {
                    Ok(Void) => port_info.v2 = true,
                    Err(RpcError::ProgMismatch { low, high }) if hint.is_none() => hint = Some(VersionRange { low, high }),
                    Err(_) => {},
                }
            }
            if !port_info.v3 {
                job.stealth.wait().await;
                match onc_rpc_client::transport::udp::call_rpc_udp::<Void, Void>(addr, 100_003, 3, 0, &Void, probe_timeout).await {
                    Ok(Void) => port_info.v3 = true,
                    Err(RpcError::ProgMismatch { low, high }) if hint.is_none() => hint = Some(VersionRange { low, high }),
                    Err(_) => {},
                }
            }
        }
    }

    // --- Stage 6: Host skip logic ---
    if !nfs_ports_info.iter().any(NfsPortInfo::any_version) {
        return None;
    }

    // --- Stage 7: MOUNT queries ---
    // Build MountPortInfo for output -- only include versions relevant to
    // confirmed NFS versions (v1=NFSv2, v3=NFSv3). Filter out mountd v2
    // (legacy Linux artifact, not tied to any NFS version).
    let confirmed_v2 = nfs_ports_info.iter().any(|p| p.v2);
    let confirmed_v3 = nfs_ports_info.iter().any(|p| p.v3);
    let mount_port_infos: Vec<MountPortInfo> = {
        let mut infos: Vec<MountPortInfo> = Vec::new();
        let all_mount = mount_from_dump.iter().chain(mount_from_getport.iter());
        for &(version, protocol, port) in all_mount {
            // Only include mount versions tied to confirmed NFS versions.
            // mountd v1 -> NFSv2, mountd v3 -> NFSv3. Skip mountd v2 (unused artifact).
            if version == 1 && !confirmed_v2 {
                continue;
            }
            if version == 2 {
                continue;
            }
            if version == 3 && !confirmed_v3 {
                continue;
            }
            // Only show TCP mount ports (UDP mountd isn't useful for the scanner).
            if protocol != 6 {
                continue;
            }
            if let Some(info) = infos.iter_mut().find(|i| i.port == port) {
                if !info.versions.contains(&version) {
                    info.versions.push(version);
                }
            } else {
                infos.push(MountPortInfo { port, tcp: true, udp: false, versions: vec![version] });
            }
        }
        infos
    };

    // v3 exports -- only query if NFSv3 version probe succeeded
    let has_v3 = nfs_ports_info.iter().any(|p| p.v3);
    let exports_v3 = if has_v3 && (mount_port_infos.iter().any(|m| m.versions.contains(&3) && m.tcp) || !mountd_ports.is_empty()) {
        job.stealth.wait().await;
        match timeout(probe_timeout, mount_client.list_exports(SocketAddr::new(ip, 111))).await {
            Ok(Ok(mut exports)) => {
                // Probe MNT per export to discover auth flavors (RFC 1813 Appendix III).
                let mount_addr = SocketAddr::new(ip, 111);
                for entry in &mut exports {
                    job.stealth.wait().await;
                    if let Ok(Ok(mr)) = timeout(probe_timeout, mount_client.mount(mount_addr, &entry.path)).await {
                        entry.auth_flavors = mr.auth_flavors;
                        drop(timeout(probe_timeout, mount_client.unmount(mount_addr, &entry.path)).await);
                    }
                }
                Some(exports)
            },
            _ => None,
        }
    } else {
        None
    };

    // v2 exports (via MOUNT v1) -- only query if NFSv2 version probe succeeded
    let has_v2 = nfs_ports_info.iter().any(|p| p.v2);
    let exports_v2 = if has_v2 && mount_port_infos.iter().any(|m| m.versions.contains(&1)) {
        job.stealth.wait().await;
        match timeout(probe_timeout, mount_client.list_exports_v1(SocketAddr::new(ip, 111))).await {
            Ok(Ok(e)) => Some(e),
            _ => None,
        }
    } else {
        None
    };

    // MOUNT DUMP
    let mounts = if !mountd_ports.is_empty() || mount_port_infos.iter().any(|m| m.tcp) {
        job.stealth.wait().await;
        match timeout(probe_timeout, mount_client.dump_clients(SocketAddr::new(ip, 111))).await {
            Ok(Ok(m)) => Some(m),
            _ => None,
        }
    } else {
        None
    };

    // --- Stage 7b: RDMA presence detection ---
    // Query rpcbind v3 GETADDR for NFS (100003) on "rdma" and "rdma6" netids
    // (RFC 1833 sec. 2.1). Also probe TCP port 20049 (conventional NFS/RDMA port).
    // RDMA bypasses the kernel TCP/IP stack and may evade host firewalls.
    let rdma_detected = detect_rdma(ip, probe_timeout, portmap_reachable && portmap_reachability.has_tcp(), &job).await;

    // --- Stage 8: NFSv4 READDIR ---
    let has_v4 = nfs_ports_info.iter().any(|p| p.v4);
    let exports_v4 = if has_v4 {
        let v4_port = nfs_ports_info.iter().find(|p| p.v4).map_or(2049, |p| p.port);
        let v4_addr = SocketAddr::new(ip, v4_port);
        job.stealth.wait().await;
        match timeout(probe_timeout, readdir_v4_pseudo_root(v4_addr, job.proxy.as_deref())).await {
            Ok(Ok(entries)) => Some(entries),
            _ => None,
        }
    } else {
        None
    };

    // --- Stage 9: Assembly ---
    // No trailing stealth delay here: pacing is applied before each outbound
    // probe above, so the per-host burst is already spread across the scan.
    Some(HostResult { ip, hostname: target.hostname, portmap_reachability, nfs_ports: nfs_ports_info, mount_ports: mount_port_infos, rpc_services: dump_entries, exports_v2, exports_v3, exports_v4, mounts, hint, rdma_detected, scan_duration: start.elapsed() })
}

/// Non-blocking TCP probe: returns true if the port accepts connections within timeout.
async fn is_port_open(addr: SocketAddr, probe_timeout: Duration, proxy: Option<&str>) -> bool {
    if let Some(p) = proxy {
        let Ok(proxy_addr) = crate::proto::conn::parse_proxy_addr(p) else { return false };
        timeout(probe_timeout, crate::proto::conn::socks5_connect(proxy_addr, addr)).await.is_ok_and(|r| r.is_ok())
    } else {
        timeout(probe_timeout, TcpStream::connect(addr)).await.is_ok_and(|r| r.is_ok())
    }
}

/// Probe all three NFS versions on a single TCP connection to `addr`.
///
/// Sends NULL v2, NULL v3, and COMPOUND(PUTROOTFH) for v4 sequentially over one
/// TCP connection so only one connect is needed.  Returns `(v2, v3, v4, hint)`.
/// The hint is the first PROG_MISMATCH version range seen, if any.
async fn probe_nfs_versions_tcp(addr: SocketAddr, probe_timeout: Duration, proxy: Option<&str>) -> (bool, bool, bool, Option<VersionRange>) {
    let connect_result = if let Some(p) = proxy {
        let Ok(proxy_addr) = crate::proto::conn::parse_proxy_addr(p) else {
            return (false, false, false, None);
        };
        timeout(probe_timeout, crate::proto::conn::socks5_connect(proxy_addr, addr)).await
    } else {
        timeout(probe_timeout, TcpStream::connect(addr)).await
    };

    let stream = match connect_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::debug!("connect to {addr}: {e}");
            return (false, false, false, None);
        },
        Err(_) => {
            tracing::debug!("connect to {addr}: timeout");
            return (false, false, false, None);
        },
    };

    let mut client = RpcClient::new(TokioIo::new(stream));
    let mut hint: Option<VersionRange> = None;

    // Classifies an RPC result as accepted / PROG_MISMATCH / other failure.
    // On connection-fatal errors, returns `Err(())` to signal that subsequent
    // probes on this socket should be skipped.
    let classify = |result: Result<Void, RpcError>, hint: &mut Option<VersionRange>| -> Result<bool, ()> {
        match result {
            Ok(Void) => Ok(true),
            Err(RpcError::ProgMismatch { low, high }) => {
                if hint.is_none() {
                    *hint = Some(VersionRange { low, high });
                }
                Ok(false)
            },
            Err(ref e) if e.is_connection_reusable() => Ok(false),
            Err(_) => Err(()),
        }
    };

    // NULL v2: program 100003, version 2, proc 0
    let Ok(v2) = classify(client.call::<Void, Void>(100_003, 2, 0, &Void).await, &mut hint) else {
        return (false, false, false, hint);
    };

    // NULL v3: program 100003, version 3, proc 0
    let Ok(v3) = classify(client.call::<Void, Void>(100_003, 3, 0, &Void).await, &mut hint) else {
        return (v2, false, false, hint);
    };

    // COMPOUND v4: program 100003, version 4, proc 1.
    // NotFullyParsed means v4 is supported but the reply had trailing bytes
    // we couldn't decode -- still a positive v4 confirmation.
    let v4_args = CompoundArgs { tag: String::new(), minorversion: 0, ops: vec![ArgOp::Putrootfh] };
    let v4 = match client.call::<CompoundArgs, CompoundRes>(100_003, 4, 1, &v4_args).await {
        Ok(_) | Err(RpcError::NotFullyParsed { .. }) => true,
        Err(RpcError::ProgMismatch { low, high }) => {
            if hint.is_none() {
                hint = Some(VersionRange { low, high });
            }
            false
        },
        Err(_) => false,
    };

    (v2, v3, v4, hint)
}

/// Enumerate top-level NFSv4 pseudo-FS entries via COMPOUND([PUTROOTFH, READDIR]).
///
/// Tries AUTH_SYS (uid=0) first since most servers require it for the pseudo-root.
/// Falls back to AUTH_NONE if AUTH_SYS fails.
async fn readdir_v4_pseudo_root(addr: SocketAddr, proxy: Option<&str>) -> anyhow::Result<Vec<V4ExportEntry>> {
    // AUTH_SYS with uid=0 (most servers require at least AUTH_SYS for READDIR)
    let result = Nfs4DirectClient::connect_with_auth_proxy(addr, 0, 0, "localhost", proxy).await;
    let mut client = match result {
        Ok(c) => c,
        Err(_) => Nfs4DirectClient::connect_proxy(addr, proxy).await?,
    };
    let root_fh = client.get_root_fh().await?;
    let entries = client.list_dir(&root_fh).await?;
    Ok(entries.into_iter().map(|name| V4ExportEntry { path: name }).collect())
}

/// Detect RDMA transport availability for NFS.
///
/// Two independent signals:
/// 1. rpcbind v3 GETADDR query for NFS (100003) with "rdma" or "rdma6" netid
///    (RFC 1833 sec. 2.1) -- returns a non-empty universal address when NFS is
///    registered on an RDMA transport.
/// 2. TCP probe on port 20049, the conventional NFS/RDMA port.
///
/// RDMA bypasses the kernel's TCP/IP stack entirely, so NFS traffic over RDMA
/// may not be subject to iptables/nftables host firewalls.
async fn detect_rdma(ip: IpAddr, probe_timeout: Duration, rpcbind_reachable: bool, job: &ScanJob) -> bool {
    // Signal 1: rpcbind GETADDR for RDMA netids.
    if rpcbind_reachable {
        let rpcbind_addr = SocketAddr::new(ip, 111);
        for netid in ["rdma", "rdma6"] {
            job.stealth.wait().await;
            if let Ok(Ok(io)) = timeout(probe_timeout, connect_tcp_for_rpcbind(rpcbind_addr, job.proxy.as_deref())).await {
                let mut rb = onc_rpcbind::RpcbindClient::new(io);
                // Query NFS v3 on this netid; any non-empty address means RDMA is registered.
                if let Ok(Ok(ref a)) = timeout(probe_timeout, rb.getaddr(100_003, 3, netid)).await
                    && !a.is_empty()
                {
                    tracing::info!(netid, addr = %a, "RDMA transport detected via rpcbind GETADDR");
                    return true;
                }
            }
        }
    }

    // Signal 2: TCP probe on the conventional NFS/RDMA port (20049).
    let rdma_addr = SocketAddr::new(ip, 20049);
    job.stealth.wait().await;
    if is_port_open(rdma_addr, probe_timeout, job.proxy.as_deref()).await {
        tracing::info!("NFS/RDMA port 20049 open");
        return true;
    }

    false
}

/// Open a TCP connection to the rpcbind port, optionally through a proxy.
///
/// Shared helper for the RDMA detection path -- needs a fresh connection for
/// each rpcbind query because `RpcbindClient` consumes the IO.
async fn connect_tcp_for_rpcbind(addr: SocketAddr, proxy: Option<&str>) -> anyhow::Result<TokioIo<TcpStream>> {
    if let Some(p) = proxy {
        let proxy_addr = crate::proto::conn::parse_proxy_addr(p)?;
        let stream = crate::proto::conn::socks5_connect(proxy_addr, addr).await?;
        Ok(TokioIo::new(stream))
    } else {
        let stream = TcpStream::connect(addr).await?;
        Ok(TokioIo::new(stream))
    }
}
