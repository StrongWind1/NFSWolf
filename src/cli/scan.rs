//! Network scanner for NFS service discovery.
//!
//! Probes port 111 (portmapper) and port 2049 (NFS) to discover NFS services,
//! confirms versions via direct NULL/COMPOUND probes, enumerates exports via
//! the MOUNT protocol and NFSv4 READDIR, and reports connected clients.
//!
//! No file-level NFS operations (no MNT, no GETATTR, no READ) -- that is
//! `analyze` and `shell` territory.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use colored::Colorize as _;
use tabled::builder::Builder;
use tabled::settings::Style;
use tokio::sync::{Mutex, Semaphore};

use crate::cli::escape::{self, EscapeOutcome};
use crate::cli::{GlobalOpts, H_BEHAVIOR, H_OUTPUT, H_TARGET};
use crate::engine::scan_types::{HostResult, NfsPortInfo};
use crate::engine::scanner::{ScanConfig, ScanOutput, Scanner};
use crate::util::stealth::StealthConfig;

// Re-export for convenience.
#[allow(unused_imports, reason = "used in type signatures below")]
use crate::engine::scan_types;

/// Discover NFS servers on a network.
///
/// Accepts IPs, CIDR ranges, hostnames, or files containing one target per line.
/// Every scan runs the full check matrix: portmapper, version detection, export
/// enumeration, and NFSv4 pseudo-FS discovery.
///
/// Examples:
///   nfswolf scan 192.168.1.0/24
///   nfswolf scan 10.0.0.1 10.0.0.2 10.0.0.3
///   nfswolf scan -f hosts.txt
///   nfswolf scan --scan-udp 10.0.0.0/16
#[derive(Parser)]
pub struct ScanArgs {
    /// Targets: IPs, CIDRs, hostnames. Omit if using -f.
    #[arg(required_unless_present = "targets_file", help_heading = H_TARGET)]
    pub targets: Vec<String>,

    /// REQUIRED (when no positional targets): file of targets, one per line.
    /// Lines starting with # and blank lines are skipped.
    #[arg(short = 'f', long = "file", value_name = "FILE", help_heading = H_TARGET)]
    pub targets_file: Option<String>,

    /// Maximum concurrent host scans
    #[arg(short = 'c', long, default_value = "256", value_name = "N", help_heading = H_BEHAVIOR)]
    pub concurrency: usize,

    /// Probe all ports over UDP in addition to TCP.
    /// Discovers UDP-accessible NFS and mountd services.
    /// Mutually exclusive with --proxy (UDP cannot be tunneled through SOCKS5).
    #[arg(long, help_heading = H_BEHAVIOR)]
    pub scan_udp: bool,

    /// Additional NFS port(s) to probe (comma-delimited). Added to the set of
    /// portmapper-discovered NFS ports (does not replace portmapper discovery or
    /// the 2049 fallback). The global `--nfs-port` override is also added to the
    /// probe set, so both flags extend the ports scanned.
    #[arg(long, value_delimiter = ',', value_name = "PORT,...", help_heading = H_BEHAVIOR)]
    pub probe_port: Vec<u16>,

    /// After discovery, automatically attempt an export escape (subtree_check
    /// bypass) against every discovered export path. On success, prints a
    /// ready-to-run `nfswolf shell --handle` command for the escaped filesystem
    /// root. The escape probe runs as uid=0 (to tell root_squash apart from a
    /// rejected handle); honours --proxy and --delay/--jitter.
    #[arg(long, help_heading = H_BEHAVIOR)]
    pub auto_escape: bool,

    /// Write JSON results to FILE (machine-readable, UTF-8).
    /// Can be used simultaneously with --csv.
    #[arg(long, value_name = "FILE", help_heading = H_OUTPUT)]
    pub json: Option<PathBuf>,

    /// Write CSV results to FILE (one row per host, UTF-8).
    /// Can be used simultaneously with --json.
    #[arg(long, value_name = "FILE", help_heading = H_OUTPUT)]
    pub csv: Option<PathBuf>,
}

impl ScanArgs {
    /// Merge positional targets and file-based targets into one list.
    pub fn all_target_specs(&self) -> Vec<String> {
        let mut specs = self.targets.clone();
        if let Some(ref f) = self.targets_file {
            specs.push(f.clone());
        }
        specs
    }
}

/// Run the scan command.
pub async fn run(args: ScanArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    // Validate mutual exclusion: --scan-udp and --proxy cannot coexist.
    if args.scan_udp && globals.proxy.is_some() {
        anyhow::bail!("UDP probes cannot be tunneled through SOCKS5");
    }

    let start = std::time::Instant::now();
    let specs = args.all_target_specs();
    tracing::info!(count = specs.len(), "starting NFS scan");

    let targets = Scanner::parse_targets(&specs)?;
    tracing::debug!(count = targets.len(), "resolved targets");

    if targets.is_empty() {
        eprintln!("{}", crate::output::status_warn("No targets to scan"));
        return Ok(());
    }

    let show_progress = !globals.quiet;
    if show_progress {
        eprintln!("{}", crate::output::status_info(&format!("Scanning {} host(s)...", targets.len())));
    }

    // Extra ports to probe: the scan-local --probe-port list plus the global
    // --nfs-port override (so the global flag is honoured by scan rather than
    // silently ignored), on top of portmapper discovery and the 2049 fallback.
    let mut probe_ports = args.probe_port.clone();
    if let Some(p) = globals.nfs_port {
        probe_ports.push(p);
    }
    let config = ScanConfig { concurrency: args.concurrency, timeout: Duration::from_millis(globals.timeout), scan_udp: args.scan_udp, nfs_ports: probe_ports, mount_port: globals.mount_port };

    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let mut scanner = Scanner::new(config, stealth);
    if let Some(ref p) = globals.proxy {
        scanner = scanner.with_proxy(p.clone());
    }
    let output = scanner.scan_range(targets).await;
    let ScanOutput { results, total, interrupted } = output;

    // Table + per-host detail always goes to stdout (even on interrupt -- partial data).
    print_table(&results, args.scan_udp);
    print_host_details(&results);

    if let Some(ref json_path) = args.json {
        write_json(json_path, &results, interrupted)?;
        if show_progress {
            eprintln!("{}", crate::output::status_ok(&format!("JSON written -> {}", json_path.display())));
        }
    }

    if let Some(ref csv_path) = args.csv {
        write_csv(csv_path, &results, interrupted)?;
        if show_progress {
            eprintln!("{}", crate::output::status_ok(&format!("CSV written -> {}", csv_path.display())));
        }
    }

    if interrupted {
        let nfs_count = results.len();
        eprintln!("{}", crate::output::status_warn(&format!("Interrupted  --  {} of {} host(s) completed, {} with NFS", results.len(), total, nfs_count)));
        std::process::exit(130);
    }

    // Auto-escape pass: only on a complete scan (a Ctrl+C above already exited).
    if args.auto_escape {
        run_auto_escape(&results, globals, args.concurrency).await;
    }

    if show_progress {
        let nfs_count = results.len();
        eprintln!("{}", crate::output::status_info(&format!("Done in {}  --  {} host(s) scanned, {} with NFS", crate::output::elapsed(start), total, nfs_count)));
    }

    crate::cli::emit_replay(globals);
    Ok(())
}

// --- Auto-escape pass --------------------------------------------------------

/// One export's auto-escape result, tagged with the host's position in the scan
/// output so results print in stable host/export order regardless of which
/// concurrent task finishes first.
struct AutoEscapeResult {
    /// Index of the host in the scan `results` slice (for stable ordering).
    idx: usize,
    /// Host the escape was attempted against (IP string).
    host: String,
    /// Export path the escape targeted.
    export: String,
    /// `Ok(outcome)` from the escape primitive, or `Err(message)` when the
    /// MOUNT/connection step failed before any handle could be probed.
    outcome: Result<EscapeOutcome, String>,
}

/// Attempt an export escape against every discovered export path and print a
/// ready-to-run `nfswolf shell --handle` command for each one that breaks out
/// to the filesystem root.
///
/// Reuses the shared `escape::find_escape` primitive so the bypass logic is
/// identical to the standalone `escape` subcommand. Escapes run with bounded
/// concurrency (mirroring the scan fan-out); results are collected and printed
/// in host/export order once every attempt completes.
async fn run_auto_escape(results: &[HostResult], globals: &GlobalOpts, concurrency: usize) {
    // Collect (host-index, host, export) targets: the union of v2/v3/v4 export
    // paths per host, deduplicated since a path can appear in more than one
    // version's list.
    let mut targets: Vec<(usize, String, String)> = Vec::new();
    for (idx, r) in results.iter().enumerate() {
        let host = r.ip.to_string();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let v3 = r.exports_v3.iter().flatten().map(|e| e.path.clone());
        let v2 = r.exports_v2.iter().flatten().map(|e| e.path.clone());
        let v4 = r.exports_v4.iter().flatten().map(|e| e.path.clone());
        for path in v3.chain(v2).chain(v4) {
            if seen.insert(path.clone()) {
                targets.push((idx, host.clone(), path));
            }
        }
    }

    if targets.is_empty() {
        eprintln!("{}", crate::output::status_warn("Auto-escape: no exports discovered to escape"));
        return;
    }

    eprintln!("{}", crate::output::status_info(&format!("Auto-escape: attempting export breakout on {} path(s)...", targets.len())));

    // Bounded-concurrency escape pass, mirroring the scan fan-out. Cap below the
    // scan concurrency since each escape is heavier (MOUNT + up to ~200 GETATTRs).
    let limit = concurrency.clamp(1, 32);
    let sem = Arc::new(Semaphore::new(limit));
    let collected = Arc::new(Mutex::new(Vec::<AutoEscapeResult>::new()));

    let mut handles = Vec::with_capacity(targets.len());
    for (idx, host, export) in targets {
        let sem = Arc::clone(&sem);
        let collected = Arc::clone(&collected);
        let g = globals.clone();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire_owned().await;
            // The NFSv3 client has no per-call timeout, so a half-open host that
            // completes the TCP handshake but never answers an RPC would hang this
            // escape task -- and the join loop waits for every task, stalling the
            // whole scan. Bound the full escape per host (scales with --timeout).
            let per_host = Duration::from_millis(g.timeout.saturating_mul(10).max(15_000));
            let outcome = match tokio::time::timeout(per_host, escape::find_escape(&host, &export, escape::DEFAULT_BTRFS_SUBVOLS, escape::DEFAULT_MAX_ROOT_SCAN, &g, false)).await {
                Ok(Ok((_client, outcome))) => Ok(outcome),
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Err(format!("timed out after {}ms", per_host.as_millis())),
            };
            collected.lock().await.push(AutoEscapeResult { idx, host, export, outcome });
        });
        handles.push(handle);
    }
    for handle in handles {
        let _ = handle.await;
    }

    // Drain and sort into stable host/export order for printing.
    let mut all = std::mem::take(&mut *collected.lock().await);
    all.sort_by(|a, b| a.idx.cmp(&b.idx).then_with(|| a.export.cmp(&b.export)));

    let mut escaped = 0usize;
    for res in &all {
        match &res.outcome {
            Ok(EscapeOutcome::Success { candidate, note }) => {
                escaped += 1;
                let hex = candidate.root_handle.to_hex();
                println!();
                println!("{}", crate::output::status_ok(&format!("{}:{} escaped  --  {:?} inode {} ({note})", res.host, res.export, candidate.fs_type, candidate.inode_number)));
                crate::output::print_handle("Root handle", &hex);
                // Carry the network globals into the rerun hint so the printed
                // command reproduces the scan's transport (proxy / fixed NFS or
                // mount port); without them the suggestion can't reach a proxied
                // or non-2049 target -- exactly the auto-escape use case.
                let proxy_flag = globals.proxy.as_ref().map(|p| format!(" --proxy {p}")).unwrap_or_default();
                let nfs_port_flag = globals.nfs_port.map(|p| format!(" --nfs-port {p}")).unwrap_or_default();
                let mount_port_flag = globals.mount_port.map(|p| format!(" --mount-port {p}")).unwrap_or_default();
                println!("    {} shell {}{proxy_flag}{nfs_port_flag}{mount_port_flag} --handle {}", "nfswolf".dimmed(), res.host, hex.cyan());
            },
            Ok(EscapeOutcome::StaleNoRoot) => {
                println!("  {}", format!("{}:{}  handle valid but root not found (raise `escape --max-root-scan`)", res.host, res.export).dimmed());
            },
            Ok(EscapeOutcome::Unsupported) => {
                println!("  {}", format!("{}:{}  not escapable (BADHANDLE / non-Linux handle)", res.host, res.export).dimmed());
            },
            Err(e) => {
                println!("  {}", format!("{}:{}  escape failed: {e}", res.host, res.export).dimmed());
            },
        }
    }

    eprintln!("{}", crate::output::status_info(&format!("Auto-escape complete: {escaped} of {} path(s) escaped", all.len())));
}

// --- Table output ------------------------------------------------------------

/// Render the summary table to stdout, hiding columns that are blank across all rows.
fn print_table(results: &[HostResult], scan_udp: bool) {
    if results.is_empty() {
        println!("{}", "  No NFS servers found.".dimmed());
        return;
    }

    // Build all rows first so we can detect blank columns.
    let headers = ["Hostname", "IP", "RPC Port 111", "NFS Port", "NFSv2", "v2 Exports", "NFSv3", "v3 Exports", "NFSv4", "v4 Exports", "Hint", "Mount Port", "Clients"];
    let mut rows: Vec<Vec<String>> = Vec::with_capacity(results.len());

    for r in results {
        rows.push(vec![
            r.hostname.as_deref().unwrap_or("").to_owned(),
            r.ip.to_string(),
            render_portmap(&r.portmap_reachability, scan_udp),
            render_nfs_ports(&r.nfs_ports),
            if r.has_v2() { "yes".to_owned() } else { "--".to_owned() },
            render_export_count(r.exports_v2.as_deref()),
            if r.has_v3() { "yes".to_owned() } else { "--".to_owned() },
            render_export_count(r.exports_v3.as_deref()),
            if r.has_v4() { "yes".to_owned() } else { "--".to_owned() },
            render_v4_export_count(r),
            render_hint(r),
            render_mount_ports(&r.mount_ports),
            render_mounts_count(r),
        ]);
    }

    // Determine which columns have at least one non-blank value.
    let col_count = headers.len();
    let visible: Vec<bool> = (0..col_count).map(|col| rows.iter().any(|row| !is_blank_cell(row.get(col).map_or("", String::as_str)))).collect();

    // Build the table with only visible columns.
    let mut builder = Builder::default();
    let filtered_headers: Vec<&str> = headers.iter().zip(visible.iter()).filter_map(|(h, &v)| if v { Some(*h) } else { None }).collect();
    builder.push_record(filtered_headers);

    for row in &rows {
        let filtered_row: Vec<&str> = row.iter().zip(visible.iter()).filter_map(|(cell, &v)| if v { Some(cell.as_str()) } else { None }).collect();
        builder.push_record(filtered_row);
    }

    let table = builder.build().with(Style::rounded()).to_string();
    println!("{table}");
}

/// A cell is "blank" if it's empty or just "--".
fn is_blank_cell(s: &str) -> bool {
    s.is_empty() || s == "--"
}

/// Render the :111 column.
fn render_portmap(reach: &crate::engine::scan_types::PortReachability, scan_udp: bool) -> String {
    use crate::engine::scan_types::PortReachability;
    if scan_udp {
        reach.to_string()
    } else {
        match reach {
            PortReachability::Tcp | PortReachability::TcpUdp => "open".to_owned(),
            _ => "--".to_owned(),
        }
    }
}

/// Render the NFS Port column.
fn render_nfs_ports(ports: &[NfsPortInfo]) -> String {
    if ports.is_empty() {
        return "--".to_owned();
    }
    // If all versions on the same port, show once.
    if let [p] = ports {
        let proto = port_proto_str(p.tcp, p.udp);
        return format!("{}/{proto}", p.port);
    }
    // Multiple ports -- show per version.
    let mut parts = Vec::new();
    for p in ports {
        if !p.any_version() {
            continue;
        }
        let proto = port_proto_str(p.tcp, p.udp);
        let mut vers = Vec::new();
        if p.v2 {
            vers.push("v2");
        }
        if p.v3 {
            vers.push("v3");
        }
        if p.v4 {
            vers.push("v4");
        }
        parts.push(format!("{}/{proto} ({})", p.port, vers.join(",")));
    }
    if parts.is_empty() { "--".to_owned() } else { parts.join(", ") }
}

const fn port_proto_str(tcp: bool, udp: bool) -> &'static str {
    match (tcp, udp) {
        (true, true) => "tcp+udp",
        (true, false) => "tcp",
        (false, true) => "udp",
        (false, false) => "?",
    }
}

/// Render the Hint column (PROG_MISMATCH version range).
///
/// Hidden (returns "--") when all versions in the hinted range are already
/// confirmed by direct probes -- the hint adds no new information in that case.
fn render_hint(r: &HostResult) -> String {
    let Some(ref hint) = r.hint else { return "--".to_owned() };
    // Check if every version in [low..=high] is already confirmed.
    let all_confirmed = (hint.low..=hint.high).all(|v| match v {
        2 => r.has_v2(),
        3 => r.has_v3(),
        4 => r.has_v4(),
        _ => false,
    });
    if all_confirmed { "--".to_owned() } else { hint.to_string() }
}

/// Render export count for v2x/v3x columns.
fn render_export_count(exports: Option<&[crate::proto::mount::ExportEntry]>) -> String {
    match exports {
        None => "--".to_owned(),
        Some(e) => e.len().to_string(),
    }
}

/// Render v4x column.
fn render_v4_export_count(r: &HostResult) -> String {
    if !r.has_v4() {
        return "--".to_owned();
    }
    match &r.exports_v4 {
        Some(entries) => format!("{}+", entries.len()),
        None => "?".to_owned(),
    }
}

/// Render mount port column.
fn render_mount_ports(ports: &[crate::engine::scan_types::MountPortInfo]) -> String {
    if ports.is_empty() {
        return "--".to_owned();
    }
    let parts: Vec<String> = ports
        .iter()
        .map(|p| {
            let proto = port_proto_str(p.tcp, p.udp);
            let vers: Vec<String> = p.versions.iter().map(|v| format!("v{v}")).collect();
            format!("{}/{proto} ({})", p.port, vers.join(","))
        })
        .collect();
    parts.join(", ")
}

/// Render mounts count.
fn render_mounts_count(r: &HostResult) -> String {
    match &r.mounts {
        None => "--".to_owned(),
        Some(m) => m.len().to_string(),
    }
}

// --- Per-host detail ---------------------------------------------------------

/// Print per-host detail below the table.
fn print_host_details(results: &[HostResult]) {
    for r in results {
        println!();
        // Header: IP (hostname) or just IP
        if let Some(ref h) = r.hostname {
            println!("{} ({h})", r.ip);
        } else {
            println!("{}", r.ip);
        }

        // Export list deduplication and display.
        print_exports(r);

        // Connected clients from MOUNT DUMP
        if let Some(ref mounts) = r.mounts
            && !mounts.is_empty()
        {
            let entries: Vec<String> = mounts.iter().map(|m| format!("{}:{}", m.hostname, m.directory)).collect();
            println!("  Clients: {}", entries.join(", "));
        }
    }
}

/// Print export lists with version-label deduplication.
fn print_exports(r: &HostResult) {
    // Collect available export lists with their version labels.
    let mut lists: Vec<(&str, ExportListKind<'_>)> = Vec::new();
    if let Some(ref v2) = r.exports_v2 {
        lists.push(("v2", ExportListKind::Mount(v2)));
    }
    if let Some(ref v3) = r.exports_v3 {
        lists.push(("v3", ExportListKind::Mount(v3)));
    }
    if let Some(ref v4) = r.exports_v4 {
        lists.push(("v4", ExportListKind::V4(v4)));
    }

    if lists.is_empty() {
        return;
    }

    // Group lists that are identical.
    let groups = group_identical_exports(&lists);
    for (labels, kind) in &groups {
        let label = labels.join(", ");
        println!("  Exports ({label}):");
        match kind {
            ExportListKind::Mount(entries) => {
                for e in *entries {
                    let acl = if e.allowed_hosts.is_empty() { "*".to_owned() } else { e.allowed_hosts.join(",") };
                    println!("    {:<40}{acl}", e.path);
                }
            },
            ExportListKind::V4(entries) => {
                for e in *entries {
                    println!("    {}", e.path);
                }
            },
        }
    }
}

#[derive(Clone)]
enum ExportListKind<'a> {
    Mount(&'a [crate::proto::mount::ExportEntry]),
    V4(&'a [crate::engine::scan_types::V4ExportEntry]),
}

/// Group export lists with identical content under combined labels.
fn group_identical_exports<'a>(lists: &[(&str, ExportListKind<'a>)]) -> Vec<(Vec<String>, ExportListKind<'a>)> {
    let mut groups: Vec<(Vec<String>, ExportListKind<'a>)> = Vec::new();

    for (label, kind) in lists {
        let mut merged = false;
        for (existing_labels, existing_kind) in &mut groups {
            if exports_equal(existing_kind, kind) {
                existing_labels.push((*label).to_owned());
                merged = true;
                break;
            }
        }
        if !merged {
            groups.push((vec![(*label).to_owned()], kind.clone()));
        }
    }
    groups
}

/// Compare two export lists for equality.
fn exports_equal(a: &ExportListKind<'_>, b: &ExportListKind<'_>) -> bool {
    match (a, b) {
        (ExportListKind::Mount(a), ExportListKind::Mount(b)) => a == b,
        (ExportListKind::V4(a), ExportListKind::V4(b)) => a == b,
        // v4 exports (path-only) can match mount exports if paths match
        (ExportListKind::Mount(m), ExportListKind::V4(v)) | (ExportListKind::V4(v), ExportListKind::Mount(m)) => m.len() == v.len() && m.iter().zip(v.iter()).all(|(me, ve)| me.path == ve.path),
    }
}

// --- JSON output -------------------------------------------------------------

/// Write JSON array of host results to a file (UTF-8).
fn write_json(path: &PathBuf, results: &[HostResult], interrupted: bool) -> anyhow::Result<()> {
    let mut wrapper = serde_json::Map::new();
    if interrupted {
        wrapper.insert("interrupted".to_owned(), serde_json::Value::Bool(true));
    }
    let json_results: Vec<serde_json::Value> = results.iter().map(host_to_json).collect();
    wrapper.insert("hosts".to_owned(), serde_json::Value::Array(json_results));
    #[allow(clippy::unwrap_used, reason = "serializing known-good structures")]
    let json = serde_json::to_string_pretty(&serde_json::Value::Object(wrapper)).unwrap();
    std::fs::write(path, json)?;
    tracing::info!(path = %path.display(), "JSON written");
    Ok(())
}

/// Convert a `HostResult` to the plan's JSON schema.
fn host_to_json(r: &HostResult) -> serde_json::Value {
    serde_json::json!({
        "ip": r.ip.to_string(),
        "hostname": r.hostname,
        "portmap": {
            "tcp": r.portmap_reachability.has_tcp(),
            "udp": matches!(r.portmap_reachability, crate::engine::scan_types::PortReachability::Udp | crate::engine::scan_types::PortReachability::TcpUdp),
        },
        "nfs_ports": r.nfs_ports.iter().map(|p| serde_json::json!({
            "port": p.port,
            "tcp": p.tcp,
            "udp": p.udp,
            "versions": {
                "v2": p.v2,
                "v3": p.v3,
                "v4": p.v4,
            }
        })).collect::<Vec<_>>(),
        "mount_ports": r.mount_ports.iter().map(|p| serde_json::json!({
            "port": p.port,
            "tcp": p.tcp,
            "udp": p.udp,
            "versions": p.versions,
        })).collect::<Vec<_>>(),
        "exports": {
            "v2": r.exports_v2.as_ref().map(|v| v.iter().map(|e| serde_json::json!({
                "path": e.path,
                "allowed": if e.allowed_hosts.is_empty() { vec!["*".to_owned()] } else { e.allowed_hosts.clone() },
            })).collect::<Vec<_>>()),
            "v3": r.exports_v3.as_ref().map(|v| v.iter().map(|e| serde_json::json!({
                "path": e.path,
                "allowed": if e.allowed_hosts.is_empty() { vec!["*".to_owned()] } else { e.allowed_hosts.clone() },
            })).collect::<Vec<_>>()),
            "v4": r.exports_v4.as_ref().map(|v| v.iter().map(|e| serde_json::json!({
                "path": e.path,
            })).collect::<Vec<_>>()),
        },
        "mounts": r.mounts.as_ref().map(|m| m.iter().map(|c| serde_json::json!({
            "hostname": c.hostname,
            "directory": c.directory,
        })).collect::<Vec<_>>()),
        "mounts_available": r.mounts.is_some(),
        "hint": r.hint.as_ref().map(ToString::to_string),
        "scan_duration_ms": u64::try_from(r.scan_duration.as_millis()).unwrap_or(u64::MAX),
    })
}

// --- CSV output --------------------------------------------------------------

/// Write CSV results to a file.
fn write_csv(path: &PathBuf, results: &[HostResult], interrupted: bool) -> anyhow::Result<()> {
    use std::fmt::Write as _;

    let mut csv = String::from("Hostname,IP,:111,NFS Port,v2,v2x,v3,v3x,v4,v4x,Hint,Mount Port,Clients,HostInfo\n");

    for r in results {
        let hostname = r.hostname.as_deref().unwrap_or("");
        let ip = r.ip.to_string();
        let portmap = if r.portmap_reachability.is_reachable() { "open" } else { "--" };
        let nfs_port = render_nfs_ports(&r.nfs_ports);
        let v2 = if r.has_v2() { "true" } else { "--" };
        let v2x = render_export_count(r.exports_v2.as_deref());
        let v3 = if r.has_v3() { "true" } else { "--" };
        let v3x = render_export_count(r.exports_v3.as_deref());
        let v4 = if r.has_v4() { "true" } else { "--" };
        let v4x = render_v4_export_count(r);
        let hint = r.hint.as_ref().map_or_else(|| "--".to_owned(), ToString::to_string);
        let mount_port = render_mount_ports(&r.mount_ports);
        let mounts = render_mounts_count(r);
        let host_info = build_host_info(r);
        // Every field is run through csv_field: the reverse-DNS hostname and the
        // HostInfo column (which folds MOUNT client names/dirs and export paths)
        // are attacker-controlled wire data, so quoting/escaping is mandatory to
        // stop column breakage and spreadsheet formula injection.
        let _ = writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            csv_field(hostname),
            csv_field(&ip),
            csv_field(portmap),
            csv_field(&nfs_port),
            csv_field(v2),
            csv_field(&v2x),
            csv_field(v3),
            csv_field(&v3x),
            csv_field(v4),
            csv_field(&v4x),
            csv_field(&hint),
            csv_field(&mount_port),
            csv_field(&mounts),
            csv_field(&host_info),
        );
    }

    if interrupted {
        csv.push_str("# INTERRUPTED -- partial results\n");
    }
    std::fs::write(path, csv)?;
    tracing::info!(path = %path.display(), "CSV written");
    Ok(())
}

/// Build the HostInfo CSV column.
fn build_host_info(r: &HostResult) -> String {
    let mut parts = Vec::new();

    // Exports (use v3 if available, else v2, formatted as path(ACL))
    let export_list = r.exports_v3.as_ref().or(r.exports_v2.as_ref());
    if let Some(exports) = export_list
        && !exports.is_empty()
    {
        let export_strs: Vec<String> = exports
            .iter()
            .map(|e| {
                let acl = if e.allowed_hosts.is_empty() { "*".to_owned() } else { e.allowed_hosts.join(",") };
                format!("{}({acl})", e.path)
            })
            .collect();
        parts.push(format!("exports:{}", export_strs.join(";")));
    }

    // Mounts
    if let Some(ref mounts) = r.mounts
        && !mounts.is_empty()
    {
        let mount_strs: Vec<String> = mounts.iter().map(|m| format!("{}:{}", m.hostname, m.directory)).collect();
        parts.push(format!("mounts:{}", mount_strs.join(";")));
    }

    parts.join(";")
}

/// Quote and escape one CSV field, mirroring `report::csv::csv_field`.
///
/// Two layers of defence, because the scan CSV folds in untrusted server data
/// (reverse-DNS hostname, MOUNT client names/directories, export paths):
///   1. Formula-injection guard. A value beginning with `=`, `+`, `-`, `@`,
///      TAB or CR is treated as a formula by Excel/LibreOffice/Sheets on open;
///      prefixing it with a single quote forces literal-text rendering.
///   2. RFC 4180 quoting. The (possibly guarded) value is always wrapped in
///      double-quotes with embedded quotes doubled, so commas, quotes and
///      newlines inside a field cannot break the row/column structure.
fn csv_field(value: &str) -> String {
    let guarded = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{value}") } else { value.to_owned() };
    let escaped = guarded.replace('"', "\"\"");
    format!("\"{escaped}\"")
}
