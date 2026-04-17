//! Network scanner for NFS service discovery.
//!
//! Detects NFS servers, enumerates exports, checks version support,
//! and flags amplification/downgrade issues.

use std::net::IpAddr;
use std::time::Duration;

use clap::Parser;
use colored::Colorize as _;
use tabled::builder::Builder;
use tabled::settings::Style;

use crate::cli::GlobalOpts;
use crate::engine::scanner::{HostResult, ScanConfig, Scanner};
use crate::util::stealth::StealthConfig;

/// Discover NFS servers on a network.
///
/// Accepts IPs, CIDR ranges, hostnames, or files containing one target per line.
///
/// Examples:
///   nfswolf scan 192.168.1.0/24
///   nfswolf scan 10.0.0.1 10.0.0.2 10.0.0.3
///   nfswolf scan -f hosts.txt
///   nfswolf scan 192.168.1.0/24 --check-downgrade --check-nis
#[derive(Parser)]
pub struct ScanArgs {
    /// Targets: IPs, CIDRs, hostnames. Omit if using -f.
    #[arg(required_unless_present = "targets_file")]
    pub targets: Vec<String>,

    /// REQUIRED (when no positional targets): file of targets, one per line
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    pub targets_file: Option<String>,

    /// Maximum concurrent probe connections
    #[arg(short = 'c', long, default_value = "256", value_name = "N")]
    pub concurrency: usize,

    /// Fast mode: skip portmapper and version detection, only probe port 2049
    #[arg(long)]
    pub fast: bool,

    /// Additional ports to probe (default: 111, 2049)
    #[arg(long, value_delimiter = ',', value_name = "PORT,...")]
    pub ports: Vec<u16>,

    /// Disable portmapper enumeration (portmapper/111 queries skipped)
    #[arg(long)]
    pub no_rpc_enum: bool,

    /// Check for portmapper UDP amplification (DDoS reflector risk).
    /// Measures the UDP response amplification factor for port 111.
    #[arg(long)]
    pub check_amplification: bool,

    /// Report NFSv2 enabled alongside v3/v4 (downgrade / Kerberos bypass risk)
    #[arg(long)]
    pub check_downgrade: bool,

    /// Report NIS/YP services co-hosted with NFS (credential theft risk)
    #[arg(long)]
    pub check_nis: bool,

    /// Report servers where port 111 is filtered but port 2049 is reachable
    #[arg(long)]
    pub check_portmap_bypass: bool,

    /// Save results to file (.json or .csv extension determines format)
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<String>,

    /// Only display hosts that have at least one accessible export
    #[arg(long)]
    pub accessible_only: bool,
}

impl ScanArgs {
    /// Effective ports to scan. Falls back to 111 + 2049 if none specified.
    pub fn effective_ports(&self) -> Vec<u16> {
        if self.ports.is_empty() { if self.fast { vec![2049] } else { vec![111, 2049] } } else { self.ports.clone() }
    }

    /// Merge positional targets and file-based targets into one list.
    pub fn all_target_specs(&self) -> Vec<String> {
        let mut specs = self.targets.clone();
        if let Some(ref f) = self.targets_file {
            specs.push(f.clone()); // Scanner::parse_targets handles file paths
        }
        specs
    }
}

/// Run the scan command.
pub async fn run(args: ScanArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    let start = std::time::Instant::now();
    let specs = args.all_target_specs();
    tracing::info!(count = specs.len(), "starting NFS scan");

    let targets = Scanner::parse_targets(&specs)?;
    tracing::debug!(count = targets.len(), "resolved targets");

    if targets.is_empty() {
        eprintln!("{}", crate::output::status_warn("No targets to scan"));
        return Ok(());
    }

    if !globals.quiet {
        eprintln!("{}", crate::output::status_info(&format!("Scanning {} host(s)...", targets.len())));
    }

    let config = ScanConfig {
        concurrency: args.concurrency,
        timeout: Duration::from_millis(globals.timeout),
        fast_mode: args.fast,
        enumerate_rpc: !args.no_rpc_enum && !args.fast,
        check_amplification: args.check_amplification,
        check_downgrade: args.check_downgrade,
        check_nis: args.check_nis,
        check_portmap_bypass: args.check_portmap_bypass,
        transport_udp: globals.transport_udp,
    };

    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let scanner = Scanner::new(config, stealth);
    let results = scanner.scan_range(targets).await;

    let results: Vec<HostResult> = if args.accessible_only { results.into_iter().filter(|r| !r.exports.is_empty()).collect() } else { results };

    print_results(&results);
    print_findings(&results);

    if !globals.quiet {
        let accessible = results.iter().filter(|r| !r.exports.is_empty()).count();
        eprintln!("{}", crate::output::status_info(&format!("Done in {}  --  {} host(s) up, {} with accessible exports", crate::output::elapsed(start), results.iter().filter(|r| r.nfs_port_open || r.portmap_open).count(), accessible,)));
    }

    if let Some(output) = &args.output {
        write_output(output, &results)?;
        if !globals.quiet {
            eprintln!("{}", crate::output::status_ok(&format!("Results saved -> {output}")));
        }
    }

    Ok(())
}

/// Print a table of scan results to stdout.
fn print_results(results: &[HostResult]) {
    let visible: Vec<&HostResult> = results.iter().filter(|r| r.nfs_port_open || r.portmap_open).collect();
    if visible.is_empty() {
        println!("{}", "  No NFS servers found.".dimmed());
        return;
    }

    let mut builder = Builder::default();
    builder.push_record(["Host", "NFS", "Versions", "Exports", "OS"]);

    for r in &visible {
        let nfs_status = if r.nfs_port_open { "open".green().to_string() } else { "closed".dimmed().to_string() };
        // Build version string: portmapper-reported versions + "v4+" if NFSv4 confirmed
        // but not in portmapper (indicates portmapper is filtered).
        let versions = {
            let mut vs: Vec<String> = r.nfs_versions.iter().map(|v| format!("v{v}")).collect();
            if r.nfs4_reachable && !r.nfs_versions.contains(&4) {
                vs.push("v4+".to_owned()); // v4+ = confirmed via direct probe, not portmapper
            }
            if vs.is_empty() { "?".dimmed().to_string() } else { vs.join(",") }
        };
        let export_count = if r.exports.is_empty() { "0".dimmed().to_string() } else { r.exports.len().to_string().green().to_string() };
        let os = r.os_guess.as_deref().unwrap_or("?").to_owned();
        builder.push_record([r.addr.ip().to_string(), nfs_status, versions, export_count, os]);
    }

    let table = builder.build().with(Style::rounded()).to_string();
    println!("{table}");
}

/// Print per-export security warnings to stdout (below the table).
fn print_findings(results: &[HostResult]) {
    for r in results {
        let ip = r.addr.ip();

        if r.nfs_versions.contains(&2) && r.nfs_versions.len() > 1 {
            println!("{}", crate::output::status_warn(&format!("{ip}  NFSv2 exposed alongside v3/v4  --  downgrade risk")));
        }

        // NFSv4 confirmed but not in portmapper = portmapper is filtered while NFS is open.
        // This is a portmapper bypass (F-3.3): firewall blocks port 111 but allows 2049.
        if r.nfs4_reachable && !r.nfs_versions.contains(&4) {
            println!("{}", crate::output::status_warn(&format!("{ip}  NFSv4 reachable but not in portmapper  --  portmapper may be filtered (F-3.3)")));
        }

        for export in &r.exports {
            let has_wildcard = export.allowed_hosts.iter().any(|h| h == "*" || h.starts_with("*."));
            if has_wildcard || export.allowed_hosts.is_empty() {
                println!("{}", crate::output::status_err(&format!("{ip}:{}  world-accessible (wildcard ACL)", export.path)));
            }
            let has_gss = export.auth_flavors.contains(&6);
            let auth_sys_only = !export.auth_flavors.is_empty() && !has_gss;
            if auth_sys_only {
                println!("{}", crate::output::status_warn(&format!("{ip}:{}  AUTH_SYS only  --  no Kerberos", export.path)));
            }
        }
    }
}

/// Write results to a file (JSON or CSV based on extension).
fn write_output(path: &str, results: &[HostResult]) -> anyhow::Result<()> {
    use std::fmt::Write as _;
    let ext = std::path::Path::new(path).extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    if ext == "json" {
        let json = serde_json::to_string_pretty(&results.iter().map(host_to_json).collect::<Vec<_>>())?;
        std::fs::write(path, json)?;
    } else if ext == "csv" {
        let mut csv = String::from("host,nfs_port,portmap,versions,exports\n");
        for r in results {
            let versions = r.nfs_versions.iter().map(ToString::to_string).collect::<Vec<_>>().join(";");
            let _ = writeln!(csv, "{},{},{},{},{}", r.addr.ip(), r.nfs_port_open, r.portmap_open, versions, r.exports.len());
        }
        std::fs::write(path, csv)?;
    } else {
        anyhow::bail!("unsupported output format  --  use .json or .csv extension");
    }
    tracing::info!(%path, "results written");
    Ok(())
}

/// Convert a `HostResult` to a `serde_json::Value` for JSON output.
fn host_to_json(r: &HostResult) -> serde_json::Value {
    serde_json::json!({
        "host": r.addr.ip().to_string(),
        "nfs_port_open": r.nfs_port_open,
        "portmap_open": r.portmap_open,
        "nfs_versions": r.nfs_versions,
        "nfs4_reachable": r.nfs4_reachable,
        "exports": r.exports.iter().map(|e| serde_json::json!({
            "path": e.path,
            "allowed_hosts": e.allowed_hosts,
            "auth_flavors": e.auth_flavors,
        })).collect::<Vec<_>>(),
        "os_guess": r.os_guess,
        "connected_clients": r.connected_clients,
    })
}

/// Unused  --  targets are parsed via Scanner::parse_targets.
fn _resolve_targets(specs: &[String]) -> anyhow::Result<Vec<IpAddr>> {
    Scanner::parse_targets(specs)
}
