//! Deep security analysis of NFS servers.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use colored::Colorize as _;

use crate::cli::GlobalOpts;
use crate::engine::analyzer::{AnalysisResult, AnalyzeConfig, Analyzer};
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::circuit::CircuitBreaker;
use crate::proto::conn::ReconnectStrategy;
use crate::proto::mount::NfsMountClient;
use crate::proto::nfs3::client::Nfs3Client;
use crate::proto::pool::{ConnectionPool, PoolKey};
use crate::proto::portmap::PortmapClient;
use crate::util::stealth::StealthConfig;

/// Deep security audit of one or more NFS servers.
///
/// Enumerates exports, detects authentication weaknesses, tests for escape
/// vulnerabilities, and reports all findings with severity ratings.
///
/// Examples:
///   nfswolf analyze 192.168.1.10           # quick audit
///   nfswolf analyze 192.168.1.10 -A        # all checks (recommended)
///   nfswolf analyze -f hosts.txt -A        # batch audit from file
///   nfswolf analyze 10.0.0.1 --check-no-root-squash --test-read /etc/shadow
#[derive(Parser)]
pub struct AnalyzeArgs {
    /// Target NFS server: IP or hostname. Omit if using -f.
    #[arg(required_unless_present = "targets_file")]
    pub target: Option<String>,

    /// REQUIRED (when no positional target): file of targets, one per line
    #[arg(short = 'f', long = "file", alias = "targets", value_name = "FILE")]
    pub targets_file: Option<String>,

    /// Run all vulnerability checks  --  equivalent to enabling every --check-* flag.
    /// Recommended for comprehensive assessments. Some checks write to the server.
    #[arg(short = 'A', long = "check-all", alias = "all-checks")]
    pub check_all: bool,

    /// Test for no_root_squash by creating a test directory as root.
    /// WARNING: this writes (then immediately removes) a directory on the server.
    #[arg(long)]
    pub check_no_root_squash: bool,

    /// Skip version detection (faster)
    #[arg(long)]
    pub skip_version_check: bool,

    /// Test if a remote file is readable after export escape.
    /// Tries multiple credentials (root, shadow GIDs, current uid).
    /// Can be specified multiple times for different paths.
    /// Default when --check-all: /etc/shadow
    #[arg(long = "test-read", value_name = "PATH")]
    pub test_read_paths: Vec<String>,

    /// GIDs to try when testing file readability (comma-separated).
    /// Applied to each --test-read path. Default: 0,42,15
    /// (root, Debian shadow, SuSE shadow).
    #[arg(long = "test-read-gids", value_delimiter = ',')]
    pub test_read_gids: Vec<u32>,

    /// UIDs to try when testing file readability (comma-separated).
    /// Applied to each --test-read path. Default: 0
    #[arg(long = "test-read-uids", value_delimiter = ',')]
    pub test_read_uids: Vec<u32>,

    /// NFSv4 directory tree depth for overview
    #[arg(long, default_value = "2")]
    pub v4_depth: u32,

    /// Run checks over NFSv4 even when v3 is available
    #[arg(long)]
    pub check_v4: bool,

    /// Probe squash configuration per export.
    /// Creates a test file to detect anonuid/anongid, root_squash, all_squash.
    /// WARNING: writes (and removes) a test file on the server.
    #[arg(long)]
    pub probe_squash: bool,

    /// Test whether the server accepts connections from unprivileged ports
    /// (detects the `insecure` export option).
    #[arg(long)]
    pub check_insecure_port: bool,

    /// Detect `nohide`/`crossmnt` export options by probing for sub-mount
    /// traversal beneath each export. Reveals hidden filesystems.
    #[arg(long)]
    pub check_nohide: bool,

    /// Detect NFSv2 downgrade risk (v2 enabled alongside v3/v4).
    /// If v3 requires sec=krb5 but v2 accepts AUTH_SYS, reports critical bypass.
    #[arg(long)]
    pub check_v2_downgrade: bool,

    /// Check if portmapper responds to UDP DUMP requests (DDoS amplification).
    #[arg(long)]
    pub check_portmap_amplification: bool,

    /// Detect NIS (YP) services co-hosted with NFS. If found, attempt
    /// domain name enumeration and credential map extraction.
    #[arg(long)]
    pub check_nis: bool,

    /// Do not perform any exploitative checks (safe audit mode)
    #[arg(long)]
    pub no_exploit: bool,

    /// Output results to file
    #[arg(short, long)]
    pub output: Option<String>,

    /// Also output plain text report
    #[arg(long)]
    pub txt: Option<String>,
}

impl AnalyzeArgs {
    /// Effective GIDs to use for file read tests.
    /// Falls back to well-known shadow GIDs if none specified.
    pub fn effective_test_gids(&self) -> Vec<u32> {
        if self.test_read_gids.is_empty() {
            vec![0, 42, 15] // root, Debian shadow, SuSE shadow
        } else {
            self.test_read_gids.clone()
        }
    }

    /// Effective UIDs to use for file read tests.
    pub fn effective_test_uids(&self) -> Vec<u32> {
        if self.test_read_uids.is_empty() { vec![0] } else { self.test_read_uids.clone() }
    }

    /// Effective paths to test readability on.
    /// When --check-all is set and no explicit paths given, defaults to /etc/shadow.
    pub fn effective_test_paths(&self) -> Vec<String> {
        if self.test_read_paths.is_empty() && self.check_all { vec!["/etc/shadow".to_owned()] } else { self.test_read_paths.clone() }
    }
}

/// Run the analyze command.
pub async fn run(args: AnalyzeArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    let targets = collect_targets(&args)?;

    for host in &targets {
        tracing::info!(%host, "analyzing NFS server");
        if !globals.quiet {
            eprintln!("{}", crate::output::status_info(&format!("Analyzing {host}...")));
        }
        let start = std::time::Instant::now();
        let result = run_single(host, &args, globals).await?;
        print_result(&result);
        if !globals.quiet {
            eprintln!("{}", crate::output::status_info(&format!("Completed in {}  --  {} finding(s)", crate::output::elapsed(start), result.findings.len(),)));
        }
        if let Some(out) = &args.output {
            write_json(out, &result)?;
            if !globals.quiet {
                eprintln!("{}", crate::output::status_ok(&format!("JSON saved -> {out}")));
            }
        }
        if let Some(txt) = &args.txt {
            write_txt(txt, &result)?;
            if !globals.quiet {
                eprintln!("{}", crate::output::status_ok(&format!("Text report saved -> {txt}")));
            }
        }
    }
    Ok(())
}

/// Collect target strings from CLI arg or targets file.
fn collect_targets(args: &AnalyzeArgs) -> anyhow::Result<Vec<String>> {
    if let Some(ref file) = args.targets_file {
        let content = std::fs::read_to_string(file).map_err(|e| anyhow::anyhow!("read targets file {file}: {e}"))?;
        Ok(content.lines().filter(|l| !l.is_empty()).map(str::to_owned).collect())
    } else {
        Ok(args.target.iter().cloned().collect())
    }
}

/// Analyze a single NFS host and return all findings.
async fn run_single(host: &str, args: &AnalyzeArgs, globals: &GlobalOpts) -> anyhow::Result<AnalysisResult> {
    let addr: SocketAddr = format!("{host}:111").parse().map_err(|_| anyhow::anyhow!("invalid host: {host}"))?;

    let pool = Arc::new(ConnectionPool::default_config());
    let circuit = Arc::new(CircuitBreaker::default_config());
    let cred = Credential::Sys(AuthSys::new(globals.uid, globals.gid, &globals.hostname));
    let pool_key = PoolKey { host: addr, export: "/".to_owned(), uid: globals.uid, gid: globals.gid };
    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let nfs3 = Arc::new(Nfs3Client::new(Arc::clone(&pool), pool_key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent));

    let analyzer = Analyzer::new(nfs3, NfsMountClient::new(), PortmapClient::default_port());
    let config = AnalyzeConfig {
        host: host.to_owned(),
        port: 2049,
        check_no_root_squash: args.check_no_root_squash || args.check_all,
        probe_squash: args.probe_squash && !args.no_exploit,
        check_insecure_port: args.check_insecure_port || args.check_all,
        check_nohide: args.check_nohide || args.check_all,
        check_v2_downgrade: args.check_v2_downgrade || args.check_all,
        check_portmap_amplification: args.check_portmap_amplification,
        check_nis: args.check_nis || args.check_all,
        no_exploit: args.no_exploit,
        test_paths: args.effective_test_paths(),
        test_uids: args.effective_test_uids(),
        test_gids: args.effective_test_gids(),
    };
    analyzer.analyze(&config).await
}

/// Print analysis result to stdout with full structured output.
fn print_result(r: &AnalysisResult) {
    println!();
    crate::output::banner(&format!("NFS Security Analysis: {}", r.host));
    println!();

    // Host summary line
    if let Some(os) = &r.os_guess {
        let versions = r.nfs_versions.join(", ");
        println!("  {}  {}  |  {}  {}", "OS:".dimmed(), os, "NFS:".dimmed(), versions);
    }
    println!("  {}  {}", "Timestamp:".dimmed(), r.timestamp);
    println!();

    // Exports table
    crate::output::section_header("Exports");
    let rows: Vec<crate::output::ExportRow> = r
        .exports
        .iter()
        .map(|e| {
            let clients = if e.allowed_hosts.is_empty() { "*".to_owned() } else { e.allowed_hosts.join(", ") };
            let auth = e.auth_methods.join(", ");
            let has_wildcard = e.allowed_hosts.is_empty() || e.allowed_hosts.iter().any(|h| h == "*");
            let has_gss = e.auth_methods.iter().any(|a| a.contains("GSS") || a.contains("krb"));
            let mut flags = Vec::new();
            if has_wildcard {
                flags.push("WILDCARD");
            }
            if !has_gss && !auth.is_empty() {
                flags.push("AUTH_SYS_ONLY");
            }
            crate::output::ExportRow { path: e.path.clone(), clients, auth, flags: flags.join(" "), handle_hex: e.file_handle.clone() }
        })
        .collect();
    crate::output::print_export_table(&rows);
    println!();

    // File handles (copy-paste friendly)
    let handles: Vec<_> = r.exports.iter().filter(|e| !e.file_handle.is_empty()).collect();
    if !handles.is_empty() {
        crate::output::section_header("File Handles");
        for e in &handles {
            crate::output::print_handle(&e.path, &e.file_handle);
        }
        println!();
    }

    // Findings
    crate::output::section_header("Findings");
    crate::output::print_findings_summary(&r.findings);
    println!();
    crate::output::print_findings(&r.findings);
    println!();
}

/// Write analysis result as JSON.
fn write_json(path: &str, result: &AnalysisResult) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    std::fs::write(path, json)?;
    tracing::info!(%path, "JSON report written");
    Ok(())
}

/// Write analysis result as plain text.
fn write_txt(path: &str, result: &AnalysisResult) -> anyhow::Result<()> {
    use std::fmt::Write as _;
    let mut buf = format!("NFS Security Analysis: {}\n", result.host);
    let _ = writeln!(buf, "Timestamp: {}\n", result.timestamp);
    for f in &result.findings {
        let _ = writeln!(buf, "[{:?}] {}: {}\n  {}", f.severity, f.id, f.title, f.description);
    }
    std::fs::write(path, buf)?;
    tracing::info!(%path, "text report written");
    Ok(())
}
