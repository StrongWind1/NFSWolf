//! Deep security analysis of NFS servers.
//!
//! Every analysis runs the full check matrix -- there are no opt-in flags
//! for individual checks. Some of those checks are mildly intrusive (squash
//! probes write a test file, no_root_squash detection creates a directory);
//! all of them clean up after themselves.
//!
//! Output split: human-readable to stdout by default; pass the global
//! `--json` flag to emit machine-readable JSON instead. Capture that JSON
//! with shell redirection (`> results.json`) and feed it to `nfswolf
//! convert` to render HTML/Markdown/CSV/etc.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use colored::Colorize as _;

use crate::cli::{GlobalOpts, H_BEHAVIOR, H_TARGET};
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
/// vulnerabilities, and reports all findings with severity ratings. Every
/// check runs unconditionally; the only knobs are which file paths to test
/// and which UIDs/GIDs to spray across them.
///
/// Output:
///   default      ANSI-coloured human-readable summary on stdout
///   --json       machine-readable JSON on stdout (capture with `> file.json`
///                and pass to `nfswolf convert` to render HTML/MD/CSV/TXT)
///
/// Examples:
///   nfswolf analyze 192.168.1.10
///   nfswolf analyze -f hosts.txt
///   nfswolf analyze 10.0.0.1 --test-read /etc/shadow --test-read-gids 0,42
///   nfswolf analyze --json target > results.json && \
///     nfswolf convert -i results.json -f html -o report.html
#[derive(Parser)]
pub struct AnalyzeArgs {
    /// Target NFS server: IP or hostname. Omit if using -f.
    #[arg(required_unless_present = "targets_file", help_heading = H_TARGET)]
    pub target: Option<String>,

    /// REQUIRED (when no positional target): file of targets, one per line
    #[arg(short = 'f', long = "file", alias = "targets", value_name = "FILE", help_heading = H_TARGET)]
    pub targets_file: Option<String>,

    /// Test if a remote file is readable after export escape.
    /// Tries multiple credentials (root, shadow GIDs, current uid).
    /// Can be specified multiple times for different paths.
    /// Defaults to /etc/shadow when omitted.
    #[arg(long = "test-read", value_name = "PATH", help_heading = H_BEHAVIOR)]
    pub test_read_paths: Vec<String>,

    /// GIDs to try when testing file readability (comma-separated).
    /// Applied to each --test-read path. Default: 0,42,15
    /// (root, Debian shadow, SuSE shadow).
    #[arg(long = "test-read-gids", value_delimiter = ',', help_heading = H_BEHAVIOR)]
    pub test_read_gids: Vec<u32>,

    /// UIDs to try when testing file readability (comma-separated).
    /// Applied to each --test-read path. Default: 0
    #[arg(long = "test-read-uids", value_delimiter = ',', help_heading = H_BEHAVIOR)]
    pub test_read_uids: Vec<u32>,

    /// NFSv4 directory tree depth for overview
    #[arg(long, default_value = "2", help_heading = H_BEHAVIOR)]
    pub v4_depth: u32,
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

    /// Effective paths to test readability on.  Defaults to /etc/shadow when
    /// the operator did not supply any explicit `--test-read` paths.
    pub fn effective_test_paths(&self) -> Vec<String> {
        if self.test_read_paths.is_empty() { vec!["/etc/shadow".to_owned()] } else { self.test_read_paths.clone() }
    }
}

/// Run the analyze command.
pub async fn run(args: AnalyzeArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    let targets = collect_targets(&args)?;
    let mut all_results: Vec<AnalysisResult> = Vec::with_capacity(targets.len());

    for host in &targets {
        tracing::info!(%host, "analyzing NFS server");
        if !globals.quiet && !globals.json {
            eprintln!("{}", crate::output::status_info(&format!("Analyzing {host}...")));
        }
        let start = std::time::Instant::now();
        let result = run_single(host, &args, globals).await?;
        if globals.json {
            // Defer printing until every host has been analysed so the JSON
            // output is a single array.
        } else {
            print_result(&result);
            if !globals.quiet {
                eprintln!("{}", crate::output::status_info(&format!("Completed in {}  --  {} finding(s)", crate::output::elapsed(start), result.findings.len(),)));
            }
        }
        all_results.push(result);
    }

    if globals.json {
        let json = serde_json::to_string_pretty(&all_results)?;
        println!("{json}");
    }

    crate::cli::emit_replay(globals);
    Ok(())
}

/// Collect target strings from CLI arg or targets file.
///
/// `<HOST>:/path` is accepted but the export portion is ignored -- analyze
/// enumerates exports itself, so the colon syntax is a convenience for
/// users running mixed pipelines (`nfswolf shell host:/srv` followed by
/// `nfswolf analyze host:/srv`).
fn collect_targets(args: &AnalyzeArgs) -> anyhow::Result<Vec<String>> {
    if let Some(ref file) = args.targets_file {
        let content = std::fs::read_to_string(file).map_err(|e| anyhow::anyhow!("read targets file {file}: {e}"))?;
        Ok(content.lines().filter(|l| !l.is_empty()).map(strip_export).collect())
    } else {
        Ok(args.target.iter().map(|t| strip_export(t)).collect())
    }
}

/// Strip the trailing `:/...` from a target string, if present.
fn strip_export(s: &str) -> String {
    s.find(":/").map_or_else(|| s.to_owned(), |idx| s[..idx].to_owned())
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
    let config = AnalyzeConfig { host: host.to_owned(), port: 2049, test_paths: args.effective_test_paths(), test_uids: args.effective_test_uids(), test_gids: args.effective_test_gids() };
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
