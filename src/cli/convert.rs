//! Offline format converter for analyze results.
//!
//! `convert` reads the JSON dump produced by `nfswolf analyze --json` and
//! re-renders it as HTML, Markdown, CSV, plain text, or ANSI-coloured
//! console output. It is purely offline -- no NFS server is contacted.

use std::fs;
use std::io::BufWriter;

use clap::Parser;

use crate::cli::{GlobalOpts, H_OUTPUT};
use crate::engine::analyzer::AnalysisResult;
use crate::report;

/// Convert an `analyze` JSON dump into a presentation format.
///
/// `convert` is the offline renderer half of the analyze pipeline. It does
/// not contact any NFS server -- it reads the JSON that `analyze --json`
/// produced earlier and re-emits it as HTML/Markdown/CSV/TXT/console.
///
/// Pipeline:
///   1. nfswolf analyze --json target > results.json     # capture findings
///   2. nfswolf convert  -i results.json -f html -o report.html
///
/// Re-running `analyze` to regenerate a different format would re-execute
/// every check (including the squash/no-root-squash probes that write to
/// the server). Use `convert` instead -- it operates entirely on the
/// captured JSON and is safe to run repeatedly.
///
/// Examples:
///   nfswolf convert -i results.json -f html     -o report.html
///   nfswolf convert -i results.json -f markdown -o report.md --title "Client NFS Audit"
///   nfswolf convert -i results.json -f csv      -o findings.csv
#[derive(Parser)]
pub struct ConvertArgs {
    /// JSON input file produced by `analyze --json > FILE`
    #[arg(short = 'i', long, value_name = "FILE", help_heading = H_OUTPUT)]
    pub input: String,

    /// Output format (see below for descriptions)
    #[arg(short = 'f', long, value_enum, default_value = "html", help_heading = H_OUTPUT)]
    pub format: ReportFormat,

    /// Output file path
    #[arg(short = 'o', long, value_name = "FILE", help_heading = H_OUTPUT)]
    pub output: String,

    /// Report title embedded in the output
    #[arg(long, default_value = "NFS Security Assessment", value_name = "TEXT", help_heading = H_OUTPUT)]
    pub title: String,
}

/// Available report output formats.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ReportFormat {
    /// ANSI-coloured terminal summary (prints to stdout)
    Console,
    /// Self-contained HTML with embedded CSS and severity charts
    Html,
    /// Machine-readable JSON  --  re-export of the analyzer result
    Json,
    /// Plain text (no colours)  --  suitable for email or logging
    Txt,
    /// GitHub-flavoured Markdown  --  paste into issues, wikis, or PRs
    Markdown,
    /// CSV, one row per finding  --  import into spreadsheets or SIEM
    Csv,
}

/// Run the convert command.
///
/// Reads `args.input` as JSON, deserialises it as `Vec<AnalysisResult>`,
/// then writes the rendered report to `args.output`.
pub fn run(args: &ConvertArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    tracing::info!(input = %args.input, output = %args.output, "generating report");

    let content = fs::read_to_string(&args.input).map_err(|e| anyhow::anyhow!("cannot read {}: {e}", args.input))?;

    // Accept both a single AnalysisResult object and an array.
    let results: Vec<AnalysisResult> = serde_json::from_str::<Vec<AnalysisResult>>(&content).or_else(|_| serde_json::from_str::<AnalysisResult>(&content).map(|r| vec![r])).map_err(|e| anyhow::anyhow!("cannot parse {}: {e}", args.input))?;

    let finding_count: usize = results.iter().map(|r| r.findings.len()).sum();

    let file = fs::File::create(&args.output).map_err(|e| anyhow::anyhow!("cannot create {}: {e}", args.output))?;
    let mut out = BufWriter::new(file);
    report::generate(&results, args.format, &args.title, &mut out)?;

    if !globals.quiet {
        eprintln!("{}", crate::output::status_ok(&format!("Report written -> {}  ({} host(s), {} finding(s), {:?} format)", args.output, results.len(), finding_count, args.format,)));
    }
    crate::cli::emit_replay(globals);
    Ok(())
}
