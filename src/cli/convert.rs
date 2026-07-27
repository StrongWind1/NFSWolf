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
///   2. nfswolf convert  -i results.json --format html -o report.html
///
/// Re-running `analyze` to regenerate a different format would re-execute
/// every check (including the squash/no-root-squash probes that write to
/// the server). Use `convert` instead -- it operates entirely on the
/// captured JSON and is safe to run repeatedly.
///
/// Examples:
///   nfswolf convert -i results.json --format html -o report.html
///   nfswolf convert -i results.json --format markdown -o report.md --title "Client NFS Audit"
///   nfswolf convert -i results.json --format csv -o findings.csv
#[derive(Parser)]
pub(crate) struct ConvertArgs {
    /// JSON input file produced by `analyze --json > FILE`
    #[arg(short = 'i', long, value_name = "FILE", help_heading = H_OUTPUT)]
    pub input: String,

    /// Output format (see below for descriptions). Long-only: `-f` is the
    /// targets-file flag in `scan`/`analyze`, so it is not reused here.
    #[arg(long, value_enum, default_value = "html", value_name = "FORMAT", help_heading = H_OUTPUT)]
    pub format: ReportFormat,

    /// Output file path (omit for stdout with --format console)
    #[arg(short = 'o', long, value_name = "FILE", help_heading = H_OUTPUT)]
    pub output: Option<String>,

    /// Report title embedded in the output
    #[arg(long, default_value = "NFS Security Assessment", value_name = "TEXT", help_heading = H_OUTPUT)]
    pub title: String,
}

/// Available report output formats.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub(crate) enum ReportFormat {
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
pub(crate) fn run(args: &ConvertArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    let content = fs::read_to_string(&args.input).map_err(|e| anyhow::anyhow!("cannot read {}: {e}", args.input))?;

    // Accept both a single AnalysisResult object and an array.
    let results: Vec<AnalysisResult> = serde_json::from_str::<Vec<AnalysisResult>>(&content).or_else(|_| serde_json::from_str::<AnalysisResult>(&content).map(|r| vec![r])).map_err(|e| anyhow::anyhow!("cannot parse {}: {e}", args.input))?;

    let finding_count: usize = results.iter().map(|r| r.findings.len()).sum();

    if let Some(path) = &args.output {
        tracing::info!(input = %args.input, output = %path, "generating report");
        let file = fs::File::create(path).map_err(|e| anyhow::anyhow!("cannot create {path}: {e}"))?;
        let mut out = BufWriter::new(file);
        report::generate(&results, args.format, &args.title, &mut out)?;
        if !globals.quiet {
            eprintln!("{}", crate::output::status_ok(&format!("Report written -> {path}  ({} host(s), {finding_count} finding(s), {:?} format)", results.len(), args.format)));
        }
    } else {
        tracing::info!(input = %args.input, output = "stdout", "generating report");
        let mut out = BufWriter::new(std::io::stdout().lock());
        report::generate(&results, args.format, &args.title, &mut out)?;
    }
    crate::cli::emit_replay(globals);
    Ok(())
}
