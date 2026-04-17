//! Report generation and export.
//!
//! Reads a JSON file produced by `analyze --output results.json`, then
//! renders it in the requested format for sharing or archiving.

use std::fs;
use std::io::BufWriter;

use clap::Parser;

use crate::cli::GlobalOpts;
use crate::engine::analyzer::AnalysisResult;
use crate::report;

/// Generate a security assessment report from analyze output.
///
/// First run `nfswolf analyze --output results.json`, then convert to any format:
///
/// Examples:
///   nfswolf export -i results.json -f html  -o report.html
///   nfswolf export -i results.json -f csv   -o findings.csv
///   nfswolf export -i results.json -f markdown -o report.md --title "Client NFS Audit"
#[derive(Parser)]
pub struct ExportArgs {
    /// JSON input file produced by `analyze --output FILE`
    #[arg(short = 'i', long, value_name = "FILE")]
    pub input: String,

    /// Output format (see below for descriptions)
    #[arg(short = 'f', long, value_enum, default_value = "html")]
    pub format: ReportFormat,

    /// Output file path
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: String,

    /// Report title embedded in the output
    #[arg(long, default_value = "NFS Security Assessment", value_name = "TEXT")]
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

/// Run the export command.
///
/// Reads `args.input` as JSON, deserialises it as `Vec<AnalysisResult>`,
/// then writes the rendered report to `args.output`.
pub fn run(args: &ExportArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
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
    Ok(())
}
