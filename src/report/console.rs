//! Coloured terminal output  --  wraps the same logic as txt.rs but adds ANSI
//! colour codes via the `colored` crate so severity is visually prominent.

use std::io::Write;

use colored::Colorize as _;

use crate::engine::analyzer::{AnalysisResult, Severity};
use crate::report::txt::sanitize_control;

/// Write a coloured security report to `out`.
///
/// Colour is applied per-severity so operators can skim findings quickly.
pub fn render(results: &[AnalysisResult], out: &mut dyn Write) -> anyhow::Result<()> {
    for result in results {
        let header = format!("Host: {} ({})", sanitize_control(&result.host), result.timestamp);
        writeln!(out, "{}", header.bold())?;
        if let Some(os) = &result.os_guess {
            writeln!(out, "  OS: {}", sanitize_control(os))?;
        }
        writeln!(out, "  NFS versions: {}", result.nfs_versions.join(", "))?;
        writeln!(out)?;

        if result.findings.is_empty() {
            writeln!(out, "  {}", "No findings.".green())?;
        } else {
            for finding in &result.findings {
                let badge = coloured_severity(finding.severity);
                writeln!(out, "  [{badge}] {}  --  {}", finding.id, sanitize_control(&finding.title).bold())?;
                if let Some(export) = &finding.export {
                    writeln!(out, "    Export:      {}", sanitize_control(export))?;
                }
                writeln!(out, "    Description: {}", sanitize_control(&finding.description))?;
                writeln!(out, "    Evidence:    {}", sanitize_control(&finding.evidence))?;
                writeln!(out, "    Remediation: {}", sanitize_control(&finding.remediation).yellow())?;
                writeln!(out)?;
            }
        }
        writeln!(out, "{}", "-".repeat(60))?;
    }
    Ok(())
}

/// Return a coloured severity badge string for terminal output.
fn coloured_severity(sev: Severity) -> colored::ColoredString {
    match sev {
        Severity::Critical => "CRITICAL".red().bold(),
        Severity::High => "HIGH".red(),
        Severity::Medium => "MEDIUM".yellow(),
        Severity::Low => "LOW".cyan(),
        Severity::Info => "INFO".white(),
    }
}
