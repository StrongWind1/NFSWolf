//! Plain-text report  --  same structure as console output but without ANSI codes.
//!
//! Designed for piping into files, email bodies, or CI log aggregators where
//! terminal escape sequences would appear as raw bytes.

use std::io::Write;

use crate::engine::analyzer::{AnalysisResult, Severity};

/// Write a plain-text security report to `out`.
pub fn render(results: &[AnalysisResult], out: &mut dyn Write) -> anyhow::Result<()> {
    for result in results {
        writeln!(out, "==============================")?;
        writeln!(out, "Host: {}", result.host)?;
        if let Some(os) = &result.os_guess {
            writeln!(out, "OS:   {os}")?;
        }
        writeln!(out, "NFS versions: {}", result.nfs_versions.join(", "))?;
        writeln!(out, "Timestamp: {}", result.timestamp)?;
        writeln!(out)?;

        if result.findings.is_empty() {
            writeln!(out, "  No findings.")?;
        } else {
            for finding in &result.findings {
                writeln!(out, "  [{}] {}  --  {}", severity_label(finding.severity), finding.id, finding.title)?;
                if let Some(export) = &finding.export {
                    writeln!(out, "    Export:      {export}")?;
                }
                writeln!(out, "    Description: {}", finding.description)?;
                writeln!(out, "    Evidence:    {}", finding.evidence)?;
                writeln!(out, "    Remediation: {}", finding.remediation)?;
                writeln!(out)?;
            }
        }
    }
    Ok(())
}

/// Return a severity label string without colour codes.
const fn severity_label(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}
