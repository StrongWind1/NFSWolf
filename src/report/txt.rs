//! Plain-text report  --  same structure as console output but without ANSI codes.
//!
//! Designed for piping into files, email bodies, or CI log aggregators where
//! terminal escape sequences would appear as raw bytes.

use std::fmt::Write as _;
use std::io::Write;

use crate::engine::analyzer::{AnalysisResult, Severity};

/// Write a plain-text security report to `out`.
pub fn render(results: &[AnalysisResult], out: &mut dyn Write) -> anyhow::Result<()> {
    for result in results {
        writeln!(out, "==============================")?;
        writeln!(out, "Host: {}", sanitize_control(&result.host))?;
        if let Some(os) = &result.os_guess {
            writeln!(out, "OS:   {}", sanitize_control(os))?;
        }
        writeln!(out, "NFS versions: {}", result.nfs_versions.join(", "))?;
        writeln!(out, "Timestamp: {}", result.timestamp)?;
        writeln!(out)?;

        if result.findings.is_empty() {
            writeln!(out, "  No findings.")?;
        } else {
            for finding in &result.findings {
                writeln!(out, "  [{}] {}  --  {}", severity_label(finding.severity), finding.id, sanitize_control(&finding.title))?;
                if let Some(export) = &finding.export {
                    writeln!(out, "    Export:      {}", sanitize_control(export))?;
                }
                writeln!(out, "    Description: {}", sanitize_control(&finding.description))?;
                writeln!(out, "    Evidence:    {}", sanitize_control(&finding.evidence))?;
                writeln!(out, "    Remediation: {}", sanitize_control(&finding.remediation))?;
                writeln!(out)?;
            }
        }
    }
    Ok(())
}

/// Neutralize ASCII/C1 control bytes in untrusted server data before printing.
///
/// Evidence previews, export paths and hostnames originate from the (hostile)
/// NFS server. Emitted raw, an embedded escape sequence (e.g. `\x1b[` ...) would
/// be interpreted by the operator's terminal or a downstream log viewer, letting
/// the server rewrite the screen, hide output, or smuggle control codes. Every
/// control codepoint (C0 `< 0x20`, DEL `0x7f`, and C1 `0x80..=0x9f`) -- newline
/// included, since these report fields are single-line -- is rendered as a
/// printable `\xNN` token instead. Shared with the coloured console renderer.
pub(super) fn sanitize_control(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let cp = u32::from(ch);
        if cp < 0x20 || cp == 0x7f || (0x80..=0x9f).contains(&cp) {
            let _ = write!(out, "\\x{cp:02x}");
        } else {
            out.push(ch);
        }
    }
    out
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
