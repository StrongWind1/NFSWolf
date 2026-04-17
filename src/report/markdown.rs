//! Markdown report  --  GitHub-flavoured Markdown suitable for pasting into
//! issue trackers, wikis, or security assessment deliverables.

use std::io::Write;

use crate::engine::analyzer::{AnalysisResult, Severity};

/// Write a Markdown-formatted security report to `out`.
///
/// Structure: document title -> per-host section -> per-finding table row.
pub fn render(results: &[AnalysisResult], title: &str, out: &mut dyn Write) -> anyhow::Result<()> {
    writeln!(out, "# {title}")?;
    writeln!(out)?;

    for result in results {
        writeln!(out, "## Host: {}", result.host)?;
        writeln!(out)?;
        writeln!(out, "- **Timestamp:** {}", result.timestamp)?;
        if let Some(os) = &result.os_guess {
            writeln!(out, "- **OS:** {os}")?;
        }
        writeln!(out, "- **NFS versions:** {}", result.nfs_versions.join(", "))?;
        writeln!(out)?;

        if result.findings.is_empty() {
            writeln!(out, "_No findings._")?;
            writeln!(out)?;
            continue;
        }

        // Summary table
        writeln!(out, "| ID | Title | Severity | Export |")?;
        writeln!(out, "|----|-------|----------|--------|")?;
        for finding in &result.findings {
            let export = finding.export.as_deref().unwrap_or(" -- ");
            writeln!(out, "| {} | {} | {} | {} |", finding.id, md_escape(&finding.title), severity_badge(finding.severity), md_escape(export))?;
        }
        writeln!(out)?;

        // Per-finding detail sections
        for finding in &result.findings {
            writeln!(out, "### {}  --  {}", finding.id, finding.title)?;
            writeln!(out)?;
            writeln!(out, "**Severity:** {}  ", severity_badge(finding.severity))?;
            if let Some(export) = &finding.export {
                writeln!(out, "**Export:** {export}  ")?;
            }
            writeln!(out)?;
            writeln!(out, "**Description**")?;
            writeln!(out)?;
            writeln!(out, "{}", finding.description)?;
            writeln!(out)?;
            writeln!(out, "**Evidence**")?;
            writeln!(out)?;
            writeln!(out, "```")?;
            writeln!(out, "{}", finding.evidence)?;
            writeln!(out, "```")?;
            writeln!(out)?;
            writeln!(out, "**Remediation**")?;
            writeln!(out)?;
            writeln!(out, "{}", finding.remediation)?;
            writeln!(out)?;
        }
    }
    Ok(())
}

/// Map severity to a Markdown badge string (GitHub-renderable).
const fn severity_badge(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "![CRITICAL](https://img.shields.io/badge/-CRITICAL-critical)",
        Severity::High => "![HIGH](https://img.shields.io/badge/-HIGH-red)",
        Severity::Medium => "![MEDIUM](https://img.shields.io/badge/-MEDIUM-yellow)",
        Severity::Low => "![LOW](https://img.shields.io/badge/-LOW-blue)",
        Severity::Info => "![INFO](https://img.shields.io/badge/-INFO-lightgrey)",
    }
}

/// Escape pipe characters so they don't break Markdown table cells.
fn md_escape(s: &str) -> String {
    s.replace('|', "&#124;")
}
