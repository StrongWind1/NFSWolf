//! Markdown report  --  GitHub-flavoured Markdown suitable for pasting into
//! issue trackers, wikis, or security assessment deliverables.

use std::fmt::Write as _;
use std::io::Write;

use crate::engine::analyzer::{AnalysisResult, Severity};

/// Write a Markdown-formatted security report to `out`.
///
/// Structure: document title -> per-host section -> per-finding table row.
pub fn render(results: &[AnalysisResult], title: &str, out: &mut dyn Write) -> anyhow::Result<()> {
    writeln!(out, "# {title}")?;
    writeln!(out)?;

    for result in results {
        writeln!(out, "## Host: {}", md_escape_text(&result.host))?;
        writeln!(out)?;
        writeln!(out, "- **Timestamp:** {}", result.timestamp)?;
        if let Some(os) = &result.os_guess {
            writeln!(out, "- **OS:** {}", md_escape_text(os))?;
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
            writeln!(out, "| {} | {} | {} | {} |", finding.id, md_escape_text(&finding.title), severity_badge(finding.severity), md_escape_text(export))?;
        }
        writeln!(out)?;

        // Per-finding detail sections
        for finding in &result.findings {
            writeln!(out, "### {}  --  {}", finding.id, md_escape_text(&finding.title))?;
            writeln!(out)?;
            writeln!(out, "**Severity:** {}  ", severity_badge(finding.severity))?;
            if let Some(export) = &finding.export {
                writeln!(out, "**Export:** {}  ", md_escape_text(export))?;
            }
            writeln!(out)?;
            writeln!(out, "**Description**")?;
            writeln!(out)?;
            writeln!(out, "{}", md_escape_text(&finding.description))?;
            writeln!(out)?;
            writeln!(out, "**Evidence**")?;
            writeln!(out)?;
            // Evidence is raw server data: pick a fence longer than any backtick
            // run inside it (CommonMark closes a fence only with an equal-or-longer
            // run) so the server cannot terminate the block, and drop control bytes.
            let evidence = sanitize_fence_content(&finding.evidence);
            let fence = "`".repeat(longest_backtick_run(&evidence).max(2) + 1);
            writeln!(out, "{fence}")?;
            writeln!(out, "{evidence}")?;
            writeln!(out, "{fence}")?;
            writeln!(out)?;
            writeln!(out, "**Remediation**")?;
            writeln!(out)?;
            writeln!(out, "{}", md_escape_text(&finding.remediation))?;
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

/// Escape Markdown- and HTML-significant characters in untrusted text.
///
/// `description`, `remediation`, titles, export paths and the host string are
/// written into the report as raw Markdown, and several embed strings supplied
/// by the (hostile) NFS server. Without escaping, server data could inject
/// headings, links, tables, or raw HTML (GitHub renders inline HTML), enabling
/// content spoofing or stored XSS when the report is viewed. Every ASCII
/// punctuation char with Markdown/HTML meaning is backslash-escaped (CommonMark
/// honours `\<punct>` for any ASCII punctuation, so `<script>` renders literal),
/// `|` included so the value is also safe inside a table cell, and control bytes
/// other than newline are rendered as a printable `\xNN` token.
fn md_escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '(' | ')' | '#' | '+' | '-' | '.' | '!' | '|' | '<' | '>' | '&' => {
                out.push('\\');
                out.push(ch);
            },
            '\n' => out.push('\n'),
            c if c.is_control() => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            },
            c => out.push(c),
        }
    }
    out
}

/// Strip control bytes (keeping newlines) from text destined for a code fence.
///
/// Inside a fence Markdown/HTML is inert, so only raw escape sequences -- which a
/// terminal would interpret when the `.md` is `cat`-ed -- need neutralizing; the
/// fence length (see `longest_backtick_run`) handles breakout separately.
fn sanitize_fence_content(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch == '\n' || !ch.is_control() {
            out.push(ch);
        } else {
            let _ = write!(out, "\\x{:02x}", u32::from(ch));
        }
    }
    out
}

/// Length of the longest run of consecutive backticks in `s`.
///
/// Used to size the evidence fence: a fence one backtick longer than any
/// internal run cannot be closed early by server-supplied content.
fn longest_backtick_run(s: &str) -> usize {
    let mut max = 0;
    let mut cur = 0;
    for ch in s.chars() {
        if ch == '`' {
            cur += 1;
            max = max.max(cur);
        } else {
            cur = 0;
        }
    }
    max
}
