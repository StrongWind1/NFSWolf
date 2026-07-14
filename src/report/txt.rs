//! Plain-text report  --  same structure as console output but without ANSI codes.
//!
//! Designed for piping into files, email bodies, or CI log aggregators where
//! terminal escape sequences would appear as raw bytes.

use std::fmt::Write as _;
use std::io::Write;

use crate::engine::analyzer::{AnalysisResult, Severity};

/// Write a plain-text security report to `out`.
pub(crate) fn render(results: &[AnalysisResult], out: &mut dyn Write) -> anyhow::Result<()> {
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
/// printable `\xNN` token instead. Unicode bidirectional and zero-width
/// formatting codepoints (the CVE-2021-42574 "trojan source" class) are not
/// C0/C1 control bytes but can still reorder or hide displayed text, so they are
/// rewritten to a `\u{NNNN}` token as well. Shared with the coloured console and
/// CSV/HTML renderers.
pub(super) fn sanitize_control(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let cp = u32::from(ch);
        if cp < 0x20 || cp == 0x7f || (0x80..=0x9f).contains(&cp) {
            let _ = write!(out, "\\x{cp:02x}");
        } else if is_bidi_or_zero_width(cp) {
            let _ = write!(out, "\\u{{{cp:04x}}}");
        } else {
            out.push(ch);
        }
    }
    out
}

/// Identify Unicode bidi-control and zero-width formatting codepoints.
///
/// These visually reorder or hide text in a terminal without being C0/C1 control
/// bytes (CVE-2021-42574 "trojan source"), so the report sanitizer neutralizes
/// them alongside the classic control bytes.
const fn is_bidi_or_zero_width(cp: u32) -> bool {
    matches!(
        cp,
        0x200b..=0x200f   // zero-width space/non-joiner/joiner, LRM, RLM
        | 0x202a..=0x202e // bidi embeddings/overrides: LRE, RLE, PDF, LRO, RLO
        | 0x2066..=0x2069 // bidi isolates: LRI, RLI, FSI, PDI
        | 0xfeff          // zero-width no-break space / BOM
    )
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
