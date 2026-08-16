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
        if let Some(fp) = &result.impl_fingerprint {
            writeln!(out, "Impl: {}", sanitize_control(fp))?;
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
            // Infallible: fmt::Write for String never fails.
            let _ = write!(out, "\\x{cp:02x}");
        } else if is_bidi_or_zero_width(cp) {
            // Infallible: fmt::Write for String never fails.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_control_strips_c0() {
        assert_eq!(sanitize_control("hello\x00world"), "hello\\x00world");
        assert_eq!(sanitize_control("\x1b[31mred\x1b[0m"), "\\x1b[31mred\\x1b[0m");
        assert_eq!(sanitize_control("a\nb\tc"), "a\\x0ab\\x09c");
    }

    #[test]
    fn sanitize_control_strips_del_and_c1() {
        assert_eq!(sanitize_control("\x7f"), "\\x7f");
        assert_eq!(sanitize_control("\u{0080}"), "\\x80");
        assert_eq!(sanitize_control("\u{009f}"), "\\x9f");
        // U+00A0 (non-breaking space) is NOT a control byte -- should pass through.
        assert_eq!(sanitize_control("\u{00a0}"), "\u{00a0}");
    }

    #[test]
    fn sanitize_control_strips_bidi_and_zero_width() {
        assert_eq!(sanitize_control("a\u{200b}b"), "a\\u{200b}b");
        assert_eq!(sanitize_control("\u{202e}RLO"), "\\u{202e}RLO");
        assert_eq!(sanitize_control("\u{feff}BOM"), "\\u{feff}BOM");
    }

    #[test]
    fn sanitize_control_passes_normal_text() {
        assert_eq!(sanitize_control("normal text"), "normal text");
        assert_eq!(sanitize_control(""), "");
        assert_eq!(sanitize_control("abc123!@#"), "abc123!@#");
    }

    #[test]
    fn is_bidi_boundary_values() {
        assert!(is_bidi_or_zero_width(0x200b));
        assert!(is_bidi_or_zero_width(0x200f));
        assert!(!is_bidi_or_zero_width(0x200a));
        assert!(!is_bidi_or_zero_width(0x2010));
        assert!(is_bidi_or_zero_width(0x202a));
        assert!(is_bidi_or_zero_width(0x202e));
        assert!(is_bidi_or_zero_width(0x2066));
        assert!(is_bidi_or_zero_width(0x2069));
        assert!(is_bidi_or_zero_width(0xfeff));
        assert!(!is_bidi_or_zero_width(0x0041)); // 'A'
    }
}
