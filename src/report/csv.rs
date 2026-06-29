//! CSV output  --  one row per finding, suitable for import into spreadsheets or
//! vulnerability-management platforms that accept generic CSV uploads.

use std::io::Write;

use crate::engine::analyzer::AnalysisResult;
use crate::report::txt::sanitize_control;

/// Column header row for the CSV output.
const HEADER: &str = "host,export,finding_id,title,severity,description,evidence,remediation";

/// Write findings as CSV to `out`, one row per finding across all hosts.
///
/// Fields that may contain commas or newlines are wrapped in double-quotes
/// with internal double-quotes escaped as `""` (RFC 4180).
pub fn render(results: &[AnalysisResult], out: &mut dyn Write) -> anyhow::Result<()> {
    writeln!(out, "{HEADER}")?;
    for result in results {
        for finding in &result.findings {
            let export = finding.export.as_deref().unwrap_or("");
            writeln!(out, "{},{},{},{},{},{},{},{}", csv_field(&result.host), csv_field(export), csv_field(&finding.id), csv_field(&finding.title), csv_field(&format!("{:?}", finding.severity)), csv_field(&finding.description), csv_field(&finding.evidence), csv_field(&finding.remediation))?;
        }
    }
    Ok(())
}

/// Wrap a field value in double-quotes and escape embedded double-quotes.
///
/// Three layers of defence, because several fields (evidence preview, export
/// paths, titles) carry data straight from an untrusted NFS server:
///   0. Control-byte neutralization. A CSV is routinely viewed with cat/less/grep
///      in a terminal, so ANSI/terminal escape sequences in server data would
///      execute and rewrite the screen. The shared `sanitize_control` helper
///      rewrites every C0/C1/DEL byte and bidi/zero-width codepoint to a printable
///      token first, matching the txt/console renderers.
///   1. Formula-injection guard. A cell beginning with `=`, `+`, `-`, `@`, TAB
///      or CR is treated as a formula by Excel/LibreOffice/Sheets on open, which
///      can exfiltrate data or trigger DDE. Prefixing such a value with a single
///      quote forces the spreadsheet to render it as literal text.
///   2. RFC 4180 quoting. The (possibly guarded) value is always wrapped in
///      double-quotes with embedded quotes doubled, so commas, quotes and
///      newlines inside the field cannot break the row/column structure.
fn csv_field(value: &str) -> String {
    let value = sanitize_control(value);
    let guarded = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{value}") } else { value };
    // Wrapping is always safer than conditional wrapping  --  avoids corner cases
    // with values that start/end with whitespace or contain commas.
    let escaped = guarded.replace('"', "\"\"");
    format!("\"{escaped}\"")
}
