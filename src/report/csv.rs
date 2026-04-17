//! CSV output  --  one row per finding, suitable for import into spreadsheets or
//! vulnerability-management platforms that accept generic CSV uploads.

use std::io::Write;

use crate::engine::analyzer::AnalysisResult;

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
            writeln!(out, "{},{},{},{},{},{},{},{}", csv_field(&result.host), csv_field(export), csv_field(&finding.id), csv_field(&finding.title), csv_field(&format!("{:?}", finding.severity)), csv_field(&finding.description), csv_field(&finding.evidence), csv_field(&finding.remediation),)?;
        }
    }
    Ok(())
}

/// Wrap a field value in double-quotes and escape embedded double-quotes.
fn csv_field(value: &str) -> String {
    // Wrapping is always safer than conditional wrapping  --  avoids corner cases
    // with values that start/end with whitespace or contain commas.
    let escaped = value.replace('"', "\"\"");
    format!("\"{escaped}\"")
}
