//! Report generation  --  console, HTML, JSON, TXT, Markdown, CSV.
//!
//! Entry point is `generate()`, which dispatches to the appropriate renderer
//! based on `ReportFormat`. Each renderer writes to a `dyn Write` so the
//! caller can target a file, stdout, or an in-memory buffer without changes.

// Toolkit API  --  not all items are used in currently-implemented phases.
pub mod console;
pub mod csv;
pub mod html;
pub mod json;
pub mod markdown;
pub mod txt;

use std::io::Write;

use crate::cli::export::ReportFormat;
use crate::engine::analyzer::{AnalysisResult, Finding, Severity};

/// Dispatch to the correct renderer for `format` and write to `out`.
///
/// `title` is used by HTML and Markdown renderers; other formats ignore it.
pub fn generate(results: &[AnalysisResult], format: ReportFormat, title: &str, out: &mut dyn Write) -> anyhow::Result<()> {
    match format {
        ReportFormat::Console => console::render(results, out),
        ReportFormat::Json => json::render(results, out),
        ReportFormat::Txt => txt::render(results, out),
        ReportFormat::Csv => csv::render(results, out),
        ReportFormat::Markdown => markdown::render(results, title, out),
        ReportFormat::Html => html::render(results, title, out),
    }
}

/// Compute a risk score for a set of findings.
///
/// Weights: Critical = 10, High = 7, Medium = 4, Low = 1, Info = 0.
/// Used for executive summary ordering and report headers.
pub fn risk_score(findings: &[Finding]) -> u32 {
    findings.iter().map(|f| severity_weight(f.severity)).sum()
}

/// Remove duplicate findings by (id, export) pair, keeping first occurrence.
///
/// Deduplication is needed when the same vulnerability appears on multiple
/// code paths (e.g., UID sprayer and manual check both detect NFS3ERR_ACCES).
pub fn deduplicate_findings(findings: &mut Vec<Finding>) {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| {
        let key = (f.id.clone(), f.export.clone());
        seen.insert(key)
    });
}

/// Map a severity level to its risk-score weight.
const fn severity_weight(sev: Severity) -> u32 {
    match sev {
        Severity::Critical => 10,
        Severity::High => 7,
        Severity::Medium => 4,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::all,
        clippy::pedantic,
        clippy::nursery,
        clippy::cargo,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        reason = "unit test  --  lints are suppressed per project policy"
    )]
    use super::*;
    use crate::engine::analyzer::{AnalysisResult, ExportAnalysis, Finding, Severity};

    fn make_test_finding(id: &str, severity: Severity, export: Option<&str>) -> Finding {
        Finding { id: id.to_owned(), title: format!("Test finding {id}"), severity, description: "Test description".to_owned(), evidence: "Test evidence".to_owned(), remediation: "Test remediation".to_owned(), export: export.map(str::to_owned) }
    }

    fn make_test_result(findings: Vec<Finding>) -> AnalysisResult {
        AnalysisResult {
            host: "192.168.1.1".to_owned(),
            timestamp: "2025-01-01T00:00:00Z".to_owned(),
            os_guess: Some("Linux/Ext4".to_owned()),
            nfs_versions: vec!["NFSv3".to_owned()],
            exports: vec![ExportAnalysis { path: "/export".to_owned(), allowed_hosts: vec!["*".to_owned()], auth_methods: vec!["1".to_owned()], writable: false, no_root_squash: None, escape_possible: false, file_handle: "01020304".to_owned(), file_access_tests: Vec::new(), nfs4_acls: Vec::new() }],
            findings,
        }
    }

    #[test]
    fn risk_score_empty_findings_is_zero() {
        assert_eq!(risk_score(&[]), 0);
    }

    #[test]
    fn risk_score_single_critical_is_10() {
        let findings = vec![make_test_finding("F-1.1", Severity::Critical, None)];
        assert_eq!(risk_score(&findings), 10);
    }

    #[test]
    fn risk_score_mixed_severities_sums_correctly() {
        let findings = vec![
            make_test_finding("F-1.1", Severity::Critical, None), // 10
            make_test_finding("F-2.1", Severity::High, None),     // 7
            make_test_finding("F-3.1", Severity::Medium, None),   // 4
            make_test_finding("F-4.1", Severity::Low, None),      // 1
            make_test_finding("F-5.1", Severity::Info, None),     // 0
        ];
        assert_eq!(risk_score(&findings), 22);
    }

    #[test]
    fn deduplicate_findings_removes_dupes() {
        let mut findings = vec![
            make_test_finding("F-1.1", Severity::High, Some("/export")),
            make_test_finding("F-1.1", Severity::High, Some("/export")), // duplicate
            make_test_finding("F-2.1", Severity::Critical, Some("/export")),
        ];
        deduplicate_findings(&mut findings);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn deduplicate_findings_preserves_unique() {
        let mut findings = vec![make_test_finding("F-1.1", Severity::High, Some("/a")), make_test_finding("F-1.1", Severity::High, Some("/b")), make_test_finding("F-2.1", Severity::Critical, Some("/a"))];
        deduplicate_findings(&mut findings);
        assert_eq!(findings.len(), 3, "distinct (id, export) pairs must be preserved");
    }

    #[test]
    fn generate_json_format_produces_valid_json() {
        let results = vec![make_test_result(vec![make_test_finding("F-1.1", Severity::High, Some("/export"))])];
        let mut buf = Vec::new();
        generate(&results, ReportFormat::Json, "Test", &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Must be valid JSON (serde_json can parse it back)
        let _: serde_json::Value = serde_json::from_str(&output).expect("JSON output must be valid");
    }

    #[test]
    fn generate_txt_format_produces_non_empty_output() {
        let results = vec![make_test_result(vec![make_test_finding("F-1.1", Severity::High, Some("/export"))])];
        let mut buf = Vec::new();
        generate(&results, ReportFormat::Txt, "Test", &mut buf).unwrap();
        assert!(!buf.is_empty(), "TXT output must be non-empty");
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("192.168.1.1"), "TXT must contain host");
    }

    #[test]
    fn generate_csv_format_contains_header_row() {
        let results = vec![make_test_result(vec![make_test_finding("F-1.1", Severity::High, Some("/export"))])];
        let mut buf = Vec::new();
        generate(&results, ReportFormat::Csv, "Test", &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("host,"), "CSV must start with header row");
        assert!(output.contains("finding_id"), "CSV header must contain finding_id");
    }

    #[test]
    fn generate_html_format_contains_html_tag() {
        let results = vec![make_test_result(vec![make_test_finding("F-1.1", Severity::High, Some("/export"))])];
        let mut buf = Vec::new();
        generate(&results, ReportFormat::Html, "Test Report", &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("<html"), "HTML output must contain html tag");
        assert!(output.contains("</html>"), "HTML output must be closed");
    }

    #[test]
    fn generate_markdown_format_contains_heading() {
        let results = vec![make_test_result(vec![make_test_finding("F-1.1", Severity::High, Some("/export"))])];
        let mut buf = Vec::new();
        generate(&results, ReportFormat::Markdown, "Security Report", &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("# Security Report"), "Markdown must contain # heading");
    }
}
