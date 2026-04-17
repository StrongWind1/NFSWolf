//! HTML report  --  a self-contained single-file report with embedded CSS.
//!
//! Intentionally avoids template engines (no askama, no Tera) to keep the
//! dependency surface small and the output deterministic. All HTML is built
//! with explicit string operations so the compiler can verify every literal.

use std::io::Write;

use crate::engine::analyzer::{AnalysisResult, Severity};

/// Write a complete HTML document to `out`.
///
/// The output is a single file with inlined CSS  --  no external assets required.
pub fn render(results: &[AnalysisResult], title: &str, out: &mut dyn Write) -> anyhow::Result<()> {
    let mut html = String::new();
    push_head(&mut html, title);
    push_body(results, title, &mut html);
    out.write_all(html.as_bytes())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Section builders  --  each pushes a logical block of the document.
// ---------------------------------------------------------------------------

/// Push the `<head>` block including embedded CSS.
fn push_head(html: &mut String, title: &str) {
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"UTF-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    html.push_str("<title>");
    html.push_str(&html_escape(title));
    html.push_str("</title>\n");
    html.push_str(CSS);
    html.push_str("</head>\n");
}

/// Push the `<body>` block: title, per-host sections, footer.
fn push_body(results: &[AnalysisResult], title: &str, html: &mut String) {
    html.push_str("<body>\n");
    html.push_str("<div class=\"container\">\n");
    html.push_str("<h1>");
    html.push_str(&html_escape(title));
    html.push_str("</h1>\n");

    for result in results {
        push_host_section(result, html);
    }

    html.push_str("</div>\n</body>\n</html>\n");
}

/// Push one `<section>` for a single host.
fn push_host_section(result: &AnalysisResult, html: &mut String) {
    html.push_str("<section class=\"host\">\n");
    html.push_str("<h2>");
    html.push_str(&html_escape(&result.host));
    html.push_str("</h2>\n");

    html.push_str("<p class=\"meta\">Timestamp: ");
    html.push_str(&html_escape(&result.timestamp));
    html.push_str("</p>\n");

    if let Some(os) = &result.os_guess {
        html.push_str("<p class=\"meta\">OS: ");
        html.push_str(&html_escape(os));
        html.push_str("</p>\n");
    }

    html.push_str("<p class=\"meta\">NFS versions: ");
    html.push_str(&html_escape(&result.nfs_versions.join(", ")));
    html.push_str("</p>\n");

    if result.findings.is_empty() {
        html.push_str("<p class=\"no-findings\">No findings.</p>\n");
    } else {
        push_findings_table(&result.findings, html);
    }

    html.push_str("</section>\n");
}

/// Push an HTML table of findings for one host.
fn push_findings_table(findings: &[crate::engine::analyzer::Finding], html: &mut String) {
    html.push_str("<table>\n");
    html.push_str("<thead><tr>");
    for col in &["ID", "Title", "Severity", "Export", "Description", "Remediation"] {
        html.push_str("<th>");
        html.push_str(col);
        html.push_str("</th>");
    }
    html.push_str("</tr></thead>\n<tbody>\n");

    for finding in findings {
        let sev_class = severity_class(finding.severity);
        html.push_str("<tr>\n");
        push_td(&html_escape(&finding.id), html);
        push_td(&html_escape(&finding.title), html);

        // Severity cell gets a coloured badge
        html.push_str("<td><span class=\"badge ");
        html.push_str(sev_class);
        html.push_str("\">");
        html.push_str(&html_escape(&format!("{:?}", finding.severity)));
        html.push_str("</span></td>\n");

        let export = finding.export.as_deref().unwrap_or(" -- ");
        push_td(&html_escape(export), html);
        push_td(&html_escape(&finding.description), html);
        push_td(&html_escape(&finding.remediation), html);
        html.push_str("</tr>\n");
    }

    html.push_str("</tbody>\n</table>\n");
}

/// Push a single `<td>` with escaped content.
fn push_td(content: &str, html: &mut String) {
    html.push_str("<td>");
    html.push_str(content);
    html.push_str("</td>\n");
}

/// Map a `Severity` to a CSS class name.
const fn severity_class(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// Escape special HTML characters to prevent XSS in evidence strings.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Embedded CSS  --  inlined to keep the report a single portable file.
// ---------------------------------------------------------------------------

const CSS: &str = r"<style>
body { font-family: system-ui, sans-serif; background: #f5f5f5; color: #222; margin: 0; padding: 0; }
.container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
h1 { font-size: 2rem; border-bottom: 3px solid #333; padding-bottom: .5rem; }
h2 { font-size: 1.4rem; margin-top: 2rem; }
.host { background: #fff; border-radius: 6px; padding: 1.5rem; margin-bottom: 2rem;
        box-shadow: 0 2px 6px rgba(0,0,0,.1); }
.meta { color: #555; margin: .25rem 0; font-size: .9rem; }
.no-findings { color: #2a9d2a; font-weight: bold; }
table { border-collapse: collapse; width: 100%; margin-top: 1rem; font-size: .875rem; }
th { background: #333; color: #fff; padding: .5rem .75rem; text-align: left; }
td { border-bottom: 1px solid #ddd; padding: .5rem .75rem; vertical-align: top; }
tr:hover td { background: #f0f4ff; }
.badge { padding: .2rem .6rem; border-radius: 4px; font-weight: bold; font-size: .8rem;
         text-transform: uppercase; }
.critical { background: #b00020; color: #fff; }
.high     { background: #d94a00; color: #fff; }
.medium   { background: #e5a100; color: #fff; }
.low      { background: #0070c0; color: #fff; }
.info     { background: #555;    color: #fff; }
</style>
";
