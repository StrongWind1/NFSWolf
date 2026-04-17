//! Shared terminal output utilities for consistent formatting across all subcommands.
//!
//! All functions respect the global `no_color` flag.  Call `apply_no_color(true)`
//! once at startup (in main.rs) when the flag is set; the `colored` crate then
//! strips escape sequences from all subsequent `.red()`, `.bold()`, etc. calls.

use std::time::{Duration, Instant};

use colored::Colorize as _;
use tabled::builder::Builder;
use tabled::settings::{Alignment, Modify, Style, object::Columns};

use crate::engine::analyzer::Severity;

// --- color / no-color control ------------------------------------------------

/// Disable ANSI colours globally when `no_color` is true.
///
/// Must be called before any output is produced.  Uses `colored`'s global
/// override so that every `.red()` / `.bold()` call becomes a no-op.
pub fn apply_no_color(no_color: bool) {
    if no_color {
        colored::control::set_override(false);
    }
}

// --- status line helpers -----------------------------------------------------

/// `[*] msg` in bold blue  --  informational progress line.
pub fn status_info(msg: &str) -> String {
    format!("{} {msg}", "[*]".bold().blue())
}

/// `[+] msg` in bold green  --  success / found.
pub fn status_ok(msg: &str) -> String {
    format!("{} {msg}", "[+]".bold().green())
}

/// `[!] msg` in bold yellow  --  advisory warning.
pub fn status_warn(msg: &str) -> String {
    format!("{} {msg}", "[!]".bold().yellow())
}

/// `[-] msg` in bold red  --  failure / not found.
pub fn status_err(msg: &str) -> String {
    format!("{} {msg}", "[-]".bold().red())
}

// --- section headers ---------------------------------------------------------

/// Print a bold section header:  `---  TITLE  -------------------------------`
pub fn section_header(title: &str) {
    let line = format!("  {}  {}", title, "-".repeat(60usize.saturating_sub(title.len() + 4)));
    println!("{}", line.bold().white());
}

/// Print a top-level banner for a host/operation.
pub fn banner(title: &str) {
    let width = title.len() + 4;
    let bar = "=".repeat(width);
    println!("{}", format!("+{bar}+").bold().white());
    println!("{}", format!("|  {title}  |").bold().white());
    println!("{}", format!("+{bar}+").bold().white());
}

// --- file handle display -----------------------------------------------------

/// Print a file handle (hex) on its own line, clearly labeled for copy-paste.
///
/// The hex is rendered in cyan so it stands out visually.  Prints to stdout.
pub fn print_handle(label: &str, hex: &str) {
    println!("  {}: {}", label.bold(), hex.cyan());
}

/// Print a "next steps" suggestion after an escape, pointing to `shell` and `read`.
pub fn print_handle_next_steps(hex: &str, host: &str) {
    println!();
    println!("  {} Copy the handle above and use it with:", "Next steps:".bold().yellow());
    println!("    {} shell {} --handle {}", "nfswolf".dimmed(), host, hex.cyan());
    println!("    {} attack read {} --handle {} --path /etc/shadow", "nfswolf".dimmed(), host, hex.cyan());
}

// --- timing ------------------------------------------------------------------

/// Format an elapsed duration as `"1.23s"` or `"304ms"`.
pub fn elapsed(start: Instant) -> String {
    let d = start.elapsed();
    if d < Duration::from_secs(1) { format!("{}ms", d.as_millis()) } else { format!("{:.2}s", d.as_secs_f64()) }
}

// --- severity badges ---------------------------------------------------------

/// Return a padded, coloured severity label for terminal output.
pub fn severity_badge(sev: Severity) -> String {
    match sev {
        Severity::Critical => "[CRITICAL]".red().bold().to_string(),
        Severity::High => "[HIGH]    ".yellow().bold().to_string(),
        Severity::Medium => "[MEDIUM]  ".cyan().to_string(),
        Severity::Low => "[LOW]     ".white().to_string(),
        Severity::Info => "[INFO]    ".dimmed().to_string(),
    }
}

/// Return a short colour-coded severity word for table cells.
pub fn severity_cell(sev: Severity) -> String {
    match sev {
        Severity::Critical => "CRITICAL".red().bold().to_string(),
        Severity::High => "HIGH".yellow().bold().to_string(),
        Severity::Medium => "MEDIUM".cyan().to_string(),
        Severity::Low => "LOW".white().to_string(),
        Severity::Info => "INFO".dimmed().to_string(),
    }
}

// --- export table -------------------------------------------------------------

/// One row for the exports summary table.
pub struct ExportRow {
    pub path: String,
    pub clients: String,
    pub auth: String,
    pub flags: String,
    pub handle_hex: String,
}

/// Build and print an exports table using the rounded tabled style.
pub fn print_export_table(rows: &[ExportRow]) {
    if rows.is_empty() {
        println!("  {}", "(no exports found)".dimmed());
        return;
    }
    let mut builder = Builder::default();
    builder.push_record(["Path", "Allowed clients", "Auth", "Flags", "Handle (partial)"]);
    for r in rows {
        let clients = if r.clients == "*" || r.clients.is_empty() { r.clients.red().to_string() } else { r.clients.normal().to_string() };
        let flags = if r.flags.contains("WILDCARD") || r.flags.contains("NO_ROOT_SQUASH") {
            r.flags.red().to_string()
        } else if !r.flags.is_empty() {
            r.flags.yellow().to_string()
        } else {
            r.flags.dimmed().to_string()
        };
        // Show only the first 16 hex chars of the handle to keep the table narrow.
        let handle_short = if r.handle_hex.len() > 16 { format!("{}...", &r.handle_hex[..16]) } else { r.handle_hex.clone() };
        builder.push_record([&r.path, &clients, &r.auth, &flags, &handle_short.dimmed().to_string()]);
    }
    let mut table = builder.build();
    table.with(Style::rounded());
    table.with(Modify::new(Columns::first()).with(Alignment::left()));
    println!("{table}");
}

// --- findings list ------------------------------------------------------------

/// Print a list of findings with severity badge, export tag, and evidence.
pub fn print_findings(findings: &[crate::engine::analyzer::Finding]) {
    if findings.is_empty() {
        println!("  {}", status_ok("No findings  --  server appears well-configured"));
        return;
    }
    for f in findings {
        let badge = severity_badge(f.severity);
        let export_tag = f.export.as_deref().map_or_else(String::new, |e| format!("  {}", e.dimmed()));
        println!("  {badge}{export_tag}  {}  {}", f.id.bold(), f.title);
        if !f.evidence.is_empty() {
            println!("    {}: {}", "Evidence".dimmed(), f.evidence);
        }
    }
}

/// Print a compact findings count summary line.
pub fn print_findings_summary(findings: &[crate::engine::analyzer::Finding]) {
    let critical = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count();
    let high = findings.iter().filter(|f| matches!(f.severity, Severity::High)).count();
    let medium = findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).count();
    let low = findings.iter().filter(|f| matches!(f.severity, Severity::Low) | matches!(f.severity, Severity::Info)).count();

    let mut parts = Vec::new();
    if critical > 0 {
        parts.push(format!("{critical} critical").red().bold().to_string());
    }
    if high > 0 {
        parts.push(format!("{high} high").yellow().to_string());
    }
    if medium > 0 {
        parts.push(format!("{medium} medium").cyan().to_string());
    }
    if low > 0 {
        parts.push(format!("{low} low/info").dimmed().to_string());
    }

    if parts.is_empty() {
        println!("  {} No findings", "[+]".bold().green());
    } else {
        println!("  Findings: {}", parts.join(", "));
    }
}
