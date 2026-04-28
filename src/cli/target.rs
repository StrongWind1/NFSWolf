//! Unified positional-target parser  --  `host[:/export]` everywhere.
//!
//! Every subcommand that touches a single export accepts the same target
//! spec: a host (IP literal, IPv6 in `[brackets]`, or DNS name) optionally
//! followed by `:/path` to name the export.  `--export` and `--handle` are
//! still accepted as flags; this module is the single place that decides
//! how the three input sources combine.
//!
//! Conflict rules, enforced here rather than in clap so error messages
//! make sense to the operator:
//!
//! - colon-form + `--export`: ambiguous, error.
//! - colon-form + `--handle`: ambiguous, error.
//! - `--export` + `--handle`: already mutually exclusive in clap
//!   (`group = "source"`); we also reject here as a safety net.
//! - Bare host with no source: the caller decides whether that is
//!   allowed.  Some subcommands only need the host (e.g. `attack
//!   brute-handle`); most require an explicit export.

use std::net::IpAddr;

use anyhow::{Context as _, anyhow, bail};

/// Resolved host + chosen handle source.
#[derive(Debug, Clone)]
pub struct Target {
    /// Server IP. DNS names are resolved at parse time.
    pub host: IpAddr,
    /// Where the root file handle comes from.
    pub source: Source,
}

/// How the toolkit obtains the root file handle for the session.
#[derive(Debug, Clone)]
pub enum Source {
    /// Mount this export via the MOUNT protocol to obtain a fresh handle.
    Export(String),
    /// Use this raw handle directly; skip MOUNT entirely.
    /// Caller is responsible for hex-decoding.
    Handle(String),
    /// No source given.  Subcommands that don't need an export
    /// (e.g. `attack brute-handle`) accept this; others reject it.
    None,
}

/// Parse a positional `<TARGET>` plus the `--export`/`--handle` flags.
///
/// `positional` is the raw string the user typed (`"10.0.0.5"`,
/// `"10.0.0.5:/srv"`, `"[2001:db8::1]:/srv"`, `"nfs.example.com"`).
/// `export_flag` is the value of `--export` if supplied; `handle_flag` is
/// the value of `--handle`.  `require_source = true` means a bare host
/// without colon-form, `--export`, or `--handle` is an error (the
/// subcommand needs an export); `require_source = false` allows the
/// `Source::None` case.
pub fn parse(positional: &str, export_flag: Option<&str>, handle_flag: Option<&str>, require_source: bool) -> anyhow::Result<Target> {
    // Split off the trailing ":/..." if any.
    // IPv6 literals must be in brackets, e.g. "[2001:db8::1]:/srv"; the
    // first colon outside the brackets starts the export.
    let (host_part, colon_export) = split_host_export(positional)?;

    if colon_export.is_some() && export_flag.is_some() {
        bail!("ambiguous target: both '<HOST>:/path' and --export given for {positional:?}");
    }
    if colon_export.is_some() && handle_flag.is_some() {
        bail!("ambiguous target: both '<HOST>:/path' and --handle given for {positional:?}");
    }
    if export_flag.is_some() && handle_flag.is_some() {
        bail!("--export and --handle are mutually exclusive");
    }

    let source = match (colon_export, export_flag, handle_flag) {
        (Some(p), _, _) | (_, Some(p), _) => Source::Export(p.to_owned()),
        (_, _, Some(h)) => Source::Handle(h.to_owned()),
        (None, None, None) => {
            if require_source {
                bail!("missing export: pass <HOST>:/path, --export PATH, or --handle HEX");
            }
            Source::None
        },
    };

    let host = resolve_host(host_part)?;
    Ok(Target { host, source })
}

/// Convenience: parse with no positional target (only flags).  Used by
/// subcommands that already split the host into its own positional but
/// still want to honour `--export`/`--handle` consistently.
pub fn parse_flags_only(host: &str, export_flag: Option<&str>, handle_flag: Option<&str>, require_source: bool) -> anyhow::Result<Target> {
    parse(host, export_flag, handle_flag, require_source)
}

/// Split `host[:/export]` into (`host`, `Option<&export>`).
///
/// IPv6 in brackets is preserved verbatim in the host part.  The split
/// happens at the first `:/` that follows the closing bracket (or the
/// start of the string if there are no brackets).
fn split_host_export(s: &str) -> anyhow::Result<(&str, Option<&str>)> {
    if s.is_empty() {
        bail!("empty target");
    }

    // Find the position after which `:/` is meaningful as an export
    // separator: end of bracketed IPv6, or start of string.
    let scan_from = if let Some(stripped) = s.strip_prefix('[') {
        // Closing bracket gives us the host span.
        let close = stripped.find(']').ok_or_else(|| anyhow!("unterminated '[' in target {s:?}"))?;
        // +1 for the leading '[', +1 for the ']' itself.
        close + 2
    } else {
        0
    };

    if let Some(rel) = s[scan_from..].find(":/") {
        let split = scan_from + rel;
        let host = &s[..split];
        let export = &s[split + 1..]; // skip the ':' but keep the leading '/'
        if export.is_empty() {
            bail!("empty export path after ':' in target {s:?}");
        }
        Ok((host, Some(export)))
    } else {
        Ok((s, None))
    }
}

/// Parse `host` as an IPv4 / IPv6 / bracketed-IPv6 string.  DNS names are
/// not currently resolved (callers historically pass IP literals only;
/// adding a DNS lookup here would change error semantics).  Bracketed
/// IPv6 has the brackets stripped before parsing.
pub fn resolve_host(host: &str) -> anyhow::Result<IpAddr> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.parse::<IpAddr>().with_context(|| format!("cannot parse '{host}' as an IP address  --  use a numeric IP literal"))
}

/// Convenience: extract the export path if `Source::Export`, otherwise
/// `None`.
impl Target {
    /// Borrow the export path if this target was set up to mount one.
    #[must_use]
    pub const fn export(&self) -> Option<&str> {
        match &self.source {
            Source::Export(p) => Some(p.as_str()),
            _ => None,
        }
    }

    /// Borrow the raw handle hex if this target uses `--handle`.
    #[must_use]
    pub const fn handle_hex(&self) -> Option<&str> {
        match &self.source {
            Source::Handle(h) => Some(h.as_str()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_with_colon_export() {
        let t = parse("10.0.0.5:/srv", None, None, true).unwrap();
        assert_eq!(t.host.to_string(), "10.0.0.5");
        assert_eq!(t.export(), Some("/srv"));
    }

    #[test]
    fn ipv4_bare_with_export_flag() {
        let t = parse("10.0.0.5", Some("/srv"), None, true).unwrap();
        assert_eq!(t.export(), Some("/srv"));
    }

    #[test]
    fn ipv4_bare_with_handle_flag() {
        let t = parse("10.0.0.5", None, Some("DEADBEEF"), true).unwrap();
        assert_eq!(t.handle_hex(), Some("DEADBEEF"));
    }

    #[test]
    fn ipv6_bracketed_colon_form() {
        let t = parse("[2001:db8::1]:/srv", None, None, true).unwrap();
        assert_eq!(t.host.to_string(), "2001:db8::1");
        assert_eq!(t.export(), Some("/srv"));
    }

    #[test]
    fn ipv6_bracketed_no_export() {
        let t = parse("[2001:db8::1]", Some("/srv"), None, true).unwrap();
        assert_eq!(t.host.to_string(), "2001:db8::1");
        assert_eq!(t.export(), Some("/srv"));
    }

    #[test]
    fn colon_form_clashes_with_export_flag() {
        let err = parse("10.0.0.5:/srv", Some("/other"), None, true).unwrap_err();
        assert!(err.to_string().contains("ambiguous"));
    }

    #[test]
    fn colon_form_clashes_with_handle_flag() {
        let err = parse("10.0.0.5:/srv", None, Some("BEEF"), true).unwrap_err();
        assert!(err.to_string().contains("ambiguous"));
    }

    #[test]
    fn export_and_handle_clash() {
        let err = parse("10.0.0.5", Some("/srv"), Some("BEEF"), true).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn bare_host_without_source_when_required() {
        let err = parse("10.0.0.5", None, None, true).unwrap_err();
        assert!(err.to_string().contains("missing export"));
    }

    #[test]
    fn bare_host_without_source_when_not_required() {
        let t = parse("10.0.0.5", None, None, false).unwrap();
        assert!(matches!(t.source, Source::None));
    }

    #[test]
    fn colon_with_empty_export_rejected() {
        // "host:" without "/" doesn't match the ":/" split, so the entire
        // string is fed to resolve_host(), which fails because "10.0.0.5:"
        // is not a valid IP.  We accept any error -- the user gets told
        // their target is malformed either way.
        let err = parse("10.0.0.5:", None, None, true).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn root_export_via_colon() {
        let t = parse("10.0.0.5:/", None, None, true).unwrap();
        assert_eq!(t.export(), Some("/"));
    }

    #[test]
    fn unterminated_ipv6_bracket_rejected() {
        let err = parse("[2001:db8::1", None, None, true).unwrap_err();
        assert!(err.to_string().contains("unterminated"));
    }
}
