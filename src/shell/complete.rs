//! Shared tab-completion infrastructure for the interactive shell.
//!
//! `ShellCompleter` is version-neutral: it delegates remote directory listing
//! to a `RemoteCompleter` trait impl provided by each NFS version, handles
//! local filesystem completion for commands that take local paths, and
//! classifies each argument position so the right completion source is used.

use std::sync::{Arc, Mutex};

/// Cached listing of the current remote working directory.
pub(crate) struct TabCache {
    /// Handle bytes for the directory whose entries are cached (version-neutral).
    pub cwd: Vec<u8>,
    /// Entry names in `cwd`, excluding `.` and `..`.
    pub entries: Vec<String>,
}

/// Version-neutral interface for listing remote NFS directories.
///
/// Each NFS version provides its own implementation. Methods are called
/// synchronously from rustyline's `complete()` callback; implementations
/// must bridge to async internally (via `block_in_place` / `block_on`).
pub(crate) trait RemoteCompleter: Send + Sync {
    /// List entry names in the directory identified by `handle` bytes.
    fn list_dir_entries(&self, handle: &[u8]) -> Vec<String>;

    /// Resolve a relative multi-component path from `start` handle,
    /// returning the target directory's handle bytes.
    fn resolve_path(&self, start: &[u8], path: &str) -> Option<Vec<u8>>;
}

/// Rustyline helper providing command, remote-path, and local-path completion.
pub(crate) struct ShellCompleter {
    remote: Box<dyn RemoteCompleter>,
    export_root: Vec<u8>,
    cache: Arc<Mutex<TabCache>>,
    commands: &'static [&'static str],
}

impl ShellCompleter {
    pub(crate) fn new(remote: Box<dyn RemoteCompleter>, export_root: Vec<u8>, cache: Arc<Mutex<TabCache>>, commands: &'static [&'static str]) -> Self {
        Self { remote, export_root, cache, commands }
    }
}

// --- Argument classification ------------------------------------------------

enum CompletionKind {
    Remote,
    Local,
    None,
}

fn classify_arg(cmd: &str, positional: usize) -> CompletionKind {
    match (cmd, positional) {
        ("get", 1) | ("put" | "lcd" | "lls" | "lmkdir", 0) => CompletionKind::Local,
        ("ls" | "cd" | "cat" | "stat" | "readlink" | "rm" | "rmdir" | "mkdir" | "find" | "tree" | "mknod" | "get", 0) | ("mv" | "cp" | "symlink" | "link", 0 | 1) | ("chmod" | "chown" | "put", 1) => CompletionKind::Remote,
        _ => CompletionKind::None,
    }
}

/// Count the 0-based positional argument index for the token at the cursor.
///
/// Skips flag tokens (starting with `-`) and consumes the value after
/// `--verify` (which takes an argument).
fn positional_index(fragment: &str) -> usize {
    let tokens: Vec<&str> = fragment.split_whitespace().collect();
    let has_trailing_space = fragment.ends_with(' ');
    let arg_tokens = tokens.get(1..).unwrap_or_default();

    let mut pos = 0usize;
    let mut skip_next = false;
    for (i, tok) in arg_tokens.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if *tok == "--verify" {
            skip_next = true;
            continue;
        }
        if tok.starts_with('-') {
            continue;
        }
        let is_last = i == arg_tokens.len() - 1;
        if is_last && !has_trailing_space {
            return pos;
        }
        pos += 1;
    }
    pos
}

// --- Local-path completion --------------------------------------------------

fn complete_local_path(partial: &str) -> Vec<String> {
    let (dir_str, name_prefix) = if let Some(slash) = partial.rfind('/') { (&partial[..=slash], &partial[slash + 1..]) } else { (".", partial) };

    let Ok(entries) = std::fs::read_dir(dir_str) else {
        return Vec::new();
    };

    let mut matches: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            if !name.starts_with(name_prefix) {
                return None;
            }
            if e.file_type().ok()?.is_dir() { Some(format!("{name}/")) } else { Some(name) }
        })
        .collect();
    matches.sort();
    matches
}

// --- Remote-path completion -------------------------------------------------

fn complete_remote_path(remote: &dyn RemoteCompleter, cache: &Mutex<TabCache>, export_root: &[u8], partial: &str) -> Vec<String> {
    let (dir_str, name_prefix) = if let Some(slash) = partial.rfind('/') { (Some(&partial[..=slash]), &partial[slash + 1..]) } else { (None, partial) };

    let entries = if let Some(dir) = dir_str {
        let (start, rel) = if dir.starts_with('/') {
            (export_root.to_vec(), dir.trim_start_matches('/').trim_end_matches('/'))
        } else {
            let cwd = cache.lock().map_or_else(|e| e.into_inner().cwd.clone(), |g| g.cwd.clone());
            (cwd, dir.trim_end_matches('/'))
        };

        let dir_handle = if rel.is_empty() {
            start
        } else {
            match remote.resolve_path(&start, rel) {
                Some(fh) => fh,
                None => return Vec::new(),
            }
        };
        remote.list_dir_entries(&dir_handle)
    } else {
        cache.lock().map_or_else(|e| e.into_inner().entries.clone(), |g| g.entries.clone())
    };

    let mut matches: Vec<String> = entries.into_iter().filter(|e| e.starts_with(name_prefix) && e != "." && e != "..").collect();
    matches.sort();
    matches
}

// --- Rustyline integration --------------------------------------------------

impl rustyline::completion::Completer for ShellCompleter {
    type Candidate = String;

    fn complete(&self, line: &str, pos: usize, _ctx: &rustyline::Context<'_>) -> rustyline::Result<(usize, Vec<String>)> {
        let fragment = &line[..pos];

        if !fragment.contains(' ') {
            let prefix = fragment;
            let mut matches: Vec<String> = self.commands.iter().filter(|c| c.starts_with(prefix)).map(|c| (*c).to_owned()).collect();
            matches.sort();
            return Ok((0, matches));
        }

        let cmd = fragment.split_whitespace().next().unwrap_or("");
        let arg_start = fragment.rfind(' ').map_or(0, |i| i + 1);
        let partial = &fragment[arg_start..];

        let pos_idx = positional_index(fragment);
        let kind = classify_arg(cmd, pos_idx);

        let name_start_offset = partial.rfind('/').map_or(0, |s| s + 1);

        match kind {
            CompletionKind::Remote => {
                let matches = complete_remote_path(&*self.remote, &self.cache, &self.export_root, partial);
                Ok((arg_start + name_start_offset, matches))
            },
            CompletionKind::Local => {
                let matches = complete_local_path(partial);
                Ok((arg_start + name_start_offset, matches))
            },
            CompletionKind::None => Ok((pos, Vec::new())),
        }
    }
}

impl rustyline::hint::Hinter for ShellCompleter {
    type Hint = String;
}
impl rustyline::highlight::Highlighter for ShellCompleter {}
impl rustyline::validate::Validator for ShellCompleter {}
impl rustyline::Helper for ShellCompleter {}

// --- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_get_remote_then_local() {
        assert!(matches!(classify_arg("get", 0), CompletionKind::Remote));
        assert!(matches!(classify_arg("get", 1), CompletionKind::Local));
    }

    #[test]
    fn classify_put_local_then_remote() {
        assert!(matches!(classify_arg("put", 0), CompletionKind::Local));
        assert!(matches!(classify_arg("put", 1), CompletionKind::Remote));
    }

    #[test]
    fn classify_lcd_local() {
        assert!(matches!(classify_arg("lcd", 0), CompletionKind::Local));
        assert!(matches!(classify_arg("lls", 0), CompletionKind::Local));
        assert!(matches!(classify_arg("lmkdir", 0), CompletionKind::Local));
    }

    #[test]
    fn classify_ls_remote() {
        assert!(matches!(classify_arg("ls", 0), CompletionKind::Remote));
        assert!(matches!(classify_arg("cd", 0), CompletionKind::Remote));
        assert!(matches!(classify_arg("cat", 0), CompletionKind::Remote));
    }

    #[test]
    fn classify_chmod_skip_mode() {
        assert!(matches!(classify_arg("chmod", 0), CompletionKind::None));
        assert!(matches!(classify_arg("chmod", 1), CompletionKind::Remote));
    }

    #[test]
    fn classify_unknown_none() {
        assert!(matches!(classify_arg("uid", 0), CompletionKind::None));
        assert!(matches!(classify_arg("help", 0), CompletionKind::None));
    }

    #[test]
    fn positional_simple() {
        assert_eq!(positional_index("get "), 0);
        assert_eq!(positional_index("get foo "), 1);
        assert_eq!(positional_index("get foo"), 0);
    }

    #[test]
    fn positional_skips_flags() {
        assert_eq!(positional_index("get -r "), 0);
        assert_eq!(positional_index("get -r foo "), 1);
        assert_eq!(positional_index("get -r foo bar"), 1);
    }

    #[test]
    fn positional_verify_consumes_next() {
        assert_eq!(positional_index("get --verify abc123 "), 0);
        assert_eq!(positional_index("get --verify abc123 remote "), 1);
    }

    #[test]
    fn local_path_nonexistent_dir() {
        let result = complete_local_path("/nonexistent_dir_12345/foo");
        assert!(result.is_empty());
    }

    #[test]
    fn local_path_root_has_entries() {
        let result = complete_local_path("/");
        assert!(!result.is_empty());
    }
}
