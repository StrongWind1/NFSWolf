//! Interactive NFS shell  --  readline-based REPL for browsing NFS exports.
//!
//! The shell is generic over `ShellOps`, so NFSv2 and NFSv3 share the same
//! command dispatch, tab completion, and help text. Version-specific behavior
//! lives in `v2::V2Ops` and `v3::V3Ops`.

pub(crate) mod complete;
pub(crate) mod ops;
pub(crate) mod v2;
pub(crate) mod v3;
pub(crate) mod v4;

use ops::{ShellDeviceType, ShellEntry, ShellFileInfo, ShellFileType, ShellHandle, ShellOps};

use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};

use colored::Colorize as _;

use crate::engine::escape::{EscapeConfig, EscapeProbe, EscapeRootOutcome, find_escape_root};
use crate::util::utmp::{LastlogRecord, UTMP_RECORD_SIZE, UtType, UtmpRecord, parse_lastlog, parse_passwd, parse_utmp};

/// Maximum bytes to read in a single `cat` command.
const CAT_MAX_BYTES: u32 = 1_048_576; // 1 MiB

/// Maximum bytes per NFS READ/WRITE chunk.
use crate::shell::ops::{CHUNK_SIZE, READ_ALL_MAX};

/// All commands available in the NFSv3 interactive shell (for Tab completion of the first token).
pub(crate) const V3_SHELL_COMMANDS: &[&str] = &[
    "ls",
    "ll",
    "dir",
    "cd",
    "pwd",
    "tree",
    "find",
    "cat",
    "type",
    "get",
    "download",
    "put",
    "upload",
    "rm",
    "del",
    "mkdir",
    "rmdir",
    "mv",
    "rename",
    "cp",
    "copy",
    "chmod",
    "chown",
    "stat",
    "readlink",
    "symlink",
    "link",
    "uid",
    "gid",
    "hostname",
    "whoami",
    "id",
    "impersonate",
    "su",
    "mknod",
    "suid-scan",
    "world-writable",
    "secrets-scan",
    "exports",
    "last",
    "lastb",
    "lastlog",
    "escape-root",
    "mount-handle",
    "handle",
    "verifier",
    "lcd",
    "lls",
    "lpwd",
    "lmkdir",
    "history",
    "help",
    "exit",
    "quit",
];

/// All commands available in the NFSv4 interactive shell (for Tab completion).
///
/// Identical to `V3_SHELL_COMMANDS` -- v4 supports mknod and verifier.
pub(crate) const V4_SHELL_COMMANDS: &[&str] = &[
    "ls",
    "ll",
    "dir",
    "cd",
    "pwd",
    "tree",
    "find",
    "cat",
    "type",
    "get",
    "download",
    "put",
    "upload",
    "rm",
    "del",
    "mkdir",
    "rmdir",
    "mv",
    "rename",
    "cp",
    "copy",
    "chmod",
    "chown",
    "stat",
    "readlink",
    "symlink",
    "link",
    "uid",
    "gid",
    "hostname",
    "whoami",
    "id",
    "impersonate",
    "su",
    "mknod",
    "suid-scan",
    "world-writable",
    "secrets-scan",
    "exports",
    "last",
    "lastb",
    "lastlog",
    "escape-root",
    "mount-handle",
    "handle",
    "verifier",
    "lcd",
    "lls",
    "lpwd",
    "lmkdir",
    "history",
    "help",
    "exit",
    "quit",
];

/// Commands available in the NFSv2 shell (Tab completion).
///
/// Excludes `mknod` (not in NFSv2).
/// The unified dispatch still handles unsupported commands with a clear error.
pub(crate) const V2_SHELL_COMMANDS: &[&str] = &[
    "ls",
    "ll",
    "dir",
    "cd",
    "pwd",
    "tree",
    "find",
    "cat",
    "type",
    "get",
    "download",
    "put",
    "upload",
    "rm",
    "del",
    "mkdir",
    "rmdir",
    "mv",
    "rename",
    "cp",
    "copy",
    "chmod",
    "chown",
    "stat",
    "readlink",
    "symlink",
    "link",
    "uid",
    "gid",
    "hostname",
    "whoami",
    "id",
    "impersonate",
    "su",
    "suid-scan",
    "world-writable",
    "secrets-scan",
    "exports",
    "last",
    "lastb",
    "lastlog",
    "escape-root",
    "mount-handle",
    "handle",
    "root",
    "lcd",
    "lls",
    "lpwd",
    "lmkdir",
    "history",
    "help",
    "exit",
    "quit",
];

/// Interactive NFS shell  --  browse and extract files from an NFS export.
///
/// Maintains a current working directory handle and path string so that
/// relative `cd` and `ls` operations feel like a local shell. Stores the
/// export root handle separately so `cd /` and absolute paths always work.
pub(crate) struct NfsShell<O: ShellOps> {
    ops: O,
    export_root: ShellHandle,
    cwd: ShellHandle,
    cwd_path: String,
    allow_write: bool,
    hostname: String,
    history: Vec<String>,
    tab_cache: Arc<Mutex<complete::TabCache>>,
    commands: &'static [&'static str],
}

/// Adapts `ShellOps` to the `EscapeProbe` trait so the shared escape engine
/// can probe handles through the shell's NFS version backend.
struct ShellEscapeProbe<'a, O: ShellOps> {
    ops: &'a O,
}

impl<O: ShellOps> EscapeProbe for ShellEscapeProbe<'_, O> {
    async fn probe_getattr(&self, handle: &[u8]) -> anyhow::Result<(bool, u64)> {
        let fh = ShellHandle(handle.to_vec());
        let info = self.ops.getattr(&fh).await?;
        Ok((info.file_type == ShellFileType::Directory, info.fileid))
    }

    async fn probe_lookup(&self, dir: &[u8], name: &str) -> anyhow::Result<Vec<u8>> {
        let fh = ShellHandle(dir.to_vec());
        let (child, _) = self.ops.lookup(&fh, name).await?;
        Ok(child.0)
    }
}

impl<O: ShellOps> NfsShell<O> {
    /// Create a new shell rooted at `root` with the given ops backend.
    #[must_use]
    pub(crate) fn new(ops: O, root: ShellHandle, allow_write: bool, hostname: String) -> Self {
        let commands = ops.commands();
        let tab_cache = Arc::new(Mutex::new(complete::TabCache { cwd: root.as_bytes().to_vec(), entries: Vec::new() }));
        Self { ops, export_root: root.clone(), cwd: root, cwd_path: "/".to_owned(), allow_write, hostname, history: Vec::new(), tab_cache, commands }
    }

    /// Return the current directory path for use in the prompt.
    #[must_use]
    pub(crate) fn cwd_path(&self) -> &str {
        &self.cwd_path
    }

    /// Current AUTH_SYS UID. Reflects mid-session `uid` / `impersonate` changes.
    #[must_use]
    pub(crate) fn current_uid(&self) -> u32 {
        self.ops.uid()
    }

    /// Current AUTH_SYS GID. Reflects mid-session `gid` / `impersonate` changes.
    #[must_use]
    pub(crate) fn current_gid(&self) -> u32 {
        self.ops.gid()
    }

    /// Build a Tab completer that shares the directory cache with this shell.
    ///
    /// Call once after construction; pass the result to rustyline `Editor::set_helper`.
    pub(crate) fn make_completer(&self) -> complete::ShellCompleter {
        complete::ShellCompleter::new(self.ops.make_completer(), self.export_root.as_bytes().to_vec(), Arc::clone(&self.tab_cache), self.commands)
    }

    /// Refresh the Tab completion cache with the current directory's entries.
    ///
    /// Called after every successful `cd` so Tab completion is immediately
    /// accurate in the new directory without an extra RPC on the first Tab press.
    pub(crate) async fn refresh_tab_cache(&self) {
        let entries = self.ops.list_dir(&self.cwd).await.map_or_else(|_| Vec::new(), |es| es.into_iter().filter(|e| e.name != "." && e.name != "..").map(|e| e.name).collect());
        if let Ok(mut cache) = self.tab_cache.lock() {
            cache.cwd = self.cwd.as_bytes().to_vec();
            cache.entries = entries;
        }
    }

    /// Parse a command line and dispatch to the appropriate handler.
    ///
    /// Errors from NFS operations are printed to stderr and do not abort the
    /// shell -- the user can retry or navigate away.
    #[expect(clippy::cognitive_complexity, reason = "shell dispatch table")]
    pub(crate) async fn dispatch(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return;
        }

        // Track history (skip duplicate consecutive entries).
        if self.history.last().map(String::as_str) != Some(line) {
            self.history.push(line.to_owned());
        }

        let mut parts = line.splitn(2, ' ');
        let cmd = parts.next().unwrap_or("");
        let arg = parts.next().unwrap_or("").trim();

        match cmd {
            // Navigation
            "ls" | "dir" => self.cmd_ls(arg).await,
            "ll" => {
                let ll_arg = format!("-a {arg}");
                self.cmd_ls(ll_arg.trim_end()).await;
            },
            "cd" => self.cmd_cd(arg).await,
            "pwd" => println!("{}", self.cwd_path),
            "tree" => self.cmd_tree(arg).await,
            "find" => self.cmd_find(arg).await,
            // File ops
            "cat" | "type" => self.cmd_cat(arg).await,
            "get" | "download" => self.cmd_get(arg).await,
            "put" | "upload" => self.cmd_put(arg).await,
            "rm" | "del" => self.cmd_rm(arg).await,
            "mkdir" => self.cmd_mkdir(arg).await,
            "rmdir" => self.cmd_rmdir(arg).await,
            "mv" | "rename" => self.cmd_mv(arg).await,
            "cp" | "copy" => self.cmd_cp(arg).await,
            // Permissions
            "chmod" => self.cmd_chmod(arg).await,
            "chown" => self.cmd_chown(arg).await,
            "stat" => self.cmd_stat(arg).await,
            "readlink" => self.cmd_readlink(arg).await,
            "symlink" => self.cmd_symlink(arg).await,
            "link" => self.cmd_link(arg).await,
            // Identity
            "uid" => self.cmd_uid(arg),
            "gid" => self.cmd_gid(arg),
            "hostname" => self.cmd_hostname(arg),
            "whoami" | "id" => self.cmd_whoami(),
            "impersonate" | "su" => self.cmd_impersonate(arg),
            // Devices
            "mknod" => self.cmd_mknod(arg).await,
            // Analysis
            "suid-scan" => self.cmd_suid_scan().await,
            "world-writable" => self.cmd_world_writable().await,
            "secrets-scan" => self.cmd_secrets_scan().await,
            "exports" => self.cmd_exports().await,
            "last" => self.cmd_last(arg, false).await,
            "lastb" => self.cmd_last(arg, true).await,
            "lastlog" => self.cmd_lastlog(arg).await,
            // Escape
            "escape-root" => self.cmd_escape_root().await,
            "mount-handle" => self.cmd_mount_handle(arg).await,
            // Handle info
            "handle" => println!("{}", self.cwd.to_hex()),
            "root" => self.cmd_root().await,
            "verifier" => self.cmd_verifier().await,
            // Local ops
            "lcd" => self.cmd_lcd(arg),
            "lls" => self.cmd_lls(arg),
            "lpwd" => self.cmd_lpwd(),
            "lmkdir" => self.cmd_lmkdir(arg),
            // Session
            "history" => self.cmd_history(),
            "help" | "?" => self.print_help(),
            "exit" | "quit" => {},
            _ => eprintln!("{}", format!("unknown command: {cmd}  (try 'help')").yellow()),
        }
    }

    // -------------------------------------------------------------------------
    // Navigation
    // -------------------------------------------------------------------------

    /// List directory contents.
    ///
    /// Usage: `ls [-a] [--sort=FIELD] [-r|--reverse] [path]`
    ///
    /// Default columns: mode, uid, gid, size, mtime, name.
    /// With `-a`: adds inode, nlink, used, rdev, atime, ctime columns.
    /// `.` and `..` are always the first two rows regardless of sort order.
    /// When sorting by ctime or atime that timestamp replaces mtime in the default view.
    async fn cmd_ls(&self, raw: &str) {
        let (sort, reverse, all_cols, path_str) = parse_ls_args(raw);
        let target = if path_str.is_empty() { None } else { Some(path_str) };

        // Resolve the target. `ls <dir>` lists the directory; `ls <file>`
        // shows just that one entry (real `ls` semantics).
        let all_entries: Vec<ShellEntry> = match target {
            None => match self.ops.list_dir(&self.cwd).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{}", format!("ls: {e}").red());
                    return;
                },
            },
            Some(p) => {
                let (fh, info) = match self.lookup_path(p).await {
                    Ok(pair) => pair,
                    Err(e) => {
                        eprintln!("{}", format!("ls: {p}: {e}").red());
                        return;
                    },
                };
                if info.file_type == ShellFileType::Directory {
                    match self.ops.list_dir(&fh).await {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("{}", format!("ls: {p}: {e}").red());
                            return;
                        },
                    }
                } else {
                    let name = p.rsplit('/').find(|s| !s.is_empty()).unwrap_or(p).to_owned();
                    vec![ShellEntry { name, info: Some(info), handle: Some(fh) }]
                }
            },
        };

        // Separate . and .. (always pinned first) from the remaining entries.
        let mut dot: Option<&ShellEntry> = None;
        let mut dotdot: Option<&ShellEntry> = None;
        let mut rest: Vec<&ShellEntry> = Vec::with_capacity(all_entries.len());
        for e in &all_entries {
            if e.name == "." {
                dot = Some(e);
            } else if e.name == ".." {
                dotdot = Some(e);
            } else {
                rest.push(e);
            }
        }

        // Stable sort the non-dot entries, then optionally reverse.
        rest.sort_by(|a, b| ls_cmp_shell(a, b, sort));
        if reverse {
            rest.reverse();
        }

        if all_cols {
            println!("{:>10}  {:<10}  {:>4}  {:>8}  {:>8}  {:>12}  {:>12}  {:>11}  {:<19}  {:<19}  {:<19}  name", "inode", "mode", "nlink", "uid", "gid", "size", "used", "rdev", "atime", "mtime", "ctime");
            println!("{}", "-".repeat(148).dimmed());
        } else {
            let time_label = match sort {
                LsSort::Ctime => "ctime",
                LsSort::Atime => "atime",
                _ => "mtime",
            };
            println!("{:<10}  {:>8}  {:>8}  {:>12}  {:<19}  name", "mode", "uid", "gid", "size", time_label);
            println!("{}", "-".repeat(75).dimmed());
        }

        let print_entry = |entry: &ShellEntry| {
            let tc = entry.info.as_ref().map_or('?', |a| a.file_type.letter());
            let mode_str = entry.info.as_ref().map_or_else(|| "?????????".to_owned(), |a| format_mode(a.mode));
            let uid = entry.info.as_ref().map_or(0u32, |a| a.uid);
            let gid = entry.info.as_ref().map_or(0u32, |a| a.gid);
            let size = entry.info.as_ref().map_or(0u64, |a| a.size);
            let name_str = colorize_name(&entry.name, tc);

            if all_cols {
                let nlink = entry.info.as_ref().map_or(0u32, |a| a.nlink);
                let inode = entry.info.as_ref().map_or(0u64, |a| a.fileid);
                let used = entry.info.as_ref().map_or(0u64, |a| a.used);
                let rdev = entry.info.as_ref().map(|a| if a.file_type == ShellFileType::Block || a.file_type == ShellFileType::Character { format!("{}:{}", a.rdev.0, a.rdev.1) } else { "-".to_owned() });
                let rdev_str = rdev.unwrap_or_else(|| "-".to_owned());
                let atime = entry.info.as_ref().map_or_else(|| "????-??-?? ??:??:??".to_owned(), |a| fmt_unix_time(a.atime_secs));
                let mtime = entry.info.as_ref().map_or_else(|| "????-??-?? ??:??:??".to_owned(), |a| fmt_unix_time(a.mtime_secs));
                let ctime = entry.info.as_ref().map_or_else(|| "????-??-?? ??:??:??".to_owned(), |a| fmt_unix_time(a.ctime_secs));
                println!("{inode:>10}  {tc}{mode_str}  {nlink:4}  {uid:8}  {gid:8}  {size:12}  {used:12}  {rdev_str:>11}  {atime}  {mtime}  {ctime}  {name_str}");
            } else {
                let time_secs = entry.info.as_ref().map(|a| match sort {
                    LsSort::Ctime => a.ctime_secs,
                    LsSort::Atime => a.atime_secs,
                    _ => a.mtime_secs,
                });
                let time_str = time_secs.map_or_else(|| "????-??-?? ??:??:??".to_owned(), fmt_unix_time);
                println!("{tc}{mode_str}  {uid:8}  {gid:8}  {size:12}  {time_str}  {name_str}");
            }
        };

        if let Some(e) = dot {
            print_entry(e);
        }
        if let Some(e) = dotdot {
            print_entry(e);
        }
        for e in &rest {
            print_entry(e);
        }
    }

    /// Change the current directory handle and update the path string.
    ///
    /// Absolute paths (starting with '/') are resolved from the export root.
    /// '/' alone resets to the export root without a network call.
    async fn cmd_cd(&mut self, target: &str) {
        let target = if target.is_empty() { "/" } else { target };

        // Fast path: cd / always resets to mount root without an RPC.
        if target == "/" {
            self.cwd.clone_from(&self.export_root);
            "/".clone_into(&mut self.cwd_path);
            self.refresh_tab_cache().await;
            return;
        }

        // For absolute paths, resolve from the export root.
        let (start_fh, path_base, rel) = if target.starts_with('/') { (self.export_root.clone(), "/", target.trim_start_matches('/')) } else { (self.cwd.clone(), self.cwd_path.as_str(), target) };

        // Empty relative part after stripping prefix means we asked for "/".
        if rel.is_empty() {
            self.cwd.clone_from(&self.export_root);
            "/".clone_into(&mut self.cwd_path);
            self.refresh_tab_cache().await;
            return;
        }

        match self.ops.lookup_path(&start_fh, rel).await {
            Ok((fh, info)) => {
                if info.file_type != ShellFileType::Directory {
                    eprintln!("{}", format!("cd: {target}: not a directory").red());
                    return;
                }
                self.cwd = fh;
                self.cwd_path = build_path(path_base, rel);
                self.refresh_tab_cache().await;
            },
            Err(e) => eprintln!("{}", format!("cd: {target}: {e}").red()),
        }
    }

    /// Recursive directory tree display.
    ///
    /// Usage: `tree [depth]` (default depth 3). Hidden dot-directories are
    /// always traversed -- this is a security tool, `.ssh` / `.aws` /
    /// `.bash_history` are exactly what we want, so there is no `-a` toggle.
    /// Any non-numeric argument is ignored, so a stray `tree -a` still works.
    async fn cmd_tree(&self, arg: &str) {
        let max_depth = arg.split_whitespace().find_map(|t| t.parse::<usize>().ok()).unwrap_or(3);
        println!("{}", self.cwd_path.bold());
        tree_recursive(&self.ops, self.cwd.clone(), String::new(), 0, max_depth).await;
    }

    /// Find files whose names contain the pattern (case-insensitive substring).
    async fn cmd_find(&self, pattern: &str) {
        if pattern.is_empty() {
            eprintln!("{}", "usage: find <pattern>".yellow());
            return;
        }
        let pattern_lower = pattern.to_ascii_lowercase();
        let filter = |entry: &ShellEntry, path: &str| -> Option<String> {
            if entry.name.to_ascii_lowercase().contains(&pattern_lower) {
                let tc = entry.info.as_ref().map_or('?', |a| a.file_type.letter());
                Some(colorize_name(path, tc))
            } else {
                None
            }
        };
        walk_recursive(&self.ops, self.cwd.clone(), self.cwd_path.clone(), &filter).await;
    }

    // -------------------------------------------------------------------------
    // File operations
    // -------------------------------------------------------------------------

    /// Read and print file contents to stdout.
    async fn cmd_cat(&self, name: &str) {
        if name.is_empty() {
            eprintln!("{}", "usage: cat <file>".yellow());
            return;
        }
        let (fh, _) = match self.lookup_path(name).await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("{}", format!("cat: {name}: {e}").red());
                return;
            },
        };
        match self.ops.read_file(&fh).await {
            Ok(data) => {
                let mut stdout = std::io::stdout();
                let len = data.len().min(CAT_MAX_BYTES as usize);
                // Stdout write failure is non-fatal during cat (pipe closed, etc.).
                drop(stdout.write_all(data.get(..len).unwrap_or(&data)));
                if data.last().is_some_and(|&b| b != b'\n') {
                    println!();
                }
                if data.len() > CAT_MAX_BYTES as usize {
                    eprintln!("{}", format!("[!] output truncated at {CAT_MAX_BYTES} bytes -- use `get` for the full file").yellow());
                }
            },
            Err(e) => eprintln!("{}", format!("cat: {name}: {e}").red()),
        }
    }

    /// Download a remote file or directory tree to a local path.
    ///
    /// Flags:
    ///   `-r`               recurse into directories (mirrors tree locally)
    ///   `--verify <hash>`  assert SHA-256 of downloaded file matches `<hash>`
    ///
    /// Flags may appear in any position (before or after the positional
    /// args). This matters in non-interactive mode (`shell -c "get foo
    /// bar --verify HEX"`) where clap is not in the loop and we have to
    /// tokenise the line ourselves.
    async fn cmd_get(&self, line: &str) {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let mut recursive = false;
        let mut verify_hash: Option<String> = None;
        let mut positional: Vec<&str> = Vec::with_capacity(2);
        let mut iter = tokens.iter().copied();
        while let Some(tok) = iter.next() {
            match tok {
                "-r" => recursive = true,
                "--verify" => {
                    if let Some(h) = iter.next() {
                        verify_hash = Some(h.to_owned());
                    } else {
                        eprintln!("{}", "get: --verify requires a hex SHA-256 hash".red());
                        return;
                    }
                },
                t if t.starts_with("--") => {
                    eprintln!("{}", format!("get: unknown flag {t}").red());
                    return;
                },
                t => positional.push(t),
            }
        }
        let Some(&remote) = positional.first() else {
            eprintln!("{}", "usage: get [-r] [--verify <sha256>] <remote> [local]".yellow());
            return;
        };
        let local = positional.get(1).copied().unwrap_or("");

        let (fh, info) = match self.lookup_path(remote).await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("{}", format!("get: {remote}: {e}").red());
                return;
            },
        };

        // Resolve the local destination. When `local` is an existing directory
        // or ends with '/', append the remote basename so `get /etc/passwd
        // /home/test/` writes /home/test/passwd (not a write into a directory
        // path, which fails). Mirrors `cp` / `scp` semantics.
        let local_is_dir = Path::new(local).is_dir();
        let dest = resolve_get_dest(remote, local, local_is_dir);
        if !local.is_empty() && (local.ends_with('/') || local_is_dir) {
            eprintln!("{}", format!("get: {local} is a directory -> saving as {dest}").yellow());
        }
        let dest = dest.as_str();

        if recursive && info.file_type == ShellFileType::Directory {
            let mp = MultiProgress::new();
            match download_tree(&self.ops, &fh, dest, &mp).await {
                Ok(bytes) => println!("{}", format!("saved {bytes} bytes -> {dest}/").green()),
                Err(e) => eprintln!("{}", format!("get -r: {e}").red()),
            }
        } else {
            match download_file(&self.ops, &fh, dest).await {
                Ok((bytes, hash)) => {
                    println!("{}", format!("saved {bytes} bytes -> {dest}  sha256:{hash}").green());
                    if let Some(ref expected) = verify_hash {
                        if hash.eq_ignore_ascii_case(expected) {
                            println!("{}", "sha256 verified".green());
                        } else {
                            eprintln!("{}", format!("get: sha256 mismatch  expected:{expected}  got:{hash}").red());
                        }
                    }
                },
                Err(e) => eprintln!("{}", format!("get: {e}").red()),
            }
        }
    }

    /// Upload a local file or directory tree to the remote export.
    ///
    /// Add `-r` before the local path to upload an entire directory recursively.
    async fn cmd_put(&self, line: &str) {
        if !self.allow_write {
            eprintln!("{}", "write disabled  --  rerun with --allow-write".red());
            return;
        }

        let mut recursive = false;
        let mut rest = line.trim();
        if let Some(r) = rest.strip_prefix("-r") {
            recursive = true;
            rest = r.trim_start();
        }

        let (local, remote) = split2(rest);
        if local.is_empty() || remote.is_empty() {
            eprintln!("{}", "usage: put [-r] <local> <remote>".yellow());
            return;
        }

        let local_path = Path::new(local);

        if recursive && local_path.is_dir() {
            let (remote_parent_fh, remote_dir_name) = match self.resolve_parent(remote).await {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{}", format!("put -r: {e}").red());
                    return;
                },
            };
            #[cfg(unix)]
            let dir_mode = std::fs::metadata(local_path).map_or(0o755, |m| m.permissions().mode() & 0o7777);
            #[cfg(not(unix))]
            let dir_mode = 0o755;
            let dir_fh = match self.ops.mkdir(&remote_parent_fh, &remote_dir_name, dir_mode).await {
                Ok(fh) => fh,
                Err(e) => {
                    eprintln!("{}", format!("put -r: create dir {remote}: {e}").red());
                    return;
                },
            };
            let mp = MultiProgress::new();
            match upload_tree(&self.ops, local_path, &dir_fh, &mp).await {
                Ok(bytes) => println!("{}", format!("put -r: {bytes} bytes -> {remote}/").green()),
                Err(e) => eprintln!("{}", format!("put -r: {e}").red()),
            }
            return;
        }

        let local_meta = match std::fs::metadata(local) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("{}", format!("put: cannot stat {local}: {e}").red());
                return;
            },
        };
        let data = match std::fs::read(local) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("{}", format!("put: cannot read {local}: {e}").red());
                return;
            },
        };

        let (parent_fh, filename) = match self.resolve_parent(remote).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", format!("put: {e}").red());
                return;
            },
        };

        #[cfg(unix)]
        let mode = local_meta.permissions().mode() & 0o7777;
        #[cfg(not(unix))]
        let mode = if local_meta.permissions().readonly() { 0o444 } else { 0o644 };
        let file_fh = match self.ops.create_file(&parent_fh, &filename, mode).await {
            Ok(fh) => fh,
            Err(e) => {
                eprintln!("{}", format!("put: create {remote}: {e}").red());
                return;
            },
        };

        match upload_data(&self.ops, &file_fh, &data).await {
            Ok(n) => println!("{}", format!("put: {n} bytes -> {remote}").green()),
            Err(e) => eprintln!("{}", format!("put: write error: {e}").red()),
        }
    }

    /// Remove a remote file.
    async fn cmd_rm(&self, path: &str) {
        if path.is_empty() {
            eprintln!("{}", "usage: rm <file>".yellow());
            return;
        }
        if !self.allow_write {
            eprintln!("{}", "write disabled  --  rerun with --allow-write".red());
            return;
        }

        let (parent_fh, filename) = match self.resolve_parent(path).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", format!("rm: {e}").red());
                return;
            },
        };
        match self.ops.remove(&parent_fh, &filename).await {
            Ok(()) => println!("{}", format!("removed {path}").green()),
            Err(e) => eprintln!("{}", format!("rm: {e}").red()),
        }
    }

    /// Create a remote directory.
    async fn cmd_mkdir(&self, path: &str) {
        if path.is_empty() {
            eprintln!("{}", "usage: mkdir <dir>".yellow());
            return;
        }
        if !self.allow_write {
            eprintln!("{}", "write disabled  --  rerun with --allow-write".red());
            return;
        }

        let (parent_fh, dirname) = match self.resolve_parent(path).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", format!("mkdir: {e}").red());
                return;
            },
        };
        match self.ops.mkdir(&parent_fh, &dirname, 0o755).await {
            Ok(_) => println!("{}", format!("created {path}").green()),
            Err(e) => eprintln!("{}", format!("mkdir: {e}").red()),
        }
    }

    /// Remove a remote directory.
    async fn cmd_rmdir(&self, path: &str) {
        if path.is_empty() {
            eprintln!("{}", "usage: rmdir <dir>".yellow());
            return;
        }
        if !self.allow_write {
            eprintln!("{}", "write disabled  --  rerun with --allow-write".red());
            return;
        }

        let (parent_fh, dirname) = match self.resolve_parent(path).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", format!("rmdir: {e}").red());
                return;
            },
        };
        match self.ops.rmdir(&parent_fh, &dirname).await {
            Ok(()) => println!("{}", format!("removed {path}").green()),
            Err(e) => eprintln!("{}", format!("rmdir: {e}").red()),
        }
    }

    /// Rename a remote file (mv src dst).
    async fn cmd_mv(&self, line: &str) {
        let (src, dst) = split2(line);
        if src.is_empty() || dst.is_empty() {
            eprintln!("{}", "usage: mv <src> <dst>".yellow());
            return;
        }
        if !self.allow_write {
            eprintln!("{}", "write disabled  --  rerun with --allow-write".red());
            return;
        }

        let ((from_fh, from_name), (to_fh, to_name)) = match (self.resolve_parent(src).await, self.resolve_parent(dst).await) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => {
                eprintln!("{}", format!("mv: {e}").red());
                return;
            },
        };

        match self.ops.rename(&from_fh, &from_name, &to_fh, &to_name).await {
            Ok(()) => println!("{}", format!("{src} -> {dst}").green()),
            Err(e) => eprintln!("{}", format!("mv: {e}").red()),
        }
    }

    /// Copy a remote file (READ + CREATE + WRITE).
    async fn cmd_cp(&self, line: &str) {
        let (src, dst) = split2(line);
        if src.is_empty() || dst.is_empty() {
            eprintln!("{}", "usage: cp <src> <dst>".yellow());
            return;
        }
        if !self.allow_write {
            eprintln!("{}", "write disabled  --  rerun with --allow-write".red());
            return;
        }

        let (src_fh, src_info) = match self.lookup_path(src).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", format!("cp: {src}: {e}").red());
                return;
            },
        };

        let data = match self.ops.read_file(&src_fh).await {
            Ok(d) => d,
            Err(e) => {
                eprintln!("{}", format!("cp: read {src}: {e}").red());
                return;
            },
        };

        let (parent_fh, filename) = match self.resolve_parent(dst).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", format!("cp: {e}").red());
                return;
            },
        };

        let dst_fh = match self.ops.create_file(&parent_fh, &filename, src_info.mode).await {
            Ok(fh) => fh,
            Err(e) => {
                eprintln!("{}", format!("cp: create {dst}: {e}").red());
                return;
            },
        };

        match upload_data(&self.ops, &dst_fh, &data).await {
            Ok(n) => println!("{}", format!("copied {n} bytes {src} -> {dst}").green()),
            Err(e) => eprintln!("{}", format!("cp: write {dst}: {e}").red()),
        }
    }

    // -------------------------------------------------------------------------
    // Permissions
    // -------------------------------------------------------------------------

    /// Set file mode via SETATTR (chmod 755 file).
    async fn cmd_chmod(&self, line: &str) {
        let (mode_str, path) = split2(line);
        if mode_str.is_empty() || path.is_empty() {
            eprintln!("{}", "usage: chmod <octal-mode> <path>".yellow());
            return;
        }
        if !self.allow_write {
            eprintln!("{}", "write disabled  --  rerun with --allow-write".red());
            return;
        }

        let Ok(mode) = u32::from_str_radix(mode_str, 8) else {
            eprintln!("{}", format!("chmod: invalid mode {mode_str}").red());
            return;
        };

        let fh = match self.resolve_handle(Some(path)).await {
            Ok(fh) => fh,
            Err(e) => {
                eprintln!("{}", format!("chmod: {e}").red());
                return;
            },
        };

        match self.ops.set_mode(&fh, mode).await {
            Ok(()) => println!("{}", format!("mode set to {mode_str} on {path}").green()),
            Err(e) => eprintln!("{}", format!("chmod: {e}").red()),
        }
    }

    /// Set file owner via SETATTR (chown uid:gid file  or  chown uid file).
    async fn cmd_chown(&self, line: &str) {
        let (spec, path) = split2(line);
        if spec.is_empty() || path.is_empty() {
            eprintln!("{}", "usage: chown <uid>[:<gid>] <path>".yellow());
            return;
        }
        if !self.allow_write {
            eprintln!("{}", "write disabled  --  rerun with --allow-write".red());
            return;
        }

        let (uid_opt, gid_opt) = parse_uid_gid(spec);
        if uid_opt.is_none() && gid_opt.is_none() {
            eprintln!("{}", format!("chown: cannot parse {spec}").red());
            return;
        }

        let fh = match self.resolve_handle(Some(path)).await {
            Ok(fh) => fh,
            Err(e) => {
                eprintln!("{}", format!("chown: {e}").red());
                return;
            },
        };

        match self.ops.set_owner(&fh, uid_opt, gid_opt).await {
            Ok(()) => println!("{}", format!("ownership set on {path}").green()),
            Err(e) => eprintln!("{}", format!("chown: {e}").red()),
        }
    }

    /// Print detailed file attributes via GETATTR.
    async fn cmd_stat(&self, name: &str) {
        let fh = match self.resolve_handle(if name.is_empty() { None } else { Some(name) }).await {
            Ok(fh) => fh,
            Err(e) => {
                eprintln!("{}", format!("stat: {e}").red());
                return;
            },
        };
        match self.ops.getattr(&fh).await {
            Ok(info) => print_stat(if name.is_empty() { "." } else { name }, &info),
            Err(e) => eprintln!("{}", format!("stat: {e}").red()),
        }
    }

    /// Read and print a symlink's target via READLINK.
    async fn cmd_readlink(&self, name: &str) {
        if name.is_empty() {
            eprintln!("{}", "usage: readlink <symlink>".yellow());
            return;
        }
        let (fh, _) = match self.lookup_path(name).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", format!("readlink: {name}: {e}").red());
                return;
            },
        };
        match self.ops.readlink(&fh).await {
            Ok(target) => println!("{target}"),
            Err(e) => eprintln!("{}", format!("readlink: {e}").red()),
        }
    }

    /// Create a symbolic link. Usage: `symlink TARGET LINKNAME`.
    async fn cmd_symlink(&self, line: &str) {
        let (target, linkname) = split2(line);
        if target.is_empty() || linkname.is_empty() {
            eprintln!("{}", "usage: symlink <target> <linkname>".yellow());
            return;
        }
        if !self.allow_write {
            eprintln!("{}", "write disabled  --  rerun with --allow-write".red());
            return;
        }

        let (parent_fh, link_filename) = match self.resolve_parent(linkname).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", format!("symlink: {e}").red());
                return;
            },
        };

        match self.ops.symlink(&parent_fh, &link_filename, target).await {
            Ok(()) => println!("{}", format!("{linkname} -> {target}").green()),
            Err(e) => eprintln!("{}", format!("symlink: {e}").red()),
        }
    }

    /// Create a hard link (NFSv3 LINK RFC 1813 §3.3.15, NFSv2 LINK RFC 1094 §2.2.12).
    async fn cmd_link(&self, line: &str) {
        let (existing, linkname) = split2(line);
        if existing.is_empty() || linkname.is_empty() {
            eprintln!("{}", "usage: link <existing> <linkname>".yellow());
            return;
        }
        if !self.allow_write {
            eprintln!("{}", "write disabled  --  rerun with --allow-write".red());
            return;
        }

        let target_fh = match self.lookup_path(existing).await {
            Ok((fh, _)) => fh,
            Err(e) => {
                eprintln!("{}", format!("link: {existing}: {e}").red());
                return;
            },
        };
        let (parent_fh, link_filename) = match self.resolve_parent(linkname).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", format!("link: {linkname}: {e}").red());
                return;
            },
        };

        match self.ops.hard_link(&target_fh, &parent_fh, &link_filename).await {
            Ok(()) => println!("{}", format!("{linkname} => {existing}").green()),
            Err(e) => eprintln!("{}", format!("link: {e}").red()),
        }
    }

    // -------------------------------------------------------------------------
    // Identity
    // -------------------------------------------------------------------------

    /// Switch UID mid-session -- creates a new pool slot, no reconnect needed.
    /// AUTH_SYS credentials are client-asserted (RFC 5531 sec. 14).
    fn cmd_uid(&mut self, arg: &str) {
        if !self.ops.supports_identity_change() {
            eprintln!("{}", format!("uid: identity changes not supported on {}", self.ops.version_name()).red());
            return;
        }
        match arg.parse::<u32>() {
            Ok(uid) => {
                let gid = self.ops.gid();
                if let Err(e) = self.ops.change_identity(uid, gid, &self.hostname) {
                    eprintln!("{}", format!("uid: {e}").red());
                    return;
                }
                println!("{}", format!("uid={uid} gid={gid} hostname={}", self.hostname).green());
            },
            Err(_) => eprintln!("{}", format!("uid: invalid number: {arg}").red()),
        }
    }

    /// Switch GID mid-session.
    fn cmd_gid(&mut self, arg: &str) {
        if !self.ops.supports_identity_change() {
            eprintln!("{}", format!("gid: identity changes not supported on {}", self.ops.version_name()).red());
            return;
        }
        match arg.parse::<u32>() {
            Ok(gid) => {
                let uid = self.ops.uid();
                if let Err(e) = self.ops.change_identity(uid, gid, &self.hostname) {
                    eprintln!("{}", format!("gid: {e}").red());
                    return;
                }
                println!("{}", format!("uid={uid} gid={gid} hostname={}", self.hostname).green());
            },
            Err(_) => eprintln!("{}", format!("gid: invalid number: {arg}").red()),
        }
    }

    /// Spoof the AUTH_SYS machine name mid-session.
    ///
    /// Some NFS servers enforce per-hostname export ACLs in addition to IP-based ACLs.
    /// Changing the machinename in AUTH_SYS (RFC 1057 S9.2) can bypass hostname checks
    /// on misconfigured servers that trust the client-supplied value.
    fn cmd_hostname(&mut self, arg: &str) {
        if arg.is_empty() {
            println!("{}", self.hostname);
            return;
        }
        if !self.ops.supports_identity_change() {
            eprintln!("{}", format!("hostname: identity changes not supported on {}", self.ops.version_name()).red());
            return;
        }
        arg.clone_into(&mut self.hostname);
        let uid = self.ops.uid();
        let gid = self.ops.gid();
        if let Err(e) = self.ops.change_identity(uid, gid, &self.hostname) {
            eprintln!("{}", format!("hostname: {e}").red());
            return;
        }
        println!("{}", format!("hostname={}", self.hostname).green());
    }

    /// Print current AUTH_SYS identity.
    fn cmd_whoami(&self) {
        println!("uid={}  gid={}  hostname={}", self.ops.uid(), self.ops.gid(), self.ops.machinename());
    }

    /// Switch both UID and GID at once (impersonate uid:gid).
    fn cmd_impersonate(&mut self, arg: &str) {
        if !self.ops.supports_identity_change() {
            eprintln!("{}", format!("impersonate: identity changes not supported on {}", self.ops.version_name()).red());
            return;
        }
        let (uid_opt, gid_opt) = parse_uid_gid(arg);
        match (uid_opt, gid_opt) {
            (Some(uid), Some(gid)) => {
                if let Err(e) = self.ops.change_identity(uid, gid, &self.hostname) {
                    eprintln!("{}", format!("impersonate: {e}").red());
                    return;
                }
                println!("{}", format!("impersonating uid={uid} gid={gid}").green());
            },
            _ => eprintln!("{}", format!("impersonate: expected uid:gid  (got {arg:?})").red()),
        }
    }

    // -------------------------------------------------------------------------
    // Devices
    // -------------------------------------------------------------------------

    /// Create a device node via MKNOD. Usage: `mknod NAME c|b MAJOR MINOR`.
    ///
    /// Exploits RFC 1813 sec. 3.3.11  --  MKNOD can create char/block device nodes
    /// with arbitrary major/minor numbers, potentially enabling raw disk access.
    async fn cmd_mknod(&self, line: &str) {
        if !self.allow_write {
            eprintln!("{}", "write disabled  --  rerun with --allow-write".red());
            return;
        }
        if !self.ops.supports_mknod() {
            eprintln!("{}", format!("mknod: not supported on {}", self.ops.version_name()).red());
            return;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 4 {
            eprintln!("{}", "usage: mknod <name> c|b <major> <minor>".yellow());
            return;
        }
        let (name, dev_type_str, major, minor) = if let (Some(&n), Some(&t), Some(&maj), Some(&min)) = (parts.first(), parts.get(1), parts.get(2), parts.get(3)) {
            (n, t, maj.parse::<u32>().unwrap_or(0), min.parse::<u32>().unwrap_or(0))
        } else {
            eprintln!("{}", "usage: mknod <name> c|b <major> <minor>".yellow());
            return;
        };

        let dev_type = match dev_type_str {
            "c" => ShellDeviceType::Char,
            "b" => ShellDeviceType::Block,
            _ => {
                eprintln!("{}", "mknod: type must be 'c' (char) or 'b' (block)".red());
                return;
            },
        };

        let (parent_fh, node_name) = match self.resolve_parent(name).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", format!("mknod: {e}").red());
                return;
            },
        };

        match self.ops.mknod(&parent_fh, &node_name, dev_type, major, minor, 0o666).await {
            Ok(_) => println!("{}", format!("mknod: created {name} ({dev_type_str} {major}:{minor})").green()),
            Err(e) => eprintln!("{}", format!("mknod: {e}").red()),
        }
    }

    // -------------------------------------------------------------------------
    // Analysis
    // -------------------------------------------------------------------------

    /// Recursively walk and report SUID/SGID binaries.
    async fn cmd_suid_scan(&self) {
        eprintln!("{}", "[*] scanning for SUID/SGID binaries...".blue());
        let filter = |entry: &ShellEntry, path: &str| -> Option<String> {
            let a = entry.info.as_ref()?;
            // SUID = 0o4000, SGID = 0o2000 (RFC 1094 sec. 2.3.5)
            if a.file_type == ShellFileType::Regular && (a.mode & 0o6000 != 0) {
                let tag = match a.mode & 0o6000 {
                    0o6000 => "SUID+SGID",
                    0o4000 => "SUID",
                    _ => "SGID",
                };
                Some(format!("{} {:04o}  uid={}  {path}", format!("[!] {tag}").yellow().bold(), a.mode & 0o7777, a.uid))
            } else {
                None
            }
        };
        walk_recursive(&self.ops, self.cwd.clone(), self.cwd_path.clone(), &filter).await;
    }

    /// Recursively walk and report world-writable files and directories.
    async fn cmd_world_writable(&self) {
        eprintln!("{}", "[*] scanning for world-writable entries...".blue());
        let filter = |entry: &ShellEntry, path: &str| -> Option<String> {
            let a = entry.info.as_ref()?;
            // World-write bit = 0o002
            if a.mode & 0o002 != 0 {
                let tc = a.file_type.letter();
                Some(format!("{} {:04o}  uid={}  {path}", format!("[!] world-writable ({tc})").yellow(), a.mode & 0o7777, a.uid))
            } else {
                None
            }
        };
        walk_recursive(&self.ops, self.cwd.clone(), self.cwd_path.clone(), &filter).await;
    }

    /// Recursively walk and report files matching known credential/secret patterns.
    async fn cmd_secrets_scan(&self) {
        eprintln!("{}", "[*] scanning for secrets and credentials...".blue());
        let filter = |entry: &ShellEntry, path: &str| -> Option<String> {
            let lower = entry.name.to_ascii_lowercase();
            if SECRET_PATTERNS.iter().any(|pat| lower.contains(pat)) {
                let size = entry.info.as_ref().map_or(0, |a| a.size);
                let mode = entry.info.as_ref().map_or(0, |a| a.mode);
                // nfsd_permission() allows READ on execute-only regular files
                // (C702 sec. 12.3.3): NFSD_MAY_OWNER_OVERRIDE is unconditionally
                // added to every file-open check, so any user with execute
                // permission can READ the file despite mode bits denying it.
                let exec_implies_read = (mode & 0o111 != 0) && (mode & 0o444 == 0);
                let suffix = if exec_implies_read { "  [execute-implies-read: readable via NFS despite mode]" } else { "" };
                Some(format!("{} {path}  ({size} bytes  {:04o}){suffix}", "[!] potential secret:".yellow().bold(), mode & 0o7777))
            } else {
                None
            }
        };
        walk_recursive(&self.ops, self.cwd.clone(), self.cwd_path.clone(), &filter).await;
    }

    /// `last [N]` / `lastb [N]` -- decode `/var/log/wtmp` (or `/var/log/btmp`).
    ///
    /// Reads the binary log via NFS READ from the export root, parses it with
    /// the canonical 384-byte glibc `struct utmpx` layout, and applies the
    /// state machine from util-linux 2.42 `login-utils/last.c::process_wtmp_file`
    /// to pair USER_PROCESS with DEAD_PROCESS by ut_line and reconstruct
    /// boot/shutdown boundaries.
    ///
    /// Always-on knobs (per the project's "this is a security tool, allow
    /// everything" stance): full ctime timestamps, numeric IPs, system events
    /// shown, host column shown. Optional positional `N` caps the number of
    /// rendered records.
    async fn cmd_last(&self, arg: &str, lastb: bool) {
        let max_recs: Option<usize> = arg.split_whitespace().next().and_then(|s| s.parse().ok());
        let path = if lastb { "/var/log/btmp" } else { "/var/log/wtmp" };
        let label = if lastb { "lastb" } else { "last" };

        let (fh, info) = match self.lookup_path(path).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", format!("{label}: {path}: {e}").red());
                eprintln!("{}", format!("       (escape-root first if you're inside a sub-export; {path} lives on the underlying filesystem)").yellow());
                return;
            },
        };
        if info.size == 0 {
            println!("{}", format!("{path} is empty -- no records to show").yellow());
            return;
        }
        let bytes = match self.ops.read_file(&fh).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{}", format!("{label}: read {path}: {e}").red());
                return;
            },
        };
        let recs = parse_utmp(&bytes);
        if recs.is_empty() {
            println!("{}", format!("{path}: no parseable records ({} bytes / {UTMP_RECORD_SIZE} per record)", bytes.len()).yellow());
            return;
        }
        if lastb {
            render_lastb(&recs, max_recs);
        } else {
            render_last(&recs, max_recs);
        }
    }

    /// `lastlog` -- decode `/var/log/lastlog` (uid-indexed 292-byte slots).
    ///
    /// Per util-linux 2.42 `liblastlog2/src/lastlog2.c::ll2_import_lastlog()`,
    /// each slot at offset `uid * 292` holds the user's most recent successful
    /// login (`ll_time` 0 == never). UIDs are mapped to usernames by reading
    /// `/etc/passwd` from the same export. The newer SQLite-backed
    /// `/var/lib/lastlog/lastlog2.db` (util-linux 2.42 default) is reported as
    /// a `get` hint when `/var/log/lastlog` is missing or empty -- pure-Rust
    /// SQLite parsing is out of scope for this command.
    async fn cmd_lastlog(&self, _arg: &str) {
        let lastlog_path = "/var/log/lastlog";
        let (fh, info) = match self.lookup_path(lastlog_path).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", format!("lastlog: {lastlog_path}: {e}").red());
                self.lastlog_hint_lastlog2().await;
                return;
            },
        };
        if info.size == 0 {
            println!("{}", format!("{lastlog_path} is empty -- no users have logged in interactively").yellow());
            self.lastlog_hint_lastlog2().await;
            return;
        }
        let bytes = match self.ops.read_file(&fh).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{}", format!("lastlog: read {lastlog_path}: {e}").red());
                return;
            },
        };
        let recs = parse_lastlog(&bytes);

        // Map UIDs to usernames via /etc/passwd if reachable; missing entries
        // render as "uid=N" rather than failing the whole command.
        let uid_to_user: Vec<(u32, String)> = match self.lookup_path("/etc/passwd").await {
            Ok((pfh, _)) => match self.ops.read_file(&pfh).await {
                Ok(b) => parse_passwd(&b),
                Err(e) => {
                    eprintln!("{}", format!("lastlog: /etc/passwd unreadable ({e}); rendering UIDs numerically").yellow());
                    Vec::new()
                },
            },
            Err(e) => {
                eprintln!("{}", format!("lastlog: /etc/passwd lookup failed ({e}); rendering UIDs numerically").yellow());
                Vec::new()
            },
        };
        render_lastlog(&recs, &uid_to_user);
    }

    /// Hint that the new SQLite-backed lastlog2 database might exist when the
    /// classic flat file is missing or empty. Util-linux 2.42 made lastlog2 the
    /// default, but the format requires a SQLite reader so we just point the
    /// operator at `get` for offline analysis.
    async fn lastlog_hint_lastlog2(&self) {
        let candidate = "/var/lib/lastlog/lastlog2.db";
        if let Ok((_fh, attrs)) = self.lookup_path(candidate).await {
            eprintln!(
                "{}",
                format!(
                    "[*] note: {candidate} is present ({} bytes); util-linux 2.42 uses an SQLite database here. \
                     Run 'get {candidate} ./lastlog2.db' and read it with `sqlite3 lastlog2.db 'select * from Lastlog2'`.",
                    attrs.size
                )
                .cyan()
            );
        }
    }

    /// Construct a filesystem-root escape handle from the current export handle.
    ///
    /// Discover reachable sibling exports via LOOKUPP traversal (F-2.12).
    ///
    /// Walks upward from the current directory via LOOKUP ".." until the handle
    /// stabilizes (pseudo-root or filesystem root), then lists all children at
    /// each level. On NFSv4, this reveals the full pseudo-FS tree including
    /// exports the client may not have been granted via MOUNT ACLs.
    async fn cmd_exports(&self) {
        /// Safety cap on parent traversal depth.
        const MAX_DEPTH: u32 = 32;
        /// Maximum directory recursion depth when enumerating sub-exports.
        const MAX_RECURSE: u32 = 4;

        struct DirItem {
            handle: ShellHandle,
            path: String,
            recurse_depth: u32,
        }

        eprintln!("{}", "Discovering reachable exports via parent traversal...".cyan());

        let mut current = self.cwd.clone();
        let mut path = self.cwd_path.clone();
        let mut depth = 0u32;

        // Walk up until handle stops changing (root is its own parent).
        loop {
            if depth >= MAX_DEPTH {
                eprintln!("{}", "  hit depth cap -- stopping".yellow());
                break;
            }
            let Ok((parent, _)) = self.ops.lookup_path(&current, "..").await else {
                break;
            };
            if parent == current {
                break;
            }
            current = parent;
            depth += 1;
            // Update path tracking
            if path == "/" {
                // already at root
            } else if let Some(idx) = path.rfind('/') {
                path = if idx == 0 { "/".to_owned() } else { path[..idx].to_owned() };
            } else {
                "/".clone_into(&mut path);
            }
        }

        eprintln!("{}", format!("Reached top: {path} (depth {depth})").cyan());
        eprintln!();

        // Walk down from the top, listing directories at each level. On NFSv4
        // the pseudo-FS tree typically has 2-3 levels (/, /srv, /srv/nfs) before
        // reaching real exports. We recurse 4 levels deep to cover all layouts.
        let mut export_count = 0u32;
        let mut stack = vec![DirItem { handle: current, path, recurse_depth: 0 }];

        while let Some(item) = stack.pop() {
            let Ok(entries) = self.ops.list_dir(&item.handle).await else {
                continue;
            };

            for entry in &entries {
                if entry.name == "." || entry.name == ".." {
                    continue;
                }
                let info = entry.info.as_ref();
                if !info.is_some_and(|i| i.file_type == ShellFileType::Directory) {
                    continue;
                }

                let child_handle = if let Some(ref h) = entry.handle {
                    h.clone()
                } else if let Ok((h, _)) = self.ops.lookup(&item.handle, &entry.name).await {
                    h
                } else {
                    continue;
                };

                let full = format!("{}/{}", item.path.trim_end_matches('/'), entry.name);

                if let Ok(children) = self.ops.list_dir(&child_handle).await {
                    let count = children.iter().filter(|e| e.name != "." && e.name != "..").count();
                    let uid = info.map_or(0, |i| i.uid);
                    let mode = info.map_or(0, |i| i.mode);
                    println!("  {}  {:<40} {:>3} entries  uid={}  mode={:04o}", "[+]".green().bold(), full, count, uid, mode);
                    export_count += 1;
                    // Recurse deeper to find sub-exports.
                    if item.recurse_depth < MAX_RECURSE {
                        stack.push(DirItem { handle: child_handle, path: full, recurse_depth: item.recurse_depth + 1 });
                    }
                } else {
                    println!("  {}  {:<40} {}", "[!]".yellow(), full, "access denied".yellow());
                    export_count += 1;
                }
            }
        }

        eprintln!();
        eprintln!("{}", format!("{export_count} directories discovered").cyan());
        if depth > 0 {
            eprintln!("{}", format!("  traversed {depth} levels via LOOKUPP (F-2.12)").cyan());
        }
    }

    /// Delegates to the shared escape engine (`engine::escape::find_escape_root`)
    /// which covers ext4, XFS, BTRFS, ZFS, and a brute-force inode scan.
    /// Implements F-2.1: when subtree_check is disabled (Linux default), the server
    /// only validates the fsid in the handle, not that the inode falls within the export.
    async fn cmd_escape_root(&mut self) {
        let probe = ShellEscapeProbe { ops: &self.ops };
        let config = EscapeConfig { announce: true, ..EscapeConfig::default() };

        match find_escape_root(&probe, self.cwd.as_bytes(), &config).await {
            EscapeRootOutcome::Success(result) => {
                let handle = ShellHandle(result.root_handle.as_bytes().to_vec());
                eprintln!("{}", format!("[+] escaped to filesystem root ({:?}, inode {})", result.fs_type, result.inode_number).green().bold());
                eprintln!("{}", format!("    handle: {}", handle.to_hex()).cyan());
                // Probe attrs for display
                if let Ok(info) = self.ops.getattr(&handle).await {
                    eprintln!("{}", format!("    inode: {}  type: {}  mode: {:04o}", info.fileid, info.type_name(), info.mode & 0o7777).cyan());
                }
                self.export_root = handle.clone();
                self.cwd = handle;
                self.cwd_path = String::from("/ [escaped]");
                self.refresh_tab_cache().await;
            },
            EscapeRootOutcome::StaleNoRoot => {
                eprintln!("{}", "[!] handle format valid (STALE hits) but root not found in scan range -- try nfswolf escape with --max-root-scan".yellow());
            },
            EscapeRootOutcome::Unsupported => {
                eprintln!("{}", "escape-root: server rejected handle format (non-Linux or unsupported filesystem)".red());
            },
        }
    }

    /// Switch the current directory to an arbitrary file handle (hex).
    ///
    /// File handles are bearer tokens (RFC 1094 sec. 2.3.3) -- any obtained handle
    /// can be used as a root regardless of how it was obtained.
    async fn cmd_mount_handle(&mut self, hex: &str) {
        if hex.is_empty() {
            eprintln!("{}", "usage: mount-handle <hex>".yellow());
            return;
        }

        let fh = match ShellHandle::from_hex(hex) {
            Ok(fh) => fh,
            Err(e) => {
                eprintln!("{}", format!("mount-handle: invalid hex: {e}").red());
                return;
            },
        };

        match self.ops.getattr(&fh).await {
            Ok(info) => {
                eprintln!("{}", format!("[+] handle OK  type={}  inode={}", info.type_name(), info.fileid).green());
                self.cwd = fh;
                self.cwd_path = String::from("<handle>");
                self.refresh_tab_cache().await;
            },
            Err(e) => eprintln!("{}", format!("mount-handle: {e}").red()),
        }
    }

    /// Probe the obsolete NFSPROC_ROOT (proc 3) for a MOUNT bypass.
    async fn cmd_root(&mut self) {
        match self.ops.probe_root().await {
            Ok(Some(fh)) => {
                eprintln!("{}", "[!] Server returned a root handle via NFSPROC_ROOT -- MOUNT bypass!".red().bold());
                eprintln!("    handle: {}", fh.to_hex());
                eprintln!("    This is obsolete per RFC 1094 sec. 2.2.3. A server that");
                eprintln!("    responds to it gives any client the root handle without");
                eprintln!("    going through MOUNT's export ACL checks.");
                self.cwd = fh;
            },
            Ok(None) => println!("{}", "NFSPROC_ROOT: server did not return a handle (expected -- procedure is obsolete since RFC 1094)".yellow()),
            Err(e) => eprintln!("{}", format!("NFSPROC_ROOT: {e}").yellow()),
        }
    }

    /// Probe the server's write verifier via zero-count COMMIT (reboot oracle).
    ///
    /// The writeverf3 is an opaque 8-byte value the server regenerates on reboot
    /// (RFC 1813 S3.3.21). Comparing verifiers across probes detects server
    /// restarts without requiring any write traffic.
    async fn cmd_verifier(&self) {
        match self.ops.write_verifier(&self.cwd).await {
            Ok(Some(verf)) => {
                use std::fmt::Write as _;
                let hex = verf.iter().fold(String::with_capacity(16), |mut s, b| {
                    let _ = write!(s, "{b:02x}");
                    s
                });
                println!("writeverf3: {hex}");
            },
            Ok(None) => println!("{}", "verifier: COMMIT not available on this NFS version".yellow()),
            Err(e) => eprintln!("{}", format!("verifier: {e}").red()),
        }
    }

    // -------------------------------------------------------------------------
    // Local filesystem
    // -------------------------------------------------------------------------

    fn cmd_lcd(&mut self, dir: &str) {
        let _ = self;
        let d = if dir.is_empty() { "." } else { dir };
        match std::env::set_current_dir(d) {
            Ok(()) => println!("{}", std::env::current_dir().map_or_else(|_| d.to_owned(), |p| p.display().to_string()).green()),
            Err(e) => eprintln!("{}", format!("lcd: {e}").red()),
        }
    }

    fn cmd_lls(&mut self, path: &str) {
        let _ = self;
        let target = if path.is_empty() { "." } else { path };
        match std::fs::read_dir(target) {
            Ok(iter) => {
                let mut names: Vec<String> = iter.filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).collect::<Vec<_>>();
                names.sort();
                for n in &names {
                    println!("{n}");
                }
            },
            Err(e) => eprintln!("{}", format!("lls: {e}").red()),
        }
    }

    fn cmd_lpwd(&mut self) {
        let _ = self;
        match std::env::current_dir() {
            Ok(p) => println!("{}", p.display()),
            Err(e) => eprintln!("{}", format!("lpwd: {e}").red()),
        }
    }

    fn cmd_lmkdir(&mut self, dir: &str) {
        let _ = self;
        if dir.is_empty() {
            eprintln!("{}", "usage: lmkdir <dir>".yellow());
            return;
        }
        match std::fs::create_dir_all(dir) {
            Ok(()) => println!("{}", format!("created {dir}").green()),
            Err(e) => eprintln!("{}", format!("lmkdir: {e}").red()),
        }
    }

    // -------------------------------------------------------------------------
    // Session
    // -------------------------------------------------------------------------

    fn cmd_history(&self) {
        for (i, line) in self.history.iter().enumerate() {
            println!("{:4}  {line}", i + 1);
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Resolve an optional name to a `ShellHandle` via LOOKUP (None = cwd).
    async fn resolve_handle(&self, name: Option<&str>) -> anyhow::Result<ShellHandle> {
        match name {
            None => Ok(self.cwd.clone()),
            Some(n) => self.lookup_path(n).await.map(|(fh, _)| fh),
        }
    }

    /// Resolve a path to (ShellHandle, ShellFileInfo), handling absolute and relative paths.
    ///
    /// Paths starting with '/' are resolved from the export root (bearer token reuse
    /// per RFC 1094 sec. 2.3.3). Relative paths start from the current directory.
    async fn lookup_path(&self, path: &str) -> anyhow::Result<(ShellHandle, ShellFileInfo)> {
        let start = if path.starts_with('/') { &self.export_root } else { &self.cwd };
        self.ops.lookup_path(start, path).await
    }

    /// Resolve a path into (parent_dir_fh, filename) for create/rename/remove operations.
    async fn resolve_parent(&self, path: &str) -> anyhow::Result<(ShellHandle, String)> {
        match path.rfind('/') {
            None => Ok((self.cwd.clone(), path.to_owned())),
            Some(pos) => {
                let parent_str = if pos == 0 { "/" } else { &path[..pos] };
                let name = path[pos + 1..].to_owned();
                if name.is_empty() {
                    anyhow::bail!("path must not end with '/'");
                }
                let (fh, _) = self.lookup_path(parent_str).await?;
                Ok((fh, name))
            },
        }
    }

    /// Print the command reference, adapted per NFS version.
    fn print_help(&self) {
        let ver = self.ops.version_name();
        println!("{}", format!("{ver} shell commands:").bold());
        println!();
        println!("{}", "Navigation:".bold().underline());
        println!("  ls [-a] [--sort=FIELD] [-r] [path]  list directory (aliases: ll = ls -a, dir)");
        println!("  cd <path>                  change directory  (/ = export root, /abs = absolute)");
        println!("  pwd                        print current path");
        println!("  tree [depth]               recursive tree (default depth 3; hidden dirs always shown)");
        println!("  find <pattern>             find filenames containing pattern");
        println!();
        println!("{}", "File operations:".bold().underline());
        println!("  cat <file>                 print file contents (alias: type)");
        println!("  get [-r] <remote> [local | dir/]  download file/tree (alias: download)");
        println!("  put [-r] <local> <remote>  upload file/tree  (alias: upload)  [--allow-write]");
        println!("  rm <file>                  remove file (alias: del)  [--allow-write]");
        println!("  mkdir <dir>                create directory  [--allow-write]");
        println!("  rmdir <dir>                remove directory  [--allow-write]");
        println!("  mv <src> <dst>             rename/move (alias: rename)  [--allow-write]");
        println!("  cp <src> <dst>             copy file (alias: copy)  [--allow-write]");
        println!("  symlink <target> <name>    create symlink  [--allow-write]");
        println!("  link <existing> <name>     create hard link  [--allow-write]");
        println!("  readlink <path>            read symlink target");
        println!();
        println!("{}", "Attributes:".bold().underline());
        println!("  stat [path]                show file attributes");
        println!("  chmod <mode> <path>        set mode (octal)  [--allow-write]");
        println!("  chown <uid>[:<gid>] <path> set owner  [--allow-write]");
        println!();
        if self.ops.supports_identity_change() {
            println!("{}", "Identity  (AUTH_SYS is client-asserted, RFC 5531 sec. 14):".bold().underline());
        } else {
            println!("{}", "Identity  (read-only on this version):".bold().underline());
        }
        println!("  whoami                     show current uid:gid (alias: id)");
        if self.ops.supports_identity_change() {
            println!("  uid <n>                    switch UID");
            println!("  gid <n>                    switch GID");
            println!("  hostname <name>            spoof AUTH_SYS machinename");
            println!("  impersonate <uid>:<gid>    switch both (alias: su)");
        }
        println!();
        if self.ops.supports_mknod() {
            println!("{}", "Devices:".bold().underline());
            println!("  mknod <name> c|b <maj> <min>  create device node  [--allow-write]");
            println!();
        }
        println!("{}", "Analysis:".bold().underline());
        println!("  suid-scan                  find SUID/SGID binaries");
        println!("  world-writable             find world-writable files");
        println!("  secrets-scan               find credential/secret files");
        println!("  exports                    discover sibling exports via LOOKUPP (F-2.12)");
        println!("  last [N]                   decode /var/log/wtmp (login history; per util-linux 2.42 last.c)");
        println!("  lastb [N]                  decode /var/log/btmp (failed-login history)");
        println!("  lastlog                    decode /var/log/lastlog (last login per UID)");
        println!();
        println!("{}", "Escape (F-2.1 -- construct filesystem root handle):".bold().underline());
        println!("  escape-root                build and switch to FS root handle");
        println!("  mount-handle <hex>         jump to arbitrary file handle");
        println!("  handle                     print current dir handle (hex)");
        if self.ops.version_name() == "NFSv2" {
            println!("  root                       probe NFSPROC_ROOT (obsolete MOUNT bypass)");
        }
        if self.ops.version_name() == "NFSv3" {
            println!("  verifier                   probe write verifier (reboot oracle, RFC 1813 S3.3.21)");
        }
        println!();
        println!("{}", "Local:".bold().underline());
        println!("  lcd [dir]   lls [dir]   lpwd   lmkdir <dir>");
        println!();
        println!("{}", "Session:".bold().underline());
        println!("  history     help     exit");
    }
}

// =============================================================================
// Version-neutral helpers (generic over ShellOps)
// =============================================================================

/// Hard cap on a single in-memory read. The NFS server is untrusted; a hostile
/// or buggy server can return endless non-EOF chunks, so `download_file` must bound
/// its buffer instead of growing until OOM.
///
/// Download `fh` to a local file path via ShellOps, reading in chunks.
///
/// Returns `(bytes_written, sha256_hex)`.  The SHA-256 is computed over the
/// full downloaded content and printed alongside the byte count so the operator
/// has an instant integrity reference for report evidence chains.
async fn download_file<O: ShellOps>(ops: &O, fh: &ShellHandle, dest_path: &str) -> anyhow::Result<(u64, String)> {
    let mut file = std::fs::File::create(dest_path).map_err(|e| anyhow::anyhow!("create {dest_path}: {e}"))?;
    let mut hasher = Sha256::new();
    let mut offset = 0u64;
    loop {
        let data = ops.read_chunk(fh, offset, CHUNK_SIZE).await?;
        if data.is_empty() {
            break;
        }
        file.write_all(&data).map_err(|e| anyhow::anyhow!("write: {e}"))?;
        hasher.update(&data);
        offset = offset.saturating_add(data.len() as u64);
        if offset > READ_ALL_MAX {
            anyhow::bail!("download aborted at {offset} bytes: exceeds {READ_ALL_MAX}-byte cap (untrusted server returning endless non-EOF data)");
        }
    }
    let hash = hasher.finalize().iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    });
    Ok((offset, hash))
}

/// Write `data` to `fh` in CHUNK_SIZE slices via ShellOps.
///
/// Driven by a byte cursor into `data`: NFSv3 WRITE may legally write fewer
/// bytes than requested (RFC 1813 sec. 3.3.7), so we advance only by the
/// server-acknowledged count, resending the unwritten tail from the exact byte.
async fn upload_data<O: ShellOps>(ops: &O, fh: &ShellHandle, data: &[u8]) -> anyhow::Result<u64> {
    let chunk_size = usize::try_from(CHUNK_SIZE).unwrap_or(65536);
    let mut pos = 0usize;
    while pos < data.len() {
        let end = pos.saturating_add(chunk_size).min(data.len());
        let Some(slice) = data.get(pos..end) else { break };
        let written = ops.write_chunk(fh, pos as u64, slice).await?;
        let adv = usize::try_from(written).unwrap_or(0).min(slice.len());
        if adv == 0 {
            anyhow::bail!("WRITE at {pos}: server acknowledged 0 bytes (no progress)");
        }
        pos = pos.saturating_add(adv);
    }
    Ok(pos as u64)
}

/// Recursively download a remote directory tree to a local path.
///
/// Creates `local_root` if it does not exist. Descends into subdirectories.
/// Shows a single spinner progress bar shared across the entire tree walk.
/// Returns total bytes downloaded.
fn download_tree<'a, O: ShellOps>(ops: &'a O, dir_fh: &'a ShellHandle, local_root: &'a str, mp: &'a MultiProgress) -> Pin<Box<dyn Future<Output = anyhow::Result<u64>> + Send + 'a>> {
    Box::pin(async move {
        std::fs::create_dir_all(local_root).map_err(|e| anyhow::anyhow!("mkdir {local_root}: {e}"))?;

        let bar = mp.add(ProgressBar::new_spinner());
        bar.set_style(ProgressStyle::default_spinner().template("{spinner} {msg}").unwrap_or_else(|_| ProgressStyle::default_spinner()));
        bar.set_message(local_root.to_owned());

        let entries = ops.list_dir(dir_fh).await?;
        let mut total = 0u64;

        for entry in &entries {
            if !is_safe_local_name(&entry.name) {
                tracing::warn!("skipping entry with unsafe server-supplied name {:?} (path-traversal guard)", entry.name);
                continue;
            }
            let local_entry = format!("{local_root}/{}", entry.name);
            let is_dir = entry.info.as_ref().is_some_and(|a| a.file_type == ShellFileType::Directory);

            if is_dir {
                if let Some(ref fh) = entry.handle {
                    total += download_tree(ops, fh, &local_entry, mp).await?;
                }
            } else {
                let fh = match &entry.handle {
                    Some(fh) => fh.clone(),
                    None => match ops.lookup(dir_fh, &entry.name).await {
                        Ok((fh, _)) => fh,
                        Err(e) => {
                            tracing::warn!("skip {}: {e}", entry.name);
                            continue;
                        },
                    },
                };
                bar.set_message(format!("{local_root}/{}", entry.name));
                match download_file(ops, &fh, &local_entry).await {
                    Ok((bytes, _hash)) => {
                        total += bytes;
                        bar.inc(1);
                    },
                    Err(e) => tracing::warn!("download {}: {e}", entry.name),
                }
            }
        }

        bar.finish_and_clear();
        Ok(total)
    })
}

/// Recursively upload a local directory tree to a remote directory via ShellOps.
fn upload_tree<'a, O: ShellOps>(ops: &'a O, local_dir: &'a Path, remote_fh: &'a ShellHandle, mp: &'a MultiProgress) -> Pin<Box<dyn Future<Output = anyhow::Result<u64>> + Send + 'a>> {
    Box::pin(async move {
        let bar = mp.add(ProgressBar::new_spinner());
        bar.set_style(ProgressStyle::default_spinner().template("{spinner} {msg}").unwrap_or_else(|_| ProgressStyle::default_spinner()));
        bar.set_message(local_dir.display().to_string());

        let mut total = 0u64;
        let read_dir = std::fs::read_dir(local_dir).map_err(|e| anyhow::anyhow!("read_dir {}: {e}", local_dir.display()))?;

        for entry_result in read_dir {
            let entry = match entry_result {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("read_dir entry: {e}");
                    continue;
                },
            };
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let local_path = entry.path();
            bar.set_message(name_str.as_ref().to_owned());

            if local_path.is_dir() {
                #[cfg(unix)]
                let dir_mode = entry.metadata().map_or(0o755, |m| m.permissions().mode() & 0o7777);
                #[cfg(not(unix))]
                let dir_mode = 0o755;
                let sub_fh = match ops.mkdir(remote_fh, name_str.as_ref(), dir_mode).await {
                    Ok(fh) => fh,
                    Err(e) => {
                        tracing::warn!("mkdir {name_str}: {e}");
                        continue;
                    },
                };
                total += upload_tree(ops, &local_path, &sub_fh, mp).await?;
            } else {
                #[cfg(unix)]
                let file_mode = entry.metadata().map_or(0o644, |m| m.permissions().mode() & 0o7777);
                #[cfg(not(unix))]
                let file_mode = 0o644;
                let data = match std::fs::read(&local_path) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::warn!("read {}: {e}", local_path.display());
                        continue;
                    },
                };
                let file_fh = match ops.create_file(remote_fh, name_str.as_ref(), file_mode).await {
                    Ok(fh) => fh,
                    Err(e) => {
                        tracing::warn!("create {name_str}: {e}");
                        continue;
                    },
                };
                match upload_data(ops, &file_fh, &data).await {
                    Ok(n) => {
                        total += n;
                        bar.inc(1);
                    },
                    Err(e) => tracing::warn!("write {name_str}: {e}"),
                }
            }
        }

        bar.finish_and_clear();
        Ok(total)
    })
}

/// Recursive tree display via ShellOps. Uses Box::pin to allow async recursion.
fn tree_recursive<'a, O: ShellOps>(ops: &'a O, dir_fh: ShellHandle, prefix: String, depth: usize, max_depth: usize) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
    Box::pin(async move {
        if depth >= max_depth {
            return;
        }

        let entries = match ops.list_dir(&dir_fh).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{prefix}  [error: {e}]");
                return;
            },
        };

        let real: Vec<_> = entries.iter().filter(|e| e.name != "." && e.name != "..").collect();
        let total = real.len();
        for (i, entry) in real.iter().enumerate() {
            let is_last = i + 1 == total;
            let branch = if is_last { "\\-- " } else { "+-- " };
            let child_prefix = format!("{prefix}{}", if is_last { "    " } else { "|   " });
            let tc = entry.info.as_ref().map_or('?', |a| a.file_type.letter());
            let name = colorize_name(&entry.name, tc);
            println!("{prefix}{branch}{name}");
            // Descend into directories. When the listing credential couldn't
            // stat the entry (tc == '?'), probe with getattr so restricted
            // dot-dirs still expand.
            if let Some(ref fh) = entry.handle {
                let is_dir = match tc {
                    'd' => true,
                    '?' => ops.getattr(fh).await.is_ok_and(|a| a.file_type == ShellFileType::Directory),
                    _ => false,
                };
                if is_dir {
                    tree_recursive(ops, fh.clone(), child_prefix, depth + 1, max_depth).await;
                }
            }
        }
    })
}

/// Generic recursive directory walker with a per-entry filter.
///
/// Walks the tree rooted at `handle`, building full paths from `base_path`.
/// For each non-dot entry, calls `filter(entry, full_path)`. If the filter
/// returns `Some(line)`, the line is printed. Directories are always recursed
/// into regardless of filter outcome, matching the behavior of the individual
/// scanners this replaces (suid-scan, world-writable, secrets-scan, find).
fn walk_recursive<'a, O: ShellOps, F>(ops: &'a O, handle: ShellHandle, base_path: String, filter: &'a F) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>
where
    F: Fn(&ShellEntry, &str) -> Option<String> + Send + Sync,
{
    Box::pin(async move {
        let Ok(entries) = ops.list_dir(&handle).await else { return };
        for entry in &entries {
            if entry.name == "." || entry.name == ".." {
                continue;
            }
            let full_path = format!("{}/{}", base_path.trim_end_matches('/'), entry.name);
            if let Some(line) = filter(entry, &full_path) {
                println!("{line}");
            }
            if entry.info.as_ref().is_some_and(|a| a.file_type == ShellFileType::Directory)
                && let Some(ref fh) = entry.handle
            {
                walk_recursive(ops, fh.clone(), full_path, filter).await;
            }
        }
    })
}

/// Validate that a server-supplied directory-entry name is safe to use as a
/// single local path component during recursive download (`get -r`).
///
/// The NFS server is untrusted (threat model): directory-entry names come
/// verbatim from the READDIRPLUS reply, so a hostile server can return a name
/// like `../../../etc/cron.d/pwn` to escape the operator's chosen download root
/// -- a zip-slip-class arbitrary local file write (and remote code execution
/// when nfswolf runs under sudo). Accept only a lone, normal path component:
/// reject empty, `.`, `..`, an embedded path separator, or a NUL byte.
fn is_safe_local_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\0')
}

/// Common credential/secret filename patterns to flag during a secrets scan.
const SECRET_PATTERNS: &[&str] = &[
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".env",
    "shadow",
    "passwd",
    ".htpasswd",
    "credentials",
    "secret",
    "password",
    "token",
    "apikey",
    "api_key",
    "private_key",
    "privkey",
    ".pem",
    ".p12",
    ".pfx",
    ".kdbx",
    "authorized_keys",
    "known_hosts",
    "docker-compose",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    "wp-config.php",
    "settings.py",
    "database.yml",
    "config.php",
    "secrets.yaml",
    "secrets.json",
    ".aws",
    ".ssh",
];
// =============================================================================
// Pure formatting helpers
// =============================================================================

/// Format a Unix permission mode word as `rwxrwxrwx` (9 chars).
fn format_mode(mode: u32) -> String {
    ops::format_rwx(mode)
}

/// Colorize a directory entry name by type.
fn colorize_name(name: &str, tc: char) -> String {
    match tc {
        'd' => name.blue().bold().to_string(),
        'l' => name.cyan().to_string(),
        'b' | 'c' => name.yellow().to_string(),
        _ => name.to_owned(),
    }
}

/// Print detailed stat output for a file (version-neutral).
fn print_stat(name: &str, a: &ShellFileInfo) {
    println!("  File: {name}");
    println!("  Type: {}", a.type_name());
    println!("  Mode: {:04o} ({})  Links: {}", a.mode & 0o7777, a.mode_string(), a.nlink);
    println!("   UID: {}  GID: {}", a.uid, a.gid);
    println!(" Inode: {}  FSID: {}", a.fileid, a.fsid);
    println!("  Size: {} bytes  Used: {} bytes (disk)", a.size, a.used);
    if a.file_type == ShellFileType::Block || a.file_type == ShellFileType::Character {
        println!(" Rdev: {}:{}", a.rdev.0, a.rdev.1);
    }
    println!(" atime: {}  ({})", fmt_unix_time(a.atime_secs), a.atime_secs);
    println!(" mtime: {}  ({})", fmt_unix_time(a.mtime_secs), a.mtime_secs);
    println!(" ctime: {}  ({})", fmt_unix_time(a.ctime_secs), a.ctime_secs);
}

/// Build a display path by appending `target` to `cwd`.
///
/// Handles `..` (pop last component) and strips trailing slashes.
fn build_path(cwd: &str, target: &str) -> String {
    let mut components: Vec<&str> = cwd.split('/').filter(|c| !c.is_empty()).collect();
    for part in target.split('/').filter(|c| !c.is_empty()) {
        if part == ".." {
            _ = components.pop();
        } else if part != "." {
            components.push(part);
        }
    }
    if components.is_empty() { "/".to_owned() } else { format!("/{}", components.join("/")) }
}

/// Split a string at the first whitespace into (first, rest).
fn split2(line: &str) -> (&str, &str) {
    let line = line.trim();
    match line.find(|c: char| c.is_whitespace()) {
        Some(pos) => (line[..pos].trim(), line[pos..].trim()),
        None => (line, ""),
    }
}

/// Resolve the local destination path for `get <remote> [local]`.
///
/// `local_is_dir` reports whether `local` already exists as a directory. When
/// `local` is empty the remote basename is used; when `local` names a directory
/// (existing, or written with a trailing `/`) the basename is appended so
/// `get /etc/passwd /home/test/` lands at `/home/test/passwd`; otherwise `local`
/// is used verbatim. Mirrors `cp` / `scp` destination semantics.
fn resolve_get_dest(remote: &str, local: &str, local_is_dir: bool) -> String {
    let basename = remote.rsplit('/').find(|s| !s.is_empty()).unwrap_or(remote);
    if local.is_empty() {
        basename.to_owned()
    } else if local.ends_with('/') || local_is_dir {
        let dir = local.trim_end_matches('/');
        if dir.is_empty() { format!("/{basename}") } else { format!("{dir}/{basename}") }
    } else {
        local.to_owned()
    }
}

/// Sort field selector for the `ls` command.
#[derive(Default, Clone, Copy, Debug)]
enum LsSort {
    /// Alphabetical by filename (default).
    #[default]
    Name,
    /// Ascending inode number (fileid).
    Inode,
    /// Ascending file size.
    Size,
    /// Ascending owner UID.
    Uid,
    /// Ascending owner GID.
    Gid,
    /// Ascending permission mode bits.
    Mode,
    /// Ascending modification time (mtime).
    Mtime,
    /// Ascending metadata-change time (ctime).
    Ctime,
    /// Ascending access time (atime).
    Atime,
}

/// Strip a known flag token from the front of `s`.
///
/// Returns `Some(remainder)` only when the flag is followed by whitespace or
/// end of string, preventing partial matches (e.g. `--reverse-foo`).
fn strip_flag<'a>(s: &'a str, flag: &str) -> Option<&'a str> {
    let after = s.strip_prefix(flag)?;
    if after.is_empty() || after.starts_with(|c: char| c.is_whitespace()) { Some(after.trim_start()) } else { None }
}

/// Parse `ls [--sort=FIELD] [-r|--reverse] [-a] [path]` into
/// `(sort, reverse, all_cols, path)`.
///
/// Flags may appear in any order before the path argument.
/// `-a` enables the extended column set: inode, nlink, used, rdev, atime, ctime.
/// Recognised FIELD values: name, inode, size, uid, gid, mode, mtime, ctime, atime.
/// Unknown fields fall back to `LsSort::Name`.
fn parse_ls_args(raw: &str) -> (LsSort, bool, bool, &str) {
    let mut rest = raw.trim();
    let mut sort = LsSort::default();
    let mut reverse = false;
    let mut all_cols = false;

    // Consume flags left-to-right; stop at the first unrecognised token (= path).
    loop {
        if let Some(after_sort) = rest.strip_prefix("--sort=") {
            let (field, remainder) = split2(after_sort);
            sort = match field {
                "inode" | "fileid" => LsSort::Inode,
                "size" => LsSort::Size,
                "uid" => LsSort::Uid,
                "gid" => LsSort::Gid,
                "mode" | "perms" => LsSort::Mode,
                "mtime" | "time" => LsSort::Mtime,
                "ctime" | "change" => LsSort::Ctime,
                "atime" | "access" => LsSort::Atime,
                _ => LsSort::Name,
            };
            rest = remainder;
        } else if let Some(r) = strip_flag(rest, "--reverse") {
            reverse = true;
            rest = r;
        } else if let Some(r) = strip_flag(rest, "-r") {
            reverse = true;
            rest = r;
        } else if let Some(r) = strip_flag(rest, "-a") {
            all_cols = true;
            rest = r;
        } else {
            break;
        }
    }

    (sort, reverse, all_cols, rest)
}

/// Compare two `ShellEntry` values for stable `ls` sorting (version-neutral).
fn ls_cmp_shell(a: &ShellEntry, b: &ShellEntry, sort: LsSort) -> std::cmp::Ordering {
    let name_ord = a.name.cmp(&b.name);
    match sort {
        LsSort::Name => name_ord,
        LsSort::Inode => {
            let ia = a.info.as_ref().map_or(0u64, |x| x.fileid);
            let ib = b.info.as_ref().map_or(0u64, |x| x.fileid);
            ia.cmp(&ib).then(name_ord)
        },
        LsSort::Size => {
            let sa = a.info.as_ref().map_or(0u64, |x| x.size);
            let sb = b.info.as_ref().map_or(0u64, |x| x.size);
            sa.cmp(&sb).then(name_ord)
        },
        LsSort::Uid => {
            let ua = a.info.as_ref().map_or(0u32, |x| x.uid);
            let ub = b.info.as_ref().map_or(0u32, |x| x.uid);
            ua.cmp(&ub).then(name_ord)
        },
        LsSort::Gid => {
            let ga = a.info.as_ref().map_or(0u32, |x| x.gid);
            let gb = b.info.as_ref().map_or(0u32, |x| x.gid);
            ga.cmp(&gb).then(name_ord)
        },
        LsSort::Mode => {
            let ma = a.info.as_ref().map_or(0u32, |x| x.mode);
            let mb = b.info.as_ref().map_or(0u32, |x| x.mode);
            ma.cmp(&mb).then(name_ord)
        },
        LsSort::Mtime => {
            let ta = a.info.as_ref().map_or(0u64, |x| x.mtime_secs);
            let tb = b.info.as_ref().map_or(0u64, |x| x.mtime_secs);
            ta.cmp(&tb).then(name_ord)
        },
        LsSort::Ctime => {
            let ta = a.info.as_ref().map_or(0u64, |x| x.ctime_secs);
            let tb = b.info.as_ref().map_or(0u64, |x| x.ctime_secs);
            ta.cmp(&tb).then(name_ord)
        },
        LsSort::Atime => {
            let ta = a.info.as_ref().map_or(0u64, |x| x.atime_secs);
            let tb = b.info.as_ref().map_or(0u64, |x| x.atime_secs);
            ta.cmp(&tb).then(name_ord)
        },
    }
}

/// Days in each month for a common (non-leap) year.
const MONTH_DAYS_NORMAL: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Days in each month for a leap year.
const MONTH_DAYS_LEAP: [u64; 12] = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Format a Unix epoch timestamp (seconds since 1970-01-01 UTC) as
/// `YYYY-MM-DD HH:MM:SS`.
///
/// Pure integer arithmetic -- no external crate required.
/// Valid for any u32 timestamp (up to 2106-02-07).
fn fmt_unix_time(secs: u64) -> String {
    let s = secs;
    let sec = s % 60;
    let min = (s / 60) % 60;
    let hour = (s / 3600) % 24;
    let mut days = s / 86400;

    // Advance year by year, subtracting its day count.
    let mut year = 1970u64;
    let mut yd = if is_leap_year(year) { 366u64 } else { 365u64 };
    while days >= yd {
        days -= yd;
        year += 1;
        yd = if is_leap_year(year) { 366 } else { 365 };
    }

    let months = if is_leap_year(year) { &MONTH_DAYS_LEAP } else { &MONTH_DAYS_NORMAL };
    let mut month = 1u64;
    for &md in months {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    let day = days + 1;

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}")
}

/// Gregorian leap-year predicate.
const fn is_leap_year(y: u64) -> bool {
    y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400))
}

/// Parse `uid`, `uid:gid`, or `:gid` into `(Option<u32>, Option<u32>)`.
fn parse_uid_gid(spec: &str) -> (Option<u32>, Option<u32>) {
    if let Some(pos) = spec.find(':') {
        let uid = spec[..pos].parse::<u32>().ok();
        let gid = spec[pos + 1..].parse::<u32>().ok();
        (uid, gid)
    } else {
        (spec.parse::<u32>().ok(), None)
    }
}

// =============================================================================
// last / lastb / lastlog rendering
// =============================================================================

/// Replace terminal control characters in untrusted log-record strings before
/// display. wtmp/btmp/lastlog content (user/line/host fields) comes from a file
/// on the UNTRUSTED NFS server, so embedded ANSI escapes or newlines must not
/// reach the operator's terminal (cursor/colour manipulation, column-layout
/// corruption). C0 controls, DEL, and C1 controls collapse to '.'.
fn sanitize_term(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '.' } else { c }).collect()
}

/// Format a wtmp `tv_sec` for the `last` / `lastb` / `lastlog` columns.
///
/// Util-linux 2.42 last.c uses `ctime(3)` ("Mon Apr 28 22:15:00 2026") -- we
/// render the same instant as `YYYY-MM-DD HH:MM:SS` (the project's existing
/// `fmt_unix_time`) to keep this command zero-dep and consistent with the
/// `stat` and `ls` views. Negative timestamps are clamped to zero (1970-01-01)
/// rather than crashing -- they only appear in corrupt records.
fn fmt_ctime(tv_sec: i32) -> String {
    let secs = u64::from(u32::try_from(tv_sec).unwrap_or(0));
    fmt_unix_time(secs)
}

/// Decide what string goes in the host column. Numeric IPs are preferred when
/// the binary `ut_addr_v6` field is populated -- mirrors util-linux last.c
/// `--ip` semantics. Falls back to the textual `ut_host` field otherwise.
fn pick_host(rec: &UtmpRecord) -> String {
    let ip = rec.addr_string();
    if !ip.is_empty() {
        return ip;
    }
    rec.host.clone()
}

/// Internal representation of one paired login record awaiting render.
/// Mirrors the union of `case R_*` outcomes in util-linux last.c::list().
struct LastEntry {
    user: String,
    line: String,
    host: String,
    login: i32,
    /// Logout outcome (controls what appears in the duration column).
    outcome: LastOutcome,
}

enum LastOutcome {
    /// Paired with a DEAD_PROCESS at this time.
    Logout(i32),
    /// Process is still alive (no logout, no shutdown observed).
    StillLoggedIn,
    /// System came down via SHUTDOWN_TIME / RUN_LVL 0|6 at this time.
    Down(i32),
    /// System rebooted without a clean shutdown -- session was crashed at this time.
    Crash(i32),
}

fn render_last(recs: &[UtmpRecord], max_recs: Option<usize>) {
    let entries = pair_wtmp(recs);
    let mut count = 0usize;
    for entry in &entries {
        if max_recs.is_some_and(|n| count >= n) {
            break;
        }
        let login = fmt_ctime(entry.login);
        let (logout, length) = match entry.outcome {
            LastOutcome::Logout(t) => {
                let dur = t.saturating_sub(entry.login);
                (fmt_ctime(t), fmt_duration(dur))
            },
            LastOutcome::StillLoggedIn => ("still running".to_owned(), String::new()),
            LastOutcome::Down(t) => {
                let dur = t.saturating_sub(entry.login);
                (format!("down  {}", fmt_ctime(t)), fmt_duration(dur))
            },
            LastOutcome::Crash(t) => {
                let dur = t.saturating_sub(entry.login);
                (format!("crash {}", fmt_ctime(t)), fmt_duration(dur))
            },
        };
        // Column layout follows util-linux last.c `list()` printf with full-time format.
        println!("{:<8.8} {:<12.12} {:<16.16} {:<19} - {:<25} {}", sanitize_term(&entry.user), sanitize_term(&entry.line), sanitize_term(&entry.host), login, logout, length);
        count += 1;
    }
    if count == 0 {
        println!("{}", "no completed sessions in wtmp".yellow());
    }
}

fn render_lastb(recs: &[UtmpRecord], max_recs: Option<usize>) {
    // btmp is just a sequence of failed login attempts; no pairing logic
    // applies. Render newest first.
    let mut count = 0usize;
    for r in recs.iter().rev() {
        if max_recs.is_some_and(|n| count >= n) {
            break;
        }
        // The login program writes ut_type=USER_PROCESS for failed attempts in
        // older util-linux but LOGIN_PROCESS in some sshd configs; we render
        // both. EMPTY records mean "no real attempt" -- skip.
        if matches!(r.ut_type, UtType::Empty) {
            continue;
        }
        let host = sanitize_term(&pick_host(r));
        let user = if r.user.is_empty() { "(unknown)".to_owned() } else { sanitize_term(&r.user) };
        println!("{:<8.8} {:<12.12} {:<16.16} {:<24} (failed login)", user, sanitize_term(&r.line), host, fmt_ctime(r.tv_sec));
        count += 1;
    }
    if count == 0 {
        println!("{}", "no failed-login records in btmp".green());
    }
}

fn render_lastlog(recs: &[LastlogRecord], uid_to_user: &[(u32, String)]) {
    println!("{:<16} {:<8} {:<24} Latest", "Username", "Port", "From");
    let mut shown = 0usize;
    for r in recs {
        if r.ll_time == 0 {
            continue;
        }
        let user = uid_to_user.iter().find(|(u, _)| *u == r.uid).map_or_else(|| format!("uid={}", r.uid), |(_, n)| n.clone());
        let when = fmt_ctime(r.ll_time);
        println!("{:<16} {:<8.8} {:<24.24} {}", sanitize_term(&user), sanitize_term(&r.ll_line), sanitize_term(&r.ll_host), when);
        shown += 1;
    }
    if shown == 0 {
        println!("{}", "no recorded interactive logins (every slot has ll_time=0)".yellow());
    }
}

/// Translate util-linux 2.42 last.c `process_wtmp_file()` into a sequence of
/// renderable entries. Records are walked forwards (oldest -> newest) and the
/// resulting list is reversed before return so the caller sees newest-first
/// like the system `last(1)`.
///
/// The state machine mirrors last.c's logic but expressed in terms of "open
/// sessions" rather than last.c's reverse-scan pending list:
///
/// - USER_PROCESS opens a session keyed by ut_line.
/// - DEAD_PROCESS closes the session on the same ut_line as a clean Logout.
/// - SHUTDOWN_TIME (sysvinit "shutdown" pseudo-record or RUN_LVL 0|6) closes
///   any still-open sessions as Down(t).
/// - BOOT_TIME closes any still-open sessions as Crash(t) unless a clean
///   shutdown was seen since the last boot, in which case the existing Down
///   close still stands.
///
/// At end-of-file: any still-open session is StillLoggedIn; the most recent
/// boot is StillLoggedIn (the system is up).
struct OpenSession {
    user: String,
    host: String,
    login: i32,
}

struct PendingBoot {
    host: String,
    login: i32,
}

const fn clone_outcome(o: &LastOutcome) -> LastOutcome {
    match o {
        LastOutcome::Logout(t) => LastOutcome::Logout(*t),
        LastOutcome::StillLoggedIn => LastOutcome::StillLoggedIn,
        LastOutcome::Down(t) => LastOutcome::Down(*t),
        LastOutcome::Crash(t) => LastOutcome::Crash(*t),
    }
}

fn close_all(open: &mut std::collections::HashMap<String, OpenSession>, entries: &mut Vec<LastEntry>, outcome: &LastOutcome) {
    let drained: Vec<(String, OpenSession)> = open.drain().collect();
    for (line, sess) in drained {
        entries.push(LastEntry { user: sess.user, line, host: sess.host, login: sess.login, outcome: clone_outcome(outcome) });
    }
}

fn pair_wtmp(recs: &[UtmpRecord]) -> Vec<LastEntry> {
    use std::collections::HashMap;

    let mut open: HashMap<String, OpenSession> = HashMap::new();
    let mut entries: Vec<LastEntry> = Vec::new();
    let mut pending_boot: Option<PendingBoot> = None;
    // Most recent clean shutdown observed since the last open boot. None means
    // the previous boot ended via crash (next BOOT) or hasn't ended yet.
    let mut clean_shutdown_since_boot: Option<i32> = None;

    for r in recs {
        // Reclassify per util-linux 2.42 last.c lines 750-786 (sysvinit
        // compatibility for boot / shutdown / runlevel pseudo-records).
        let mut rec = r.clone();
        if rec.line == "~" {
            if rec.user == "shutdown" {
                rec.ut_type = UtType::Other(254); // last.c's SHUTDOWN_TIME constant
            } else if rec.user == "reboot" {
                rec.ut_type = UtType::BootTime;
            } else if rec.user == "runlevel" {
                rec.ut_type = UtType::RunLvl;
            }
        } else if !rec.user.is_empty() && !rec.line.is_empty() && rec.user != "LOGIN" && !matches!(rec.ut_type, UtType::DeadProcess) {
            rec.ut_type = UtType::UserProcess;
        }
        if rec.user.is_empty() {
            rec.ut_type = UtType::DeadProcess;
        }

        match rec.ut_type {
            UtType::Other(254) => {
                // SHUTDOWN_TIME -- close all open sessions as clean Down.
                close_all(&mut open, &mut entries, &LastOutcome::Down(rec.tv_sec));
                clean_shutdown_since_boot = Some(rec.tv_sec);
            },
            UtType::RunLvl => {
                // Per last.c lines 815-826, runlevel 0 or 6 is treated as a clean shutdown.
                let lvl = rec.pid & 0xff;
                if lvl == i32::from(b'0') || lvl == i32::from(b'6') {
                    close_all(&mut open, &mut entries, &LastOutcome::Down(rec.tv_sec));
                    clean_shutdown_since_boot = Some(rec.tv_sec);
                }
            },
            UtType::BootTime => {
                // Resolve the previously pending boot first.
                if let Some(pb) = pending_boot.take() {
                    let outcome = clean_shutdown_since_boot.map_or(LastOutcome::Crash(rec.tv_sec), LastOutcome::Down);
                    entries.push(LastEntry { user: "reboot".to_owned(), line: "system boot".to_owned(), host: pb.host, login: pb.login, outcome });
                }
                // Any sessions still open at this boot crashed: a clean shutdown
                // would have closed them already (Down) in the branch above.
                close_all(&mut open, &mut entries, &LastOutcome::Crash(rec.tv_sec));
                pending_boot = Some(PendingBoot { host: rec.host.clone(), login: rec.tv_sec });
                clean_shutdown_since_boot = None;
            },
            UtType::UserProcess => {
                // Replacing a record with the same ut_line means the previous
                // entry was orphaned (no DEAD_PROCESS). The most recent USER on
                // this line is what we keep.
                // Previous session on this ut_line (if any) was orphaned; discard it.
                drop(open.insert(rec.line.clone(), OpenSession { user: rec.user.clone(), host: pick_host(&rec), login: rec.tv_sec }));
            },
            UtType::DeadProcess => {
                if let Some(sess) = open.remove(&rec.line) {
                    entries.push(LastEntry { user: sess.user, line: rec.line.clone(), host: sess.host, login: sess.login, outcome: LastOutcome::Logout(rec.tv_sec) });
                }
            },
            // EMPTY, INIT_PROCESS, LOGIN_PROCESS, NEW_TIME, OLD_TIME, ACCOUNTING,
            // and any unknown future ut_type get ignored (matches last.c default cases).
            _ => {},
        }
    }

    // End of file: any pending boot has no follow-up -- system is still up.
    if let Some(pb) = pending_boot {
        entries.push(LastEntry { user: "reboot".to_owned(), line: "system boot".to_owned(), host: pb.host, login: pb.login, outcome: LastOutcome::StillLoggedIn });
    }
    // Sessions that never closed are still logged in.
    let mut still_open: Vec<(String, OpenSession)> = open.into_iter().collect();
    still_open.sort_by_key(|(_, s)| s.login);
    for (line, sess) in still_open {
        entries.push(LastEntry { user: sess.user, line, host: sess.host, login: sess.login, outcome: LastOutcome::StillLoggedIn });
    }

    // util-linux's `last` prints newest first; we built oldest first.
    entries.reverse();
    entries
}

fn fmt_duration(secs: i32) -> String {
    if secs <= 0 {
        return String::new();
    }
    let days = secs / 86_400;
    let hours = (secs / 3600) % 24;
    let mins = (secs / 60) % 60;
    if days > 0 { format!("({days}+{hours:02}:{mins:02})") } else { format!("({hours:02}:{mins:02})") }
}

#[cfg(test)]
mod tests {
    use super::{is_safe_local_name, resolve_get_dest};

    #[test]
    fn safe_local_name_accepts_normal_entries() {
        assert!(is_safe_local_name("passwd"));
        assert!(is_safe_local_name(".hidden"));
        assert!(is_safe_local_name("..."));
        assert!(is_safe_local_name("file.tar.gz"));
    }

    #[test]
    fn safe_local_name_rejects_traversal_and_separators() {
        // A hostile server controls READDIRPLUS entry names; these must never
        // reach std::fs during `get -r` (path-traversal / zip-slip guard).
        assert!(!is_safe_local_name(""));
        assert!(!is_safe_local_name("."));
        assert!(!is_safe_local_name(".."));
        assert!(!is_safe_local_name("../etc/passwd"));
        assert!(!is_safe_local_name("../../root/.ssh/authorized_keys"));
        assert!(!is_safe_local_name("sub/dir"));
        assert!(!is_safe_local_name("/etc/cron.d/pwn"));
        assert!(!is_safe_local_name("a\0b"));
    }

    #[test]
    fn get_dest_uses_basename_when_local_empty() {
        assert_eq!(resolve_get_dest("/etc/passwd", "", false), "passwd");
        assert_eq!(resolve_get_dest("passwd", "", false), "passwd");
    }

    #[test]
    fn get_dest_keeps_plain_local_filename() {
        assert_eq!(resolve_get_dest("/etc/passwd", "/home/test/out", false), "/home/test/out");
        assert_eq!(resolve_get_dest("/etc/passwd", "copy", false), "copy");
    }

    #[test]
    fn get_dest_appends_basename_for_trailing_slash() {
        // `get /etc/passwd /home/test/` -> /home/test/passwd  (the reported bug).
        assert_eq!(resolve_get_dest("/etc/passwd", "/home/test/", false), "/home/test/passwd");
        assert_eq!(resolve_get_dest("/etc/passwd", "/", false), "/passwd");
    }

    #[test]
    fn get_dest_appends_basename_for_existing_dir() {
        // `local` exists as a directory even without a trailing slash.
        assert_eq!(resolve_get_dest("/etc/shadow", "/home/test", true), "/home/test/shadow");
    }

    #[test]
    fn get_dest_handles_trailing_slash_on_remote() {
        // Directory remote: basename is the last non-empty component.
        assert_eq!(resolve_get_dest("/var/log/", "", false), "log");
    }
}
