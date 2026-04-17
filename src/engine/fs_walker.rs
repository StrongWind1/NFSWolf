//! Recursive filesystem walker with pattern matching.
//!
//! Walks the remote NFS filesystem looking for interesting files
//! using parallel READDIRPLUS calls. Pattern categories are built-in
//! defaults but fully user-extensible via custom patterns and pattern files.

// Toolkit API  --  not all items are used in currently-implemented phases.
use nfs3_types::nfs3::{Nfs3Result, READDIRPLUS3args};
use tracing::{debug, warn};

use crate::engine::credential::CredentialManager;
use crate::proto::nfs3::client::Nfs3Client;
use crate::proto::nfs3::types::{FileAttrs, FileHandle, FileType};
use crate::util::stealth::StealthConfig;

/// Mode bit for SUID (RFC 1094 S2.3.5 / POSIX). Server sets this on exec files
/// that should run as the file owner  --  critical for privilege escalation.
const MODE_SUID: u32 = 0o4000;

/// Mode bit for SGID.
const MODE_SGID: u32 = 0o2000;

/// Mask for world-writable (other write) permission bit.
const MODE_WORLD_WRITE: u32 = 0o0002;

/// File pattern categories for secret detection.
///
/// Built-in defaults cover common credential and config file patterns.
/// Users extend this via `--extra-patterns` (CLI glob list) or
/// `--patterns-file` (newline-delimited file of globs).
#[derive(Debug)]
pub struct SecretPatterns {
    /// Named pattern categories. Each category has a name and a list of globs.
    /// Users can select/disable specific categories with `--categories`.
    pub categories: Vec<PatternCategory>,
}

/// A named group of file-matching patterns.
#[derive(Debug, Clone)]
pub struct PatternCategory {
    /// Human-readable name shown in report output.
    pub name: String,
    /// Glob strings matched against filenames (basename only, not full path).
    pub patterns: Vec<String>,
    /// Whether this category is active; false means it is silently skipped.
    pub enabled: bool,
}

impl Default for SecretPatterns {
    fn default() -> Self {
        Self {
            categories: vec![
                PatternCategory { name: "ssh_keys".into(), patterns: vec!["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "*.pem", "*.key", "*.p12", "*.pfx"].into_iter().map(String::from).collect(), enabled: true },
                PatternCategory { name: "env_files".into(), patterns: vec![".env", ".env.local", ".env.production", "*.env", ".envrc"].into_iter().map(String::from).collect(), enabled: true },
                PatternCategory { name: "config_files".into(), patterns: vec!["wp-config.php", "config.yml", "config.yaml", "application.properties", "settings.py", "database.yml", "secrets.yml"].into_iter().map(String::from).collect(), enabled: true },
                PatternCategory { name: "database_files".into(), patterns: vec!["*.sqlite", "*.sqlite3", "*.db", "*.sql", "dump.sql"].into_iter().map(String::from).collect(), enabled: true },
                PatternCategory { name: "credential_files".into(), patterns: vec![".netrc", ".pgpass", ".my.cnf", ".aws/credentials", ".docker/config.json", "credentials", "passwords.txt", ".git-credentials", ".npmrc"].into_iter().map(String::from).collect(), enabled: true },
            ],
        }
    }
}

impl SecretPatterns {
    /// Add custom patterns under a "custom" category.
    pub fn add_custom(&mut self, patterns: Vec<String>) {
        if !patterns.is_empty() {
            self.categories.push(PatternCategory { name: "custom".into(), patterns, enabled: true });
        }
    }

    /// Load additional patterns from a file (one glob per line, # comments).
    pub fn load_from_file(&mut self, path: &str) -> std::io::Result<()> {
        let content = std::fs::read_to_string(path)?;
        let patterns: Vec<String> = content.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(String::from).collect();
        self.add_custom(patterns);
        Ok(())
    }

    /// Enable only the named categories (disable all others).
    pub fn select_categories(&mut self, names: &[String]) {
        for cat in &mut self.categories {
            cat.enabled = names.iter().any(|n| n == &cat.name);
        }
    }

    /// Get all enabled patterns as a flat list.
    #[must_use]
    pub fn all_enabled_patterns(&self) -> Vec<&str> {
        self.categories.iter().filter(|c| c.enabled).flat_map(|c| c.patterns.iter().map(String::as_str)).collect()
    }
}

/// Walker configuration.
#[derive(Debug)]
pub struct WalkConfig {
    /// Maximum directory recursion depth (0 = root only).
    pub max_depth: u32,
    /// Filename patterns to match for secret detection.
    pub patterns: SecretPatterns,
    /// Whether to compute SHA-256 hashes of matching files.
    pub compute_hashes: bool,
    /// Detect SUID/SGID binaries.
    pub detect_suid: bool,
    /// Detect world-writable files/directories.
    pub detect_world_writable: bool,
}

/// Result of a filesystem walk.
#[derive(Debug, Clone)]
pub struct WalkResult {
    /// Total regular files seen (not just interesting ones).
    pub total_files: u64,
    /// Total directories traversed.
    pub total_dirs: u64,
    /// Files that matched at least one pattern category.
    pub interesting_files: Vec<InterestingFile>,
    /// Paths of SUID or SGID binaries.
    pub suid_binaries: Vec<String>,
    /// Paths of world-writable files or directories.
    pub world_writable: Vec<String>,
    /// SHA-256 hashes for files that were read (if `compute_hashes` is set).
    pub file_hashes: Vec<FileHash>,
}

/// SHA-256 hash for a transferred file.
#[derive(Debug, Clone)]
pub struct FileHash {
    /// Remote path of the hashed file.
    pub path: String,
    /// Hex-encoded SHA-256 digest.
    pub sha256: String,
    /// File size in bytes.
    pub size: u64,
}

/// A file flagged as potentially interesting.
#[derive(Debug, Clone)]
pub struct InterestingFile {
    /// Remote path.
    pub path: String,
    /// Name of the pattern category that matched.
    pub category: String,
    /// File size in bytes.
    pub size: u64,
    /// File owner UID.
    pub uid: u32,
    /// File owner GID.
    pub gid: u32,
    /// File permission mode (lower 12 bits used).
    pub mode: u32,
}

/// Recursive filesystem walker backed by NFSv3 READDIRPLUS.
///
/// Uses the credential manager to automatically select the best credential
/// for each directory, allowing walking of permission-restricted trees.
pub struct FsWalker {
    nfs3: Nfs3Client,
    credential_mgr: CredentialManager,
    stealth: StealthConfig,
}

impl std::fmt::Debug for FsWalker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsWalker").finish_non_exhaustive()
    }
}

impl FsWalker {
    /// Create a new walker with the given NFSv3 client and credential manager.
    #[must_use]
    pub const fn new(nfs3: Nfs3Client, credential_mgr: CredentialManager, stealth: StealthConfig) -> Self {
        Self { nfs3, credential_mgr, stealth }
    }

    /// Walk the filesystem rooted at `root_fh` and return all interesting files.
    ///
    /// Iterates directories with paginated READDIRPLUS calls. Each page produces
    /// file handles immediately usable for subsequent operations (RFC 1094 S2.3.3  --
    /// handles are bearer tokens, not bound to the requesting credential).
    pub async fn walk(&self, root_fh: &FileHandle, config: &WalkConfig) -> anyhow::Result<WalkResult> {
        let mut result = WalkResult { total_files: 0, total_dirs: 0, interesting_files: Vec::new(), suid_binaries: Vec::new(), world_writable: Vec::new(), file_hashes: Vec::new() };

        let root_path = String::from("/");
        self.walk_dir(root_fh, &root_path, 0, config, &mut result).await?;
        Ok(result)
    }

    /// Recursively walk one directory, appending findings to `result`.
    async fn walk_dir(&self, dir_fh: &FileHandle, path: &str, depth: u32, config: &WalkConfig, result: &mut WalkResult) -> anyhow::Result<()> {
        result.total_dirs += 1;

        let entries = self.readdirplus_all(dir_fh).await?;

        // Collect subdirectories for later recursion (avoid borrow conflict).
        let mut subdirs: Vec<(FileHandle, String)> = Vec::new();

        for entry in &entries {
            // Skip navigation entries.
            if entry.name == "." || entry.name == ".." {
                continue;
            }

            let entry_path = format!("{}/{}", path.trim_end_matches('/'), entry.name);

            let Some(attrs) = &entry.attrs else {
                debug!(path = %entry_path, "no attrs in READDIRPLUS entry, skipping");
                continue;
            };

            match attrs.file_type {
                FileType::Directory => {
                    if depth < config.max_depth
                        && let Some(fh) = &entry.handle
                    {
                        subdirs.push((fh.clone(), entry_path.clone()));
                    }
                },
                FileType::Regular => {
                    result.total_files += 1;
                    Self::check_file(&entry_path, attrs, config, result);
                },
                _ => {
                    // Skip symlinks, devices, etc.
                },
            }
        }

        // Now recurse into subdirectories.
        for (fh, subpath) in subdirs {
            if let Err(e) = Box::pin(self.walk_dir(&fh, &subpath, depth + 1, config, result)).await {
                warn!(path = %subpath, err = %e, "skipping directory due to error");
            }
        }

        Ok(())
    }

    /// Check a single file against all configured rules and record findings.
    fn check_file(path: &str, attrs: &FileAttrs, config: &WalkConfig, result: &mut WalkResult) {
        let name = path.rsplit('/').next().unwrap_or(path);

        // Pattern matching  --  check against all enabled categories.
        let patterns = config.patterns.all_enabled_patterns();
        for pattern in &patterns {
            if glob_matches(pattern, name) {
                result.interesting_files.push(InterestingFile { path: path.to_owned(), category: category_for_pattern(pattern, &config.patterns), size: attrs.size, uid: attrs.uid, gid: attrs.gid, mode: attrs.mode });
                break; // Only record once per file even if multiple patterns match.
            }
        }

        // SUID/SGID detection.
        if config.detect_suid && (attrs.mode & (MODE_SUID | MODE_SGID) != 0) {
            result.suid_binaries.push(path.to_owned());
        }

        // World-writable detection.
        if config.detect_world_writable && (attrs.mode & MODE_WORLD_WRITE != 0) {
            result.world_writable.push(path.to_owned());
        }
    }

    /// Paginate through all READDIRPLUS entries for a directory.
    ///
    /// On NFS3ERR_ACCES, escalates credentials using the shared ladder so
    /// restricted directories are listed with the first credential that works.
    /// Each page applies the stealth delay.  Includes a GETATTR fill-in pass
    /// for entries where the server omitted inline attributes (cross-mount points).
    async fn readdirplus_all(&self, dir_fh: &FileHandle) -> anyhow::Result<Vec<crate::proto::nfs3::types::DirEntryPlus>> {
        use crate::engine::credential::escalation_list;
        use crate::proto::auth::{AuthSys, Credential};
        use nfs3_types::nfs3::{GETATTR3args, cookieverf3};

        // Resolve the credential to use for this directory.
        // Try the current client first; on ACCES, walk the escalation ladder.
        let escalated: Option<NfsClient>;
        {
            let probe = READDIRPLUS3args { dir: dir_fh.to_nfs_fh3(), cookie: 0, cookieverf: cookieverf3([0u8; 8]), dircount: 4096, maxcount: 65536 };
            let needs_escalation = matches!(self.nfs3.readdirplus(&probe).await, Ok(Nfs3Result::Err((nfs3_types::nfs3::nfsstat3::NFS3ERR_ACCES | nfs3_types::nfs3::nfsstat3::NFS3ERR_PERM, _))));
            escalated = if needs_escalation {
                let owner = {
                    let ga = GETATTR3args { object: dir_fh.to_nfs_fh3() };
                    self.nfs3.getattr(&ga).await.ok().and_then(|r| if let Nfs3Result::Ok(ok) = r { Some((ok.obj_attributes.uid, ok.obj_attributes.gid)) } else { None })
                };
                let caller = (self.nfs3.uid(), self.nfs3.gid());
                let mut found: Option<NfsClient> = None;
                for (uid, gid) in escalation_list(caller, owner) {
                    let cred = Credential::Sys(AuthSys::with_groups(uid, gid, &[gid], "nfswolf"));
                    let esc = self.nfs3.with_credential(cred, uid, gid);
                    let p2 = READDIRPLUS3args { dir: dir_fh.to_nfs_fh3(), cookie: 0, cookieverf: cookieverf3([0u8; 8]), dircount: 4096, maxcount: 65536 };
                    if matches!(esc.readdirplus(&p2).await, Ok(Nfs3Result::Ok(_))) {
                        debug!(uid, gid, "harvest escalated READDIRPLUS succeeded");
                        found = Some(esc);
                        break;
                    }
                }
                found
            } else {
                None
            };
        }
        let nfs: &NfsClient = escalated.as_ref().unwrap_or(&self.nfs3);

        let mut all_entries = Vec::new();
        let mut cookie: u64 = 0;
        let mut cookieverf = cookieverf3([0u8; 8]);
        let nfs_fh = dir_fh.to_nfs_fh3();

        loop {
            self.stealth.wait().await;
            let args = READDIRPLUS3args { dir: nfs_fh.clone(), cookie, cookieverf, dircount: 4096, maxcount: 65536 };

            let res = nfs.readdirplus(&args).await?;
            match res {
                Nfs3Result::Ok(ok) => {
                    cookieverf = ok.cookieverf;
                    let eof = ok.reply.eof;
                    let page = ok.reply.entries.into_inner();
                    let is_empty = page.is_empty();

                    for raw in page {
                        let last_cookie = raw.cookie;
                        let entry = raw_to_dir_entry_plus(raw);
                        cookie = last_cookie;
                        all_entries.push(entry);
                    }

                    if eof || is_empty {
                        break;
                    }
                },
                Nfs3Result::Err((stat, _)) => {
                    debug!(?stat, "READDIRPLUS error");
                    break;
                },
            }
        }

        // Fill-in pass: GETATTR for entries whose inline attrs were omitted
        // (typical for cross-mount-point entries like /proc, /dev, /home).
        for entry in &mut all_entries {
            if entry.attrs.is_some() || entry.name == "." || entry.name == ".." {
                continue;
            }
            if let Some(ref fh) = entry.handle.clone() {
                let ga = GETATTR3args { object: fh.to_nfs_fh3() };
                if let Ok(Nfs3Result::Ok(ok)) = nfs.getattr(&ga).await {
                    entry.attrs = Some(FileAttrs::from_fattr3(&ok.obj_attributes));
                }
            }
        }

        Ok(all_entries)
    }
}

/// Type alias used in escalation returns inside FsWalker.
type NfsClient = Nfs3Client;

/// Convert a raw nfs3_types `entryplus3` to our `DirEntryPlus`.
fn raw_to_dir_entry_plus(entry: nfs3_types::nfs3::entryplus3<'_>) -> crate::proto::nfs3::types::DirEntryPlus {
    use nfs3_types::nfs3::Nfs3Option;

    let name = String::from_utf8_lossy(entry.name.0.as_ref()).into_owned();
    let attrs = match entry.name_attributes {
        Nfs3Option::Some(fa) => Some(FileAttrs::from_fattr3(&fa)),
        Nfs3Option::None => None,
    };
    let handle = match entry.name_handle {
        Nfs3Option::Some(fh) => Some(FileHandle::from_nfs_fh3(&fh)),
        Nfs3Option::None => None,
    };
    crate::proto::nfs3::types::DirEntryPlus { fileid: entry.fileid, name, cookie: entry.cookie, attrs, handle }
}

/// Minimal glob matcher  --  supports `*` wildcard only.
///
/// Rust's std lib has no glob support; the full `glob` crate is not a
/// dependency. This covers the patterns we use (prefix/suffix wildcards).
fn glob_matches(pattern: &str, name: &str) -> bool {
    if pattern == name {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return name.ends_with(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return name.starts_with(prefix);
    }
    // Exact match without glob.
    pattern == name
}

/// Find the category name that owns `pattern`.
fn category_for_pattern(pattern: &str, patterns: &SecretPatterns) -> String {
    for cat in &patterns.categories {
        if cat.enabled && cat.patterns.iter().any(|p| p == pattern) {
            return cat.name.clone();
        }
    }
    "unknown".to_owned()
}
