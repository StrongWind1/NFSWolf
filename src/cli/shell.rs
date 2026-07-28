//! Interactive NFS exploration shell.
//!
//! Connects to an NFS server, mounts an export, and enters a readline REPL
//! so the operator can browse the filesystem without a kernel NFS client.
//! A single `--command` flag lets it run headlessly (useful in scripts).

use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use rustyline::Editor;
use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;

use crate::cli::probe::{build_gid_list, make_mount_client};
use crate::cli::target::Source as TargetSource;
use crate::cli::{GlobalOpts, H_BEHAVIOR, H_PERMISSIONS, H_TARGET};
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::circuit::CircuitBreaker;
use crate::proto::conn::ReconnectStrategy;
use crate::proto::nfs3::Nfs3Client;
use crate::proto::nfs3::types::FileHandle;
use crate::proto::pool::{ConnectionPool, PoolKey};
use crate::proto::transport::PooledTransport;
use crate::shell::NfsShell;
use crate::shell::V3_SHELL_COMMANDS;
use crate::shell::complete::ShellCompleter;
use crate::shell::ops::ShellHandle;
use crate::shell::v3::V3Ops;
use crate::util::stealth::StealthConfig;

/// Interactive NFS exploration shell.
///
/// Opens a readline REPL over NFS so you can browse exports without a kernel
/// NFS client.  Use -c for non-interactive (scripting) mode.
///
/// Target formats (same shape across every subcommand):
///   host              mount root /, no export needed  (rare)
///   host:/export      mount the named export
///   host --export /p  same, but supplied as a flag
///   host --handle HEX bypass MOUNT, use a raw root file handle
///
/// Examples:
///   nfswolf shell 192.168.1.10:/srv
///   nfswolf shell 192.168.1.10 -c "ls /etc"
///   nfswolf shell 192.168.1.10 --handle 01000200abcdef... --allow-write
///   nfswolf shell 192.168.1.10:/srv --uid 0
#[derive(Parser)]
pub(crate) struct ShellArgs {
    /// Target host with optional :/export suffix (e.g. 10.0.0.5:/srv)
    #[arg(help_heading = H_TARGET)]
    pub target: String,

    /// Export path (alternative to host:/export in the positional target)
    #[arg(short = 'e', long, value_name = "PATH", help_heading = H_TARGET)]
    pub export: Option<String>,

    /// Enable write operations (CREATE, WRITE, MKDIR, REMOVE, etc.)
    #[arg(long, help_heading = H_PERMISSIONS)]
    pub allow_write: bool,

    /// Run a single shell command then exit (non-interactive / scripting mode)
    #[arg(short = 'c', long, value_name = "CMD", help_heading = H_BEHAVIOR)]
    pub command: Option<String>,

    /// Use a raw file handle (hex) as the shell root  --  skips MOUNT entirely.
    /// Obtain handles from `nfswolf escape` or `nfswolf brute-handle`.
    #[arg(long, value_name = "HEX", help_heading = H_TARGET)]
    pub handle: Option<String>,

    /// NFS protocol version (2, 3, or 4).
    #[arg(long, default_value = "3", value_name = "VER", help_heading = H_BEHAVIOR)]
    pub nfs_version: u32,
}

/// Entry point for the `shell` subcommand.
pub(crate) async fn run(args: ShellArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    tracing::info!(target = %args.target, "starting NFS shell");

    // NFSv4 mode: bypass MOUNT, connect directly to port 2049.
    if args.nfs_version == 4 {
        return run_nfs4_shell(args, globals).await;
    }

    // NFSv2 mode: MOUNT v1 for the 32-byte handle, then Nfs2Client.
    if args.nfs_version == 2 {
        return run_nfs2_shell(args, globals).await;
    }

    if args.nfs_version != 3 {
        anyhow::bail!("--nfs-version {} is not supported (use 2, 3, or 4)", args.nfs_version);
    }

    // Parse `<TARGET>` + --export + --handle into the unified form. The
    // shell tolerates a bare host (no source) by defaulting to "/", since
    // `shell host` was historically a valid invocation.
    let target = crate::cli::target::parse(&args.target, args.export.as_deref(), args.handle.as_deref(), false)?;
    let host = target.host;
    let (export, handle_hex_arg): (String, Option<String>) = match &target.source {
        TargetSource::Export(p) => (p.clone(), None),
        TargetSource::Handle(h) => (String::from("/"), Some(h.clone())),
        TargetSource::None => (String::from("/"), None),
    };
    let uid = globals.uid;
    let gid = globals.gid;

    let addr = SocketAddr::new(host, 111);
    let pool = Arc::new(match &globals.proxy {
        Some(p) => ConnectionPool::with_proxy(p.clone()),
        None => ConnectionPool::default_config(),
    });
    let circuit = Arc::new(CircuitBreaker::default_config());
    let gids = build_gid_list(gid, &globals.aux_gids);
    let cred = Credential::Sys(AuthSys::with_groups(uid, gid, &gids, &globals.hostname));

    // When --handle is given, skip MOUNT entirely and connect straight to the
    // NFS data port. The raw handle is the shell root (file handles are bearer
    // tokens per RFC 1094 S2.3.3 / RFC 2623 S2.6), so no MOUNT/EXPORT RPC is
    // needed. Issuing MNTPROC_EXPORT here would block on SYN timeouts when
    // portmapper/mountd (TCP/111) is firewalled -- the exact case --handle
    // exists to bypass.
    let (root_fh, pool_key, direct_nfs_port) = if let Some(ref hex) = handle_hex_arg {
        let fh = FileHandle::from_hex(hex).map_err(|e| anyhow::anyhow!("invalid --handle: {e}"))?;
        eprintln!("{}", crate::output::status_info(&format!("Using raw handle: {hex}")));

        let nfs_port = globals.nfs_port.unwrap_or(2049);
        eprintln!("{}", crate::output::status_info(&format!("Session via {host}:{nfs_port} (MOUNT bypassed)")));
        let key = PoolKey { host: SocketAddr::new(host, nfs_port), export: format!("__handle__{nfs_port}"), uid, gid };
        (fh, key, Some(nfs_port))
    } else {
        let mount_client = make_mount_client(globals);
        eprintln!("{}", crate::output::status_info(&format!("Mounting {host}:{export}")));
        let mount_result = mount_client.mount(addr, &export).await?;
        let key = PoolKey { host: addr, export: export.clone(), uid, gid };
        // Honour --nfs-port on the MOUNT path too: when set, route the data
        // client directly to the chosen port (new_direct) instead of resolving
        // it via portmapper, which hangs when TCP/111 is firewalled. `None`
        // keeps the portmapper default (mirrors src/cli/mount.rs).
        (mount_result.handle, key, globals.nfs_port)
    };

    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let nfs3 = if let Some(nfs_port) = direct_nfs_port {
        Arc::new(Nfs3Client::new(PooledTransport::new_direct(Arc::clone(&pool), pool_key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent, nfs_port)))
    } else {
        Arc::new(Nfs3Client::new(PooledTransport::new(Arc::clone(&pool), pool_key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent)))
    };

    let ops = V3Ops::new(Arc::clone(&nfs3));
    let root_handle = ShellHandle(root_fh.as_bytes().to_vec());
    let mut shell = NfsShell::new(ops, root_handle, args.allow_write, globals.hostname.clone(), V3_SHELL_COMMANDS);
    shell.refresh_tab_cache().await;
    eprintln!("{}", crate::output::status_ok(&format!("Connected to {host} as uid={uid} gid={gid}{}   --   type 'help' for commands", if args.allow_write { "  [write enabled]" } else { "" })));
    eprintln!("# rerun: nfswolf shell {host}:{export} --uid {uid} --gid {gid}");

    if let Some(cmd) = args.command {
        // Non-interactive: run one command and return.
        shell.dispatch(&cmd).await;
        crate::cli::emit_replay(globals);
        return Ok(());
    }

    // Interactive REPL with Tab completion.
    let completer = shell.make_completer();
    let mut rl = Editor::<ShellCompleter, DefaultHistory>::new()?;
    rl.set_helper(Some(completer));

    loop {
        // Read uid/gid from the shell so the prompt tracks mid-session
        // `uid` / `gid` / `impersonate` changes (the credential lives on the
        // client, not the captured `uid` local).
        let prompt = format!("nfswolf@{host}:{} uid={} gid={}> ", shell.cwd_path(), shell.current_uid(), shell.current_gid());
        match rl.readline(&prompt) {
            Ok(line) => {
                // History add failure is non-fatal (in-memory only).
                drop(rl.add_history_entry(&line));
                let trimmed = line.trim();
                if trimmed == "exit" || trimmed == "quit" {
                    break;
                }
                shell.dispatch(&line).await;
                // Keep completer's shared cache pointer in sync after commands
                // that might change the cwd (mount-handle, escape-root update
                // self.cwd but don't call refresh_tab_cache). Cheaply sync the
                // cwd file handle pointer so live lookups in the completer use
                // the right parent.
            },
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("readline error: {e}");
                break;
            },
        }
    }
    crate::cli::emit_replay(globals);
    Ok(())
}

// `parse_target` / `resolve_host` removed -- target parsing now lives in
// `crate::cli::target`, shared by all subcommands.

// =============================================================================
// NFSv4 shell  --  minimal REPL for NFSv4-only servers
// =============================================================================

/// Hard cap on a single NFSv4 shell `cat` / `get` read.
///
/// The NFS server is untrusted (CLAUDE.md threat model): a hostile server can
/// return full 64 KiB chunks with `eof = false` forever, so the read loop must
/// bound its total instead of buffering until OOM or looping indefinitely.
/// Mirrors the v3 shell's `READ_ALL_MAX_BYTES` (src/shell.rs).
const NFS4_READ_MAX_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB

/// Run an interactive NFSv4 shell.
///
/// Used when `--nfs-version 4` is set.  Connects directly to port 2049 without
/// the MOUNT protocol (which is not required for NFSv4).  Supports a subset of
/// the full NFSv3 shell commands sufficient to explore NFSv4-only servers.
async fn run_nfs4_shell(args: ShellArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    use crate::proto::nfs4::compound::Nfs4DirectClient;

    let target = crate::cli::target::parse(&args.target, args.export.as_deref(), args.handle.as_deref(), false)?;
    let host = target.host;
    // NFSv4 path doesn't use MOUNT or raw handle; drop the source.
    drop(target.source);
    let nfs_port = globals.nfs_port.unwrap_or(2049);
    let addr = SocketAddr::new(host, nfs_port);
    let mut uid = globals.uid;
    let mut gid = globals.gid;
    let mut hostname = globals.hostname.clone();

    // Send the primary GID plus any --aux-gids (RFC 5531 S14, up to 16) so the
    // shadow-GID trick (e.g. GID 42 to read /etc/shadow) works in v4 mode just as
    // it does in the v3 shell. The client retains the aux GIDs, so a later
    // `uid`/`gid`/`hostname` change (dispatch_nfs4) re-applies them on reconnect.
    eprintln!("{}", crate::output::status_info(&format!("Connecting to {host}:{nfs_port} via NFSv4 (no MOUNT)")));
    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let mut client = Nfs4DirectClient::connect_with_groups_proxy(addr, uid, gid, &globals.aux_gids, &hostname, globals.proxy.as_deref()).await.map_err(|e| anyhow::anyhow!("NFSv4 connect to {addr} failed: {e}"))?.with_stealth(stealth);

    // Fetch the root FH from PUTROOTFH + GETFH.
    let root_fh = client.get_root_fh().await.map_err(|e| anyhow::anyhow!("PUTROOTFH failed: {e}"))?;
    eprintln!("{}", crate::output::status_ok(&format!("Connected to {host} as uid={uid} gid={gid} hostname={hostname}  (NFSv4 shell  --  type 'help' for commands)")));
    eprintln!("# rerun: nfswolf shell {host} --nfs-version 4 --uid {uid} --gid {gid}");

    let mut cwd_fh = root_fh.clone();
    let mut cwd_path = "/".to_owned();

    // Non-interactive mode: run one command and return.
    if let Some(ref cmd) = args.command {
        dispatch_nfs4(&mut client, cmd, &mut cwd_fh, &mut cwd_path, args.allow_write, &mut uid, &mut gid, &mut hostname).await;
        crate::cli::emit_replay(globals);
        return Ok(());
    }

    // Tab completion: wrap client for shared access, populate cache.
    let client = Arc::new(tokio::sync::Mutex::new(client));
    let tab_cache = {
        let entries = client.lock().await.list_dir(&cwd_fh).await.unwrap_or_default();
        Arc::new(std::sync::Mutex::new(crate::shell::complete::TabCache { cwd: cwd_fh.clone(), entries }))
    };
    let completer = ShellCompleter::new(Box::new(Nfs4RemoteCompleter { client: Arc::clone(&client) }), root_fh.clone(), Arc::clone(&tab_cache), V4_SHELL_COMMANDS);
    let mut rl = Editor::<ShellCompleter, DefaultHistory>::new()?;
    rl.set_helper(Some(completer));

    loop {
        let prompt = format!("nfswolf@{host}:{cwd_path} uid={uid} gid={gid} [v4]> ");
        match rl.readline(&prompt) {
            Ok(line) => {
                drop(rl.add_history_entry(&line));
                let trimmed = line.trim();
                if trimmed == "exit" || trimmed == "quit" {
                    break;
                }
                let mut c = client.lock().await;
                dispatch_nfs4(&mut c, trimmed, &mut cwd_fh, &mut cwd_path, args.allow_write, &mut uid, &mut gid, &mut hostname).await;
                // Refresh tab cache after every command (cheap if cwd unchanged).
                if let Ok(entries) = c.list_dir(&cwd_fh).await
                    && let Ok(mut cache) = tab_cache.lock()
                {
                    cache.cwd.clone_from(&cwd_fh);
                    cache.entries = entries;
                }
            },
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("readline error: {e}");
                break;
            },
        }
    }
    crate::cli::emit_replay(globals);
    Ok(())
}

/// Read a remote file and stream its contents to stdout (NFSv4 `cat`).
async fn nfs4_cat(client: &mut crate::proto::nfs4::compound::Nfs4DirectClient, file_fh: &[u8]) {
    let mut offset: u64 = 0;
    loop {
        match client.read_chunk(file_fh, offset, 65536).await {
            Ok((data, eof)) => {
                if let Err(e) = std::io::stdout().write_all(&data) {
                    eprintln!("cat: write to stdout: {e}");
                    break;
                }
                offset += data.len() as u64;
                if eof || data.is_empty() {
                    break;
                }
                // Untrusted server: stop once the cap is hit so a server
                // that never sets eof can't loop forever.
                if offset > NFS4_READ_MAX_BYTES {
                    eprintln!("cat: aborted at {offset} bytes: exceeds {NFS4_READ_MAX_BYTES}-byte cap (untrusted server returning endless non-EOF data)");
                    break;
                }
            },
            Err(e) => {
                eprintln!("cat: {e}");
                break;
            },
        }
    }
    drop(std::io::stdout().flush());
}

/// Read a remote file and save it locally (NFSv4 `get`).
async fn nfs4_get(client: &mut crate::proto::nfs4::compound::Nfs4DirectClient, file_fh: &[u8], local_name: &str) {
    let mut buf = Vec::new();
    let mut offset: u64 = 0;
    loop {
        match client.read_chunk(file_fh, offset, 65536).await {
            Ok((data, eof)) => {
                offset += data.len() as u64;
                buf.extend_from_slice(&data);
                if eof || data.is_empty() {
                    break;
                }
                // Untrusted server: abort (don't write a partial file)
                // once the cap is hit so endless non-EOF chunks can't
                // grow `buf` without bound.
                if offset > NFS4_READ_MAX_BYTES {
                    eprintln!("get: aborted at {offset} bytes: exceeds {NFS4_READ_MAX_BYTES}-byte cap (untrusted server returning endless non-EOF data)");
                    return;
                }
            },
            Err(e) => {
                eprintln!("get: read error: {e}");
                return;
            },
        }
    }
    match std::fs::write(local_name, &buf) {
        Ok(()) => println!("{}", crate::output::status_ok(&format!("saved {} bytes -> {local_name}", buf.len()))),
        Err(e) => eprintln!("get: write {local_name}: {e}"),
    }
}

/// Dispatch a single command in the NFSv4 shell REPL.
async fn dispatch_nfs4(client: &mut crate::proto::nfs4::compound::Nfs4DirectClient, line: &str, cwd_fh: &mut Vec<u8>, cwd_path: &mut String, allow_write: bool, uid: &mut u32, gid: &mut u32, hostname: &mut String) {
    // NFSv4 write operations (CREATE, WRITE, REMOVE, RENAME, etc.) require
    // OPEN+WRITE+CLOSE with stateid tracking (RFC 7530 S16.2.5), which is out
    // of scope until stateful v4 support is added.  Suppress the unused warning
    // until then.
    let _ = allow_write;
    let mut parts = line.split_whitespace();
    let Some(cmd) = parts.next() else { return };
    let args: Vec<&str> = parts.collect();

    match cmd {
        "help" | "?" => {
            println!("NFSv4 shell commands:");
            println!("  ls              list current directory");
            println!("  ls <path>       list a subdirectory");
            println!("  cd <dir>        change directory (cd / for root)");
            println!("  pwd             print current directory");
            println!("  cat <file>      print file contents");
            println!("  get <file>      download file to current local directory");
            println!("  uid <n>         set AUTH_SYS UID (reconnects)");
            println!("  gid <n>         set AUTH_SYS GID (reconnects)");
            println!("  hostname <name> spoof AUTH_SYS machine name (reconnects)");
            println!("  whoami          show current uid/gid/hostname");
            println!("  handle          print current file handle as hex");
            println!("  lcd <dir>       change local working directory");
            println!("  lls [dir]       list local directory");
            println!("  lpwd            print local working directory");
            println!("  lmkdir <dir>    create local directory");
            println!("  exit / quit     exit the shell");
        },
        "whoami" => println!("uid={uid}  gid={gid}  hostname={hostname}"),
        "uid" => match args.first().and_then(|s| s.parse::<u32>().ok()) {
            Some(new_uid) => {
                *uid = new_uid;
                match client.reconnect_with_auth(*uid, *gid, hostname).await {
                    Ok(()) => println!("uid={uid} gid={gid} hostname={hostname}"),
                    Err(e) => eprintln!("uid: reconnect failed: {e}"),
                }
            },
            None => eprintln!("uid: usage: uid <number>"),
        },
        "gid" => match args.first().and_then(|s| s.parse::<u32>().ok()) {
            Some(new_gid) => {
                *gid = new_gid;
                match client.reconnect_with_auth(*uid, *gid, hostname).await {
                    Ok(()) => println!("uid={uid} gid={gid} hostname={hostname}"),
                    Err(e) => eprintln!("gid: reconnect failed: {e}"),
                }
            },
            None => eprintln!("gid: usage: gid <number>"),
        },
        "hostname" => {
            if let Some(new_host) = args.first() {
                (*new_host).clone_into(hostname);
                match client.reconnect_with_auth(*uid, *gid, hostname).await {
                    Ok(()) => println!("hostname={hostname}"),
                    Err(e) => eprintln!("hostname: reconnect failed: {e}"),
                }
            } else {
                println!("{hostname}");
            }
        },
        "pwd" => println!("{cwd_path}"),
        "ls" => {
            let target_fh = if let Some(subdir) = args.first() {
                // Resolve subdir relative to cwd.
                let components = cwd_path_plus(cwd_path, subdir);
                let refs: Vec<&str> = components.iter().map(String::as_str).collect();
                match client.lookup_fh(&refs).await {
                    Ok(fh) => fh,
                    Err(e) => {
                        eprintln!("ls: {e}");
                        return;
                    },
                }
            } else {
                cwd_fh.clone()
            };
            match client.list_dir(&target_fh).await {
                Ok(names) => {
                    let mut sorted = names;
                    sorted.sort();
                    for name in &sorted {
                        println!("{name}");
                    }
                },
                Err(e) => eprintln!("ls: {e}"),
            }
        },
        "cd" => {
            let target = args.first().copied().unwrap_or("/");
            let new_path = if target == "/" {
                // Return to root.
                match client.get_root_fh().await {
                    Ok(fh) => {
                        *cwd_fh = fh;
                        "/".to_owned()
                    },
                    Err(e) => {
                        eprintln!("cd /: {e}");
                        return;
                    },
                }
            } else {
                let components = cwd_path_plus(cwd_path, target);
                let refs: Vec<&str> = components.iter().map(String::as_str).collect();
                match client.lookup_fh(&refs).await {
                    Ok(fh) => {
                        *cwd_fh = fh;
                        format!("/{}", components.join("/"))
                    },
                    Err(e) => {
                        eprintln!("cd: {e}");
                        return;
                    },
                }
            };
            *cwd_path = new_path;
        },
        "cat" => {
            let Some(filename) = args.first() else {
                eprintln!("usage: cat <file>");
                return;
            };
            let file_components = cwd_path_plus(cwd_path, filename);
            let refs: Vec<&str> = file_components.iter().map(String::as_str).collect();
            let file_fh = match client.lookup_fh(&refs).await {
                Ok(fh) => fh,
                Err(e) => {
                    eprintln!("cat: {e}");
                    return;
                },
            };
            nfs4_cat(client, &file_fh).await;
        },
        "get" => {
            let Some(filename) = args.first() else {
                eprintln!("usage: get <file>");
                return;
            };
            let file_components = cwd_path_plus(cwd_path, filename);
            let refs: Vec<&str> = file_components.iter().map(String::as_str).collect();
            let file_fh = match client.lookup_fh(&refs).await {
                Ok(fh) => fh,
                Err(e) => {
                    eprintln!("get: {e}");
                    return;
                },
            };
            // Derive local filename from the last component.
            let local_name = file_components.last().map_or(*filename, String::as_str);
            nfs4_get(client, &file_fh, local_name).await;
        },
        "handle" => {
            let hex = cwd_fh.iter().fold(String::with_capacity(cwd_fh.len() * 2), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            });
            println!("{hex}");
        },
        "lcd" => {
            let dir = args.first().copied().unwrap_or(".");
            match std::env::set_current_dir(dir) {
                Ok(()) => println!("{}", std::env::current_dir().map_or_else(|_| dir.to_owned(), |p| p.display().to_string())),
                Err(e) => eprintln!("lcd: {e}"),
            }
        },
        "lls" => {
            let target = args.first().copied().unwrap_or(".");
            match std::fs::read_dir(target) {
                Ok(iter) => {
                    let mut names: Vec<String> = iter.filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
                    names.sort();
                    for n in &names {
                        println!("{n}");
                    }
                },
                Err(e) => eprintln!("lls: {e}"),
            }
        },
        "lpwd" => match std::env::current_dir() {
            Ok(p) => println!("{}", p.display()),
            Err(e) => eprintln!("lpwd: {e}"),
        },
        "lmkdir" => {
            let Some(dir) = args.first() else {
                eprintln!("usage: lmkdir <dir>");
                return;
            };
            match std::fs::create_dir_all(dir) {
                Ok(()) => println!("created {dir}"),
                Err(e) => eprintln!("lmkdir: {e}"),
            }
        },
        "history" => eprintln!("history: use up/down arrow keys (readline) to navigate command history"),
        "exit" | "quit" => {}, // handled by the REPL loop
        // Write commands exist in the v2/v3 shell but require stateful v4
        // operations (OPEN+WRITE+CLOSE with stateid tracking, RFC 7530
        // S16.2.5).  Tell the user explicitly rather than falling through to
        // "unknown command".
        "put" | "mkdir" | "rm" | "rmdir" | "mv" | "chmod" | "chown" | "symlink" | "link" | "mknod" => {
            eprintln!("{cmd}: not supported in NFSv4 mode (requires stateful OPEN/CLOSE with stateid tracking)");
        },
        _ => eprintln!("unknown command '{cmd}'  --  type 'help' for commands"),
    }
}

/// Build the full path component list for `target` relative to `cwd_path`.
///
/// Handles absolute paths (starting with `/`), parent navigation (`..`),
/// and current-dir navigation (`.`).
fn cwd_path_plus(cwd_path: &str, target: &str) -> Vec<String> {
    let base: Vec<&str> = if target.starts_with('/') {
        // Absolute path: ignore cwd.
        vec![]
    } else {
        cwd_path.trim_start_matches('/').split('/').filter(|s| !s.is_empty()).collect()
    };

    let mut components: Vec<String> = base.iter().map(|s| (*s).to_owned()).collect();
    for part in target.trim_start_matches('/').split('/') {
        match part {
            "" | "." => {},
            ".." => {
                // Pop returns None at root -- that's fine, stay at root.
                drop(components.pop());
            },
            other => components.push(other.to_owned()),
        }
    }
    components
}

// =============================================================================
// Version-specific command lists + remote completers
// =============================================================================

const V4_SHELL_COMMANDS: &[&str] = &["ls", "cd", "pwd", "cat", "get", "uid", "gid", "hostname", "whoami", "handle", "lcd", "lls", "lpwd", "lmkdir", "history", "help", "exit", "quit"];

struct Nfs4RemoteCompleter {
    client: Arc<tokio::sync::Mutex<crate::proto::nfs4::compound::Nfs4DirectClient>>,
}

impl crate::shell::complete::RemoteCompleter for Nfs4RemoteCompleter {
    fn list_dir_entries(&self, handle: &[u8]) -> Vec<String> {
        let client = Arc::clone(&self.client);
        let fh = handle.to_vec();
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(async move { client.lock().await.list_dir(&fh).await.unwrap_or_default() }))
    }

    fn resolve_path(&self, start: &[u8], path: &str) -> Option<Vec<u8>> {
        let client = Arc::clone(&self.client);
        let fh = start.to_vec();
        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(async move { client.lock().await.lookup_from_fh(&fh, &components).await.ok() }))
    }
}

// =============================================================================
// NFSv2 shell  --  MOUNT v1 + Nfs2Client, routed through NfsShell<V2Ops>
// =============================================================================

/// Run an interactive NFSv2 shell via the unified `NfsShell<V2Ops>`.
///
/// Connects with MOUNT v1 for the 32-byte handle (or accepts `--handle` for
/// direct bypass), then delegates all command dispatch to the shared shell.
async fn run_nfs2_shell(args: ShellArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    use nfswolf_nfs2::Nfs2Client;
    use nfswolf_rpc::{rpc::opaque_auth, transport::direct::DirectTransport, transport::tokio::TokioIo};

    use crate::cli::target::{Source, parse as parse_target};
    use crate::proto::auth::next_stamp;
    use crate::proto::mount::NfsMountClient;
    use crate::proto::portmap::PortmapClient;
    use crate::shell::V2_SHELL_COMMANDS;
    use crate::shell::v2::V2Ops;

    if globals.proxy.is_some() {
        tracing::warn!("--proxy not supported with NFSv2; connecting directly");
    }
    if globals.delay > 0 || globals.jitter > 0 {
        tracing::warn!("--delay/--jitter not supported with NFSv2");
    }

    let target = parse_target(&args.target, args.export.as_deref(), args.handle.as_deref(), false)?;
    let host = target.host;
    let uid = globals.uid;
    let gid = globals.gid;
    let hostname = globals.hostname.clone();

    let (root_fh, export) = match &target.source {
        Source::Export(p) => {
            let addr = SocketAddr::new(host, 111);
            let mount_client = NfsMountClient::new().with_credential(Credential::Sys(AuthSys::new(uid, gid, &hostname)));
            let mount_result = mount_client.mount_v1(addr, p).await?;
            let fh = nfswolf_nfs2::wire::Nfs2FileHandle::from_bytes(mount_result.handle.as_bytes());
            (fh, p.clone())
        },
        Source::Handle(hex) => {
            let generic = FileHandle::from_hex(hex).map_err(|e| anyhow::anyhow!("invalid --handle: {e}"))?;
            let fh = nfswolf_nfs2::wire::Nfs2FileHandle::from_bytes(generic.as_bytes());
            eprintln!("{}", crate::output::status_info(&format!("Using raw handle (NFSv2): {hex}")));
            (fh, String::from("/"))
        },
        Source::None => {
            let addr = SocketAddr::new(host, 111);
            let export = "/".to_owned();
            let mount_client = NfsMountClient::new().with_credential(Credential::Sys(AuthSys::new(uid, gid, &hostname)));
            let mount_result = mount_client.mount_v1(addr, &export).await?;
            let fh = nfswolf_nfs2::wire::Nfs2FileHandle::from_bytes(mount_result.handle.as_bytes());
            (fh, export)
        },
    };

    let addr = SocketAddr::new(host, 111);
    let nfs_port = if let Some(p) = globals.nfs_port {
        p
    } else {
        let portmap = PortmapClient::default_port();
        portmap.query_port(addr, 100_003, 2).await.unwrap_or(2049)
    };

    let nfs_addr = SocketAddr::new(host, nfs_port);
    let stream = tokio::net::TcpStream::connect(nfs_addr).await?;
    let io = TokioIo::new(stream);
    let cred = AuthSys::with_groups(uid, gid, &[gid], &hostname);
    let opaque = cred.to_opaque_auth(next_stamp());
    let transport = DirectTransport::with_auth(io, opaque, opaque_auth::default());
    let client = Arc::new(Nfs2Client::new(transport));

    let v2ops = V2Ops::new(client, uid, gid, hostname.clone(), addr, export.clone(), nfs_port);
    let root = ShellHandle(root_fh.0.to_vec());
    let mut shell = NfsShell::new(v2ops, root, args.allow_write, hostname, V2_SHELL_COMMANDS);
    shell.refresh_tab_cache().await;
    eprintln!("{}", crate::output::status_ok(&format!("Connected to {host} as uid={uid} gid={gid} (NFSv2 shell  --  type 'help' for commands)")));
    eprintln!("# rerun: nfswolf shell {host}:{export} --nfs-version 2 --uid {uid} --gid {gid}");

    if let Some(cmd) = args.command {
        shell.dispatch(&cmd).await;
        crate::cli::emit_replay(globals);
        return Ok(());
    }

    // Interactive REPL with Tab completion.
    let completer = shell.make_completer();
    let mut rl = Editor::<ShellCompleter, DefaultHistory>::new()?;
    rl.set_helper(Some(completer));

    loop {
        let prompt = format!("nfswolf@{host}:{} uid={} gid={} [v2]> ", shell.cwd_path(), shell.current_uid(), shell.current_gid());
        match rl.readline(&prompt) {
            Ok(line) => {
                drop(rl.add_history_entry(&line));
                let trimmed = line.trim();
                if trimmed == "exit" || trimmed == "quit" {
                    break;
                }
                shell.dispatch(&line).await;
            },
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("readline error: {e}");
                break;
            },
        }
    }
    crate::cli::emit_replay(globals);
    Ok(())
}
