//! Interactive NFS exploration shell.
//!
//! Connects to an NFS server, mounts an export, and enters a readline REPL
//! so the operator can browse the filesystem without a kernel NFS client.
//! A single `--command` flag lets it run headlessly (useful in scripts).

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use rustyline::Editor;
use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;

use crate::cli::target::Source as TargetSource;
use crate::cli::{GlobalOpts, H_BEHAVIOR, H_IDENTITY, H_PERMISSIONS, H_TARGET};
use crate::proto::auth::{AuthSys, Credential};
use crate::proto::circuit::CircuitBreaker;
use crate::proto::conn::ReconnectStrategy;
use crate::proto::mount::NfsMountClient;
use crate::proto::nfs3::client::Nfs3Client;
use crate::proto::nfs3::types::FileHandle;
use crate::proto::pool::{ConnectionPool, PoolKey};
use crate::shell::{NfsCompleter, NfsShell};
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
pub struct ShellArgs {
    /// Target host with optional :/export suffix (e.g. 10.0.0.5:/srv)
    #[arg(help_heading = H_TARGET)]
    pub target: String,

    /// Export path (alternative to host:/export in the positional target)
    #[arg(short = 'e', long, value_name = "PATH", help_heading = H_TARGET)]
    pub export: Option<String>,

    /// UID for NFS operations (overrides global --uid for this session)
    #[arg(long, value_name = "UID", help_heading = H_IDENTITY)]
    pub uid: Option<u32>,

    /// GID for NFS operations (overrides global --gid for this session)
    #[arg(long, value_name = "GID", help_heading = H_IDENTITY)]
    pub gid: Option<u32>,

    /// Enable write operations (CREATE, WRITE, MKDIR, REMOVE, etc.)
    #[arg(long, help_heading = H_PERMISSIONS)]
    pub allow_write: bool,

    /// Run a single shell command then exit (non-interactive / scripting mode)
    #[arg(short = 'c', long, value_name = "CMD", help_heading = H_BEHAVIOR)]
    pub command: Option<String>,

    /// Use a raw file handle (hex) as the shell root  --  skips MOUNT entirely.
    /// Obtain handles from `attack escape` or `attack brute-handle`.
    #[arg(long, value_name = "HEX", help_heading = H_TARGET)]
    pub handle: Option<String>,

    /// NFS protocol version (2, 3, or 4)
    #[arg(long, default_value = "3", value_name = "VER", help_heading = H_BEHAVIOR)]
    pub nfs_version: u32,
}

/// Entry point for the `shell` subcommand.
pub async fn run(args: ShellArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    tracing::info!(target = %args.target, "starting NFS shell");

    // NFSv4 mode: bypass MOUNT, connect directly to port 2049.
    if args.nfs_version == 4 {
        return run_nfs4_shell(args, globals).await;
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
    let uid = args.uid.unwrap_or(globals.uid);
    let gid = args.gid.unwrap_or(globals.gid);

    let addr = SocketAddr::new(host, 111);
    let pool = Arc::new(match &globals.proxy {
        Some(p) => ConnectionPool::with_proxy(p.clone()),
        None => ConnectionPool::default_config(),
    });
    let circuit = Arc::new(CircuitBreaker::default_config());
    let cred = Credential::Sys(AuthSys::new(uid, gid, &globals.hostname));

    // When --handle is given, skip MOUNT for the root handle.
    // The raw handle is used as the shell root (file handles are bearer tokens per RFC 1094
    // S2.3.3), but we still need an NFS TCP session which requires mounting some export.
    // Strategy:
    //   1. List exports via portmapper to find a mountable one.
    //   2. If portmapper is filtered, fall back to a direct NFS port connection.
    let (root_fh, pool_key, direct_nfs_port) = if let Some(ref hex) = handle_hex_arg {
        let fh = FileHandle::from_hex(hex).map_err(|e| anyhow::anyhow!("invalid --handle: {e}"))?;
        eprintln!("{}", crate::output::status_info(&format!("Using raw handle: {hex}")));

        let nfs_port = globals.nfs_port.unwrap_or(2049);
        let mc = globals.mount_port.map_or_else(NfsMountClient::new, NfsMountClient::with_port);

        match mc.list_exports(addr).await {
            Ok(exports) if !exports.is_empty() => {
                // Use the first available export to establish the NFS TCP session.
                // The raw handle overrides the root fh for all file operations.
                let session_export = exports.into_iter().next().map(|e| e.path).unwrap_or_default();
                eprintln!("{}", crate::output::status_info(&format!("Session via {host}:{session_export}")));
                let key = PoolKey { host: addr, export: session_export, uid, gid };
                (fh, key, None)
            },
            _ => {
                // Portmapper unreachable -- connect directly to NFS port without MOUNT.
                eprintln!("{}", crate::output::status_warn(&format!("Portmapper unavailable  --  connecting direct to port {nfs_port}")));
                let key = PoolKey { host: addr, export: format!("__direct__{nfs_port}"), uid, gid };
                (fh, key, Some(nfs_port))
            },
        }
    } else {
        let mount_client = globals.mount_port.map_or_else(NfsMountClient::new, NfsMountClient::with_port);
        eprintln!("{}", crate::output::status_info(&format!("Mounting {host}:{export}")));
        let mount_result = mount_client.mount(addr, &export).await?;
        let key = PoolKey { host: addr, export: export.clone(), uid, gid };
        (mount_result.handle, key, None)
    };

    let stealth = StealthConfig::new(globals.delay, globals.jitter);
    let nfs3 = if let Some(nfs_port) = direct_nfs_port {
        Arc::new(Nfs3Client::new_direct(Arc::clone(&pool), pool_key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent, nfs_port))
    } else {
        Arc::new(Nfs3Client::new(Arc::clone(&pool), pool_key, Arc::clone(&circuit), stealth, cred, ReconnectStrategy::Persistent))
    };

    let mut shell = NfsShell::new(Arc::clone(&nfs3), root_fh, args.allow_write, globals.hostname.clone());
    eprintln!("{}", crate::output::status_ok(&format!("Connected to {host} as uid={uid} gid={gid}{}   --   type 'help' for commands", if args.allow_write { "  [write enabled]" } else { "" },)));

    if let Some(cmd) = args.command {
        // Non-interactive: run one command and return.
        shell.dispatch(&cmd).await;
        crate::cli::emit_replay(globals);
        return Ok(());
    }

    // Interactive REPL with Tab completion.
    let completer = shell.make_completer();
    let mut rl = Editor::<NfsCompleter, DefaultHistory>::new()?;
    rl.set_helper(Some(completer));

    loop {
        let prompt = format!("nfswolf@{host}:{} uid={}> ", shell.cwd_path(), uid);
        match rl.readline(&prompt) {
            Ok(line) => {
                let _ = rl.add_history_entry(&line);
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

/// Run an interactive NFSv4 shell.
///
/// Used when `--nfs-version 4` is set.  Connects directly to port 2049 without
/// the MOUNT protocol (which is not required for NFSv4).  Supports a subset of
/// the full NFSv3 shell commands sufficient to explore NFSv4-only servers.
async fn run_nfs4_shell(args: ShellArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    use crate::proto::nfs4::compound::Nfs4DirectClient;
    use rustyline::DefaultEditor;

    let target = crate::cli::target::parse(&args.target, args.export.as_deref(), args.handle.as_deref(), false)?;
    let host = target.host;
    let _ = target.source; // NFSv4 path doesn't use MOUNT or raw handle
    let nfs_port = globals.nfs_port.unwrap_or(2049);
    let addr = SocketAddr::new(host, nfs_port);
    let mut uid = args.uid.unwrap_or(globals.uid);
    let mut gid = args.gid.unwrap_or(globals.gid);
    let mut hostname = globals.hostname.clone();

    eprintln!("{}", crate::output::status_info(&format!("Connecting to {host}:{nfs_port} via NFSv4 (no MOUNT)")));
    let mut client = Nfs4DirectClient::connect_with_auth(addr, uid, gid, &hostname).await.map_err(|e| anyhow::anyhow!("NFSv4 connect to {addr} failed: {e}"))?;

    // Fetch the root FH from PUTROOTFH + GETFH.
    let root_fh = client.get_root_fh().await.map_err(|e| anyhow::anyhow!("PUTROOTFH failed: {e}"))?;
    eprintln!("{}", crate::output::status_ok(&format!("Connected to {host} as uid={uid} gid={gid} hostname={hostname}  (NFSv4 shell  --  type 'help' for commands)")));

    let mut cwd_fh = root_fh;
    let mut cwd_path = "/".to_owned();

    // Non-interactive mode: run one command and return.
    if let Some(ref cmd) = args.command {
        dispatch_nfs4(&mut client, cmd, &mut cwd_fh, &mut cwd_path, args.allow_write, &mut uid, &mut gid, &mut hostname).await;
        crate::cli::emit_replay(globals);
        return Ok(());
    }

    // Interactive REPL (no Tab completion for NFSv4 shell).
    let mut rl = DefaultEditor::new()?;
    loop {
        let prompt = format!("nfswolf@{host}:{cwd_path} uid={uid} hostname={hostname} [v4]> ");
        match rl.readline(&prompt) {
            Ok(line) => {
                let _ = rl.add_history_entry(&line);
                let trimmed = line.trim();
                if trimmed == "exit" || trimmed == "quit" {
                    break;
                }
                dispatch_nfs4(&mut client, trimmed, &mut cwd_fh, &mut cwd_path, args.allow_write, &mut uid, &mut gid, &mut hostname).await;
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

/// Dispatch a single command in the NFSv4 shell REPL.
#[allow(clippy::too_many_arguments, reason = "NFSv4 shell session state requires uid/gid/hostname alongside client and path")]
async fn dispatch_nfs4(client: &mut crate::proto::nfs4::compound::Nfs4DirectClient, line: &str, cwd_fh: &mut Vec<u8>, cwd_path: &mut String, allow_write: bool, uid: &mut u32, gid: &mut u32, hostname: &mut String) {
    let _ = allow_write; // write ops not yet implemented in NFSv4 shell
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
            let mut offset: u64 = 0;
            loop {
                match client.read_chunk(&file_fh, offset, 65536).await {
                    Ok((data, eof)) => {
                        // Safety: print as lossy UTF-8 to avoid crashing on binary files.
                        print!("{}", String::from_utf8_lossy(&data));
                        offset += data.len() as u64;
                        if eof || data.is_empty() {
                            break;
                        }
                    },
                    Err(e) => {
                        eprintln!("cat: {e}");
                        break;
                    },
                }
            }
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
            let mut buf = Vec::new();
            let mut offset: u64 = 0;
            loop {
                match client.read_chunk(&file_fh, offset, 65536).await {
                    Ok((data, eof)) => {
                        offset += data.len() as u64;
                        buf.extend_from_slice(&data);
                        if eof || data.is_empty() {
                            break;
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
        },
        "exit" | "quit" => {}, // handled by the REPL loop
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
                components.pop();
            },
            other => components.push(other.to_owned()),
        }
    }
    components
}
