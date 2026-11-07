//! `clean` subcommand  --  remove your mount list entries from an NFS server.
//!
//! Uses MNTPROC_UMNTALL (RFC 1813 Appendix I sec. 5.2.4) and falls back
//! to looped MNTPROC_UMNT (sec. 5.2.3) to drain reference-counted entries.
//! Both v3 and v1 are called so entries from either version are cleaned up.
//!
//! `--list` mode calls MNTPROC_DUMP to show the current mount list without
//! modifying anything.
//!
//! Linux mountd identifies the caller by TCP source IP (host_ntop in
//! nfs-utils rmtab.c), not AUTH_SYS machinename. You can only clear
//! entries that the server stored under your source IP.
//!
//! NOTE: UMNT/UMNTALL only remove advisory rmtab entries.  File handles
//! already issued remain valid (F-2.5).

use std::net::SocketAddr;

use clap::Parser;
use tabled::builder::Builder;
use tabled::settings::Style;

use crate::cli::{self, GlobalOpts, H_BEHAVIOR};
use crate::output::{sanitize_terminal, status_info, status_ok, status_warn};
use crate::proto::mount::{MountedClient, NfsMountClient};

/// Remove your mount list entries from an NFS server.
///
/// Clears the advisory rmtab entries that `showmount -a` reports.
/// The server identifies you by TCP source IP, so this clears entries
/// stored under your IP. File handles are NOT invalidated (F-2.5).
///
/// Examples:
///   nfswolf clean 10.0.0.5 --list   # inspect the mount list
///   nfswolf clean 10.0.0.5          # remove your entries
#[derive(Parser)]
pub(crate) struct CleanArgs {
    /// Target NFS server
    #[arg(value_name = "TARGET")]
    target: String,

    /// Show the current mount list (MNTPROC_DUMP) without removing anything
    #[arg(long, help_heading = H_BEHAVIOR)]
    list: bool,
}

pub(crate) async fn run(args: CleanArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    let target = cli::target::parse(&args.target, None, None, false)?;
    let addr = SocketAddr::new(target.host, 0);

    if args.list {
        return run_list(addr, globals).await;
    }

    run_drain(addr, globals).await?;

    cli::emit_replay(globals);
    Ok(())
}

/// MNTPROC_DUMP: show the current mount list.
async fn run_list(addr: SocketAddr, globals: &GlobalOpts) -> anyhow::Result<()> {
    let mount = cli::probe::make_mount_client(globals);
    let clients = dump_with_fallback(&mount, addr).await?;

    if clients.is_empty() {
        eprintln!("{}", status_info("mount list is empty (no clients currently mounted)"));
        return Ok(());
    }

    eprintln!("{}", status_info(&format!("{} mount entries on {}", clients.len(), addr.ip())));

    let mut builder = Builder::default();
    builder.push_record(["Hostname", "Export"]);
    for c in &clients {
        builder.push_record([&sanitize_terminal(&c.hostname), &sanitize_terminal(&c.directory)]);
    }
    let mut table = builder.build();
    _ = table.with(Style::rounded());
    println!("{table}");

    Ok(())
}

/// Try UMNTALL, then drain remaining entries via UMNT loop.
///
/// UMNTALL removes all entries at once when the server can reverse-resolve
/// the caller's IP. When it can't (no PTR record), nfs-utils mountd
/// silently skips the deletion (host_canonname returns NULL). The UMNT
/// fallback loop handles that case by decrementing reference counts one
/// export at a time until the entries disappear from DUMP.
///
/// Linux mountd matches UMNT by the caller's TCP source IP
/// (host_ntop(sap) in nfs-utils rmtab.c), not by AUTH_SYS machinename.
async fn run_drain(addr: SocketAddr, globals: &GlobalOpts) -> anyhow::Result<()> {
    let mount = cli::probe::make_mount_client(globals);

    // Snapshot before cleanup.
    let before = dump_with_fallback(&mount, addr).await?;
    if before.is_empty() {
        eprintln!("{}", status_info("mount list is already empty"));
        return Ok(());
    }

    let before_count = before.len();

    // Try UMNTALL first (instant when reverse DNS works).
    eprintln!("{}", status_info("sending UMNTALL"));
    drop(mount.unmount_all(addr).await);
    drop(mount.unmount_all_v1(addr).await);

    // Check what's left.
    let remaining = dump_with_fallback(&mount, addr).await.unwrap_or_default();
    if remaining.len() < before_count {
        let removed = before_count - remaining.len();
        eprintln!("{}", status_ok(&format!("{removed} entries removed via UMNTALL")));
        if remaining.is_empty() {
            return Ok(());
        }
    }

    // Collect exports that still have our entries. We don't know our
    // source IP as the server sees it, so we try UMNT for every entry
    // and let the stall detector figure out which ones are ours.
    let exports: Vec<String> = remaining.iter().map(|c| c.directory.clone()).collect();
    let unique_exports: Vec<String> = {
        let mut seen = std::collections::BTreeSet::new();
        exports.into_iter().filter(|e| seen.insert(e.clone())).collect()
    };

    eprintln!("{}", status_info(&format!("{} entries remain -- draining via UMNT loop", remaining.len())));

    let mut round = 0u32;
    let mut best_count = remaining.len();
    let mut stall_since_best = 0u32;
    loop {
        round += 1;
        for export in &unique_exports {
            drop(mount.unmount(addr, export).await);
            drop(mount.unmount_v1(addr, export).await);
        }

        // Only check progress periodically -- refcount decrements are
        // invisible in DUMP until the count reaches zero, so checking
        // every round would false-stall on high refcounts.
        if !round.is_multiple_of(10) {
            continue;
        }

        let left = dump_with_fallback(&mount, addr).await.unwrap_or_default();
        if left.is_empty() {
            break;
        }

        let cur_count = left.len();
        if cur_count < best_count {
            best_count = cur_count;
            stall_since_best = 0;
        } else {
            stall_since_best += 1;
        }

        if stall_since_best >= 3 {
            let cleared = before_count - cur_count;
            if cleared > 0 {
                eprintln!("{}", status_ok(&format!("{cleared} of your entries cleared")));
            }
            eprintln!("{}", status_warn(&format!("{cur_count} entries remain from other clients (server matches by source IP -- cannot clear entries for other IPs)")));
            return Ok(());
        }

        eprintln!("{}", status_info(&format!("round {round}: {} entries remaining", left.len())));
    }

    eprintln!("{}", status_ok(&format!("all {before_count} entries cleared after {round} rounds")));
    Ok(())
}

/// DUMP with v3 -> v1 fallback.
async fn dump_with_fallback(mount: &NfsMountClient, addr: SocketAddr) -> anyhow::Result<Vec<MountedClient>> {
    match mount.dump_clients(addr).await {
        Ok(c) => Ok(c),
        Err(e) => {
            tracing::debug!(%addr, error = %e, "MOUNT v3 DUMP failed, trying v1");
            mount.dump_clients_v1(addr).await
        },
    }
}
