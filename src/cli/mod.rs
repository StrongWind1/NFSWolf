//! CLI argument parsing and subcommand dispatch.

pub mod analyze;
pub mod brute_handle;
pub mod convert;
pub mod escape;
pub mod mount;
pub mod probe;
pub mod scan;
pub mod shell;
pub mod target;
pub mod uid_spray;

use clap::{Parser, Subcommand};

// --- Help section headings ---------------------------------------------------
//
// Every `#[arg]` carries a `help_heading = H_xxx` so `--help` renders in fixed
// sections (Target / Identity / Permissions / Network / Stealth / Output /
// Behavior). Section ordering follows declaration order of unique heading
// strings, so the constants are listed below in the order we want them to
// appear in `--help`.

/// Where the toolkit gets the root file handle from (positional target,
/// `--export`, or `--handle`).
pub const H_TARGET: &str = "Target / Source";

/// AUTH_SYS credential fields (uid, gid, hostname, auto-uid).
pub const H_IDENTITY: &str = "Identity";

/// Per-operation safety belts (`--allow-write`, `--allow-root`, FUSE-mount
/// permission flags).
pub const H_PERMISSIONS: &str = "Permissions";

/// Network-level toggles: alternate ports, transport, proxy, timeout.
pub const H_NETWORK: &str = "Network";

/// Timing knobs that make traffic less recognisable.
pub const H_STEALTH: &str = "Stealth";

/// Reporting / verbosity / file-output flags.
pub const H_OUTPUT: &str = "Output";

/// Per-subcommand behavior switches (the long tail of `--check-*`,
/// `--probe-*`, `--no-*`, etc.).
pub const H_BEHAVIOR: &str = "Behavior";

// -----------------------------------------------------------------------------

/// NFS security scanner, analyzer and exploitation toolkit for authorized assessments.
///
/// Common workflows:
///   nfswolf scan 192.168.1.0/24            # discover NFS servers
///   nfswolf analyze 192.168.1.10           # full security audit
///   nfswolf shell 192.168.1.10:/srv        # interactive exploration
///   nfswolf escape 192.168.1.10:/srv       # subtree-check bypass -> root handle
///   nfswolf shell 192.168.1.10 --handle HEX  # HEX = output from escape
#[derive(Parser)]
#[command(name = "nfswolf", version, about, long_about = None)]
pub struct Cli {
    /// AUTH_SYS UID to present to the NFS server (spoofed  --  server trusts this)
    #[arg(short = 'u', long, global = true, default_value = "1000", value_name = "UID", help_heading = H_IDENTITY)]
    pub uid: u32,

    /// AUTH_SYS GID to present to the NFS server
    #[arg(short = 'g', long, global = true, default_value = "1000", value_name = "GID", help_heading = H_IDENTITY)]
    pub gid: u32,

    /// Client hostname injected into AUTH_SYS credentials (spoofed)
    #[arg(long, global = true, default_value = "localhost", value_name = "NAME", help_heading = H_IDENTITY)]
    pub hostname: String,

    /// Bind from a privileged source port (<1024). Required by servers with
    /// the `secure` export option. Needs root or CAP_NET_BIND_SERVICE.
    #[arg(long, global = true, help_heading = H_NETWORK)]
    pub privileged_port: bool,

    /// Route all connections through a SOCKS5 proxy
    #[arg(long, global = true, value_name = "HOST:PORT", help_heading = H_NETWORK)]
    pub proxy: Option<String>,

    /// Use UDP instead of TCP for portmapper and NFS probes.
    /// Required for servers that block TCP/111 or only serve NFS over UDP
    /// (legacy embedded devices, older HP-UX and NetApp configurations).
    #[arg(long = "transport-udp", global = true, help_heading = H_NETWORK)]
    pub transport_udp: bool,

    /// Connection timeout in milliseconds
    #[arg(short = 't', long, global = true, default_value = "3000", value_name = "MS", help_heading = H_NETWORK)]
    pub timeout: u64,

    /// Override the NFS port (skip portmapper). Applies to every subcommand
    /// that opens an NFS connection -- mount, shell, attack modules.
    #[arg(long, global = true, value_name = "PORT", help_heading = H_NETWORK)]
    pub nfs_port: Option<u16>,

    /// Override the mount-daemon port (skip portmapper). Applies to every
    /// subcommand that calls MOUNT.
    #[arg(long, global = true, value_name = "PORT", help_heading = H_NETWORK)]
    pub mount_port: Option<u16>,

    /// Delay between RPC calls in milliseconds (stealth mode)
    #[arg(long, global = true, default_value = "0", value_name = "MS", help_heading = H_STEALTH)]
    pub delay: u64,

    /// Random jitter added to each delay (0 = no jitter)
    #[arg(long, global = true, default_value = "0", value_name = "MS", help_heading = H_STEALTH)]
    pub jitter: u64,

    /// Disable ANSI colour output (also set by NO_COLOR env var)
    #[arg(long, global = true, help_heading = H_OUTPUT)]
    pub no_color: bool,

    /// Emit machine-readable JSON instead of human-readable output
    #[arg(long, global = true, help_heading = H_OUTPUT)]
    pub json: bool,

    /// Increase log verbosity (-v info, -vv debug, -vvv trace)
    #[arg(short, long, global = true, action = clap::ArgAction::Count, help_heading = H_OUTPUT)]
    pub verbose: u8,

    /// Suppress status lines; only emit findings and errors
    #[arg(short, long, global = true, help_heading = H_OUTPUT)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Discover NFS servers on a network
    Scan(scan::ScanArgs),

    /// Deep security audit of an NFS server
    Analyze(analyze::AnalyzeArgs),

    /// FUSE-mount an NFS export with UID spoofing
    #[cfg(feature = "fuse")]
    Mount(mount::MountArgs),

    /// Interactive NFS exploration shell
    Shell(shell::ShellArgs),

    /// Escape an export to the filesystem root via subtree_check bypass
    Escape(escape::EscapeArgs),

    /// Brute-force NFS file handles using the STALE/BADHANDLE oracle
    BruteHandle(brute_handle::BruteHandleArgs),

    /// UID/GID spray (last-resort credential discovery)
    UidSpray(uid_spray::UidSprayArgs),

    /// Convert an `analyze --json` dump into HTML/Markdown/CSV/TXT/console
    Convert(convert::ConvertArgs),

    /// Generate shell completions
    Completions(CompletionsArgs),
}

#[derive(Parser)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

/// Global options extracted from the top-level CLI for passing to subcommands.
#[derive(Debug, Clone)]
pub struct GlobalOpts {
    /// Override UID for all NFS operations.
    pub uid: u32,
    /// Override GID for all NFS operations.
    pub gid: u32,
    /// Spoofed client hostname in AUTH_SYS credentials.
    pub hostname: String,
    /// Whether to bind to a privileged port (<1024).
    pub privileged_port: bool,
    /// Optional SOCKS5 proxy address.
    pub proxy: Option<String>,
    /// Use UDP transport for portmapper and NFS probes.
    pub transport_udp: bool,
    /// Connection timeout in milliseconds.
    pub timeout: u64,
    /// Override NFS port (skip portmapper) when set.
    pub nfs_port: Option<u16>,
    /// Override mount-daemon port (skip portmapper) when set.
    pub mount_port: Option<u16>,
    /// Delay between operations in milliseconds.
    pub delay: u64,
    /// Random jitter added to delay in milliseconds.
    pub jitter: u64,
    /// Disable colored output.
    pub no_color: bool,
    /// Output JSON instead of human-readable format.
    pub json: bool,
    /// Verbose logging level.
    pub verbose: u8,
    /// Suppress non-essential output.
    pub quiet: bool,
}

impl Cli {
    /// Extract the global options into a standalone struct.
    ///
    /// Called in main() before matching on the subcommand so global
    /// values survive the partial move of `cli.command`.
    #[must_use]
    pub fn global_opts(&self) -> GlobalOpts {
        GlobalOpts {
            uid: self.uid,
            gid: self.gid,
            hostname: self.hostname.clone(),
            privileged_port: self.privileged_port,
            proxy: self.proxy.clone(),
            transport_udp: self.transport_udp,
            timeout: self.timeout,
            nfs_port: self.nfs_port,
            mount_port: self.mount_port,
            delay: self.delay,
            jitter: self.jitter,
            no_color: self.no_color,
            json: self.json,
            verbose: self.verbose,
            quiet: self.quiet,
        }
    }
}

pub fn completions(args: &CompletionsArgs) {
    let mut cmd = <Cli as clap::CommandFactory>::command();
    clap_complete::generate(args.shell, &mut cmd, "nfswolf", &mut std::io::stdout());
}

/// Print a `# rerun: ...` line to stderr after a successful subcommand.
///
/// The line echoes back the literal argv the user typed (minus the
/// program name), which is the most useful thing to copy into shell
/// history. Skipped when `--quiet` or `--json` is set so machine-readable
/// output stays clean.
pub fn emit_replay(globals: &GlobalOpts) {
    if globals.quiet || globals.json {
        return;
    }
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        return;
    }
    eprintln!("# rerun: nfswolf {}", argv.join(" "));
}
