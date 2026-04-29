//! nfswolf  --  Fast native NFSv3 security scanner and analysis toolkit
//!
//! A unified tool for discovering, analyzing, and exploiting NFSv3
//! misconfigurations during authorized security assessments.

mod cli;
mod engine;
mod output;
mod proto;
mod report;
mod util;

#[cfg(feature = "fuse")]
mod fuse;

mod shell;

use clap::Parser;
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).with_target(false).init();

    let cli = cli::Cli::parse();
    let globals = cli.global_opts();

    // Apply no-color globally before any output is produced.
    output::apply_no_color(globals.no_color);

    // The `mount` subcommand is special: the FUSE handler thread must
    // outlive the operator's shell, otherwise the kernel mount goes
    // "Transport endpoint is not connected" the moment we return.
    // We detach via libc::daemon BEFORE building any tokio runtime --
    // fork() only copies the calling thread, so a tokio runtime created
    // in the parent would be left without workers in the daemon child
    // and every async call would deadlock.  Sync pre-flight (mountpoint
    // checks, flag conflicts) and the user-visible status banner happen
    // here too, so any argv-level error reaches the foreground shell
    // with a non-zero exit code.
    #[cfg(feature = "fuse")]
    if let cli::Command::Mount(args) = &cli.command {
        cli::mount::preflight(args)?;
        eprintln!("{}", output::status_info(&format!("Mounting at {} (background; unmount with `fusermount3 -u {}`)", args.mountpoint, args.mountpoint)));
        cli::emit_replay(&globals);
        // nochdir = 1 keeps cwd so relative paths still resolve.
        // noclose = 1 keeps stdio attached so any post-fork MOUNT or
        // FUSE error still surfaces in the operator's terminal (it
        // appears after the next shell prompt redraw rather than
        // blocking the prompt).
        #[allow(unsafe_code, reason = "libc::daemon is the only POSIX way to detach without dropping into raw fork(); confined to this single call site")]
        let rc = unsafe { libc::daemon(1, 1) };
        if rc != 0 {
            anyhow::bail!("daemonize failed: {}", std::io::Error::last_os_error());
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        match cli.command {
            cli::Command::Scan(args) => cli::scan::run(args, &globals).await,
            cli::Command::Analyze(args) => cli::analyze::run(args, &globals).await,
            #[cfg(feature = "fuse")]
            cli::Command::Mount(args) => cli::mount::run(args, &globals).await,
            cli::Command::Shell(args) => cli::shell::run(args, &globals).await,
            cli::Command::Escape(args) => cli::escape::run(args, &globals).await,
            cli::Command::BruteHandle(args) => cli::brute_handle::run(args, &globals).await,
            cli::Command::UidSpray(args) => cli::uid_spray::run(args, &globals).await,
            cli::Command::Convert(args) => cli::convert::run(&args, &globals),
            cli::Command::Completions(args) => {
                cli::completions(&args);
                Ok(())
            },
        }
    })
}
