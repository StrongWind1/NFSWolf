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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).with_target(false).init();

    let cli = cli::Cli::parse();
    let globals = cli.global_opts();

    // Apply no-color globally before any output is produced.
    output::apply_no_color(globals.no_color);

    match cli.command {
        cli::Command::Scan(args) => cli::scan::run(args, &globals).await,
        cli::Command::Analyze(args) => cli::analyze::run(args, &globals).await,
        #[cfg(feature = "fuse")]
        cli::Command::Mount(args) => cli::mount::run(args, &globals).await,
        cli::Command::Shell(args) => cli::shell::run(args, &globals).await,
        cli::Command::Attack(args) => cli::attack::run(args, &globals).await,
        cli::Command::Export(args) => cli::export::run(&args, &globals),
        cli::Command::Completions(args) => {
            cli::completions(&args);
            Ok(())
        },
    }
}
