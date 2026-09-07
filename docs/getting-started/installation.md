# Installation

NFSWolf is distributed as a single binary with no runtime dependencies. Pick whichever installation method fits your workflow.

!!! warning "Authorization required"
    NFSWolf is a security research tool. Only use it against systems you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal in most jurisdictions.

## Install methods

=== "crates.io"

    The simplest path if you already have a Rust toolchain (1.95+):

    ```bash
    cargo install nfswolf
    ```

    This pulls the latest published release, compiles it with all default features (including FUSE mount support), and drops the binary into `~/.cargo/bin/`.

=== "GitHub (latest)"

    Install directly from the main branch to get unreleased changes:

    ```bash
    cargo install --git https://github.com/StrongWind1/NFSWolf
    ```

    This tracks the latest commit. If you want a specific tag:

    ```bash
    cargo install --git https://github.com/StrongWind1/NFSWolf --tag v1.2.0
    ```

=== "Pre-built binary"

    Download a statically-linked binary from [GitHub Releases](https://github.com/StrongWind1/NFSWolf/releases). No Rust toolchain required, no system dependencies.

    ```bash
    # Download the latest release (x86_64 Linux, static musl build)
    wget https://github.com/StrongWind1/NFSWolf/releases/latest/download/nfswolf-linux-x86_64

    # Make it executable
    chmod +x nfswolf-linux-x86_64

    # Move to a directory on your PATH
    sudo mv nfswolf-linux-x86_64 /usr/local/bin/nfswolf
    ```

    Available pre-built targets:

    | Artifact | Platform | Notes |
    |----------|----------|-------|
    | `nfswolf-linux-x86_64` | Linux x86_64 (musl) | Static binary, no dependencies, no FUSE |
    | `nfswolf-linux-x86_64-full` | Linux x86_64 (glibc) | Dynamic, includes FUSE mount support |
    | `nfswolf-linux-arm64` | Linux ARM64 (musl) | Static binary, no dependencies, no FUSE |
    | `nfswolf-linux-arm64-full` | Linux ARM64 (glibc) | Dynamic, includes FUSE mount support |
    | `nfswolf-macos-arm64` | macOS Apple Silicon | No FUSE |
    | `nfswolf-macos-x86_64` | macOS Intel | No FUSE |
    | `nfswolf-macos-universal` | macOS Universal | Fat binary (arm64 + x86_64) |

    !!! note "Static vs full builds"
        The musl builds are fully static and run on any Linux distribution without dependencies. The `-full` builds link against glibc and libfuse3, enabling the `nfswolf mount` subcommand. If you do not need FUSE mounting, use the static build.

=== "Build from source"

    Clone the repository and build with Make:

    ```bash
    git clone https://github.com/StrongWind1/NFSWolf.git
    cd NFSWolf

    # Optimized release build (recommended)
    make build

    # Debug build for development (faster compilation)
    make dev
    ```

    The release binary lands in `target/release/nfswolf`. The debug binary goes to `target/debug/nfswolf`.

    To build distribution artifacts for your platform:

    ```bash
    make dist
    ```

    This auto-detects your OS and architecture and produces the appropriate binaries in the `dist/` directory.

## Requirements

| Method | Requirements |
|--------|-------------|
| Pre-built binary | None |
| `cargo install` | Rust 1.95+ (install via [rustup](https://rustup.rs/)) |
| Build from source | Rust 1.95+, `git`, `make` |

### Optional dependencies

**libfuse3-dev** -- Required only for the `nfswolf mount` subcommand, which FUSE-mounts an NFS export as a local directory. Install it before building if you want mount support:

```bash
# Debian / Ubuntu
sudo apt install libfuse3-dev pkg-config

# Fedora / RHEL
sudo dnf install fuse3-devel pkg-config

# Arch
sudo pacman -S fuse3 pkgconf
```

The static musl builds intentionally omit FUSE because libfuse3 cannot be statically linked. If you need both static linking and FUSE, use the glibc `-full` build.

## Cargo features

NFSWolf has two Cargo features:

| Feature | Default | Description |
|---------|---------|-------------|
| `fuse` | On | Enables the `nfswolf mount` subcommand (requires libfuse3 at build time) |
| `auth-dh` | Off | Enables AUTH_DH cryptographic sessions ([RFC 2695](../reference/rfcs.md)) for testing Diffie-Hellman authentication |

To build without FUSE (for static musl builds or systems without libfuse3):

```bash
cargo build --release --no-default-features
```

To build with AUTH_DH support:

```bash
cargo build --release --features auth-dh
```

To build with everything:

```bash
cargo build --release --all-features
```

## Verify the installation

```bash
nfswolf --version
```

```
nfswolf 1.2.0
```

```bash
nfswolf --help
```

??? example "Full `--help` output"

    ```
    NFS security scanner, analyzer and exploitation toolkit for authorized assessments.

    Usage: nfswolf [OPTIONS] <COMMAND>

    Commands:
      Recon:
        scan          Discover NFS servers on a network
        analyze       Deep security audit of an NFS server
        escape        Break out of an export to the filesystem root (subtree_check bypass)
      Connect:
        shell         Interactive NFS exploration shell
        mount         FUSE-mount an NFS export with UID spoofing
      Advanced:
        brute-handle  Brute-force file handles via the STALE/BADHANDLE oracle
        uid-spray     UID/GID spray (last-resort credential discovery)
      Utilities:
        convert       Render an `analyze --json` dump to HTML/MD/CSV/TXT/console
        decode        Decode an NFS file handle and print every field
        completions   Generate shell completions

    Run `nfswolf <COMMAND> --help` for per-command options.
    ```

## Shell completions

Generate tab completions for your shell:

```bash
# Bash
nfswolf completions bash > ~/.local/share/bash-completion/completions/nfswolf

# Zsh
nfswolf completions zsh > ~/.zfunc/_nfswolf

# Fish
nfswolf completions fish > ~/.config/fish/completions/nfswolf.fish
```

## Next steps

Head to the [Quick Start](quick-start.md) to run your first scan.
