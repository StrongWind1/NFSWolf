# nfswolf

Fast, native NFS security toolkit. One static binary — recon, analysis, escape, exploitation, and an interactive shell — for **authorized security research only**.

[![CI](https://github.com/StrongWind1/NFSWolf/actions/workflows/ci.yml/badge.svg)](https://github.com/StrongWind1/NFSWolf/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV 1.94](https://img.shields.io/badge/msrv-1.94-informational)](rust-toolchain.toml)

## Authorized use only

nfswolf is a penetration-testing and security-research tool. Operating it against systems without explicit written authorization is illegal in most jurisdictions. You alone are responsible for how you use it. By using nfswolf you accept full responsibility for compliance with applicable laws, contracts, and policies.

If you believe you have found a security issue in nfswolf itself, please read [SECURITY.md](SECURITY.md) for the disclosure channel.

## Why nfswolf

The NFS security ecosystem is scattered across a dozen small tools written in the 1990s and 2000s, most of which only work on Linux and depend on `libnfs`. nfswolf consolidates the full NFS attack path — reconnaissance, analysis, export escape, shell access, and targeted exploitation — into a single pure-Rust binary that links statically under `musl`.

| Capability | nfswolf | showmount | nfsspy | msf NFS | nfs-ls | nfsshell |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| NFSv2 / v3 / v4 | yes | no | v3 | v3 | v3 | v3 |
| Async / concurrent scan | yes | no | no | yes | no | no |
| AUTH_SYS UID spraying | yes | no | yes | yes | no | no |
| Export escape (ext4/XFS/BTRFS) | yes | no | no | no | no | no |
| Interactive NFS shell (35+ commands) | yes | no | no | no | no | yes |
| FUSE mount (`nfswolf mount`) | yes | no | no | no | no | no |
| Portmapper / mountd enumeration | yes | partial | no | no | no | no |
| Self-contained HTML / JSON / CSV reports | yes | no | no | no | no | no |
| Static musl binary (no C deps) | yes | no | no | no | no | no |
| SOCKS5 proxy + privileged-port binding | yes | no | no | no | no | no |
| Stealth delay + jitter | yes | no | no | no | no | no |

## Features at a glance

- **Documented security findings** across export, transport, file-handle, and credential attack categories — full catalog in [docs/FINDINGS.md](docs/FINDINGS.md).
- **Protocols**: NFSv2 / NFSv3 / NFSv4.0 over TCP (UDP transport for portmapper), MOUNT v1/v3, portmapper v2.
- **Engines**: pool-backed RPC with circuit breaker, AUTH_SYS stamp injection, auto-UID escalation ladder, handle-oracle disambiguation (STALE vs BADHANDLE).
- **Offensive subcommands**: `escape` (export breakout), `brute-handle` (handle oracle), `uid-spray` (last-resort credential discovery).
- **Interactive shell** with tab completion, `get -r` / `put -r`, `--verify <sha256>`, and all standard POSIX-style verbs.
- **FUSE**: mount any NFS export locally with spoofed credentials via `nfswolf mount`.
- **Six report formats**: HTML, JSON, CSV, Markdown, plain-text, ANSI console.

## Installation

### Prebuilt binaries

Download from the [Releases page](https://github.com/StrongWind1/NFSWolf/releases). Each release ships with a `SHA256SUMS` checksum file, a `SHA256SUMS.sig` cosign signature, and per-artifact SLSA build-provenance attestations.

### Pick your artifact carefully — the `mount` subcommand is NOT in the musl static build

| File | Link | FUSE / `nfswolf mount` | When to use it |
|---|---|:---:|---|
| `nfswolf-linux-x86_64` | musl, static | **no** | Zero-dependency binary, runs on any Linux kernel (Alpine, distroless, CI runners). You only need `scan` / `analyze` / `shell` / `escape` / `brute-handle` / `uid-spray`. |
| `nfswolf-linux-x86_64-full` | glibc, dynamic | **yes** | `nfswolf mount` (FUSE). Requires libfuse3 on the host. |
| `nfswolf-linux-arm64`, `nfswolf-linux-arm64-full` | same split on ARM64 | same split | Same trade-off on ARM64. |
| `nfswolf-macos-universal`, `nfswolf-macos-arm64`, `nfswolf-macos-x86_64` | macOS | macFUSE required | macOS has no bundled FUSE; install [macFUSE](https://osxfuse.github.io/) separately if you want `mount`. |
| `nfswolf-windows-x86_64-msvc.exe`, `-gnu.exe`, `-arm64-msvc.exe` | Windows | **no** | FUSE is Linux / macOS only; `nfswolf mount` is not available on Windows regardless of build. |

If you download the static-musl Linux binary and then try `nfswolf mount ...`, the command will not exist in the binary and `nfswolf --help` will not list it. This is by design — `libfuse3` cannot be statically linked against `musl`.

### Verify your download

```sh
# Integrity (anyone):
sha256sum -c SHA256SUMS --ignore-missing

# Authenticity (requires cosign + the repo's expected OIDC identity):
cosign verify-blob \
  --certificate-identity-regexp "^https://github\\.com/StrongWind1/NFSWolf/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature SHA256SUMS.sig \
  SHA256SUMS
```

### From source

```sh
git clone https://github.com/StrongWind1/NFSWolf
cd nfswolf
make build            # release build for the native target
sudo install -Dm755 target/release/nfswolf /usr/local/bin/nfswolf
```

### From crates.io

```sh
cargo install nfswolf --locked
```

## Quick start

The positional `<TARGET>` accepts the colon shorthand `host:/export` on
every subcommand; `--export` and `--handle` still work as flags. See
`nfswolf <subcommand> --help` for the per-section flag layout.

```sh
# Discover NFS infrastructure on a /24:
nfswolf scan 192.168.1.0/24

# Deep security analysis of a single host (capture JSON, render HTML offline):
nfswolf analyze --json 192.168.1.10 > results.json
nfswolf convert -i results.json -f html -o report.html

# Interactive shell against an export:
nfswolf shell 192.168.1.10:/srv/nfs --uid 0

# Mount an export locally via FUSE, spoofing UID 0:
sudo nfswolf --uid 0 mount 192.168.1.10:/srv/nfs /mnt/target

# Construct an escape handle to reach the underlying filesystem root:
nfswolf escape 192.168.1.10:/srv/nfs

# Last-resort UID/GID brute force when the auto-UID ladder doesn't find a hit:
nfswolf uid-spray 192.168.1.10:/srv/nfs --uid-start 0 --uid-end 5000 --path /etc/shadow

# Re-runnable replay: every successful command prints a `# rerun: ...`
# line on stderr that you can paste back into your shell.
```

## CLI reference

| Subcommand | Purpose |
|---|---|
| `scan` | Network-wide NFS discovery (CIDR, target file, single host) |
| `analyze` | Per-host security audit against the documented finding catalog |
| `shell` | Interactive REPL over NFSv3 or NFSv4, with `get -r` / `put -r` / `--verify` |
| `mount` | FUSE mount with spoofed AUTH_SYS credentials (`--features fuse`) |
| `escape` | Construct ext4 / XFS / BTRFS escape handles to break out of an export |
| `brute-handle` | Brute-force file handles using the STALE / BADHANDLE oracle |
| `uid-spray` | Last-resort UID/GID brute force when auto-UID escalation fails |
| `convert` | Render a saved analysis result to HTML / JSON / CSV / Markdown / text |
| `completions <shell>` | Generate shell completions for bash, zsh, fish, PowerShell |

Global flags common to every subcommand:

```
--uid <UID>              AUTH_SYS UID (default 1000; use 0 for root spoof)
--gid <GID>              AUTH_SYS primary GID (default 1000)
--aux-gids <G1,G2,...>   Auxiliary GIDs (max 16 per RFC 1057 §9.2)
--hostname <NAME>        AUTH_SYS machinename field
--privileged-port        Bind source port <1024 (may require CAP_NET_BIND_SERVICE / root)
--proxy <HOST:PORT>      Route all RPC through SOCKS5 (no-auth) proxy
--transport-udp          Use UDP for portmapper probes where supported
--stealth-delay <MS>     Baseline inter-RPC delay
--stealth-jitter <MS>    Random jitter added to each delay
--no-color               Strip ANSI colors
-v / -vv / -vvv          Verbosity (info / debug / trace)
```

See `nfswolf <subcommand> --help` for per-subcommand flags.

## What nfswolf does NOT do

- Does not exploit RPCSEC_GSS / Kerberized mounts (detection only).
- Does not attack NFS-over-TLS channels (detects `NONE`/`TLS_V1` negotiation only).
- Does not modify server state without `--allow-write`.
- Does not run without an authorized target specified on the command line.

## Platform support

| Platform | Scan / Analyze / Escape / Spray | `mount` (FUSE) |
|---|:---:|:---:|
| Linux x86_64 (glibc) | yes | yes |
| Linux x86_64 (musl static) | yes | no |
| Linux arm64 | yes | yes |
| macOS (Apple Silicon & Intel) | yes | macFUSE req. |
| Windows x86_64 / arm64 | yes | no |

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version:

```sh
make hooks        # install the repo pre-commit hook
make dev          # debug build, fast iteration
make check-all    # full gate: fmt, lint, audit, check, test-matrix, doc, hygiene, machete
```

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Acknowledgments

- [nfs3-rs](https://github.com/Vaiz/nfs3) by Vaiz — the NFSv3 / MOUNT / portmapper / XDR foundation.
- Authors of RFC 1057, RFC 1094, RFC 1813, RFC 5531, RFC 7530, RFC 2623, RFC 9289.
- Prior-art tools that inspired this consolidation: `nfsspy`, `nfsshell`, `showmount`, Metasploit NFS modules.
