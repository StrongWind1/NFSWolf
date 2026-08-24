# NFSWolf

**NFS security toolkit — recon, analysis, escape, shell, and exploitation in one native binary.**

NFSWolf replaces 10+ fragmented NFS security tools with one fast Rust binary. It covers recon, analysis, export escape, interactive shell access, and file exfiltration -- all without mounting anything or requiring root on the attacker's machine.

## What NFSWolf does

| Phase | Subcommand | What it does |
|-------|-----------|-------------|
| Recon | `scan` | Port discovery, service enumeration, export listing, OS/FS fingerprinting |
| Analysis | `analyze` | 30+ security checks across 62 findings, risk scoring, multi-format reports |
| Escape | `escape` | Export directory escape to reach the full filesystem via file handle manipulation |
| Shell | `shell` | Interactive NFS shell with 52 commands — `ls`, `cat`, `get`, `put`, SUID scanning, secrets scanning |
| Mount | `mount` | FUSE mount of remote NFS exports as local directories |
| Brute | `brute-handle` | File handle brute-force using the STALE/BADHANDLE oracle |
| Spray | `uid-spray` | UID/GID brute-force for access to restricted files |
| Decode | `decode` | Offline file handle decoder with OS/FS fingerprinting |
| Convert | `convert` | Render analysis results to HTML, Markdown, CSV, or plain text |

## Quick start

```bash
# Install from crates.io
cargo install nfswolf

# Scan a target
nfswolf scan 10.0.0.1

# Analyze security posture
nfswolf analyze 10.0.0.1

# Drop into an interactive shell
nfswolf shell 10.0.0.1:/export

# Attempt export escape
nfswolf escape 10.0.0.1:/export
```

## Key features

- **Pure Rust, zero C dependencies** — statically links via musl for a single portable binary
- **Own protocol stack** — NFSv2, NFSv3, NFSv4, MOUNT v1/v3, portmapper, rpcbind, NFS_ACL, RQUOTA all implemented in-tree. An NFS export is a directory the server shares over the network; NFSWolf targets these exports.
- **No mount required** — operates entirely in userspace via raw RPC, no kernel NFS client needed
- **62 documented security findings** — each traced to an RFC (protocol specification) section, with severity, detection method, and exploitation steps
- **Auto-credential escalation** — automatically tries different user IDs in sequence based on file ownership and directory listings
- **Export escape across 18 filesystem types** — ext2/3/4, XFS, BTRFS, ZFS, f2fs, JFS, and more
- **Stealth-aware** — configurable inter-RPC delays with jitter to avoid detection

## About this site

This site is an NFS security reference and the documentation for the nfswolf tool. Use the tabs above to navigate:

- **NFSWolf** — Installation, every subcommand, shell commands, CLI reference, and examples
- **NFS** — Protocol background, wire-level deep dives (XDR through NFSv4), research, and related tools
- **Security** — 62 findings organized by category/protocol/stage, the attack chain, and defense/hardening guidance
- **Reference** — RFC index, kernel source map, escape matrix, tool comparison, glossary, and changelog
