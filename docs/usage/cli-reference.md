# CLI Reference

Complete reference for every nfswolf command and flag. For narrative walkthroughs, see the individual subcommand pages in the NFSWolf tab.

Subcommands that work on a single export take the target as `host:/export` or `host --export /p`. `shell` and `mount` also accept `host --handle HEX` to skip MOUNT and use a raw file handle as the root; `brute-handle` takes its seed handle with `--seed-handle HEX`. IPv6 must be bracketed: `[2001:db8::1]:/export`.

---

## nfswolf

Global options inherited by every subcommand. They can be given before or after the subcommand name.

### Identity

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-u`, `--uid` | `UID` | `1000` | AUTH_SYS UID presented to the NFS server (spoofed; server trusts this) |
| `-g`, `--gid` | `GID` | `1000` | AUTH_SYS GID presented to the NFS server |
| `--hostname` | `NAME` | `localhost` | Client hostname injected into AUTH_SYS credentials (spoofed) |
| `--aux-gids` | `G1,G2,...` | -- | Auxiliary GIDs in AUTH_SYS (comma-separated, max 16 per RFC 1057 S9.2). Add 42 (Debian/Ubuntu shadow) or 15 (SUSE shadow) to read `/etc/shadow` without `no_root_squash`. |

### Network

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--privileged-port` | bool | `false` | Bind from a privileged source port (<1024). Required by servers with the `secure` export option. Honored by every MOUNT call in every subcommand, `scan` included. Needs root or `CAP_NET_BIND_SERVICE`. |
| `--proxy` | `HOST:PORT` | -- | Route all connections through a SOCKS5 proxy |
| `-t`, `--timeout` | `MS` | per subcommand | Probe timeout in milliseconds. When omitted: 3000 for `scan` probes, 5000 for `analyze` probes, 2000 for NFS version detection in `shell` and `mount`. An explicit value applies to all of them. Calls on an established NFS session keep a fixed 30 s deadline that this flag does not change. |
| `--nfs-port` | `PORT` | -- | Override the NFS port (skip portmapper GETPORT). Applies to every subcommand that opens an NFS connection, `analyze` included, and to every pooled NFS connection. |
| `--mount-port` | `PORT` | -- | Override the mount-daemon port (skip portmapper GETPORT). Applies to every MOUNT call in every subcommand, including those made inside pooled connections. |
| `--rpc-port` | `PORT` | `111` | Override the portmapper/rpcbind port. Applies to every portmapper/rpcbind query: `scan` and `analyze` discovery, `shell`/`mount` version detection, and the MOUNT port lookups in `escape`, `brute-handle`, `uid-spray`, `clean`, `shell`, and `mount`. |

### Stealth

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--delay` | `MS` | `0` | Delay between RPC calls in milliseconds |
| `--jitter` | `MS` | `0` | Random jitter added to each delay (0 = no jitter) |

### Behavior

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--skip-rpc` | bool | `false` | Never contact the portmapper/rpcbind (DUMP, GETPORT, port 111), in any subcommand. NFS uses `--nfs-port` or 2049. MOUNT uses `--mount-port`, or probes the well-known mountd ports 2049 and 20048. `shell`/`mount` version detection probes v3 then v2 with an RPC NULL on the NFS port, then v4. |
| `--skip-mountd` | bool | `false` | Skip MOUNT daemon queries (EXPORT, MNT, DUMP) in `scan` and `analyze`. NFSv4 pseudo-FS discovery still runs; `analyze` discovers exports through it and runs its NFSv4 per-export checks. No effect on `shell`, `mount`, or `escape`: `shell` and `mount` bypass MOUNT with `--handle` or `--nfs-version 4`, and `escape` gathers NFSv4 seeds on its own when MOUNT does not answer. |

### Output

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--no-color` | bool | `false` | Disable ANSI colour output (also set by `NO_COLOR` env var) |
| `-v`, `--verbose` | count | `0` | Increase log verbosity (`-v` info, `-vv` debug, `-vvv` trace) |
| `-q`, `--quiet` | bool | `false` | Suppress status lines; only emit findings and errors |

---

## nfswolf scan

Discover NFS servers on a network. Accepts IPs, CIDRs, hostnames, or target files. Runs portmapper, version detection, export enumeration, and NFSv4 pseudo-FS discovery.

```
nfswolf scan [OPTIONS] [TARGETS...]
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `TARGETS` | positional | -- | IPs, CIDRs, hostnames. Omit if using `-f`. |
| `-f`, `--file` | `FILE` | -- | File of targets, one per line. Lines starting with `#` and blank lines are skipped. |
| `-c`, `--concurrency` | `N` | `256` | Maximum concurrent host scans |
| `--scan-udp` | bool | `false` | Probe all ports over UDP in addition to TCP. Discovers UDP-accessible NFS and mountd. Mutually exclusive with `--proxy`. |
| `--probe-port` | `PORT,...` | -- | Additional NFS port(s) to probe (comma-delimited). Added to portmapper-discovered ports and the 2049 fallback. |
| `--auto-escape` | bool | `false` | After discovery, automatically attempt an export escape (subtree_check bypass) against every discovered export. On success, prints a ready-to-run `nfswolf shell --handle` command. |
| `--json` | `FILE` | -- | Write JSON results to FILE (machine-readable, UTF-8). Can be used simultaneously with `--csv`. |
| `--csv` | `FILE` | -- | Write CSV results to FILE (one row per host, UTF-8). Can be used simultaneously with `--json`. |

---

## nfswolf analyze

Deep security audit of one or more NFS servers. Enumerates exports, detects authentication weaknesses, tests for escape vulnerabilities, and reports all findings with severity ratings.

```
nfswolf analyze [OPTIONS] [TARGET]
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `TARGET` | positional | -- | Target NFS server: IP or hostname. Omit if using `-f`. Trailing `:/path` is accepted but the export portion is ignored (analyze enumerates exports itself). |
| `-f`, `--file` | `FILE` | -- | File of targets, one per line. `--targets` is accepted as an alias. |
| `--test-read` | `PATH` | `/etc/shadow` | Test if a remote file is readable after export escape. Tries multiple credentials (root, shadow GIDs, current uid). Can be specified multiple times. |
| `--test-read-gids` | `G1,G2,...` | `0,42,15` | GIDs to try when testing file readability (root, Debian shadow, SUSE shadow) |
| `--test-read-uids` | `U1,U2,...` | `0` | UIDs to try when testing file readability |
| `--allow-write` | bool | `false` | Run the squash probes, which create and remove a test file as uid 99999 and uid 0 (the only checks for F-1.2, F-4.1, F-7.5). Without it `analyze` never writes. |
| `--json` | `[FILE]` | -- | Emit machine-readable JSON. With no value, goes to stdout. With a path, written to that file. |

---

## nfswolf escape

Escape an export to the filesystem root via subtree_check bypass. Seven-phase pipeline: gather seeds, construct candidates, probe, deduplicate, detect rootfs, score, and report. Full mode is the default: every export and every handle source (MOUNT v3, MOUNT v1, NFSv4) on every NFS version. `--fast` limits the run to one export.

```
nfswolf escape [OPTIONS] <TARGET>
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `TARGET` | positional | required | Target host with optional `:/export` suffix |
| `-e`, `--export` | `PATH` | -- | Export path (alternative to `host:/export` in the positional target) |
| `--fast` | bool | `false` | Reduced pipeline: one export, one version, no brute-force, no children. Requires `host:/export`. ~10-80 RPCs. |
| `--btrfs-subvols` | `N` | `16` | Number of BTRFS subvolume IDs to try (starting at 256) |
| `--max-root-scan` | `N` | `200` | Inode scan depth for the fallback brute-force pass |
| `--json` | bool | `false` | Output results as JSON to stdout |
| `--read-shadow` | bool | `false` | Read `/etc/shadow` from the best OS-ESCAPE handle after reporting |
| `--all-handles` | bool | `false` | Show all handles including duplicates across exports. Default collapses to one handle per filesystem. Use when exports may carry different permissions (ro vs rw, root_squash vs no_root_squash). |

---

## nfswolf shell

Interactive NFS exploration shell with 46 commands (plus 12 aliases) over NFSv2, v3, and v4. See [Shell Commands](shell-commands.md) for the interactive command reference.

```
nfswolf shell [OPTIONS] <TARGET>
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `TARGET` | positional | required | Target host with optional `:/export` suffix |
| `-e`, `--export` | `PATH` | -- | Export path (alternative to `host:/export`) |
| `--handle` | `HEX` | -- | Raw file handle (hex) as the shell root -- skips MOUNT entirely. Obtain from `nfswolf escape` or `nfswolf brute-handle`. |
| `--allow-write` | bool | `false` | Enable write operations (CREATE, WRITE, MKDIR, REMOVE, etc.) |
| `-c`, `--command` | `CMD` | -- | Run a single shell command then exit (non-interactive / scripting mode) |
| `--nfs-version` | `2\|3\|4` | auto | NFS protocol version. Auto-detected (v3 -> v2 -> v4) when omitted. |
| `--short-token` | `HEX` | -- | AUTH_SHORT session token (hex). Replays a server-issued opaque token as the RPC credential instead of AUTH_SYS. |
| `--auth-dh-netname` | `NAME` | -- | AUTH_DH network name (e.g. `unix.0@domain`). Enables AUTH_DH authentication using 192-bit DH + 56-bit DES (RFC 1057 S9.3). Requires `--auth-dh-pubkey`. |
| `--auth-dh-pubkey` | `HEX` | -- | Server's DH public key (48 hex chars = 192 bits). Obtain from the NIS `publickey.byname` map. |

---

## nfswolf mount

FUSE-mount an NFS export with transparent UID spoofing. Requires the `fuse` Cargo feature (enabled by default; omitted in the musl-static build). Auto-detects NFS version when `--nfs-version` is omitted.

```
nfswolf mount [OPTIONS] <TARGET> <MOUNTPOINT>
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `TARGET` | positional | required | Target host with optional `:/export` suffix |
| `MOUNTPOINT` | positional | required | Local mount point (must already exist and be a directory) |
| `-e`, `--export` | `PATH` | -- | Export path to mount (mutually exclusive with `--handle`) |
| `--handle` | `HEX` | -- | Raw file handle in hex (for escaped mounts) |
| `--nfs-version` | `2\|3\|4` | auto | NFS protocol version. Auto-detected when omitted. |
| `--allow-write` | bool | `false` | Allow write operations (default: read-only) |
| `--hide` | bool | `false` | Immediately unmount from server after capturing the handle (stealth). No effect with `--handle`. |

Unmount manually with `fusermount3 -u MOUNTPOINT` (Linux) or `umount MOUNTPOINT` (macOS). The FUSE handler runs as a daemon.

---

## nfswolf brute-handle

Brute-force NFS file handles using the STALE/BADHANDLE oracle. Derives a seed handle by mounting the target export (or from `--seed-handle`), then generates candidates: fingerprint-driven known roots first, then an inode/generation sweep. Read-only.

```
nfswolf brute-handle [OPTIONS] <TARGET>
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `TARGET` | positional | required | Target host with optional `:/export`. The export is mounted to derive the seed handle when `--seed-handle` is omitted. |
| `-e`, `--export` | `PATH` | -- | Export path (alternative to `host:/export`) |
| `--seed-handle` | `HEX` | -- | Seed handle (hex) from a prior mount or escape. Provides fsid + format. When omitted, derived by mounting the target export. |
| `--max-attempts` | `N` | `10000` | Maximum number of handles to probe across the full inode x gen space |
| `--inode-start` | `INODE` | `0` | Start of the inode range |
| `--inode-end` | `INODE` | `500` | End of the inode range (inclusive) |
| `--gen-start` | `GEN` | `0` | Start of the generation range |
| `--gen-end` | `GEN` | `0` | End of the generation range (inclusive). Full search space: `(inode_end - inode_start + 1) * (gen_end - gen_start + 1)`. |
| `--mask` | `HEXMASK` | -- | Nibble-mask mode: a hex handle with `?` for each unknown nibble (up to 16). Enumerates every combination, connecting straight to the NFS port without MOUNT; `--seed-handle`, `--inode-*`, and `--gen-*` are ignored, `--max-attempts` still caps the probe count. Works against any server OS. |

---

## nfswolf uid-spray

Last-resort UID/GID brute-force using the NFSv3 ACCESS procedure as the permission oracle. The auto-UID ladder in `shell` and `mount` handles most cases without this.

```
nfswolf uid-spray [OPTIONS] <TARGET>
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `TARGET` | positional | required | Target host with optional `:/export` suffix |
| `-e`, `--export` | `PATH` | -- | Export path (alternative to `host:/export`) |
| `--uid-start` | `UID` | `0` | UID range start |
| `--uid-end` | `UID` | `65535` | UID range end |
| `--gid-start` | `GID` | -- | GID range start. Unset: each UID is tried with matching GID. Set: sweeps the full UID x GID cross product. |
| `--gid-end` | `GID` | -- | GID range end. Unset: each UID is tried with matching GID. |
| `--max-attempts` | `N` | `100000` | Refuse to start a sweep larger than this. Guard against accidental 4.3B probe cross products. Raise deliberately if needed. |
| `--path` | `PATH` | `/` | Path to check access against |
| `--attempt-delay` | `MS` | `0` | Delay between attempts in ms (independent of global `--delay`) |

---

## nfswolf clean

Remove your entries from the server's mount list (the advisory rmtab that `showmount -a` reports). Sends MNTPROC_UMNTALL, then a looped MNTPROC_UMNT over MOUNT v3 and v1 with a stall detector. Linux mountd matches UMNT by TCP source IP, not AUTH_SYS machinename, so only entries recorded under your source IP can be removed. File handles already issued stay valid. See [Clean](clean.md).

```
nfswolf clean [OPTIONS] <TARGET>
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `TARGET` | positional | required | Target NFS server (IP or hostname) |
| `--list` | bool | `false` | Show the current mount list (MNTPROC_DUMP) without removing anything |

---

## nfswolf convert

Convert an `analyze --json` dump into a presentation format. Purely offline; no NFS server is contacted.

```
nfswolf convert [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-i`, `--input` | `FILE` | required | JSON input file produced by `analyze --json` |
| `--format` | enum | `html` | Output format: `console`, `html`, `json`, `txt`, `markdown`, `csv` |
| `-o`, `--output` | `FILE` | -- | Output file path (omit for stdout with `--format console`) |
| `--title` | `TEXT` | `NFS Security Assessment` | Report title embedded in the output |

Formats: `console` (ANSI terminal), `html` (self-contained with CSS/charts), `json` (re-export), `txt` (plain text), `markdown` (GFM), `csv` (one row per finding).

---

## nfswolf decode

Offline NFS file handle decoder. Prints header fields, fsid, fileid, OS/FS fingerprint, and security assessment. No network access.

```
nfswolf decode <HANDLE>
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `HANDLE` | positional | required | Hex-encoded file handle (e.g. `010007020300240000000000...`). Minimum 4 bytes (8 hex chars). |

---

## nfswolf completions

Generate shell completion scripts for `bash`, `zsh`, `fish`, `elvish`, or `powershell`. Output goes to stdout.

```
nfswolf completions <SHELL>
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `SHELL` | positional | required | Target shell: `bash`, `zsh`, `fish`, `elvish`, `powershell` |

=== "Bash"
    ```bash
    nfswolf completions bash > /etc/bash_completion.d/nfswolf
    ```
=== "Zsh"
    ```bash
    nfswolf completions zsh > ~/.zfunc/_nfswolf
    ```
=== "Fish"
    ```bash
    nfswolf completions fish > ~/.config/fish/completions/nfswolf.fish
    ```
