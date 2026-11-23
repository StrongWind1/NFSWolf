# Global Options

Every NFSWolf subcommand inherits these flags. They control the identity presented to the NFS server, network transport, stealth timing, and output formatting. Set them before the subcommand name or after it -- clap treats them as global either way. The AUTH_SHORT and AUTH_DH flags documented under [Shell-only credential flags](#shell-only-credential-flags) are the exception: they belong to `shell` alone.

```bash
nfswolf --uid 0 --delay 500 shell 10.0.0.1:/srv
nfswolf shell 10.0.0.1:/srv --uid 0 --delay 500   # equivalent
```

## Identity

These flags control the AUTH_SYS credentials injected into every RPC call. NFS servers running AUTH_SYS trust these values without verification -- they are spoofed, not authenticated.

### `--uid <UID>` / `-u <UID>`

UID presented in the AUTH_SYS credential. The server uses this to make access-control decisions. Default: `1000`.

```bash
# Connect as root
nfswolf shell 10.0.0.1:/srv --uid 0

# Connect as the www-data service account
nfswolf shell 10.0.0.1:/srv -u 33
```

!!! note "root_squash"
    When the export has `root_squash` enabled (the default), uid 0 is mapped to `nobody` (65534) on the server side. Use `--uid 0` to test whether squashing is in effect; if the server returns `NFS3ERR_ACCES` on files owned by root, squash is working.

### `--gid <GID>` / `-g <GID>`

Primary GID in the AUTH_SYS credential. Default: `1000`.

```bash
# Connect with the shadow group to read /etc/shadow
nfswolf shell 10.0.0.1:/srv -u 0 -g 42
```

### `--aux-gids <G1,G2,...>`

Auxiliary GIDs added to the AUTH_SYS credential, comma-separated. Capped at 16 per RFC 1057 S9.2. These are checked for group-permission bits on every file access.

```bash
# Add the shadow group (42 on Debian, 15 on SUSE) to read /etc/shadow
# without needing no_root_squash
nfswolf shell 10.0.0.1:/srv --uid 0 --aux-gids 42,15

# Multiple service-account groups
nfswolf shell 10.0.0.1:/srv --aux-gids 33,34,1001
```

### `--hostname <NAME>`

Client hostname injected into the AUTH_SYS `machinename` field. Default: `localhost`. This field is cosmetic -- Linux knfsd uses the TCP source IP for export ACL decisions, not this string.

```bash
# Spoof the hostname to match an expected client
nfswolf shell 10.0.0.1:/srv --hostname prod-web-01
```

### Shell-only credential flags

These two replace the AUTH_SYS credential with a different flavor. They are options of the `shell` subcommand, not global flags: no other subcommand accepts them, and they must come after `shell` on the command line.

#### `--short-token <HEX>` { #short-token }

`shell` only. Replay an AUTH_SHORT opaque token as the RPC credential instead of AUTH_SYS. Some non-Linux NFS servers (Solaris, NetApp ONTAP) issue AUTH_SHORT tokens in reply verifiers; capturing and replaying one bypasses normal credential checks. The token applies to the whole session on NFSv2, v3, and v4.

```bash
# Replay a captured AUTH_SHORT token
nfswolf shell 10.0.0.1:/srv --short-token 0a1b2c3d4e5f
```

#### `--auth-dh-netname <NAME>` and `--auth-dh-pubkey <HEX>` { #auth-dh }

`shell` only. Enable AUTH_DH (Diffie-Hellman) authentication using 192-bit DH + 56-bit DES (RFC 1057 S9.3). Only useful against Solaris/Illumos servers that still support AUTH_DH. Requires the `auth-dh` Cargo feature. Both flags must be provided together.

```bash
# AUTH_DH session against a Solaris server
nfswolf shell 10.0.0.1:/srv \
  --auth-dh-netname "unix.0@example.com" \
  --auth-dh-pubkey 3a4b5c6d7e8f...  # 48 hex chars = 192 bits
```

## Network

### `--timeout <MS>` / `-t <MS>`

Probe timeout in milliseconds. When the flag is omitted, each subcommand uses its own default:

| Subcommand | What the timeout bounds | Default |
|------------|-------------------------|---------|
| `scan` | Each port and RPC probe | 3000 ms |
| `analyze` | Each probe | 5000 ms |
| `shell`, `mount` | NFS version auto-detection (skipped when `--nfs-version` is given) | 2000 ms |

An explicit `--timeout` replaces all of these defaults. It does not change established NFS sessions: once a shell, mount, or pooled connection is up, every call keeps a fixed 30-second deadline. Increase the timeout for high-latency targets or when running through a proxy.

```bash
# 10-second probes for a remote target
nfswolf scan 10.0.0.0/24 --timeout 10000

# Faster version detection on a local network
nfswolf shell 192.168.1.10:/srv -t 1000
```

### `--nfs-port <PORT>`

Override the NFS service port, skipping the portmapper GETPORT. The default NFS port is 2049, but portmapper may report a different port. Applies to every subcommand that opens an NFS connection, `analyze` included, and to every pooled NFS connection. Use this when portmapper is firewalled or returns incorrect data.

```bash
# NFS on a non-standard port
nfswolf shell 10.0.0.1:/srv --nfs-port 12049
```

### `--mount-port <PORT>`

Override the MOUNT daemon port, skipping the portmapper GETPORT. Honored by every MOUNT call in every subcommand, including the MOUNT calls made inside pooled connections. Useful when mountd runs on a non-standard port or portmapper is unavailable.

```bash
# MOUNT daemon on a known port
nfswolf analyze 10.0.0.1 --mount-port 20048
```

### `--rpc-port <PORT>`

Override the portmapper/rpcbind port. Default: `111`. Honored by every portmapper/rpcbind query in every subcommand: `scan` and `analyze` discovery, NFS version detection in `shell` and `mount`, and the MOUNT port lookups that `escape`, `brute-handle`, `uid-spray`, `clean`, `shell`, and `mount` perform. Rarely needed unless the target runs portmapper on an alternate port.

```bash
# Portmapper on a non-standard port
nfswolf scan 10.0.0.1 --rpc-port 1111
```

### `--privileged-port`

Bind the source TCP port to a value below 1024. Required by servers that export with the `secure` option (the default on Linux). Honored by every MOUNT call in every subcommand (including `scan`), as well as by NFS connections. Needs root or `CAP_NET_BIND_SERVICE`.

```bash
# Connect to a server requiring privileged source ports
sudo nfswolf shell 10.0.0.1:/srv --privileged-port
```

!!! info "When is this needed?"
    The `secure` export option (default on Linux knfsd) rejects connections from unprivileged source ports. If you see `NFS3ERR_ACCES` immediately on MOUNT, try adding `--privileged-port`. NFSWolf already runs as root in most assessment scenarios, so this flag mainly signals intent.

### `--proxy <HOST:PORT>`

Route all TCP connections through a SOCKS5 proxy. The proxy handles DNS resolution. Cannot be combined with `--scan-udp` (UDP cannot be tunneled through SOCKS5).

```bash
# Through an SSH SOCKS proxy
ssh -D 1080 jumpbox -N &
nfswolf shell 10.0.0.1:/srv --proxy 127.0.0.1:1080

# Through a Chisel tunnel
nfswolf scan 10.0.0.0/24 --proxy 127.0.0.1:1080
```

## Behavior

### `--skip-rpc`

Never contact the portmapper/rpcbind (no DUMP, no GETPORT, nothing sent to port 111), in any subcommand. Use when portmapper is firewalled or when you want to keep the traffic off it. Without the portmapper to ask:

- NFS uses `--nfs-port`, or 2049.
- MOUNT uses `--mount-port`, or probes the well-known mountd ports 2049 and 20048 (the same fallback nfswolf uses when the portmapper does not answer).
- NFS version auto-detection in `shell` and `mount` probes v3 and then v2 with an RPC NULL on the NFS port, then v4.

```bash
# Portmapper firewalled, NFS and mountd on their usual ports
nfswolf shell 10.0.0.1:/srv --skip-rpc

# Portmapper firewalled, NFS and mountd on custom ports
nfswolf escape 10.0.0.1:/srv --skip-rpc --nfs-port 12049 --mount-port 32767
```

### `--skip-mountd`

Skip MOUNT daemon queries (EXPORT, MNT, DUMP) in `scan` and `analyze`. NFSv4 pseudo-FS discovery still runs: `scan` lists the v4 exports, and `analyze` discovers exports through the pseudo-filesystem and runs its NFSv4 per-export checks. Use when mountd is firewalled or should not see the traffic.

```bash
# Discovery without touching mountd
nfswolf scan 10.0.0.0/24 --skip-mountd

# NFSv4-only audit
nfswolf analyze 10.0.0.1 --skip-mountd
```

`--skip-mountd` does not change `shell`, `mount`, or `escape`. To keep those away from MOUNT, give `shell` or `mount` a raw handle with `--handle`, or select NFSv4 with `--nfs-version 4`, which never uses MOUNT. `escape` gathers NFSv4 seed handles by itself, so it still finds seeds when MOUNT does not answer.

```bash
# Already have a handle: no MOUNT call
nfswolf shell 10.0.0.1 --handle 0100070200...

# NFSv4: no MOUNT call
nfswolf shell 10.0.0.1:/srv --nfs-version 4
```

## Stealth

These flags insert delays between RPC calls to reduce traffic volume and make the assessment less visible to IDS/IPS systems. Both default to `0` (no delay).

### `--delay <MS>`

Fixed delay in milliseconds inserted before each RPC call.

```bash
# 200ms between every RPC call
nfswolf analyze 10.0.0.1 --delay 200
```

### `--jitter <MS>`

Random jitter in milliseconds added on top of `--delay`. The actual per-call delay is `delay + rand(0..jitter)`. Use with `--delay` for realistic-looking traffic patterns.

```bash
# 100-300ms between calls (100ms base + 0-200ms jitter)
nfswolf scan 10.0.0.0/24 --delay 100 --jitter 200

# Slow, stealthy assessment
nfswolf analyze 10.0.0.1 --delay 500 --jitter 500
```

!!! warning "Stealth vs. speed"
    Even moderate delays significantly increase scan time. A scan of a /24 with `--delay 200` adds ~200ms per RPC call per host. For a full `analyze` run that makes hundreds of calls, expect the assessment to take minutes instead of seconds.

## Output

### `--verbose` / `-v`

Increase log verbosity. Stacks up to three times:

| Flag | Level | What it shows |
|------|-------|---------------|
| (none) | warn | Warnings and errors only |
| `-v` | info | Status messages, connection events |
| `-vv` | debug | RPC call/response details, credential switches |
| `-vvv` | trace | Full XDR payloads, raw bytes |

```bash
# See every RPC call
nfswolf shell 10.0.0.1:/srv -vv

# Full wire-level tracing
nfswolf escape 10.0.0.1:/srv -vvv 2>trace.log
```

### `--quiet` / `-q`

Suppress status lines and informational output. Only findings, errors, and data output are emitted. Useful in scripts and pipelines.

```bash
# Quiet scan, only print discovered hosts
nfswolf scan 10.0.0.0/24 --quiet

# Pipe analyze JSON without status noise
nfswolf analyze 10.0.0.1 --json --quiet > results.json
```

### `--no-color`

Disable ANSI color codes in output. Also activated by setting the `NO_COLOR` environment variable (per [no-color.org](https://no-color.org/)).

```bash
# Pipe to a file without escape codes
nfswolf analyze 10.0.0.1 --no-color > results.txt

# Via environment variable
NO_COLOR=1 nfswolf scan 10.0.0.0/24
```

## Summary table

| Flag | Short | Default | Section | Description |
|------|-------|---------|---------|-------------|
| `--uid` | `-u` | `1000` | Identity | AUTH_SYS UID |
| `--gid` | `-g` | `1000` | Identity | AUTH_SYS GID |
| `--aux-gids` | | (none) | Identity | Auxiliary GIDs (comma-separated, max 16) |
| `--hostname` | | `localhost` | Identity | AUTH_SYS machine name |
| `--timeout` | `-t` | per subcommand | Network | Probe timeout in milliseconds (scan 3000, analyze 5000, shell/mount detection 2000) |
| `--nfs-port` | | (auto) | Network | Override NFS service port |
| `--mount-port` | | (auto) | Network | Override MOUNT daemon port |
| `--rpc-port` | | `111` | Network | Override portmapper port |
| `--privileged-port` | | off | Network | Bind source port < 1024 |
| `--proxy` | | (none) | Network | SOCKS5 proxy address |
| `--skip-rpc` | | off | Behavior | Never contact the portmapper |
| `--skip-mountd` | | off | Behavior | Skip MOUNT queries in scan and analyze |
| `--delay` | | `0` | Stealth | Inter-RPC delay (ms) |
| `--jitter` | | `0` | Stealth | Random jitter added to delay (ms) |
| `--verbose` | `-v` | warn | Output | Log verbosity (stacks to `-vvv`) |
| `--quiet` | `-q` | off | Output | Suppress status output |
| `--no-color` | | off | Output | Disable ANSI colors |
