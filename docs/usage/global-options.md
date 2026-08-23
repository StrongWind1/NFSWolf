# Global Options

Every NFSWolf subcommand inherits these flags. They control the identity presented to the NFS server, network transport, stealth timing, and output formatting. Set them before the subcommand name or after it -- clap treats them as global either way.

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

### `--short-token <HEX>` { #short-token }

Replay an AUTH_SHORT opaque token as the RPC credential instead of AUTH_SYS. Some non-Linux NFS servers (Solaris, NetApp ONTAP) issue AUTH_SHORT tokens in reply verifiers; capturing and replaying one bypasses normal credential checks. Per-subcommand flag on `shell`.

```bash
# Replay a captured AUTH_SHORT token
nfswolf shell 10.0.0.1:/srv --short-token 0a1b2c3d4e5f
```

### `--auth-dh-netname <NAME>` and `--auth-dh-pubkey <HEX>` { #auth-dh }

Enable AUTH_DH (Diffie-Hellman) authentication using 192-bit DH + 56-bit DES (RFC 1057 S9.3). Only useful against Solaris/Illumos servers that still support AUTH_DH. Requires the `auth-dh` Cargo feature. Both flags must be provided together.

```bash
# AUTH_DH session against a Solaris server
nfswolf shell 10.0.0.1:/srv \
  --auth-dh-netname "unix.0@example.com" \
  --auth-dh-pubkey 3a4b5c6d7e8f...  # 48 hex chars = 192 bits
```

## Network

### `--timeout <MS>` / `-t <MS>`

RPC connection and call timeout in milliseconds. Default: `3000` (3 seconds). Increase for high-latency targets or when running through a proxy.

```bash
# 10-second timeout for a remote target
nfswolf scan 10.0.0.0/24 --timeout 10000

# Fast local network
nfswolf shell 192.168.1.10:/srv -t 1000
```

### `--nfs-port <PORT>`

Override the NFS service port, skipping portmapper resolution. The default NFS port is 2049, but portmapper may report a different port. Use this when portmapper is firewalled or returns incorrect data.

```bash
# NFS on a non-standard port
nfswolf shell 10.0.0.1:/srv --nfs-port 12049
```

### `--mount-port <PORT>`

Override the MOUNT daemon port, skipping portmapper resolution. Useful when mountd runs on a non-standard port or portmapper is unavailable.

```bash
# MOUNT daemon on a known port
nfswolf analyze 10.0.0.1 --mount-port 20048
```

### `--rpc-port <PORT>`

Override the portmapper/rpcbind port. Default: `111`. Rarely needed unless the target runs portmapper on an alternate port.

```bash
# Portmapper on a non-standard port
nfswolf scan 10.0.0.1 --rpc-port 1111
```

### `--privileged-port`

Bind the source TCP port to a value below 1024. Required by servers that export with the `secure` option (the default on Linux). Needs root or `CAP_NET_BIND_SERVICE`.

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

Skip all portmapper/rpcbind probes (DUMP, GETPORT, port 111). Use when portmapper is firewalled and you know the NFS port. Pair with `--nfs-port` to specify the NFS service port directly.

```bash
# Portmapper firewalled, NFS on default port
nfswolf shell 10.0.0.1:/srv --skip-rpc

# Portmapper firewalled, NFS on a custom port
nfswolf escape 10.0.0.1:/srv --skip-rpc --nfs-port 12049
```

### `--skip-mountd`

Skip all MOUNT daemon queries (EXPORT, MNT, DUMP). NFSv4 pseudo-FS discovery still runs. Use when mountd is firewalled or unnecessary (e.g., working with a known handle or NFSv4-only target).

```bash
# NFSv4 only, no MOUNT needed
nfswolf shell 10.0.0.1:/srv --skip-mountd --nfs-version 4

# Already have a handle, skip MOUNT entirely
nfswolf shell 10.0.0.1 --handle 0100070200... --skip-mountd
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
| `--timeout` | `-t` | `3000` | Network | RPC timeout in milliseconds |
| `--nfs-port` | | (auto) | Network | Override NFS service port |
| `--mount-port` | | (auto) | Network | Override MOUNT daemon port |
| `--rpc-port` | | `111` | Network | Override portmapper port |
| `--privileged-port` | | off | Network | Bind source port < 1024 |
| `--proxy` | | (none) | Network | SOCKS5 proxy address |
| `--skip-rpc` | | off | Behavior | Skip portmapper probes |
| `--skip-mountd` | | off | Behavior | Skip MOUNT daemon queries |
| `--delay` | | `0` | Stealth | Inter-RPC delay (ms) |
| `--jitter` | | `0` | Stealth | Random jitter added to delay (ms) |
| `--verbose` | `-v` | warn | Output | Log verbosity (stacks to `-vvv`) |
| `--quiet` | `-q` | off | Output | Suppress status output |
| `--no-color` | | off | Output | Disable ANSI colors |
