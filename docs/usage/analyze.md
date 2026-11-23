# Analyze

The `analyze` subcommand performs a security audit of one or more NFS servers. It detects 43 of the 62 documented findings; of the other 19, the three denial-of-service findings (F-6.x) are out of scope and 16 are documented for manual testing. It enumerates exports, tests authentication weaknesses, probes for export escape vulnerabilities, checks squash configuration, and reports every finding with a severity rating, evidence, and remediation guidance.

```
nfswolf analyze <TARGET> [OPTIONS]
nfswolf analyze -f <FILE> [OPTIONS]
```

!!! warning "Read-only unless you pass `--allow-write`"
    By default `analyze` never writes to the server. With `--allow-write` it adds the squash probes: in each writable export it creates a test file (`.nfswolf_squash_probe`) as uid 99999 and then as uid 0, reads back its owner, and removes it. Those probes are the only checks for F-1.2, F-4.1 and F-7.5, so without the flag the report says those three were not tested. The server logs every probe either way; use `--delay` and `--jitter` for pacing.

## Target formats

The analyzer accepts a single host or a file of hosts. Unlike [scan](scan.md), it does not accept CIDR ranges -- analyze runs a deep per-host audit, not a broad sweep.

| Format | Example | Description |
|--------|---------|-------------|
| Single IP | `192.168.1.10` | One host |
| Hostname | `nfs-server.corp.local` | Resolved via DNS |
| Host with export | `192.168.1.10:/srv` | The export path is accepted but ignored -- analyze enumerates exports itself |
| File (`-f`) | `-f hosts.txt` | One target per line; `#` comments and blank lines are skipped |

## Flags

### Target / Source

| Flag | Default | Description |
|------|---------|-------------|
| `<TARGET>` | -- | Positional: IP or hostname. Required unless `-f` is used. |
| `-f`, `--file <FILE>` | -- | File of targets, one per line. `--targets <FILE>` is accepted as an alias. |

### Behavior

| Flag | Default | Description |
|------|---------|-------------|
| `--test-read <PATH>` | `/etc/shadow` | Remote file to test for readability after export escape. Can be specified multiple times for different paths. |
| `--test-read-gids <G1,G2,...>` | `0,42,15` | GIDs to try when testing file readability (comma-separated). 0 = root, 42 = Debian/Ubuntu shadow group, 15 = SUSE shadow group. |
| `--test-read-uids <U1,U2,...>` | `0` | UIDs to try when testing file readability (comma-separated). |

### Permissions

| Flag | Default | Description |
|------|---------|-------------|
| `--allow-write` | off | Run the write probes: create and remove a test file as uid 99999 and as uid 0 in each writable export. They are the only checks for honoured forged UIDs (F-1.2), `no_root_squash` (F-4.1) and `all_squash` with `anonuid=0` (F-7.5). Every report records whether they ran. |

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | -- | Emit machine-readable JSON to stdout. Capture with `> file.json` and pass to `nfswolf convert` for other formats. |
| `--json <FILE>` | -- | Write JSON directly to a file instead of stdout. |

### Global flags affecting analyze

These are set on the `nfswolf` command itself, before the `analyze` subcommand. See [Global Options](global-options.md) for the full list.

| Flag | Effect on analyze |
|------|-------------------|
| `-u`, `--uid <UID>` / `-g`, `--gid <GID>` | AUTH_SYS credentials for the initial connection. The analyzer also tries escalated credentials internally. |
| `--aux-gids <G1,G2,...>` | Auxiliary GIDs in AUTH_SYS, sent with every credential the analyzer builds. Adding 42 (Debian shadow group) can unlock `/etc/shadow` reads without `no_root_squash`. |
| `--hostname <NAME>` | Spoofed client hostname in AUTH_SYS credentials. |
| `--nfs-port <PORT>` | Override the NFS port (skip portmapper GETPORT). Honored by every NFS connection the analyzer opens. |
| `--mount-port <PORT>` | Override the mount-daemon port for every MOUNT call. |
| `--rpc-port <PORT>` | Override the portmapper/rpcbind port (default 111) for every portmapper and rpcbind query. |
| `--skip-rpc` | Never contact the portmapper. Portmapper checks are skipped; NFS uses `--nfs-port` or 2049, and MOUNT uses `--mount-port` or probes 2049 and 20048. |
| `--skip-mountd` | Skip MOUNT EXPORT, MNT, and DUMP. Exports are discovered through the NFSv4 pseudo-filesystem instead, and the NFSv4 per-export checks run against them. |
| `--proxy <HOST:PORT>` | Route all connections through a SOCKS5 proxy. |
| `-t`, `--timeout <MS>` | Probe timeout (default 5000 ms for analyze). |
| `--delay <MS>` / `--jitter <MS>` | Stealth pacing between RPC calls. |
| `--privileged-port` | Bind from a source port below 1024, for MOUNT and NFS calls. |
| `-q`, `--quiet` | Suppress status lines; only emit findings. |

## What it checks

The analyzer runs every read-only check unconditionally; `--allow-write` adds the three write probes (F-1.2, F-4.1, F-7.5). Findings are organized by attack category, each referencing an ID from the [findings catalog](../security/index.md). The table below covers the whole catalog of 62 findings; `analyze` detects 43 of them. The three F-6.x denial-of-service findings are out of scope, and the remaining 16 are documented for manual testing.

### Finding categories

| Category | IDs | What it covers |
|----------|-----|---------------|
| Identity Attacks | F-1.1 through F-1.8 | AUTH_SYS trust, UID/GID spoofing, root squash bypass, auxiliary group injection, machine name spoofing, credential replay, NFSv2 downgrade, RPCSEC_GSS flavor downgrade, AUTH_TOOWEAK oracle |
| Access Control Bypass | F-2.1 through F-2.12 | Export escape via filesystem root handle, handle guessing/brute force, Windows handle signing, BTRFS subvolume construction, stale handle reuse, bind mount escape, bearer token property, cross-export lateral access, WebNFS public handle, SIGN_FH bypass, NFSv4 LOOKUPP escape |
| Network Attacks | F-3.1 through F-3.9 | Plaintext traffic interception, portmapper UDP amplification, IP spoofing, STRIPTLS downgrade, portmapper bypass, UDP MOUNT handle theft, AUTH_DH, RPC-with-TLS, AUTH_SHORT session credentials |
| Privilege Escalation | F-4.1 through F-4.6 | `no_root_squash` exploitation, SUID/SGID binary creation, device node creation via MKNOD, symlink escape, SELinux/MAC label bypass, unrestricted chown |
| Information Disclosure | F-5.1 through F-5.17 | Export list enumeration, READDIRPLUS handle harvesting, NIS credential extraction, RPC service enumeration, NFSv4 pseudo-FS leakage, metadata on access denial, filesystem fingerprinting, AUTH_NONE attribute leak, execute-only file disclosure, pNFS layout downgrade, POSIX ACL exposure, rquotad UID oracle |
| Denial of Service | F-6.x | Out of scope (NLM lock attacks, grace-period blocking, SETCLIENTID state destruction) |
| Configuration Weaknesses | F-7.1 through F-7.7 | Wildcard exports, insecure port bypass, nohide/crossmnt exposure, missing nosuid/nodev, all_squash misconfiguration, audit logging gaps, FreeBSD truncated subnet fingerprint |

### Severity levels

| Severity | Color | Meaning |
|----------|-------|---------|
| Critical | :red_square: Red | Immediate exploitable access (e.g., `no_root_squash` + readable shadow file) |
| High | :orange_square: Orange | Direct path to unauthorized access with minimal effort |
| Medium | :yellow_square: Yellow | Exploitable with additional steps or information |
| Low | :blue_square: Blue | Information leak or minor misconfiguration |
| Info | :white_large_square: Gray | Informational finding, no direct security impact |

## Output formats

The analyzer itself supports two output modes: console (default) and JSON. For other formats, pipe the JSON through [convert](convert.md).

=== "Console"

    The default output is an ANSI-colored structured report to stdout. This run used `--allow-write`; without it the `Write probes` line says the probes were not run and F-4.1 cannot appear:

    ```
    +========================================+
    |  NFS Security Analysis: 10.129.40.115  |
    +========================================+

      OS:  Linux  |  NFS:  v3, v4
      Impl:  Linux knfsd (GARBAGE_ARGS on null-name LOOKUP)
      Timestamp:  2025-04-12T14:23:01Z
      Write probes:  run (test file created and removed as uid 0 and uid 99999)

      Exports  -------------------------------------------------
    ╭──────────────┬─────────────────┬──────────┬────────────────────────┬─────────────────────╮
    │ Path         │ Allowed clients │ Auth     │ Flags                  │ Handle (partial)    │
    ├──────────────┼─────────────────┼──────────┼────────────────────────┼─────────────────────┤
    │ /srv/data    │ *               │ AUTH_SYS │ WILDCARD AUTH_SYS_ONLY │ 0100070003000100... │
    │ /srv/backups │ 10.0.0.0/24     │ AUTH_SYS │ AUTH_SYS_ONLY          │ 0100070005000100... │
    ╰──────────────┴─────────────────┴──────────┴────────────────────────┴─────────────────────╯

      File Handles  --------------------------------------------
      /srv/data: 0100070003000100020000000000000028ce886800000000
      /srv/backups: 0100070005000100020000000000000045af129a00000000

      Findings  ------------------------------------------------
      Findings: 3 critical, 2 high, 1 low/info

      [CRITICAL]  /srv/data  F-2.1  Export escape possible -- filesystem root accessible via crafted handle
        Evidence: constructed ext4 root handle (inode 2) accepted; GETATTR returned a directory
      [CRITICAL]  /srv/data  F-4.1  no_root_squash detected  --  uid=0 credentials not remapped
        Evidence: probe file created as uid=0 is owned by uid 0
      [CRITICAL]  /srv/data  F-1.3  Sensitive file readable via UID/GID credential
        Evidence: /etc/shadow readable as uid=0 gid=0 via escaped handle
      [HIGH]      /srv/data  F-7.1  Export accessible to all hosts (world-accessible export)
      [HIGH]      /srv/data  F-1.1  Export uses AUTH_SYS only (no Kerberos)
      [INFO]      F-3.1  NFS traffic is unencrypted  --  no RPCSEC_GSS privacy advertised
    ```

=== "JSON"

    With `--json`, the analyzer emits a structured JSON array (one element per host) suitable for programmatic consumption or conversion to other formats:

    ```bash
    nfswolf analyze 10.129.40.115 --json > results.json
    ```

    ??? example "JSON structure"

        ```json
        [
          {
            "host": "10.129.40.115",
            "timestamp": "2025-04-12T14:23:01Z",
            "os_guess": "Linux 5.x",
            "impl_fingerprint": "Linux knfsd (GARBAGE_ARGS on null-name LOOKUP)",
            "nfs_versions": ["v3", "v4"],
            "exports": [
              {
                "path": "/srv/data",
                "allowed_hosts": [],
                "auth_methods": ["AUTH_SYS"],
                "writable": true,
                "no_root_squash": true,
                "escape_possible": true,
                "file_handle": "0100070003000100...",
                "file_access_tests": [
                  {
                    "path": "/etc/shadow",
                    "uid": 0, "gid": 0,
                    "readable": true,
                    "preview": "root:$6$rounds=65536$...",
                    "via_escape": true
                  }
                ],
                "nfs4_acls": []
              }
            ],
            "findings": [
              {
                "id": "F-4.1",
                "title": "no_root_squash detected  --  uid=0 credentials not remapped",
                "severity": "critical",
                "description": "UID 0 can create files owned by root...",
                "evidence": "probe file created as uid=0 is owned by uid 0",
                "remediation": "add root_squash to the export options...",
                "export": "/srv/data"
              }
            ]
          }
        ]
        ```

=== "HTML / Markdown / CSV / TXT"

    These formats are produced by piping JSON through `nfswolf convert`:

    ```bash
    # Self-contained HTML with embedded CSS and severity charts
    nfswolf convert -i results.json --format html -o report.html

    # GitHub-flavored Markdown for issues or wikis
    nfswolf convert -i results.json --format markdown -o report.md

    # CSV with one row per finding (import into spreadsheets or SIEM)
    nfswolf convert -i results.json --format csv -o findings.csv

    # Plain text (no ANSI colors) for email or logging
    nfswolf convert -i results.json --format txt -o report.txt

    # Re-render to terminal (useful after piping from a batch run)
    nfswolf convert -i results.json --format console
    ```

    See [convert](convert.md) for all options including `--title`.

## Examples

### Basic audit of a single host

```bash
nfswolf analyze 192.168.1.10
```

### Audit with custom file read tests

```bash
nfswolf analyze 10.0.0.1 \
    --test-read /etc/shadow \
    --test-read /etc/passwd \
    --test-read /root/.ssh/id_rsa \
    --test-read-gids 0,42,15 \
    --test-read-uids 0,1000
```

### Batch audit with JSON capture and HTML report

```bash
nfswolf analyze -f hosts.txt --json results.json
nfswolf convert -i results.json --format html -o report.html --title "Q3 NFS Audit"
```

### Audit through a SOCKS5 proxy with stealth pacing

```bash
nfswolf --proxy 127.0.0.1:1080 --delay 500 --jitter 200 analyze 10.0.0.1
```

### Audit a server with the secure export option

```bash
sudo nfswolf --privileged-port -u 0 -g 0 analyze 10.0.0.1
```

### Full pipeline: scan, analyze, report

```bash
# Discover NFS servers
nfswolf scan 10.0.0.0/24 --json scan.json

# Audit each discovered host
nfswolf analyze -f <(jq -r '.hosts[].ip' scan.json) --json results.json

# Generate reports
nfswolf convert -i results.json --format html -o report.html
nfswolf convert -i results.json --format csv -o findings.csv
```

## Relationship to other subcommands

The analyze subcommand sits between [scan](scan.md) (broad discovery) and [shell](shell.md) (interactive exploitation). A typical workflow:

1. **scan** -- find NFS servers on the network
2. **analyze** -- audit each server for vulnerabilities
3. **escape** -- break out of exports flagged by analyze
4. **shell** -- explore the filesystem with an escaped handle

The analyzer runs its own export escape probes internally (to test file readability via escaped handles), so you do not need to run `escape` separately before `analyze`. However, the standalone [escape](escape.md) subcommand provides more detail and control over the escape process.
