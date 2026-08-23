# Shell Commands

Complete reference for all commands available in the NFSWolf interactive shell. Commands are shared across NFSv2, NFSv3, and NFSv4 through the unified `NfsShell<O: ShellOps>` architecture. Version-specific exceptions are noted where they apply.

Commands that modify the remote filesystem are gated behind `--allow-write` and marked with :material-pencil: below.

## Navigation

### ls

List directory contents.

```
ls [-a] [--sort=FIELD] [-r|--reverse] [path]
```

Default columns: mode, uid, gid, size, mtime, name. With `-a`: adds inode, nlink, used, rdev, atime, ctime. The `.` and `..` entries are always pinned first regardless of sort order. When `path` points to a file, shows that single entry.

| Flag | Description |
|------|-------------|
| `-a` | Show all columns (inode, nlink, used, rdev, atime, ctime) |
| `--sort=FIELD` | Sort by `name` (default), `size`, `mtime`, `ctime`, `atime`, `uid`, `gid` |
| `-r`, `--reverse` | Reverse sort order |

When sorting by `ctime` or `atime`, that timestamp replaces `mtime` in the default view.

**Aliases:** `dir`, `ll` (equivalent to `ls -a`)

### cd

Change directory. Absolute paths resolve from the export root. `cd /` resets to root without an RPC. After `escape-root`, the root becomes the escaped filesystem root.

```
cd <path>
```

### pwd

Print the current working directory path.

### tree

Recursive directory tree display. Default depth 3. Hidden dot-directories are always traversed.

```
tree [depth]
```

### find

Recursive case-insensitive filename search from the current directory.

```
find <pattern>
```

## File operations

### cat

Read and print file contents to stdout. Truncated at 1 MiB; use `get` for larger files. **Alias:** `type`

```
cat <file>
```

### get

Download a remote file or directory tree to a local path. **Alias:** `download`

```
get [-r] [--verify <sha256>] <remote> [local]
```

| Flag | Description |
|------|-------------|
| `-r` | Recurse into directories (mirrors tree locally with progress spinner) |
| `--verify HASH` | Assert SHA-256 of downloaded file matches the given hex hash |

If `local` is omitted, saves in the local cwd with the remote basename. If `local` is a directory or ends with `/`, appends the remote basename (scp semantics). Every download reports bytes and SHA-256. A 256 MiB cap per file guards against hostile servers.

??? example "Example"
    ```
    nfswolf> get /etc/shadow ./shadow
    saved 1204 bytes -> ./shadow  sha256:a1b2c3d4...

    nfswolf> get -r /etc ./evidence/etc
    saved 2847392 bytes -> ./evidence/etc/
    ```

### put :material-pencil:

Upload a local file or directory tree. Local permissions are preserved. **Alias:** `upload`

```
put [-r] <local> <remote>
```

### rm :material-pencil:

Remove a remote file. **Alias:** `del`

```
rm <file>
```

### mkdir :material-pencil:

Create a remote directory (mode 0755).

```
mkdir <dir>
```

### rmdir :material-pencil:

Remove an empty remote directory.

```
rmdir <dir>
```

### mv :material-pencil:

Rename or move a remote file or directory. Cross-directory moves are supported if the server allows them. **Alias:** `rename`

```
mv <src> <dst>
```

### cp :material-pencil:

Copy a remote file (READ + CREATE + WRITE). Source permissions are preserved. **Alias:** `copy`

```
cp <src> <dst>
```

## Links

### symlink :material-pencil:

Create a symbolic link on the remote filesystem. The target is stored as-is.

```
symlink <target> <linkname>
```

### link :material-pencil:

Create a hard link (NFSv3 LINK per RFC 1813 S3.3.15, NFSv2 LINK per RFC 1094 S2.2.12). Both entries must be on the same filesystem.

```
link <existing> <linkname>
```

### readlink

Read and print a symbolic link's target.

```
readlink <path>
```

## Attributes

### stat

Print detailed file attributes (type, mode, nlink, uid, gid, size, used, rdev, fileid, fsid, timestamps). Without a path, shows the current directory.

```
stat [path]
```

### chmod :material-pencil:

Set file mode via SETATTR.

```
chmod <octal-mode> <path>
```

### chown :material-pencil:

Set file owner and/or group via SETATTR. Omit `:<gid>` to change only the owner; use `:<gid>` alone to change only the group.

```
chown <uid>[:<gid>] <path>
```

## Identity

AUTH_SYS credentials are client-asserted (RFC 5531 sec. 14). The server trusts whatever UID/GID the client sends.

### whoami

Print current AUTH_SYS identity: uid, gid, hostname. **Alias:** `id`

### uid

Switch UID mid-session. On NFSv3/v4 this swaps credentials in-place. On NFSv2 it triggers a full reconnect.

```
uid <n>
```

### gid

Switch GID mid-session.

```
gid <n>
```

### hostname

Show or spoof the AUTH_SYS machine name (RFC 1057 S9.2). Without argument, prints current value.

```
hostname [name]
```

### impersonate

Switch both UID and GID at once. **Alias:** `su`

```
impersonate <uid>:<gid>
```

??? example "Example"
    ```
    nfswolf> impersonate 0:0
    impersonating uid=0 gid=0
    ```

## Devices

### mknod :material-pencil:

Create a character or block device node via MKNOD (RFC 1813 S3.3.11) with mode 0666. Enables raw disk access when the export lacks `nodev` (F-4.3).

```
mknod <name> c|b <major> <minor>
```

!!! warning "NFSv3 and NFSv4 only"
    NFSv2 does not support MKNOD.

## Security analysis

### suid-scan

Recursively walk from the current directory and report all SUID (0o4000) and SGID (0o2000) binaries. Reports mode, owner UID, and full path.

```
suid-scan
```

### world-writable

Recursively walk and report all entries with the world-write bit (0o002) set. World-writable directories without the sticky bit are particularly interesting for privilege escalation.

```
world-writable
```

### secrets-scan

Recursively walk and report files matching known credential/secret patterns: `id_rsa`, `id_ed25519`, `.env`, `shadow`, `passwd`, `.htpasswd`, `credentials`, `secret`, `password`, `token`, `apikey`, `private_key`, `.pem`, `.p12`, `.kdbx`, `authorized_keys`, `.git-credentials`, `wp-config.php`, `secrets.yaml`, `.aws`, `.ssh`, and more. Files where execute-implies-read (the knfsd `NFSD_MAY_OWNER_OVERRIDE` behavior) are flagged.

```
secrets-scan
```

### exports

Discover sibling exports via LOOKUPP parent traversal (F-2.12). Walks upward from the current directory until the handle stabilizes, then lists child directories at each level. On NFSv4, reveals the full pseudo-FS tree including exports not granted via MOUNT ACLs. Recurses 4 levels deep.

```
exports
```

### last

Decode `/var/log/wtmp` (login history). Parses the 384-byte glibc `struct utmpx` layout and reconstructs sessions per the util-linux 2.42 `last.c` state machine. Optional `N` caps output.

```
last [N]
```

### lastb

Decode `/var/log/btmp` (failed login attempts). Same format as `last`.

```
lastb [N]
```

### lastlog

Decode `/var/log/lastlog` (last login per UID). Maps UIDs to usernames via `/etc/passwd`. If the classic file is absent but the SQLite-backed `lastlog2.db` exists, suggests downloading it for offline analysis.

```
lastlog
```

## Escape

### escape-root

Run the fast escape pipeline to break out of the export boundary and reach the filesystem root. Supports 18 of 19 Linux filesystem types. On success, replaces the shell root and current directory with the escaped handle (prompt changes to `/ [escaped]`).

```
escape-root
```

### mount-handle

Jump to an arbitrary file handle. File handles are bearer tokens (RFC 1094 S2.3.3), so any handle works regardless of export boundaries. Validates with GETATTR before switching.

```
mount-handle <hex>
```

### handle

Print the current directory's raw file handle in hex.

```
handle
```

### root

Probe the obsolete NFSPROC_ROOT (procedure 3) for a MOUNT bypass. A server that responds gives any client a root handle without MOUNT ACL checks.

```
root
```

!!! warning "NFSv2 only"

### verifier

Probe the server's write verifier via zero-count COMMIT. The `writeverf3` is an opaque 8-byte value regenerated on reboot (RFC 1813 S3.3.21), enabling reboot detection without write traffic.

```
verifier
```

!!! info "NFSv3 only"

## Local filesystem

These commands operate on the local (attacker's) machine, not the remote NFS export.

| Command | Syntax | Description |
|---------|--------|-------------|
| `lcd` | `lcd [dir]` | Change local working directory |
| `lls` | `lls [dir]` | List local directory |
| `lpwd` | `lpwd` | Print local working directory |
| `lmkdir` | `lmkdir <dir>` | Create local directory (including parents) |

## Session

| Command | Syntax | Description |
|---------|--------|-------------|
| `history` | `history` | Print command history for this session |
| `help` | `help` or `?` | Print built-in command reference (version-adapted) |
| `exit` | `exit` or `quit` | Exit the shell |

## Command availability by NFS version

| Command | NFSv2 | NFSv3 | NFSv4 | Notes |
|---------|:-----:|:-----:|:-----:|-------|
| All base commands | Yes | Yes | Yes | Shared via `ShellOps` trait |
| `mknod` | -- | Yes | Yes | NFSv2 has no MKNOD procedure |
| `root` | Yes | -- | -- | NFSPROC_ROOT is NFSv2 only |
| `verifier` | -- | Yes | -- | COMMIT writeverf is NFSv3 only |
| `uid`/`gid`/`su` | Reconnect | In-place | In-place | NFSv2 requires new TCP socket |

## See also

- [Shell](shell.md) -- Shell subcommand options, features, and walkthrough
- [Mount](mount.md) -- FUSE mount for using standard tools against NFS exports
