# Mount

The `mount` subcommand exposes a remote NFS export as a local FUSE filesystem. Once mounted, the export is accessible through standard Unix tools (`ls`, `cat`, `find`, `grep`, `cp`, `file`, `strings`, etc.) without a kernel NFS client or any NFS-specific tooling. The FUSE layer is generic over NFS version and provides auto-credential escalation, attribute caching, and full SUID/device passthrough for security testing.

!!! note "Requires the `fuse` Cargo feature and libfuse3"
    The `fuse` feature is enabled by default in native builds. It is not available in the musl-static distribution because libfuse3 cannot be statically linked against musl. Install `libfuse3-dev` (Debian/Ubuntu) or `fuse3-devel` (RHEL/Fedora) before building.

## Usage

```
nfswolf mount <target>[:/export] <mountpoint> [options]
```

The mountpoint must already exist and be a directory.

??? example "Basic mount and exploration"

    ```bash
    # Create a mountpoint
    mkdir -p /mnt/nfs

    # Mount the remote export
    nfswolf mount 10.0.0.5:/srv/nfs /mnt/nfs

    # Use standard tools
    ls -la /mnt/nfs/
    cat /mnt/nfs/etc/passwd
    find /mnt/nfs -name "*.conf" -exec grep -l password {} \;
    file /mnt/nfs/usr/bin/*
    strings /mnt/nfs/var/lib/mysql/ibdata1 | grep -i password

    # Unmount when done
    fusermount3 -u /mnt/nfs
    ```

## Options

### Target

| Flag | Description |
|------|-------------|
| `-e`, `--export PATH` | Export path (alternative to `host:/export` syntax) |
| `--handle HEX` | Mount from a raw file handle (bypasses MOUNT RPC) |

### Behavior

| Flag | Description |
|------|-------------|
| `--nfs-version VER` | NFS protocol version: `2`, `3`, or `4`. Auto-detected if omitted. |
| `--allow-write` | Enable write operations (default: read-only mount) |
| `--hide` | Immediately unmount from the server after capturing the handle (stealth). The local FUSE mount remains active. Has no effect with `--handle`. |

## Features

### Version-neutral operation

The FUSE adapter works with NFSv2, NFSv3, and NFSv4 through the same `ShellOps` trait that powers the interactive shell. Version detection follows the same probe sequence as the shell (v3, then v2, then v4) when `--nfs-version` is omitted.

```bash
# Auto-detect (default)
nfswolf mount 10.0.0.5:/srv /mnt/nfs

# Force NFSv4
nfswolf mount 10.0.0.5:/srv /mnt/nfs --nfs-version 4

# Force NFSv2
nfswolf mount 10.0.0.5:/srv /mnt/nfs --nfs-version 2
```

### Auto-credential escalation

Every FUSE callback that returns `EACCES` triggers the same credential escalation ladder the interactive shell uses. The resolved (uid, gid) pair is cached per inode, so subsequent accesses to the same file skip the search. This means `cat /mnt/nfs/etc/shadow` will automatically try root credentials if the initial UID cannot read the file.

### Server-side symlink resolution

When a LOOKUP lands on a symlink, the FUSE layer issues READLINK and re-resolves the target relative to the parent (or the FUSE root for absolute paths). The local kernel never sees the underlying symlink, so `cd /mnt/nfs/link` enters the server-side target transparently. A depth cap prevents symlink loops.

### SUID and device passthrough

The mount is configured with SUID and device passthrough enabled (`MountOption::Suid`, `MountOption::Dev`). This is intentional for security testing: it makes SUID binaries and device nodes on the NFS export functional through the local mount, matching the behavior that findings F-4.2 and F-4.3 describe.

!!! danger "Security testing only"
    SUID/device passthrough means programs on the remote export can execute with elevated privileges on your local machine. Only mount exports from controlled test environments.

### Stealth unmount

The `--hide` flag tells the server to forget this client's mount immediately after the handle is captured. The local FUSE mount continues to work because file handles are bearer tokens -- once obtained, the handle works without an active MOUNT session. The server's `showmount` output will not list this client.

```bash
nfswolf mount 10.0.0.5:/srv /mnt/nfs --hide
```

### Daemonization

The FUSE handler detaches from the terminal after the mount is established, just like `mount(8)`. The mount survives the operator's shell exiting. Always unmount manually when done.

## Handle-based mount

When portmapper or mountd is firewalled, you can mount using a raw file handle obtained from `nfswolf escape` or `nfswolf brute-handle`:

```bash
nfswolf mount 10.0.0.5 /mnt/nfs --handle 01000007020000020000000001000000...
```

This connects directly to the NFS data port (2049 by default) without any MOUNT RPC, bypassing export ACL checks entirely.

## Cleanup

Always unmount the FUSE filesystem when done:

```bash
# Linux
fusermount3 -u /mnt/nfs

# macOS
umount /mnt/nfs
```

After a SIGKILL or hard crash of the daemon process, the kernel may leave the mount in a `Transport endpoint is not connected` state. The same unmount command clears it.

## Limitations

| Limitation | Details |
|------------|---------|
| **Requires libfuse3** | The `fuse` feature links against libfuse3. Install the `-dev` / `-devel` package for your distro. |
| **Not in musl-static builds** | The cross-compiled static binary (`dist/`) drops the `fuse` feature because libfuse3 cannot be statically linked. Use a native build instead. |
| **Requires root or fuse group** | FUSE mounts require either root privileges or membership in the `fuse` group, depending on the system's `/etc/fuse.conf` settings. |
| **Attribute cache TTL** | Attributes are cached for 1 second. Rapidly changing files on the server may show stale metadata briefly. |
| **Read-only by default** | Write operations require `--allow-write`. Without it, all mutating FUSE operations return `EACCES`. |

## See also

- [Shell](shell.md) -- Interactive shell for NFS exploration when you need per-command control
- [Shell Commands](shell-commands.md) -- Complete command reference for the interactive shell
- [Escape](escape.md) -- Obtain filesystem root handles for `--handle` mounts
- [Global Options](global-options.md) -- Proxy, stealth, credential, and port options
