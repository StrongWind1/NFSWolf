# NFS client setup

This page covers installing the NFS client utilities, mounting remote exports manually and persistently, configuring `autofs` for on-demand mounting, and setting up NFSv4 ID mapping. It assumes an NFS server is already running -- see [Server setup](server.md) if not.

## Install packages

=== "Debian/Ubuntu"

    ```bash
    sudo apt update
    sudo apt install -y nfs-common
    ```

    `nfs-common` provides `mount.nfs`, `showmount`, `rpcinfo`, and `rpc.statd`.

=== "RHEL/Fedora"

    ```bash
    sudo dnf install -y nfs-utils
    ```

=== "Arch Linux"

    ```bash
    sudo pacman -S nfs-utils
    ```

After installation, ensure `rpcbind` is running (required for NFSv2/v3 mounts):

```bash
sudo systemctl enable --now rpcbind
```

!!! note "NFSv4 does not require rpcbind"
    If you mount exclusively with `vers=4`, `rpcbind` is not needed on the client. The NFS client connects directly to port 2049 without portmapper lookups.

## Manual mount

```bash
sudo mount -t nfs 192.168.1.10:/srv/nfs/shared /mnt
```

This uses the system default NFS version (typically v4 on modern kernels, falling back to v3). To force a specific version:

```bash
sudo mount -t nfs -o vers=3 192.168.1.10:/srv/nfs/shared /mnt   # NFSv3
sudo mount -t nfs -o vers=4 192.168.1.10:/srv/nfs/shared /mnt   # NFSv4
```

!!! tip "Verify before mounting"
    ```bash
    rpcinfo -p 192.168.1.10         # portmapper connectivity
    showmount -e 192.168.1.10       # available exports
    ```

## Persistent mounts with /etc/fstab

To mount automatically at boot, add a line to `/etc/fstab`:

```bash title="/etc/fstab"
192.168.1.10:/srv/nfs/shared  /mnt/shared  nfs  defaults,_netdev  0  0
```

Create the mount point and test:

```bash
sudo mkdir -p /mnt/shared
sudo mount /mnt/shared          # mounts using fstab entry
```

The `_netdev` option delays the mount until the network is up. Always use it for NFS entries in fstab.

??? example "Common fstab configurations"

    ```bash title="/etc/fstab"
    # NFSv4, read-write, hard mount, Kerberos integrity
    192.168.1.10:/shared   /mnt/shared   nfs4  sec=krb5i,hard,_netdev  0 0

    # NFSv3, read-only, soft mount with 30s timeout
    10.0.0.5:/backups      /mnt/backups  nfs   vers=3,ro,soft,timeo=300,_netdev  0 0
    ```

## Autofs configuration

`autofs` mounts NFS exports on demand when a user accesses the mount point, and unmounts them after an idle timeout.

=== "Debian/Ubuntu"

    ```bash
    sudo apt install -y autofs
    ```

=== "RHEL/Fedora"

    ```bash
    sudo dnf install -y autofs
    ```

=== "Arch Linux"

    ```bash
    sudo pacman -S autofs
    ```

Add an entry to `/etc/auto.master`:

```bash title="/etc/auto.master"
/mnt/nfs  /etc/auto.nfs  --timeout=300
```

Create the map file:

```bash title="/etc/auto.nfs"
shared   -fstype=nfs,rw,hard,_netdev   192.168.1.10:/srv/nfs/shared
backups  -fstype=nfs,ro,hard,_netdev   192.168.1.10:/srv/nfs/backups
```

Enable and test:

```bash
sudo systemctl enable --now autofs
ls /mnt/nfs/shared              # triggers on-demand mount
```

## Verify the mount

```bash
df -hT | grep nfs               # mounted NFS filesystems
findmnt -t nfs,nfs4             # detailed mount information with options
```

## NFSv4 ID mapping

NFSv4 transmits file ownership as `user@domain` strings instead of raw UID/GID integers. The `idmapd` daemon translates between these strings and local UIDs/GIDs. If ID mapping is misconfigured, all files appear owned by `nobody:nogroup`.

Edit `/etc/idmapd.conf` on both client and server:

```ini title="/etc/idmapd.conf"
[General]
Domain = example.com

[Mapping]
Nobody-User = nobody
Nobody-Group = nogroup
```

!!! warning "Domain must match"
    The `Domain` value must be identical on client and server. A mismatch causes all file ownership to map to `nobody`. This is the most common cause of ownership display issues on NFSv4 mounts.

Restart `idmapd` after editing:

```bash
sudo systemctl restart nfs-idmapd
sudo nfsidmap -c                # flush the kernel ID mapping cache
```

## Common mount options

| Option | Default | Description |
|--------|---------|-------------|
| `vers=N` | Auto | Force NFS version (2, 3, 4, 4.1, 4.2) |
| `sec=MODE` | `sys` | Auth flavor: `sys`, `krb5`, `krb5i`, `krb5p` |
| `hard` | Yes | Retry indefinitely on server failure (prevents data loss, can hang) |
| `soft` | No | Return errors after `retrans` retries (prevents hangs, risks corruption) |
| `timeo=N` | 600 | RPC timeout in tenths of a second |
| `retrans=N` | 2 | Retries before soft-mount error or hard-mount warning |
| `_netdev` | No | Delay mount until network is up (always use in fstab) |
| `nosuid` | No | Ignore setuid/setgid bits ([F-4.2](../../privesc/F-4.2-suid-sgid-escalation.md)) |
| `nodev` | No | Ignore device nodes ([F-4.3](../../privesc/F-4.3-device-node-creation.md)) |
| `noexec` | No | Prevent binary execution |
| `proto=tcp` | TCP | Transport protocol (UDP also supported for v2/v3) |

!!! tip "Minimum security options for untrusted exports"
    When mounting an export you do not control, always add `nosuid,nodev,noexec`:

    ```bash
    sudo mount -t nfs -o nosuid,nodev,noexec 192.168.1.10:/export /mnt
    ```

    This prevents three classes of privilege escalation via crafted files on the remote export. See [F-7.4](../../config/F-7.4-missing-nosuid-nodev.md).

## Next steps

- [/etc/exports syntax](../configure/exports-syntax.md) -- understand server-side export definitions
- [Export options reference](../configure/export-options.md) -- server-side options with security implications
- [Hardening checklist](../hardening/checklist.md) -- secure both client and server
- [Kerberos authentication](../hardening/kerberos.md) -- replace AUTH_SYS with cryptographic authentication
