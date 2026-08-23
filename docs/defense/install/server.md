# NFS server setup

This page walks through installing, configuring, and starting an NFS server on Linux. By the end you will have a running `nfs-server` daemon exporting a directory over NFSv3 and NFSv4, verified with `showmount`, and firewalled to the minimum required ports.

!!! danger "Default NFS is not secure"
    The setup on this page produces a functional NFS server, not a hardened one. AUTH_SYS credentials are plaintext and trivially spoofed ([F-1.1](../../findings/identity/F-1.1-uid-gid-spoofing.md)), file handles are bearer tokens ([F-2.1](../../findings/access-control/F-2.1-export-escape.md)), and `root_squash` is the only identity restriction enabled by default. Continue to [Export options](../configure/export-options.md) and [Hardening](../hardening/index.md) before exposing the server to production traffic.

## Install packages

=== "Debian/Ubuntu"

    ```bash
    sudo apt update
    sudo apt install -y nfs-kernel-server
    ```

    This pulls in `nfs-common`, `rpcbind`, and the kernel NFS daemon.

=== "RHEL/Fedora"

    ```bash
    sudo dnf install -y nfs-utils
    ```

=== "Arch Linux"

    ```bash
    sudo pacman -S nfs-utils
    ```

## Enable and start services

The NFS server depends on `rpcbind` for portmapper (NFSv2/v3) and on `nfs-server` for the kernel daemon. Enable both:

=== "Debian/Ubuntu"

    ```bash
    sudo systemctl enable --now rpcbind
    sudo systemctl enable --now nfs-kernel-server
    ```

=== "RHEL/Fedora"

    ```bash
    sudo systemctl enable --now rpcbind
    sudo systemctl enable --now nfs-server
    ```

=== "Arch Linux"

    ```bash
    sudo systemctl enable --now rpcbind
    sudo systemctl enable --now nfs-server
    ```

!!! tip "Check service status"
    ```bash
    systemctl status rpcbind
    systemctl status nfs-server        # or nfs-kernel-server on Debian
    ```

## Create an export directory

```bash
sudo mkdir -p /srv/nfs/shared
sudo chown nobody:nogroup /srv/nfs/shared
sudo chmod 0755 /srv/nfs/shared
```

## Define the export

Add the directory to `/etc/exports`. Each line defines one export path, followed by client specifications with options in parentheses.

```bash title="/etc/exports"
/srv/nfs/shared    192.168.1.0/24(rw,sync,no_subtree_check,root_squash)
```

| Option | Meaning |
|--------|---------|
| `rw` | Read-write access (use `ro` for read-only) |
| `sync` | Writes committed to disk before the server replies |
| `no_subtree_check` | Avoids stale handle errors when files are renamed outside the export root |
| `root_squash` | Maps remote UID 0 to `nobody` (default, but worth stating explicitly) |

!!! warning "Whitespace matters"
    There must be **no space** between the client specification and the opening parenthesis. `192.168.1.0/24 (rw)` (with a space) is parsed as two entries: `192.168.1.0/24` with default options and `(rw)` applied to the world. See [/etc/exports Syntax](../configure/exports-syntax.md) for the full grammar.

??? example "Multiple exports and client patterns"

    ```bash title="/etc/exports"
    /srv/nfs/shared     192.168.1.0/24(rw,sync,root_squash)
    /srv/nfs/backups    10.0.0.5(ro,sync,root_squash)
    /srv/nfs/public     *.internal.lan(ro,sync,all_squash)
    /srv/nfs/data       10.0.0.10(rw,sync) 10.0.0.11(rw,sync)
    ```

## Apply the export configuration

After editing `/etc/exports`, tell the running NFS server to re-read the file:

```bash
sudo exportfs -ra
```

To see the currently active exports with their resolved options:

```bash
sudo exportfs -v
```

## Verify with showmount

From the server itself, confirm that the export is visible:

```bash
showmount -e localhost
```

Expected output:

```text
Export list for localhost:
/srv/nfs/shared 192.168.1.0/24
```

!!! warning "showmount is unauthenticated"
    `showmount -e` queries the MOUNT protocol's EXPORT procedure, which has no authentication. Anyone who can reach port 111 and the mountd port can enumerate all exports and their ACLs ([F-5.1](../../findings/info-disclosure/F-5.1-export-list-enumeration.md)). In hardened environments, restrict portmapper access or serve NFSv4-only.

## Firewall rules

NFS requires several ports. By default, `rpc.mountd` and `rpc.statd` pick random high ports on each restart. Pin them to fixed ports for predictable firewall rules.

| Port | Service | Required for |
|------|---------|-------------|
| 111 (TCP/UDP) | rpcbind | NFSv2/v3 (not needed for NFSv4-only) |
| 2049 (TCP) | nfsd | All versions |
| 20048 (TCP/UDP) | rpc.mountd (pinned) | NFSv2/v3 |
| 32765 (TCP/UDP) | rpc.statd (pinned) | NFSv2/v3 |

### Pin dynamic service ports

Edit `/etc/nfs.conf` (on Debian, also works via `/etc/default/nfs-kernel-server`):

```ini title="/etc/nfs.conf"
[mountd]
port = 20048

[statd]
port = 32765
```

Then restart the NFS server (`sudo systemctl restart nfs-server`).

### Apply firewall rules

=== "firewalld"

    ```bash
    sudo firewall-cmd --permanent --add-service=nfs
    sudo firewall-cmd --permanent --add-service=rpc-bind
    sudo firewall-cmd --permanent --add-port=20048/tcp
    sudo firewall-cmd --permanent --add-port=20048/udp
    sudo firewall-cmd --permanent --add-port=32765/tcp
    sudo firewall-cmd --permanent --add-port=32765/udp
    sudo firewall-cmd --reload
    ```

=== "iptables"

    ```bash
    sudo iptables -A INPUT -p tcp --dport 111 -s 192.168.1.0/24 -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 2049 -s 192.168.1.0/24 -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 20048 -s 192.168.1.0/24 -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 32765 -s 192.168.1.0/24 -j ACCEPT
    sudo iptables -A INPUT -p udp --dport 111 -s 192.168.1.0/24 -j ACCEPT
    sudo iptables -A INPUT -p udp --dport 20048 -s 192.168.1.0/24 -j ACCEPT
    sudo iptables -A INPUT -p udp --dport 32765 -s 192.168.1.0/24 -j ACCEPT
    ```

=== "nftables"

    ```bash
    sudo nft add rule inet filter input ip saddr 192.168.1.0/24 tcp dport { 111, 2049, 20048, 32765 } accept
    sudo nft add rule inet filter input ip saddr 192.168.1.0/24 udp dport { 111, 20048, 32765 } accept
    ```

!!! tip "NFSv4-only simplifies the firewall"
    If you serve NFSv4 exclusively, the only port you need is TCP 2049. No rpcbind, no mountd, no statd. See [Firewall rules](../configure/firewall.md) for a detailed breakdown.

## Systemd service management

```bash
systemctl status nfs-server              # current status
sudo systemctl restart nfs-server        # restart after config changes
sudo exportfs -ra                        # reload exports without full restart
journalctl -eu nfs-server --since "10 minutes ago"  # recent logs
cat /proc/fs/nfsd/versions               # enabled NFS versions
```

??? note "Controlling NFS versions"
    By default, Linux serves NFSv3 and NFSv4. To change which versions are active:

    ```ini title="/etc/nfs.conf"
    [nfsd]
    vers2 = n
    vers3 = y
    vers4 = y
    vers4.1 = y
    vers4.2 = y
    ```

    Restart the NFS server and verify with `cat /proc/fs/nfsd/versions` -- enabled versions show as `+3 +4 +4.1 +4.2`, disabled as `-2`.

## Verify the full stack

Once the server is running and the firewall is configured, verify end-to-end:

```bash
rpcinfo -p localhost            # rpcbind is listening
sudo exportfs -v                # exports are active
showmount -e localhost          # export is visible
cat /proc/fs/nfsd/versions      # NFS versions are correct
cat /proc/fs/nfsd/threads       # nfsd threads are running
```

If all five checks pass, proceed to [Client setup](client.md) to mount the export from a remote machine, then to [Configuring NFS](../configure/index.md) for production-grade export options.

## Next steps

- [Client setup](client.md) -- mount the export from a client machine
- [/etc/exports syntax](../configure/exports-syntax.md) -- full grammar reference for export definitions
- [Export options reference](../configure/export-options.md) -- every export option with security implications
- [Hardening checklist](../hardening/checklist.md) -- secure the server before exposing it to the network
