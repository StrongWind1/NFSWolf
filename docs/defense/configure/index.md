# Configuring NFS

NFS server configuration on Linux centers on three things: the export table (`/etc/exports`), the kernel parameters that control knfsd behavior, and the firewall rules that determine who can reach the NFS services. Getting any one of these wrong undermines the others. A locked-down export table means nothing if portmapper is open to the internet, and strict firewall rules do not help if the export grants `no_root_squash` to a compromised subnet.

This section covers the configuration layer. For what to actually set these options to, see [Hardening](../hardening/index.md). For why the defaults are dangerous, see the [Findings](../../findings/index.md) catalog.

## Sub-pages

| Page | What it covers |
|------|---------------|
| [/etc/exports Syntax](exports-syntax.md) | Line format, client specifications, option syntax, the space-before-paren trap, `exportfs` commands, and `rpcdebug` troubleshooting |
| [Export options](export-options.md) | Every `/etc/exports` option explained: security impact, default value, when to use it, and which nfswolf findings it relates to |
| [Kernel parameters](kernel-params.md) | `/proc/sys/fs/nfs/` and `/proc/fs/nfsd/` tunables, thread counts, lease times, and debug flags |
| [Firewall rules](firewall.md) | iptables/nftables rules for NFS, portmapper, mountd, and sideband services; port pinning via `/etc/nfs.conf` |

## Configuration file locations

| File | Purpose |
|------|---------|
| `/etc/exports` | Static export table, the primary configuration file. Parsed by `exportfs`. |
| `/etc/exports.d/*.exports` | Drop-in export fragments. Same syntax as `/etc/exports`. Loaded automatically by `exportfs -a`. |
| `/etc/nfs.conf` | Daemon configuration: thread counts, port assignments, protocol versions, GSS settings. INI-format. Replaces the older `/etc/sysconfig/nfs` and `/etc/default/nfs-kernel-server`. |
| `/etc/idmapd.conf` | NFSv4 ID mapping (username/group string to local UID/GID). Only relevant when NFSv4 is in use. |
| `/var/lib/nfs/etab` | Runtime export table maintained by `exportfs`. Shows the effective options after defaults are applied. Read-only; never edit directly. |

!!! tip "Check the effective configuration"
    The file you write (`/etc/exports`) is not what the kernel sees. Run `exportfs -v` to see the fully expanded export table with all defaults filled in, or inspect `/var/lib/nfs/etab` directly. Many security issues come from default options that are not visible in `/etc/exports` but are active in `etab`.

## Reading order

If you are setting up NFS for the first time, read the pages in this order:

1. [/etc/exports Syntax](exports-syntax.md): learn the file format and avoid the most common mistakes
2. [Export options](export-options.md): understand what each option does and its security implications
3. [Firewall rules](firewall.md): lock down network access to NFS services
4. [Kernel parameters](kernel-params.md): tune knfsd behavior and debugging

Then proceed to [Hardening](../hardening/index.md) for a checklist of what to enable and what to disable.
