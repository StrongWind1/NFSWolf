# Hardening checklist

A prioritized checklist for securing NFS deployments, ordered by impact within each tier. Each item links to the finding it mitigates. Complete all Critical items before moving to High.

## Priority 1 -- Critical

These controls eliminate the most severe attack paths. An NFS deployment missing any of these is trivially exploitable from any host that can reach port 2049.

### 1.1 Use Kerberos (`sec=krb5p`) on all exports

- [ ] **Configure RPCSEC_GSS with `sec=krb5p` on every export line in `/etc/exports`**

The single most effective control -- blocks UID spoofing, credential replay, group injection, and wire sniffing in one setting. See [F-1.1](../../identity/F-1.1-uid-gid-spoofing.md) for why AUTH_SYS is insecure and [Kerberos authentication](kerberos.md) for deployment steps.

**Mitigates:** [F-1.1](../../identity/F-1.1-uid-gid-spoofing.md), [F-1.2](../../identity/F-1.2-root-squash-bypass.md), [F-1.3](../../identity/F-1.3-auxiliary-group-injection.md), [F-1.5](../../identity/F-1.5-credential-replay.md), [F-3.1](../../network/F-3.1-plaintext-wire-protocol.md)

!!! danger "Do not mix `sec=krb5:sys`"
    Adding `sys` as a fallback negates the benefit -- attackers simply send AUTH_SYS. Use `sec=krb5p` alone, or `sec=krb5p:krb5i:krb5` (all Kerberos, no AUTH_SYS). See [F-1.7](../../identity/F-1.7-rpcsec-gss-flavor-downgrade.md).

### 1.2 Never use `no_root_squash`

- [ ] **Confirm no export line contains `no_root_squash`**
- [ ] **Run `exportfs -v` and verify every export shows `root_squash`**

Without root squash, any client operates as UID 0 on the export, enabling SUID upload and device node creation. See [F-4.1](../../privesc/F-4.1-no-root-squash.md) for the full attack chain.

**Mitigates:** [F-4.1](../../privesc/F-4.1-no-root-squash.md), [F-4.2](../../privesc/F-4.2-suid-sgid-escalation.md), [F-4.3](../../privesc/F-4.3-device-node-creation.md)

!!! warning "root_squash is not a security boundary"
    `root_squash` only blocks UID 0 and GID 0. Attackers can still spoof any non-root UID/GID via AUTH_SYS. On Debian/Ubuntu, `/etc/shadow` is readable by GID 42 (`shadow` group), so root squash does not prevent credential theft after an [export escape](../../access-control/F-2.1-export-escape.md).

### 1.3 Export separate filesystems, not bind-mounted subdirectories

- [ ] **Each export path is the root of its own filesystem (LVM volume, partition, or ZFS dataset)**
- [ ] **No export is a subdirectory of a larger filesystem**

When the export is the filesystem root, there is nothing outside it to escape to. This is the primary defense against [F-2.1: Export Escape](../../access-control/F-2.1-export-escape.md), which exploits the gap between filesystem boundaries and export boundaries.

**Mitigates:** [F-2.1](../../access-control/F-2.1-export-escape.md), [F-2.4](../../access-control/F-2.4-btrfs-subvolume-escape.md), [F-2.6](../../access-control/F-2.6-bind-mount-escape.md)

```bash
# Create a dedicated LVM volume for the export
lvcreate -L 10G -n nfs_share vg0
mkfs.ext4 /dev/vg0/nfs_share
mount /dev/vg0/nfs_share /srv/share
# /srv/share is now the filesystem root -- escape impossible
```

### 1.4 Use `all_squash` for public or semi-public exports

- [ ] **Any export accessible by multiple users or untrusted hosts uses `all_squash`**

Maps every incoming UID/GID to `nobody`, neutralizing [AUTH_SYS identity spoofing](../../identity/F-1.1-uid-gid-spoofing.md). Trade-off: all files must be readable/writable by `nobody`. Use Kerberos when per-user permissions are needed.

**Mitigates:** [F-1.1](../../identity/F-1.1-uid-gid-spoofing.md), [F-1.3](../../identity/F-1.3-auxiliary-group-injection.md)

---

## Priority 2 -- High

These controls reduce the attack surface and provide defense-in-depth behind the Critical controls.

### 2.1 Restrict exports to specific hosts or networks

- [ ] **Every export line specifies explicit hosts or CIDR ranges -- no `*` or bare hostnames**

Restricting to specific IPs or subnets limits who can obtain mount handles. Not a substitute for authentication -- see [F-3.3](../../network/F-3.3-ip-spoofing-host-trust.md) and [F-1.4](../../identity/F-1.4-machine-name-spoofing.md).

**Mitigates:** [F-7.1](../../config/F-7.1-wildcard-export-policy.md), [F-3.3](../../network/F-3.3-ip-spoofing-host-trust.md)

### 2.2 Use read-only (`ro`) wherever possible

- [ ] **Exports that serve static content, backups, or reference data use `ro`**

Blocks all write-dependent attacks ([SUID upload](../../privesc/F-4.2-suid-sgid-escalation.md), [device node creation](../../privesc/F-4.3-device-node-creation.md)) even if an attacker gains arbitrary credentials.

**Mitigates:** [F-4.1](../../privesc/F-4.1-no-root-squash.md), [F-4.2](../../privesc/F-4.2-suid-sgid-escalation.md), [F-4.3](../../privesc/F-4.3-device-node-creation.md)

### 2.3 Fix NFS port numbers for firewall rules

- [ ] **`mountd`, `statd`, and `lockd` use fixed ports configured in `/etc/nfs.conf` or sysconfig**
- [ ] **Firewall rules allow only the fixed ports from authorized networks**

Fixed ports enable precise firewall rules instead of relying on portmapper. See [Firewall rules](../configure/firewall.md) for port assignment and `iptables`/`nftables` examples.

**Mitigates:** [F-5.4](../../info-disclosure/F-5.4-rpc-service-enumeration.md), [F-3.2](../../network/F-3.2-portmapper-amplification.md)

### 2.4 Disable NFSv2 and NFSv3 if only NFSv4 is needed

- [ ] **Set `vers2=n` and `vers3=n` in `/etc/nfs.conf`**
- [ ] **Verify with `nfsstat --server` or `cat /proc/fs/nfsd/versions`**

Eliminates the MOUNT protocol, portmapper, and auxiliary RPC services entirely. See [F-1.6](../../identity/F-1.6-nfsv2-downgrade.md) for the version downgrade attack this prevents.

**Mitigates:** [F-1.6](../../identity/F-1.6-nfsv2-downgrade.md), [F-5.1](../../info-disclosure/F-5.1-export-list-enumeration.md)

---

## Priority 3 -- Medium

### 3.1 Enable `subtree_check` where feasible

- [ ] **Exports that are subdirectories of a larger filesystem use `subtree_check`**

Blocks [export escape](../../access-control/F-2.1-export-escape.md) by rejecting handles outside the exported subtree. Prefer separate filesystems (item 1.3) where possible.

**Mitigates:** [F-2.1](../../access-control/F-2.1-export-escape.md)

!!! warning "Performance and reliability impact"
    `subtree_check` causes `ESTALE` errors on renames (why Linux defaults to `no_subtree_check`). Prefer separate filesystems per export (item 1.3).

### 3.2 Remove portmapper access from untrusted networks

- [ ] **Port 111 (TCP and UDP) is firewalled from all networks except authorized NFS clients**
- [ ] **rpcbind is bound to localhost or specific interfaces**

Prevents [RPC service enumeration](../../info-disclosure/F-5.4-rpc-service-enumeration.md) and [amplification attacks](../../network/F-3.2-portmapper-amplification.md) from untrusted networks.

**Mitigates:** [F-5.4](../../info-disclosure/F-5.4-rpc-service-enumeration.md), [F-3.2](../../network/F-3.2-portmapper-amplification.md)

### 3.3 Monitor MOUNT DUMP output for unauthorized clients

- [ ] **Periodic `showmount -a` or `nfswolf scan` output is reviewed for unexpected client IPs**

Surfaces unauthorized mounts via the [MOUNT DUMP list](../../info-disclosure/F-5.1-export-list-enumeration.md). Detection only, not prevention.

**Mitigates:** [F-5.1](../../info-disclosure/F-5.1-export-list-enumeration.md)

### 3.4 Use NFS over TLS (RFC 9289) where supported

- [ ] **Server and clients support kernel 6.x+ with `ktls` and `tlshd`**
- [ ] **`xprtsec=tls` or `xprtsec=mtls` is set on exports**

Encrypts data in transit without Kerberos infrastructure. Mutual TLS (`mtls`) also provides client certificate authentication. See [NFS over TLS](tls.md) for setup details.

**Mitigates:** [F-3.1](../../network/F-3.1-plaintext-wire-protocol.md), [F-3.4](../../network/F-3.4-striptls-downgrade.md)

!!! note "Limited availability"
    Requires Linux kernel 6.x+ on both server and client, plus the `tlshd` daemon. Most enterprise distributions now ship a compatible kernel, but the feature is still early-adoption.

---

## Verification

After completing all applicable checklist items, run a full security audit:

```bash
# Comprehensive analysis -- reports every remaining finding
nfswolf analyze target

# JSON output for tracking over time
nfswolf analyze target --json > audit-$(date +%Y%m%d).json
```

A fully hardened deployment (all Critical and High items) should produce zero Critical and zero High findings from `nfswolf analyze`. Medium-tier items reduce the remaining surface further.

