# Example configurations

Three complete `/etc/exports` configurations, from maximum security to minimum acceptable. Each example includes the full export file, a line-by-line explanation, the findings it mitigates, and the residual risks that remain.

Pick the profile that matches your environment, then use `nfswolf analyze` to verify the result.

---

=== "Maximum security"

    ## Maximum security

    This configuration is appropriate for environments handling sensitive data (financial, medical, classified) where NFS access is restricted to a small set of known hosts with Kerberos infrastructure already deployed.

    ### `/etc/exports`

    ```bash
    # Maximum security NFS exports
    # Requirements: Kerberos KDC, separate filesystem per export, NFSv4 only

    /srv/finance    gss/krb5p(ro,sync,no_subtree_check,all_squash,anonuid=65534,anongid=65534)
    /srv/medical    gss/krb5p(ro,sync,no_subtree_check,all_squash,anonuid=65534,anongid=65534)
    /srv/shared     gss/krb5p(rw,sync,no_subtree_check,root_squash,anonuid=65534,anongid=65534)
    ```

    ### `/etc/nfs.conf`

    ```ini
    [nfsd]
    # Disable NFSv2 and NFSv3 entirely -- only v4 served
    vers2 = n
    vers3 = n
    vers4 = y
    vers4.0 = y
    vers4.1 = y
    vers4.2 = y

    # Limit concurrent threads
    threads = 8

    [exportd]
    # No mountd needed for NFSv4-only
    manage-gids = y

    [mountd]
    # Fixed port in case mountd still runs (v4-only should not need it)
    port = 20048
    ```

    ### Option Explanation

    | Option | Purpose |
    |--------|---------|
    | `gss/krb5p` | Kerberos privacy: authentication + integrity + encryption. No AUTH_SYS fallback. |
    | `ro` | Read-only. Blocks all write operations. |
    | `sync` | Commits writes to stable storage before replying. |
    | `no_subtree_check` | Safe because each export is its own filesystem root; nothing to escape to. |
    | `all_squash` | Maps every identity to `nobody` (65534). Used on read-only exports. |
    | `root_squash` | On the `rw` export, maps UID 0 to `nobody` while preserving per-user Kerberos identity. |
    | `anonuid=65534,anongid=65534` | Explicit anonymous mapping target. Defensive default. |

    ### Filesystem Layout

    ```bash
    # Each export is the root of its own LVM volume
    lvcreate -L 50G -n finance vg0 && mkfs.ext4 /dev/vg0/finance
    lvcreate -L 50G -n medical vg0 && mkfs.ext4 /dev/vg0/medical
    lvcreate -L 20G -n shared  vg0 && mkfs.ext4 /dev/vg0/shared

    mount /dev/vg0/finance /srv/finance
    mount /dev/vg0/medical /srv/medical
    mount /dev/vg0/shared  /srv/shared
    ```

    ### Findings Mitigated

    [F-1.1](../../identity/F-1.1-uid-gid-spoofing.md) (Kerberos replaces AUTH_SYS), [F-1.2](../../identity/F-1.2-root-squash-bypass.md) (`all_squash` + Kerberos), [F-1.3](../../identity/F-1.3-auxiliary-group-injection.md) (groups from KDC), [F-1.5](../../identity/F-1.5-credential-replay.md) (replay protection), [F-1.6](../../identity/F-1.6-nfsv2-downgrade.md) (v2/v3 disabled), [F-1.7](../../identity/F-1.7-rpcsec-gss-flavor-downgrade.md) (no AUTH_SYS fallback), [F-2.1](../../access-control/F-2.1-export-escape.md) (separate filesystems), [F-2.6](../../access-control/F-2.6-bind-mount-escape.md) (no bind mounts), [F-3.1](../../network/F-3.1-plaintext-wire-protocol.md) (krb5p encrypts wire), [F-4.1](../../privesc/F-4.1-no-root-squash.md) (root_squash + read-only), [F-4.2](../../privesc/F-4.2-suid-sgid-escalation.md) (read-only prevents upload), [F-5.1](../../info-disclosure/F-5.1-export-list-enumeration.md) (no mountd for v4-only)

    ### Residual Risks

    !!! warning "What this does NOT protect against"
        - A compromised Kerberos KDC grants access to all exports
        - Users with valid Kerberos tickets can still read files permitted to `nobody` (the `all_squash` target)
        - The `/srv/shared` export allows authenticated write access; a compromised principal can modify shared files
        - NFSv4 pseudo-filesystem traversal ([F-5.5](../../info-disclosure/F-5.5-nfsv4-pseudo-fs-leakage.md)) may reveal export paths
        - Server-side logging of NFS operations remains limited ([F-7.6](../../config/F-7.6-no-audit-logging.md))

=== "Practical security"

    ## Practical security

    This configuration balances security with operational reality. Kerberos is preferred, but AUTH_SYS is permitted for legacy clients. Network restrictions limit access. Suitable for internal enterprise environments where a full Kerberos migration is in progress.

    ### `/etc/exports`

    ```bash
    # Practical security NFS exports
    # Kerberos preferred, AUTH_SYS allowed for legacy clients

    /srv/engineering  192.168.10.0/24(rw,sync,no_subtree_check,root_squash,sec=krb5p:krb5i:krb5:sys)
    /srv/builds       192.168.10.0/24(ro,sync,no_subtree_check,root_squash,sec=krb5p:krb5i:krb5:sys)
    /srv/iso          192.168.0.0/16(ro,sync,no_subtree_check,all_squash,sec=sys)
    ```

    ### `/etc/nfs.conf`

    ```ini
    [nfsd]
    # Allow v3 for legacy clients, prefer v4
    vers2 = n
    vers3 = y
    vers4 = y
    vers4.1 = y
    vers4.2 = y
    threads = 16

    [mountd]
    port = 20048
    manage-gids = y

    [statd]
    port = 32765

    [lockd]
    port = 32803
    udp-port = 32803
    ```

    ### Option Explanation

    | Option | Purpose |
    |--------|---------|
    | `192.168.10.0/24` | Restricts mounting to the engineering VLAN. |
    | `rw` / `ro` | Read-write for engineering workspace; read-only for builds and ISOs. |
    | `root_squash` | Default, made explicit. UID 0 maps to `nobody`. |
    | `sec=krb5p:krb5i:krb5:sys` | Kerberos preferred, AUTH_SYS as last resort for legacy clients. |
    | `all_squash` | On the ISO export, all identities map to `nobody`. |
    | `sec=sys` | ISO export uses AUTH_SYS only; content is public read-only. |

    ### Filesystem Layout

    ```bash
    # Separate filesystems prevent export escape
    lvcreate -L 100G -n engineering vg0 && mkfs.xfs /dev/vg0/engineering
    lvcreate -L 200G -n builds     vg0 && mkfs.xfs /dev/vg0/builds
    lvcreate -L 50G  -n iso        vg0 && mkfs.ext4 /dev/vg0/iso

    mount /dev/vg0/engineering /srv/engineering
    mount /dev/vg0/builds      /srv/builds
    mount /dev/vg0/iso         /srv/iso
    ```

    ### Findings Mitigated

    [F-1.1](../../identity/F-1.1-uid-gid-spoofing.md) (partial: Kerberos clients protected, AUTH_SYS clients not), [F-2.1](../../access-control/F-2.1-export-escape.md) (separate filesystems), [F-4.1](../../privesc/F-4.1-no-root-squash.md) (`root_squash`), [F-4.2](../../privesc/F-4.2-suid-sgid-escalation.md) (builds/ISO read-only), [F-5.1](../../info-disclosure/F-5.1-export-list-enumeration.md) (mountd firewalled), [F-7.1](../../config/F-7.1-wildcard-export-policy.md) (subnet restrictions), [F-1.6](../../identity/F-1.6-nfsv2-downgrade.md) (v2 disabled)

    ### Residual Risks

    !!! warning "What this does NOT protect against"
        - AUTH_SYS clients on the `192.168.10.0/24` subnet can spoof any non-root UID ([F-1.1](../../identity/F-1.1-uid-gid-spoofing.md))
        - The engineering export is writable; a compromised host can upload SUID binaries (blocked only by `root_squash`, not by `nosuid` on the client mount)
        - IP-based restrictions can be bypassed by an attacker who compromises a host on the authorized subnet or spoofs its IP ([F-3.3](../../network/F-3.3-ip-spoofing-host-trust.md))
        - NFSv3 traffic without Kerberos is unencrypted ([F-3.1](../../network/F-3.1-plaintext-wire-protocol.md))
        - The `sec=krb5p:...:sys` ordering is a preference hint: the client chooses, and a malicious client always chooses `sys`

    ??? tip "Migration path to maximum security"
        1. Audit which clients still use AUTH_SYS: check `nfswolf scan target` output for auth flavor negotiation results
        2. Deploy Kerberos keytabs to remaining clients
        3. Remove `sys` from the `sec=` list on each export as clients are migrated
        4. Once all exports are `sec=krb5p` only, disable NFSv3 in `/etc/nfs.conf`

=== "Minimum acceptable"

    ## Minimum acceptable

    This is the absolute floor for an NFS deployment that is not trivially exploitable. It uses AUTH_SYS only (no Kerberos), but applies every other available control. It is suitable for isolated lab environments, development networks, or legacy systems where Kerberos deployment is not feasible.

    !!! danger "AUTH_SYS is fundamentally insecure"
        Without Kerberos, any host on the authorized network can impersonate any non-root user. This configuration limits the blast radius but cannot prevent identity spoofing. Treat it as a temporary posture, not a final state.

    ### `/etc/exports`

    ```bash
    # Minimum acceptable NFS exports
    # AUTH_SYS only -- every other control applied

    /srv/devdata    10.0.5.0/24(rw,sync,no_subtree_check,root_squash,sec=sys)
    /srv/packages   10.0.5.0/24(ro,sync,no_subtree_check,all_squash,sec=sys)
    /srv/backups    10.0.5.10(ro,sync,no_subtree_check,root_squash,sec=sys)
    ```

    ### `/etc/nfs.conf`

    ```ini
    [nfsd]
    # Disable v2 -- no legitimate reason to allow it
    vers2 = n
    vers3 = y
    vers4 = y
    vers4.1 = y
    vers4.2 = y
    threads = 8

    [mountd]
    port = 20048
    manage-gids = y

    [statd]
    port = 32765

    [lockd]
    port = 32803
    udp-port = 32803
    ```

    ### Option Explanation

    | Option | Purpose |
    |--------|---------|
    | `10.0.5.0/24` / `10.0.5.10` | Subnet restriction for dev; single-host restriction for backups. |
    | `rw` / `ro` | Only devdata allows writes. Packages and backups are read-only. |
    | `root_squash` | Explicit on all exports. UID 0 maps to `nobody`. |
    | `all_squash` | Packages export maps all UIDs to `nobody`. |
    | `sec=sys` | AUTH_SYS: weakest option, only choice without Kerberos. |

    ### Filesystem Layout

    The key hardening control in this profile is separate filesystems. Without Kerberos, this is the strongest remaining defense because it eliminates the export escape attack.

    ```bash
    # Each export on its own filesystem -- THIS IS NON-NEGOTIABLE
    lvcreate -L 100G -n devdata  vg0 && mkfs.ext4 /dev/vg0/devdata
    lvcreate -L 50G  -n packages vg0 && mkfs.ext4 /dev/vg0/packages
    lvcreate -L 200G -n backups  vg0 && mkfs.xfs  /dev/vg0/backups

    mount /dev/vg0/devdata  /srv/devdata
    mount /dev/vg0/packages /srv/packages
    mount /dev/vg0/backups  /srv/backups
    ```

    !!! danger "Never use bind mounts as a substitute"
        `mount --bind /data/dev /srv/devdata` does NOT create filesystem isolation. Bind mounts share the parent filesystem's fsid, so the export escape attack works through them as if the bind mount did not exist ([F-2.6](../../access-control/F-2.6-bind-mount-escape.md)).

    ### Firewall Rules

    ```bash
    # nftables: allow NFS only from authorized subnet, block portmapper externally
    nft add rule inet filter input ip saddr 10.0.5.0/24 tcp dport { 2049, 20048, 32765, 32803 } accept
    nft add rule inet filter input tcp dport 111 drop
    nft add rule inet filter input udp dport 111 drop
    ```

    ### Findings Mitigated

    [F-2.1](../../access-control/F-2.1-export-escape.md) (separate filesystems), [F-2.6](../../access-control/F-2.6-bind-mount-escape.md) (no bind mounts), [F-4.1](../../privesc/F-4.1-no-root-squash.md) (`root_squash`), [F-1.6](../../identity/F-1.6-nfsv2-downgrade.md) (v2 disabled), [F-5.4](../../info-disclosure/F-5.4-rpc-service-enumeration.md) (portmapper firewalled), [F-3.2](../../network/F-3.2-portmapper-amplification.md) (amplification blocked), [F-7.1](../../config/F-7.1-wildcard-export-policy.md) (subnet/host restrictions), [F-4.2](../../privesc/F-4.2-suid-sgid-escalation.md) (packages/backups read-only; devdata still writable)

    ### Residual Risks

    !!! danger "Accepted risks without Kerberos"
        - **UID/GID spoofing is fully possible** ([F-1.1](../../identity/F-1.1-uid-gid-spoofing.md)): any host on `10.0.5.0/24` can claim any non-root UID
        - **Auxiliary group injection** ([F-1.3](../../identity/F-1.3-auxiliary-group-injection.md)): clients can claim membership in any group
        - **Wire sniffing** ([F-3.1](../../network/F-3.1-plaintext-wire-protocol.md)): all data transmitted in cleartext
        - **IP spoofing** ([F-3.3](../../network/F-3.3-ip-spoofing-host-trust.md)): export ACLs rely on source IP, which can be spoofed on the local network
        - **SUID upload on devdata** ([F-4.2](../../privesc/F-4.2-suid-sgid-escalation.md)): writable export with `root_squash` still allows non-root SUID binaries
        - **No audit trail** ([F-7.6](../../config/F-7.6-no-audit-logging.md)): NFS operations are not logged

    ??? tip "Quick wins to improve this posture"
        1. **Add `nosuid,nodev` to client mount options**: prevents SUID/device-node attacks even on writable exports
        2. **Deploy NFS over TLS** (kernel 6.x+): encrypts the wire without Kerberos
        3. **Move packages and backups to NFSv4-only**: eliminates mountd exposure for those exports
        4. **Begin Kerberos deployment**: even one export converted to `sec=krb5p` is progress

---

## Comparison

| Control | Maximum | Practical | Minimum |
|---------|---------|-----------|---------|
| Authentication | `krb5p` only | `krb5p` preferred, `sys` fallback | `sys` only |
| Wire encryption | Yes (krb5p) | Partial | No |
| Separate filesystems | Yes | Yes | Yes |
| NFSv2/v3 | Disabled | v2 disabled, v3 enabled | v2 disabled, v3 enabled |
| UID spoofing blocked | Yes | Partial | No |
| Export escape blocked | Yes | Yes | Yes |

## Verification

After applying any configuration, validate it:

```bash
# Full security audit
nfswolf analyze target

# Verify escape is blocked
nfswolf escape target:/srv/devdata

# Check what an unauthorized host sees (from outside the authorized subnet)
nfswolf scan target

# Review effective exports on the server
exportfs -v
```
