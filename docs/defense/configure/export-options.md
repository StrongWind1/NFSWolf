# Export options reference

Every option available in `/etc/exports` on Linux, with defaults, security implications, and cross-references to nfswolf findings where the option is exploitable or mitigating.

## Quick-reference table

| Option | Default | Security | Notes |
|--------|---------|----------|-------|
| `ro` | **Yes** | :material-shield-check: Safe | Read-only access |
| `rw` | No | :material-alert: Warning | Enables write access |
| `sync` | **Yes** | :material-shield-check: Safe | Data integrity on crash |
| `async` | No | :material-alert: Warning | Data loss on crash |
| `wdelay` | **Yes** | :material-shield-check: Safe | Write coalescing optimization |
| `no_wdelay` | No | :material-shield-check: Safe | Disables write coalescing |
| `hide` | **Yes** (v3) | :material-shield-check: Safe | Hides sub-mounts |
| `nohide` | No | :material-alert: Warning | Exposes sub-mounts ([F-7.3](../../findings/config/F-7.3-nohide-crossmnt-exposure.md)) |
| `crossmnt` | No | :material-alert-octagon: Dangerous | Exposes ALL sub-mounts recursively ([F-7.3](../../findings/config/F-7.3-nohide-crossmnt-exposure.md)) |
| `no_subtree_check` | **Yes** | :material-alert-octagon: Dangerous | Enables export escape ([F-2.1](../../findings/access-control/F-2.1-export-escape.md)) |
| `subtree_check` | No | :material-shield-check: Safe | Prevents export escape (with caveats) |
| `root_squash` | **Yes** | :material-shield-check: Safe | Maps UID 0 to nobody |
| `no_root_squash` | No | :material-alert-octagon: Dangerous | Full root trust ([F-4.1](../../findings/privesc/F-4.1-no-root-squash.md)) |
| `all_squash` | No | :material-shield-check: Safe | Maps all UIDs to nobody |
| `no_all_squash` | **Yes** | :material-alert: Warning | Trusts client UIDs ([F-1.1](../../findings/identity/F-1.1-uid-gid-spoofing.md)) |
| `anonuid` / `anongid` | 65534 | :material-alert: Warning | Must be unprivileged ([F-7.5](../../findings/config/F-7.5-squash-misconfiguration.md)) |
| `sec=sys` | **Yes** | :material-alert-octagon: Dangerous | No real authentication ([F-1.1](../../findings/identity/F-1.1-uid-gid-spoofing.md)) |
| `sec=krb5p` | No | :material-shield-check: Safe | Kerberos with encryption |
| `insecure` | No | :material-alert: Warning | Allows unprivileged ports ([F-7.2](../../findings/config/F-7.2-privileged-port-bypass.md)) |
| `insecure_locks` | No | :material-alert: Warning | Unauthenticated locking |
| `no_acl` | No | :material-alert: Warning | Disables POSIX ACLs |
| `fsid=0` | -- | :material-alert: Warning | NFSv4 pseudo-root ([F-5.5](../../findings/info-disclosure/F-5.5-nfsv4-pseudo-fs-leakage.md)) |
| `mountpoint` | -- | :material-shield-check: Safe | Conditional export |
| `pnfs` | No | :material-alert: Warning | pNFS layout exposure ([F-5.10](../../findings/info-disclosure/F-5.10-pnfs-layout-security-downgrade.md)) |
| `security_label` | No | :material-shield-check: Safe | SELinux labels over NFS |

---

## General options

### `ro` / `rw`

**Values:** `ro` (read-only) or `rw` (read-write). **Default:** `ro`.

Controls whether clients can modify files on the export. The server enforces this in the kernel's VFS layer. A WRITE request on a `ro` export returns `NFS3ERR_ROFS` ("read-only file system") regardless of file permissions.

!!! tip "Always prefer `ro`"
    Use `rw` only when clients genuinely need write access. A read-only export eliminates entire attack classes: SUID binary planting ([F-4.2](../../findings/privesc/F-4.2-suid-sgid-escalation.md)), device node creation ([F-4.3](../../findings/privesc/F-4.3-device-node-creation.md)), and symlink attacks ([F-4.4](../../findings/privesc/F-4.4-symlink-escape.md)) all require write access.

```bash title="/etc/exports"
# Good: read-only unless writes are truly needed
/srv/packages    10.1.0.0/24(ro,sync,no_subtree_check)
/srv/uploads     10.1.0.0/24(rw,sync,no_subtree_check,root_squash)
```

!!! warning "Common mistake: missing parentheses"
    `/data 10.1.0.0/24 (rw)` (with a space before the parenthesis) exports `/data` read-only to 10.1.0.0/24 and read-write to **everyone else**. The options in parentheses apply to an implicit `*` host. Always write `/data 10.1.0.0/24(rw)` with no space.

### `sync` / `async`

**Values:** `sync` or `async`. **Default:** `sync`.

Controls whether the server commits data to stable storage before replying to the client.

- **`sync`**: The server writes data to disk before sending the RPC reply. The client knows that an acknowledged write is durable.
- **`async`**: The server may reply before data reaches disk. Faster, but a server crash can silently lose acknowledged writes, corrupting client state.

!!! warning "Data integrity risk"
    `async` violates the NFS protocol contract: the client believes its write is committed, but the data may exist only in the server's page cache. A power failure or kernel panic loses that data with no client-side indication. Use `sync` unless you accept this risk for throwaway data (build caches, scratch space).

nfswolf detects `async` exports during analysis and flags them as a data-integrity concern.

### `wdelay` / `no_wdelay`

**Values:** `wdelay` or `no_wdelay`. **Default:** `wdelay`. Only meaningful with `sync`.

When `wdelay` is active, the server batches multiple small synchronous writes into a single disk commit to improve throughput. `no_wdelay` forces each write to commit individually.

No direct security implications. `no_wdelay` reduces write latency at the cost of throughput. Most deployments should leave the default.

### `hide` / `nohide`

**Values:** `hide` or `nohide`. **Default:** `hide` for NFSv3 (but see `crossmnt` below).

Controls whether a child filesystem mounted inside an export is visible to NFS clients.

With `hide` (default on v3), a LOOKUP that crosses a mount point boundary returns `NFS3ERR_NOENT`, and the sub-mounted filesystem is invisible. `nohide` makes it visible, effectively merging two filesystems from the client's perspective.

!!! warning "Sub-mount exposure ([F-7.3](../../findings/config/F-7.3-nohide-crossmnt-exposure.md))"
    `nohide` exposes filesystems that may contain more sensitive data than the parent export. If `/srv/data` is exported and `/srv/data/secrets` is a separate filesystem mounted inside it, `nohide` on `/srv/data/secrets` lets clients reach it through the parent without a separate MOUNT call or export ACL check.

### `crossmnt`

**Values:** Present or absent. **Default:** absent (except on the NFSv4 pseudo-root, where it is implicit).

Like `nohide`, but recursive: ALL filesystems mounted anywhere under the export become visible to NFS clients.

!!! danger "Recursive sub-mount exposure ([F-7.3](../../findings/config/F-7.3-nohide-crossmnt-exposure.md))"
    `crossmnt` on a high-level directory (e.g., `/`) exposes every mounted filesystem on the server. Bind mounts, tmpfs instances, procfs, sysfs: anything under the export tree becomes accessible. This is the most common way administrators accidentally expose the entire server filesystem.

    nfswolf detects `crossmnt` during analysis and reports every reachable sub-mount.

```bash title="/etc/exports — dangerous"
# crossmnt on / exposes proc, sys, dev, and every mounted filesystem
/    *(ro,crossmnt,no_subtree_check)
```

### `subtree_check` / `no_subtree_check`

**Values:** `subtree_check` or `no_subtree_check`. **Default:** `no_subtree_check` (since Linux 2.6.25, kernel commit `e6f3e7e`).

Controls whether the server verifies that a file handle refers to a file inside the exported directory subtree, or only checks that it belongs to the correct filesystem (identified by its fsid).

!!! danger "Export escape ([F-2.1](../../findings/access-control/F-2.1-export-escape.md))"
    With `no_subtree_check`, the server validates [file handles](../../nfs/file-handles.md) against the filesystem boundary, not the export boundary. Any file on the same filesystem is reachable regardless of what directory was exported. This is the single most impactful default in `/etc/exports`; nfswolf's `escape` subcommand directly exploits it.

??? note "Why `subtree_check` is not the default"
    `subtree_check` has real problems:

    - **Rename race**: If a file is renamed out of the exported subtree while a client holds its handle, the handle becomes stale, even if the file still exists. This breaks `rsync`, mail delivery (Maildir), and anything that renames files across directories.
    - **Performance**: Every NFS operation requires an extra directory walk from the filesystem root to the file, verifying each component is inside the export tree.
    - **Hardlink ambiguity**: A file with multiple hardlinks inside and outside the export tree may or may not pass the check depending on which link the kernel resolves first.

    The kernel developers chose correctness (no false stales) over security (no export escape). The better mitigation is to export entire filesystems on dedicated partitions, making `subtree_check` unnecessary.

### `insecure_locks` / `no_auth_nlm`

**Values:** `insecure_locks` (or its alias `no_auth_nlm`). **Default:** locks require authentication.

Tells the NLM to accept lock requests without authentication credentials. Some older NFS clients send lock requests without proper AUTH_SYS credentials.

!!! warning
    Disabling lock authentication allows any host to acquire or release locks on the export, enabling denial-of-service through lock contention.

### `no_acl`

**Values:** Present or absent. **Default:** ACLs enabled.

Disables POSIX ACL support for the export. When set, the server ignores filesystem ACLs and falls back to traditional Unix mode bits only.

!!! warning
    If the underlying filesystem uses POSIX ACLs for fine-grained access control, `no_acl` silently drops those restrictions. Files protected by ACL entries beyond the basic owner/group/other become accessible based on mode bits alone.

### `mountpoint` / `mp`

**Values:** `mountpoint` or `mp` (optionally `mp=/path`). **Default:** absent.

Only exports the directory if it is a mount point (or if the specified path is a mount point). Prevents exporting an empty directory when the intended filesystem is not mounted.

No direct security implications, but prevents accidental exposure of a parent directory's contents when a mount fails.

### `fsid`

**Values:** `fsid=num` (integer), `fsid=root` or `fsid=0` (NFSv4 pseudo-root), `fsid=UUID`. **Default:** derived from the filesystem's device number.

Sets the fsid embedded in NFS file handles. This value is how the server maps handles back to filesystems.

!!! warning "NFSv4 pseudo-root (`fsid=0`)"
    `fsid=0` (or `fsid=root`) designates the [NFSv4 pseudo-filesystem root](../../protocols/nfsv4/pseudo-fs.md). Clients can enumerate the pseudo-FS structure to discover all exports ([F-5.5](../../findings/info-disclosure/F-5.5-nfsv4-pseudo-fs-leakage.md)), even when mountd is firewalled. Every NFSv4 server should have exactly one `fsid=0` export, typically `/` or `/export`.

```bash title="/etc/exports"
# NFSv4 pseudo-root
/export          *(fsid=0,ro,no_subtree_check)
/export/data     10.1.0.0/24(rw,sync)
```

### `refer`

**Values:** `refer=host:/path` or `refer=host:/path@host2:/path2`. **Default:** absent.

NFSv4 referral: the server returns an `NFS4ERR_MOVED` status for this export, directing the client to the specified remote server. Used for transparent namespace federation across multiple NFS servers.

No direct security implications beyond expanding the trust boundary to include the referred server.

### `replicas`

**Values:** `replicas=host:/path` (one or more). **Default:** absent.

Specifies NFSv4 replica locations for read-only failover. Clients supporting transparent state migration (NFSv4.1+) can fail over to a replica when the primary is unavailable.

No direct security implications, but replica servers must enforce the same access controls as the primary.

### `pnfs`

**Values:** Present or absent. **Default:** absent.

Enables pNFS layouts for this export. pNFS allows clients to perform I/O directly to storage devices (block, object, or file layout), bypassing the NFS server for data transfer.

!!! warning "Layout security downgrade ([F-5.10](../../findings/info-disclosure/F-5.10-pnfs-layout-security-downgrade.md))"
    pNFS layouts expose storage-layer topology (block device addresses, object store endpoints, or data server hostnames) to clients. The data path between client and storage device may bypass NFS authentication entirely, depending on the layout type. Block and object layouts are particularly exposed: the client receives raw storage addresses.

### `security_label`

**Values:** Present or absent. **Default:** absent.

Enables SELinux label transport over NFSv4.2. When set, the server includes SELinux security contexts in file attributes, and clients can set them. Requires both server and client to run SELinux in enforcing mode.

!!! tip
    Enable `security_label` when both endpoints use SELinux. Without it, NFS-served files receive a default context (`nfs_t`) on the client, which may be too permissive or too restrictive depending on policy.

---

## Identity mapping options

### `root_squash` / `no_root_squash`

**Values:** `root_squash` or `no_root_squash`. **Default:** `root_squash`.

Controls whether UID 0 (root) from the client is mapped to the anonymous user (typically `nobody`, UID 65534) on the server.

!!! danger "Critical: `no_root_squash` ([F-4.1](../../findings/privesc/F-4.1-no-root-squash.md), [F-7.5](../../findings/config/F-7.5-squash-misconfiguration.md))"
    `no_root_squash` trusts the client's root user as root on the server. An attacker with root on any allowed client (or anyone spoofing UID 0 with AUTH_SYS) gets full root access to every file on the export. Combined with `rw`, they can plant SUID root binaries, create device nodes, or overwrite `/etc/shadow`.

    This is the single most dangerous export option. nfswolf's scanner checks for it first and reports it as Critical severity. The `escape` subcommand exploits it to demonstrate full filesystem access.

```bash title="/etc/exports — good vs. bad"
# Bad: full root trust
/data   10.1.0.0/24(rw,no_root_squash)

# Good: root mapped to nobody
/data   10.1.0.0/24(rw,root_squash)
```

!!! note "`root_squash` does not protect non-root files"
    `root_squash` only remaps UID 0. Any other UID sent by the client is trusted as-is. An attacker can still access files owned by UID 1000 by sending UID 1000 in AUTH_SYS credentials ([F-1.1](../../findings/identity/F-1.1-uid-gid-spoofing.md)). Only `all_squash` or `sec=krb5` defend against arbitrary UID spoofing.

### `all_squash` / `no_all_squash`

**Values:** `all_squash` or `no_all_squash`. **Default:** `no_all_squash`.

Controls whether ALL client UIDs (not just root) are mapped to the anonymous user.

!!! tip "Strongest identity defense under AUTH_SYS"
    `all_squash` neutralizes UID spoofing entirely: every client request runs as a single identity regardless of what UID the client claims. Combined with `anonuid`/`anongid` set to an unprivileged user, this is the strongest protection available without Kerberos.

    The trade-off is that all clients share one identity, making per-user file ownership meaningless on the export.

```bash title="/etc/exports"
# Every client becomes uid=65534, gid=65534 regardless of claimed identity
/srv/public   *(ro,all_squash)

# All clients map to a dedicated service account
/srv/uploads  10.1.0.0/24(rw,all_squash,anonuid=2000,anongid=2000)
```

### `anonuid` / `anongid`

**Values:** `anonuid=N`, `anongid=N` (integer UID/GID). **Default:** 65534 (typically `nobody`/`nfsnobody`).

Sets the UID and GID that squashed users are mapped to.

!!! danger "Never set `anonuid=0` ([F-7.5](../../findings/config/F-7.5-squash-misconfiguration.md))"
    Setting `anonuid=0` with `all_squash` maps every client to root, the opposite of the intended protection. Similarly, setting `anonuid` to any UID that owns sensitive files (e.g., the UID of `www-data`, `mysql`, or `postgres`) grants those service accounts' file access to all clients.

    The anonymous UID should be an unprivileged UID that owns no files on the server. The default of 65534 is safe on most systems.

```bash title="/etc/exports — dangerous"
# all_squash + anonuid=0 = everyone is root
/data  *(rw,all_squash,anonuid=0,anongid=0)
```

### `squash_uids` / `squash_gids` (legacy)

**Values:** `squash_uids=N-M` or `squash_gids=N-M`. **Default:** absent.

Maps specific UID or GID ranges to the anonymous user. This is a legacy option from older Linux NFS implementations and is not widely used. Prefer `root_squash` or `all_squash` for new configurations.

---

## Security flavor options

### `sec`

**Values:** `sec=flavor[:flavor:...]`. Flavors: `none`, `sys`, `krb5`, `krb5i`, `krb5p`. **Default:** `sec=sys`.

Specifies which authentication flavors the export accepts. Multiple flavors are listed in preference order, separated by colons. The client negotiates the strongest mutually supported flavor.

| Flavor | Authentication | Integrity | Encryption | Security |
|--------|---------------|-----------|------------|----------|
| `none` | None | No | No | :material-alert-octagon: None |
| `sys` | UID/GID (client-asserted) | No | No | :material-alert-octagon: None |
| `krb5` | Kerberos | No | No | :material-alert: Partial |
| `krb5i` | Kerberos | Yes | No | :material-shield-check: Good |
| `krb5p` | Kerberos | Yes | Yes | :material-shield-check: Best |

!!! danger "`sec=sys` provides no authentication ([F-1.1](../../findings/identity/F-1.1-uid-gid-spoofing.md))"
    AUTH_SYS is configured via `sec=sys` and [provides zero cryptographic authentication](../../nfs/authentication.md). Any client can claim any identity, enabling UID spoofing ([F-1.1](../../findings/identity/F-1.1-uid-gid-spoofing.md)), group injection ([F-1.3](../../findings/identity/F-1.3-auxiliary-group-injection.md)), and root squash bypass ([F-1.2](../../findings/identity/F-1.2-root-squash-bypass.md)).

!!! warning "Mixed flavors enable downgrade ([F-1.7](../../findings/identity/F-1.7-rpcsec-gss-flavor-downgrade.md))"
    `sec=krb5p:sys` accepts both Kerberos and AUTH_SYS. An attacker simply uses AUTH_SYS and ignores Kerberos. The server accepts both; there is no enforcement that the client uses the strongest available flavor. If you require Kerberos, do not include `sys` in the flavor list.

!!! tip "Recommended configuration"
    Use `sec=krb5p` for sensitive data. This provides Kerberos authentication (real identity verification), integrity protection (tampering detection), and encryption (confidentiality). See the [Kerberos hardening guide](../hardening/kerberos.md) for deployment details.

```bash title="/etc/exports"
# Bad: attacker picks sys, ignores krb5p
/data   10.1.0.0/24(rw,sec=krb5p:sys)

# Good: Kerberos required, no fallback
/data   10.1.0.0/24(rw,sec=krb5p)

# Acceptable for truly public read-only data
/pub    *(ro,all_squash,sec=sys)
```

### `insecure`

**Values:** `insecure` or `secure` (default). **Default:** `secure` (implicit; there is no explicit `secure` keyword, and omitting `insecure` means secure).

Controls whether the server requires clients to connect from a privileged source port (< 1024).

!!! warning "Weak protection ([F-7.2](../../findings/config/F-7.2-privileged-port-bypass.md))"
    The privileged-port check is [trivially bypassed](../../findings/config/F-7.2-privileged-port-bypass.md) on modern systems, but keep the default (`secure`) as a minor speed bump. Use `insecure` only when clients legitimately connect from high ports (some NAS appliances, WebNFS clients, macOS in certain configurations).

---

## NFSv4-specific options

### `xprtsec`

**Values:** `xprtsec=none`, `xprtsec=tls`, `xprtsec=mtls`. **Default:** all transport modes accepted (kernel `NFSEXP_XPRTSEC_ALL` enables none, tls, and mtls simultaneously).

Controls RPC-with-TLS (RFC 9289) transport security requirements. Available on Linux kernel 6.x+ with TLS-capable nfsd.

!!! danger "Permissive default ([F-7.7](../../findings/config/F-7.7-xprtsec-permissive-default.md))"
    Adding `xprtsec=tls` does NOT disable plaintext. The kernel default `ex_xprtsec_modes` is `NFSEXP_XPRTSEC_ALL`, which sets the NONE, TLS, and MTLS bits simultaneously. To actually require TLS, you must ensure the `none` bit is cleared. Some kernel versions require specifying `xprtsec=tls` alone without the `none` mode. An attacker simply connects without TLS and all operations succeed. Verify enforcement with nfswolf's scanner, which probes both TLS and plaintext paths.

### NFSv4 pseudo-filesystem interaction

NFSv4 clients access exports through a [pseudo-filesystem](../../protocols/nfsv4/pseudo-fs.md) rooted at `fsid=0`; all exports should live under a common root (e.g., `/export`), with `fsid=0` on the root:

```bash title="/etc/exports — NFSv4 layout"
/export          *(fsid=0,ro,no_subtree_check,sec=krb5p)
/export/home     10.1.0.0/24(rw,sec=krb5p)
/export/data     10.1.0.0/24(rw,sec=krb5p)
```

---

## Recommended baseline

A minimal secure export configuration for environments that have not yet deployed Kerberos:

```bash title="/etc/exports — hardened baseline (AUTH_SYS)"
# Dedicated filesystem per export (eliminates subtree_check concern)
# Read-only where possible, root always squashed, tight subnet
/srv/packages    10.1.5.0/24(ro,sync,root_squash,no_subtree_check)
/srv/uploads     10.1.5.0/24(rw,sync,root_squash,no_subtree_check)
```

The target state with Kerberos:

```bash title="/etc/exports — hardened baseline (Kerberos)"
/export          gss/krb5p(fsid=0,ro,no_subtree_check)
/export/home     gss/krb5p(rw,sec=krb5p,no_subtree_check)
/export/data     gss/krb5p(rw,sec=krb5p,no_subtree_check)
```

!!! tip "Verify with nfswolf"
    After editing `/etc/exports` and running `exportfs -ra`, scan your server with nfswolf to verify the configuration:

    ```bash
    nfswolf scan <server-ip>
    nfswolf analyze <server-ip>
    ```

    The analyzer checks for every dangerous default and misconfiguration described on this page.

## See also

- [Exports file syntax](exports-syntax.md) -- Host specifiers, whitespace rules, and `exportfs` commands
- [Kernel parameters](kernel-params.md) -- `nfsd` module and sysctl tuning
- [Firewall configuration](firewall.md) -- Port and protocol filtering
- [Hardening checklist](../hardening/checklist.md) -- Step-by-step server lockdown
- [Kerberos deployment](../hardening/kerberos.md) -- Replacing AUTH_SYS with real authentication
- [What does not work](../what-does-not-work.md) -- Common "hardening" measures that provide no real protection
