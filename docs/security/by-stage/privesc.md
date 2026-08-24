# Privilege escalation

Privilege escalation over NFS converts file-level access into control over the server's operating system. The attacker already has filesystem access from [initial access](access.md) and potentially full filesystem scope from [lateral movement](lateral.md). This stage uses writable NFS exports to plant artifacts that execute with elevated privileges when triggered on the server or by legitimate clients.

The core enabler is `no_root_squash`: when the server does not remap `uid=0`, the attacker operates as root over NFS and can create SUID binaries, device nodes, and crontab entries. Even with `root_squash` active, non-root privilege escalation is possible through file ownership spoofing and supplemental group injection.

---

## Findings in this stage

| Finding | Name | Severity | nfswolf Subcommand | What It Enables |
|---------|------|----------|-------------------|----------------|
| [F-1.2](../identity/F-1.2-root-squash-bypass.md) | Root Squash Bypass via Non-Root UID | High | `shell uid`, `analyze` | Any non-zero UID is trusted; claim the file owner's UID to get full access |
| [F-4.1](../privesc/F-4.1-no-root-squash.md) | no_root_squash Exploitation | Critical | `analyze`, `shell uid 0` | uid=0 credentials accepted without remapping -- full root access over NFS |
| [F-4.2](../privesc/F-4.2-suid-sgid-escalation.md) | SUID/SGID Binary Creation | High | `shell suid-scan` | Create setuid-root binaries over NFS; execute on the client or via cron on the server |
| [F-4.3](../privesc/F-4.3-device-node-creation.md) | Device Node Creation via MKNOD | High | `shell` | Create character/block device nodes with arbitrary major/minor numbers |
| [F-4.4](../privesc/F-4.4-symlink-escape.md) | Crontab/Symlink Injection | High | `shell symlink` | Plant symlinks or crontab entries that execute attacker-controlled code |
| [F-1.5](../identity/F-1.5-credential-replay.md) | Credential Replay from Wire | High | -- | Captured AUTH_SYS credentials are replayable indefinitely (no nonce, timestamp, or sequence number) |
| [F-4.6](../privesc/F-4.6-unrestricted-chown.md) | Unrestricted chown | High | `analyze` | When PATHCONF `chown_restricted=false`, any user can chown files to root |
| [F-4.5](../privesc/F-4.5-selinux-label-bypass.md) | SELinux/MAC Label Bypass | Medium | -- | NFS root receives `CAP_MAC_OVERRIDE`, bypassing SELinux/AppArmor entirely |

---

## Escalation paths

### Path 1: SUID binary (requires no_root_squash + writable)

The most direct escalation. The attacker creates a file as `uid=0`, writes a compiled binary (a shell wrapper or static ELF), sets mode `04755` (setuid-root), and waits for execution. If the NFS export is mounted on a client without `nosuid`, any user on that client executes the binary as root.

```text
1. nfswolf shell target:/export
2. uid 0                          # claim root (no_root_squash required)
3. put /tmp/escalate escalate     # upload binary
4. chmod 04755 escalate           # set SUID bit via NFS SETATTR
```

The `suid-scan` shell command searches the entire accessible filesystem for existing SUID/SGID binaries, reporting their paths, owners, and permissions. Pre-existing SUID binaries are often more useful than planting new ones -- they are already trusted by the system's security policy.

### Path 2: device node (requires no_root_squash + writable)

MKNOD (RFC 1813 Section 3.3.11) creates character and block device nodes with arbitrary major/minor numbers. A block device node for `/dev/sda` (major 8, minor 0) provides raw disk access from a client that mounts the export without `nodev`. A character device node for `/dev/mem` provides direct memory access.

### Path 3: crontab injection (requires writable access to /var/spool/cron or /etc/cron.d)

After escaping the export boundary ([lateral movement](lateral.md)), the attacker writes directly to `/var/spool/cron/crontabs/root` or drops a file into `/etc/cron.d/`. The cron daemon executes the contents as the crontab owner. This does not require `no_root_squash` if the attacker can write as the crontab owner's UID (F-1.2).

### Path 4: ownership hijack (requires chown_restricted=false)

When PATHCONF reports `chown_restricted=false` (F-4.6), any user can change file ownership via NFS SETATTR. The attacker writes a binary as any UID, then chowns it to root and sets the SUID bit. This bypasses `root_squash` because the chown operation itself does not require `uid=0`.

---

## The credential ladder

nfswolf's credential ladder (`engine::credential::credential_ladder()`) automates privilege escalation at the authentication layer. When a file operation fails with `NFS3ERR_ACCES` or `NFS3ERR_PERM`, the ladder tries UIDs in order of likelihood:

1. **File owner UID** -- extracted from the file's attributes. The owner always has access (RFC 1813 Section 4.4).
2. **Caller UID with the file's GID** -- matches group permission bits.
3. **Root (uid=0)** -- works when `no_root_squash` is active.
4. **Observed identities** -- UIDs/GIDs harvested from READDIRPLUS directory listings, ranked by frequency.
5. **Common service accounts** -- well-known UIDs (www-data, nobody, mysql, postgres) tried only when mode bits show no "other" access.

The ladder runs automatically in the shell, FUSE mount, and escape subcommands. It never brute-forces; blind UID spraying is the `uid-spray` subcommand, kept separate from the evidence-driven ladder.

!!! warning "CAP_MAC_OVERRIDE via NFS root"
    When `no_root_squash` is active, NFS root receives `CAP_NFSD_SET` (kernel `fs/nfsd/auth.c:80`), which includes `CAP_FS_MASK | CAP_SYS_RESOURCE`. `CAP_FS_MASK` includes `CAP_MAC_OVERRIDE`, meaning NFS root bypasses all mandatory access controls -- SELinux, AppArmor, SMACK. A file labeled `system_u:object_r:shadow_t:s0` is fully readable over NFS. NFS root is strictly more powerful than local root in the quota dimension (`CAP_SYS_RESOURCE`).

---

## What prevents escalation

| Defense | Blocks SUID? | Blocks device nodes? | Blocks crontab? | Blocks UID spoofing? |
|---------|-------------|---------------------|-----------------|---------------------|
| `root_squash` (default) | uid=0 only | uid=0 only | No (non-root UIDs) | No |
| `all_squash` | Yes | Yes | Yes (if nobody lacks write) | Partial |
| `nosuid` on client mount | Yes | No | No | No |
| `nodev` on client mount | No | Yes | No | No |
| `ro` (read-only export) | Yes | Yes | Yes | No |
| `sec=krb5` (exclusive) | Yes | Yes | Yes | Yes |

Only `sec=krb5` (without `sys` fallback) prevents all escalation paths. Every other defense is partial.

!!! tip "nfswolf workflow"
    `nfswolf analyze target:/export` probes for `no_root_squash` (squash probe), PATHCONF `chown_restricted`, and FSINFO link/symlink support. Inside the shell, `suid-scan` finds existing SUID/SGID binaries, `world-writable` finds directories where files can be planted, and the credential ladder escalates automatically on access denial.
