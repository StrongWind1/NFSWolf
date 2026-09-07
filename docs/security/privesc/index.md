# Privilege escalation (F-4.x)

Post-access privilege escalation findings. Once an attacker has write access to an NFS export (via identity spoofing, export escape, or misconfiguration), these findings cover the paths from "file access" to "root shell on the server."

The common thread: NFS faithfully stores whatever the client sends (SUID bits, device nodes, ownership changes) because the protocol has no concept of "this client shouldn't be allowed to do that." The server trusts the client's AUTH_SYS credentials and applies standard UNIX permission checks against them, but those checks are meaningless when the credentials are forged.

## Summary

| Finding | Title | Severity | RFC Basis | Detected by | Write-up |
|---------|-------|----------|-----------|-------------|----------|
| F-4.1 | no_root_squash Exploitation | :material-alert-circle:{ .critical } Critical | RFC 1813 sec 4.4, RFC 2623 sec 2.5 | `analyze`, `shell uid 0` | [Detail](F-4.1-no-root-squash.md) |
| F-4.2 | SUID/SGID Binary Creation | :material-alert:{ .high } High | RFC 1094 sec 2.3.5 | `shell suid-scan`, `mount` | [Detail](F-4.2-suid-sgid-escalation.md) |
| F-4.3 | Device Node Creation via MKNOD | :material-alert:{ .high } High | RFC 1813 sec 3.3.11 | `shell mknod` | [Detail](F-4.3-device-node-creation.md) |
| F-4.4 | Symlink Escape | :material-alert:{ .high } High | RFC 1813 sec 3.3.5, sec 3.3.10 | `analyze`, `shell symlink` | [Detail](F-4.4-symlink-escape.md) |
| F-4.5 | SELinux/MAC Label Bypass | :material-information:{ .medium } Medium | RFC 7861 sec 4 | Not implemented | [Detail](F-4.5-selinux-label-bypass.md) |
| F-4.6 | Unrestricted chown | :material-alert:{ .high } High | RFC 1094 sec 3.3, RFC 1813 sec 4.4 | `analyze` (PATHCONF) | [Detail](F-4.6-unrestricted-chown.md) |

## Findings

### F-4.1: no_root_squash Exploitation

!!! danger "Critical -- direct root access"
    When `no_root_squash` is set on an export, UID 0 credentials are accepted without remapping. An attacker with network access to the export operates as full root on the server's filesystem.

Root squash is the NFS server's only defense against forged root credentials. It maps UID 0 to `nobody` (65534) so that clients claiming to be root are demoted. When an administrator disables this with `no_root_squash`, every file on the export becomes readable and writable by any client that sends `uid=0` in its AUTH_SYS credentials.

The kernel grants NFS root `CAP_NFSD_SET`, which includes `CAP_FS_MASK` and `CAP_SYS_RESOURCE`. `CAP_FS_MASK` contains `CAP_MAC_OVERRIDE`, meaning NFS root bypasses all mandatory access controls (SELinux, AppArmor, SMACK). NFS root is strictly more powerful than local root in the quota dimension because `CAP_SYS_RESOURCE` allows bypassing disk quotas.

**RFC basis**: "This superuser permission may not be allowed on the server, since anyone who can become superuser on their client could gain access to all remote files." (RFC 1813 sec 4.4)

**Detection**: `nfswolf analyze` performs a squash probe -- writes a test file as UID 0 and checks whether the resulting ownership is root or nobody.

---

### F-4.2: SUID/SGID Binary Creation

!!! warning "High -- local privilege escalation"
    An attacker with write access and `no_root_squash` can create setuid-root binaries on the NFS export. When a legitimate user on the server executes one, they gain a root shell.

The NFS CREATE and SETATTR operations accept a `sattr` structure that includes UNIX mode bits. Bit `04000` (set-user-ID on execution) is defined in RFC 1094 sec 2.3.5 and is faithfully stored by the server. With F-4.1 providing root write access, an attacker uploads a compiled binary with mode `04755`. Any user who runs it gets root.

The server-side defense is the `nosuid` mount option on the client, but this is a client-side control that the NFS server cannot enforce or verify. See F-7.4.

**Detection**: `nfswolf shell suid-scan` recursively searches for existing SUID/SGID binaries on the export.

---

### F-4.3: Device Node Creation via MKNOD

!!! warning "High -- raw disk access"
    MKNOD creates character and block device nodes with arbitrary major/minor numbers. An attacker can create `/dev/sda` on the export and read raw disk contents from a client that mounts without `nodev`.

RFC 1813 sec 3.3.11 defines MKNOD: "Creates a special file of the type, specdata..." with `NF3CHR` and `NF3BLK` types. The server stores the device node; a client that mounts the export without the `nodev` option can open it and interact with the underlying device driver.

This is primarily a client-side risk -- the device node references devices on the machine that opens it, not on the NFS server. An attacker plants the device node on the export, then waits for a victim to mount it.

**Detection**: `nfswolf shell mknod` can create device nodes (requires `--allow-write`).

---

### F-4.4: Symlink Escape

!!! warning "High -- application-level escape"
    An attacker creates a symlink on a writable export that points outside the export boundary. Applications on the server that follow symlinks are tricked into reading or writing files outside the intended scope.

RFC 1813 sec 3.3.5 states the symlink target data is "not necessarily interpreted by the server, just stored in the file." The server does not validate symlink targets against export boundaries. This is distinct from the file handle escape (F-2.1). Symlink escape works at the application layer, not the NFS protocol layer.

The attack requires an application on the server (or a client that follows server-stored symlinks) to dereference the symlink. Crontab injection (see below) is a specific instance of this pattern.

**Detection**: `nfswolf analyze` checks for writable parent directories. `nfswolf shell symlink` creates symlinks (requires `--allow-write`).

---

### F-4.5: SELinux/MAC Label Bypass via NFS

!!! note "Medium -- MAC bypass"
    NFS-created files receive default SELinux contexts rather than the labels intended by security policy. Mandatory access controls are effectively bypassed for NFS-mounted filesystems.

RFC 7861 sec 4 acknowledges the limitation: "RPCSEC_GSSv3 is not a complete solution for labeling: it conveys the labels of actors but not the labels of objects." Without labeled NFS (extremely rare in practice), every file created over NFS gets a default context regardless of the directory's security policy.

On `no_root_squash` exports, NFS root receives `CAP_MAC_OVERRIDE` via the `CAP_NFSD_SET` capability set (`fs/nfsd/auth.c:80`), which bypasses SELinux and AppArmor enforcement entirely. Even files with restrictive labels like `shadow_t` are fully accessible over NFS.

!!! info "Not implemented in nfswolf"
    No SELinux/MAC check exists in `nfswolf analyze`. This finding is documented for awareness -- testing it requires a target with enforcing SELinux and labeled NFS, which is rare enough that automated detection would produce mostly noise.

---

### F-4.6: Unrestricted chown (Any User Can Change File Ownership)

!!! warning "High -- ownership hijacking"
    When `_POSIX_CHOWN_RESTRICTED` is not enforced, any user can change file ownership via SETATTR. An attacker writes a file, then chowns it to root and sets the SUID bit, achieving instant privilege escalation without needing `no_root_squash`.

PATHCONF (RFC 1813 sec 3.3.20) exposes the `chown_restricted` flag per filesystem. When `false`, the POSIX restriction that only root can change file ownership is not enforced. Most modern Linux systems restrict chown to root, but some NFS server implementations, older UNIX systems, or specific filesystem configurations do not.

The attack chain: create a file with a shell payload, `chown 0:0`, `chmod 04755`, then execute it. No `no_root_squash` needed because the chown itself runs as an unprivileged user.

**Detection**: `nfswolf analyze` calls PATHCONF on each export root and flags `chown_restricted=false`.

## Attack chains

These findings combine with other categories to form complete exploitation paths:

1. **F-1.1 + F-4.1 + F-4.2**: Forge UID 0 credentials (identity attack) on a `no_root_squash` export, upload a SUID binary, execute it from a legitimate session for persistent root.
2. **F-2.1 + F-4.1**: Escape the export boundary to reach `/etc/crontab`, inject a cron job that runs as root.
3. **F-4.6 + F-4.2**: On a filesystem without `chown_restricted`, any user creates a SUID-root binary without needing root credentials at all.
4. **F-7.5 + F-4.1**: `all_squash` with `anonuid=0` gives every client root access, enabling all privilege escalation paths.

## Mitigation

| Defense | Findings mitigated | Notes |
|---------|--------------------|-------|
| `root_squash` (default) | F-4.1, F-4.2 | Maps UID 0 to nobody; does not stop non-root escalation (F-1.2) |
| Client-side `nosuid,nodev` | F-4.2, F-4.3 | Server cannot enforce this -- it is a client mount option |
| `sec=krb5` | F-4.1, F-4.2, F-4.3, F-4.4 | Prevents credential forging, making write access harder to obtain |
| SELinux with labeled NFS | F-4.5 | Requires `security_label` export option and RPCSEC_GSSv3 -- extremely rare |
| `chown_restricted` sysctl | F-4.6 | Default on modern Linux; verify with PATHCONF |
