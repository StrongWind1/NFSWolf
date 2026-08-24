# Data exfiltration

Data exfiltration is the final stage of the NFS attack chain. The attacker has completed [reconnaissance](recon.md), gained [initial access](access.md), moved [laterally](lateral.md) across the filesystem, and optionally [escalated privileges](privesc.md). Now the objective is extracting sensitive data: credentials, configuration files, database contents, private keys, and anything else of value on the server's filesystem.

NFS makes exfiltration straightforward because the protocol provides direct READ access to file contents with no intermediary. There is no shell to log commands, no audit trail for file reads, and no DLP inspection point. The attacker reads raw bytes over a TCP socket.

---

## Findings in this stage

| Finding | Name | Severity | nfswolf Subcommand | What It Enables |
|---------|------|----------|-------------------|----------------|
| [F-2.1](../access-control/F-2.1-export-escape.md) + [F-1.1](../identity/F-1.1-uid-gid-spoofing.md) | Escape + UID Spoofing | Critical | `escape`, `shell` | Escape to filesystem root, then spoof uid to read any file on the partition |
| [F-2.8](../access-control/F-2.8-sibling-export-lateral-access.md) | Sibling Export Lateral Access | Critical | `escape`, `shell` | After escape-root, LOOKUP into IP-restricted sibling exports on the same filesystem |
| [F-5.2](../info-disclosure/F-5.2-readdirplus-handle-harvesting.md) | READDIRPLUS Metadata Harvesting | High | `shell ls`, `shell find` | Single READDIRPLUS call returns handles, UIDs, GIDs, sizes, and timestamps for every file in a directory |
| [F-3.1](../network/F-3.1-plaintext-wire-protocol.md) | Plaintext Wire Protocol | High | `analyze` | All file contents traverse the network in cleartext -- passive sniffing extracts data without active exploitation |
| [F-5.6](../info-disclosure/F-5.6-metadata-on-access-denial.md) | Metadata Disclosed on Access Denial | Low | `analyze` | Even when READ is denied, post_op_attr leaks uid, gid, mode, and file size |
| [F-5.8](../info-disclosure/F-5.8-auth-none-metadata-leak.md) | AUTH_NONE Metadata Leak | Low | `analyze` | GETATTR with AUTH_NONE reveals export root attributes to any unauthenticated client |
| [F-5.9](../info-disclosure/F-5.9-read-if-exec-content-disclosure.md) | Execute-Only File Content Disclosure | Low | `analyze` | Files with mode 0111 (execute-only) are readable via NFS READ_IF_EXEC fallback |

---

## High-value targets

After escaping the export boundary, the attacker has the entire filesystem to search. These are the targets that produce the most operational value:

| Path | Contents | Required UID |
|------|----------|-------------|
| `/etc/shadow` | Password hashes (crackable offline) | root or shadow group (gid=42) |
| `/etc/passwd` | User list, home directories, shells | Any (world-readable) |
| `/home/*/.ssh/id_*` | SSH private keys | File owner |
| `/home/*/.ssh/authorized_keys` | SSH public keys (plant for persistence) | File owner (write) |
| `/root/.bash_history` | Command history (may contain passwords) | root |
| `/etc/krb5.keytab` | Kerberos keytab (service ticket forgery) | root |
| `/var/lib/mysql/` | Database files (direct read) | mysql (uid varies) |
| `/etc/exports` | NFS export configuration (plan further attacks) | Any (world-readable) |
| `/var/spool/cron/crontabs/` | Scheduled tasks (persistence vector) | root or crontab owner |
| `/etc/kubernetes/pki/` | Kubernetes CA keys (cluster compromise) | root |

---

## Exfiltration techniques

### Targeted file read

The simplest approach. The attacker knows what file they want and reads it directly:

```text
nfswolf shell target:/export
> escape-root                      # reach filesystem root
> uid 0                            # or the file owner's UID
> cat /etc/shadow                  # read the file
> get /etc/shadow /tmp/shadow      # download to local disk
```

The `--read-shadow` flag on the `escape` subcommand automates this: after escaping, it attempts to read `/etc/shadow` as proof of impact.

### Recursive download

The `get -r` shell command recursively downloads entire directory trees with progress indicators. Combined with export escape, this extracts complete directory structures:

```text
> get -r /home /tmp/exfil/home     # download all home directories
> get -r /etc /tmp/exfil/etc       # download system configuration
```

### Secrets scanning

The `secrets-scan` shell command searches directory trees for files matching patterns associated with credentials: SSH keys, PGP keys, password files, AWS credentials, Kubernetes secrets, TLS certificates, and shell history files. It walks the directory tree via READDIRPLUS and reports matches without downloading them, allowing the attacker to prioritize targets.

### Passive sniffing (F-3.1)

NFS traffic is plaintext by default. An attacker with network access between a legitimate client and the server can passively capture file contents, credentials, and handles without sending any packets. This is the only exfiltration technique that leaves zero trace on the server -- no RPC calls, no log entries, no file access timestamps.

---

## Metadata as intelligence

Even when file READ is denied, NFS leaks metadata that guides further exploitation:

- **post_op_attr on denial (F-5.6)**: When LOOKUP or READ returns `NFS3ERR_ACCES`, Linux knfsd includes the file's full attributes in the error response: uid, gid, mode, size, timestamps. This tells the attacker exactly which UID to spoof.
- **READDIRPLUS (F-5.2)**: Returns attributes and handles for every directory entry in a single call. The attacker learns file sizes (is this `/etc/shadow` or an empty file?), modification times (was this recently updated?), and ownership (which UID to impersonate).
- **AUTH_NONE attributes (F-5.8)**: Some servers allow GETATTR with AUTH_NONE credentials on valid handles, leaking export root attributes without any authentication at all.

!!! danger "No audit trail"
    Linux knfsd processes file operations in kernel space, bypassing the auditd framework ([F-7.6](../config/F-7.6-no-audit-logging.md)). No file access logs are generated for NFS READ operations regardless of audit rules. The attacker reads `/etc/shadow` and no log entry is created. Detection requires network-level monitoring (tcpdump, IDS) or filesystem-level inotify watches -- neither of which is standard on most NFS deployments.

---

## What prevents exfiltration

| Defense | Blocks file reads? | Blocks metadata? | Blocks sniffing? |
|---------|-------------------|------------------|-----------------|
| `sec=krb5p` (exclusive) | Yes | Yes | Yes |
| `sec=krb5` (exclusive) | Yes | Yes | No (integrity only, no privacy) |
| `all_squash` | 0600 files only | No | No |
| `root_squash` | uid=0 reads only | No | No |
| `ro` (read-only) | No (reads allowed) | No | No |
| Separate filesystem per export | Limits scope | Limits scope | No |

Read-only (`ro`) exports are a common miscalibration: administrators think `ro` prevents data theft, but `ro` only prevents writes. Every read operation works normally on a read-only export. The only defense that prevents all exfiltration is `sec=krb5p` deployed without AUTH_SYS fallback.

!!! tip "nfswolf workflow"
    `nfswolf escape target:/export --read-shadow` runs the full escape pipeline and attempts to read `/etc/shadow` as proof of impact. Inside the shell, `secrets-scan` finds credential files, `get -r` downloads directory trees recursively, and `get --verify <sha256>` confirms file integrity after download. The `--json` flag on escape produces machine-readable output for integration with reporting pipelines.
