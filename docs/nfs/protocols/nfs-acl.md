# NFS_ACL Protocol

**NFS_ACL is a sideband RPC program that exposes POSIX Access Control Lists over the wire. It reveals exactly which users and groups have access to a file, information that standard NFS mode bits hide behind coarse owner/group/other categories.**

NFS_ACL is not defined in any RFC. It originated as a Solaris extension (`nfsacl_prot.x`) and was adopted by Linux knfsd. The protocol rides alongside NFS as RPC program 100227, typically sharing NFS's port 2049 on Linux. Solaris deployments may register it on a separate dynamic port via portmapper. The wire format is XDR-encoded and uses the same file handles as NFS, so a valid NFSv3 file handle works for both NFS and NFS_ACL calls on the same connection.

## Why NFS_ACL exists

Standard Unix mode bits encode access as three fixed categories: owner, group, and other. Each gets read, write, and execute flags, 9 bits total. This model cannot express "user `alice` gets read-write access to a file owned by `root`" without changing ownership, widening group membership, or opening the file to everyone.

POSIX ACLs (IEEE 1003.1e draft 17, never formally ratified but universally implemented) extend this with per-user and per-group entries. A file can have an ACL granting `uid=1001` read-write and `gid=42` read-only, independent of the file's owner and group. The kernel enforces these entries alongside mode bits.

The problem: NFS has no built-in mechanism to query POSIX ACLs. GETATTR returns mode bits, not ACL entries. NFS_ACL fills this gap as a sideband protocol, letting NFS clients retrieve (and on some implementations, set) POSIX ACL data for remote files.

## Protocol details

NFS_ACL is registered as RPC program 100227. nfswolf uses version 3 of the protocol, which operates on NFSv3 file handles.

### Port discovery

On Linux knfsd, NFS_ACL shares port 2049 with NFS. The portmapper DUMP output confirms this:

```text
100227    3    TCP    2049    nfs_acl
```

On Solaris, NFS_ACL may use a separate port. In either case, portmapper GETPORT resolves program 100227 to the correct port. If portmapper is firewalled, nfswolf falls back to probing port 2049 directly.

### GETACL procedure

GETACL (procedure 1) is the primary operation. It takes a file handle and a bitmask indicating which ACL types to retrieve, and returns the POSIX ACL entries for that file or directory.

**Request arguments:**

| Field | Type | Description |
|-------|------|-------------|
| `fh` | `nfs_fh3` | NFSv3 file handle for the target file or directory |
| `mask` | `uint32` | Bitmask: `NFS_ACL` (0x0001) for access ACL, `NFS_DFACL` (0x0004) for default ACL |

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `status` | `nfsstat3` | 0 on success, standard NFS error codes on failure |
| `post_op_attr` | `post_op_attr` | Optional `fattr3` attributes (same as NFS GETATTR) |
| `access_acl` | `secattr` | Access ACL entries that control who can access this file |
| `default_acl` | `secattr` | Default ACL entries, inherited by new files created in this directory |

nfswolf requests both ACL types in a single call by setting `mask = NFS_ACL | NFS_DFACL` (0x0005).

## ACL entry types

Each ACL entry is a 12-byte triple: `(type, id, permissions)`. The type determines what the `id` field means.

| Wire value | Type name | `id` field | What it controls |
|------------|-----------|------------|------------------|
| `0x01` | `USER_OBJ` | Ignored (file owner) | Permissions for the file's owning UID. Equivalent to the "user" bits in `mode`. |
| `0x02` | `USER` | UID | Permissions for a specific named user. **Not visible in mode bits.** |
| `0x04` | `GROUP_OBJ` | Ignored (file group) | Permissions for the file's owning GID. Equivalent to the "group" bits in `mode` when no MASK entry exists. |
| `0x08` | `GROUP` | GID | Permissions for a specific named group. **Not visible in mode bits.** |
| `0x10` | `MASK` | Ignored | Upper bound on effective permissions for USER, GROUP_OBJ, and GROUP entries. The kernel ANDs each entry's permissions with the MASK to compute effective access. |
| `0x20` | `OTHER` | Ignored | Permissions for everyone not covered by another entry. Equivalent to the "other" bits in `mode`. |

Default ACL entries use the same types but are flagged with `NFS_ACL_DEFAULT` (0x1000) OR'd into the wire type value. Default ACLs exist only on directories and are inherited by files and subdirectories created within.

!!! danger "Named entries leak identity information"
    The `USER` and `GROUP` entry types are the security-relevant ones. Each carries a numeric UID or GID that has been explicitly granted access. These identities are invisible to standard NFS operations. `GETATTR` returns only the file's owner UID and group GID, and `READDIRPLUS` returns only file attributes. NFS_ACL GETACL is the only way to discover them remotely.

### Permission bits

Each ACL entry carries a 3-bit permission field, identical to Unix mode bits:

| Bit | Meaning |
|-----|---------|
| `4` (r) | Read |
| `2` (w) | Write |
| `1` (x) | Execute / search (directories) |

Effective permissions for USER, GROUP_OBJ, and GROUP entries are the intersection of the entry's permission bits and the MASK entry. USER_OBJ and OTHER are not masked.

## Access ACL vs default ACL

**Access ACL**: Controls who can access the file or directory right now. Every file with POSIX ACLs has an access ACL. The minimum access ACL contains USER_OBJ, GROUP_OBJ, and OTHER (equivalent to standard mode bits).

**Default ACL**: Exists only on directories. When a new file or subdirectory is created inside the directory, the default ACL is copied as the new entry's access ACL (modified by the creating process's umask for files, inherited directly for subdirectories). Default ACLs reveal the administrator's intended permission model for future files.

!!! tip "Default ACLs reveal security policy"
    A default ACL on `/srv/nfs/data` with `USER uid=1001 rwx` means every file created in that directory will grant `uid=1001` full access. This tells an attacker who has access now, who will have access to future content, and the exact UID to spoof.

## Security implications

### F-5.14: POSIX ACL entries expose access beyond mode bits

NFS_ACL GETACL reveals named USER and GROUP ACL entries that are invisible to standard NFS attribute queries. A file with `mode 0750` and an ACL granting `uid=1001 rw-` appears to allow access only for the owner and the owning group, but `uid=1001` also has read-write access through the ACL.

This has direct implications for credential escalation:

- **Named USER entries** disclose UIDs that have access to the file. Combined with UID spoofing ([F-1.1](../../security/identity/F-1.1-uid-gid-spoofing.md)), an attacker knows exactly which UID to claim in AUTH_SYS credentials.
- **Named GROUP entries** disclose GIDs with access paths not visible in the file's owning group. These feed auxiliary group injection ([F-1.3](../../security/identity/F-1.3-auxiliary-group-injection.md)).
- **Default ACL entries** on directories reveal the permission model for future files, letting an attacker pre-position with the right credentials before sensitive files are created.

!!! warning "No authentication required"
    NFS_ACL uses AUTH_SYS credentials, which the server trusts without verification. An attacker with network access to port 2049 and a valid file handle can call GETACL with `uid=0` (or any UID) and retrieve ACLs for any file on the export. Combined with READDIRPLUS handle harvesting ([F-5.2](../../security/info-disclosure/F-5.2-readdirplus-handle-harvesting.md)), this enables bulk ACL enumeration across an entire export.

### ACL data feeds the credential ladder

nfswolf's credential ladder (`src/engine/credential.rs`) uses ACL-discovered UIDs and GIDs alongside READDIRPLUS-harvested file ownership to build a ranked list of credentials for escalation. ACL entries are especially valuable because they expose access paths that file ownership analysis alone misses. A file owned by `root:root` with mode `0700` and an ACL entry for `uid=1001` is invisible to ownership-based scanning.

## nfswolf implementation

The NFS_ACL client lives in `src/proto/nfs_acl.rs`. It provides a single function:

```rust
pub(crate) async fn getacl3(
    addr: SocketAddr,
    fh_bytes: &[u8],
    proxy: Option<&str>,
    stealth: &StealthConfig,
) -> anyhow::Result<Getacl3Result>
```

The function opens a direct TCP connection to the NFS_ACL port, sends a GETACL3 request with `mask = NFS_ACL | NFS_DFACL`, and manually decodes the XDR response. It uses the shared sideband connection helper (`src/proto/sideband.rs`) for SOCKS5 proxy support and stealth pacing.

The analyzer (`src/engine/analyzer.rs`) calls `check_nfs_acl()` on every export root. If GETACL returns named USER or GROUP entries (in either the access ACL or the default ACL), a finding is emitted with the specific UIDs and GIDs discovered.

!!! info "Related findings"
    - [F-5.14: POSIX ACL Entries Expose Access Beyond Mode Bits](../../security/info-disclosure/index.md#f-514-posix-acl-entries-expose-access-beyond-mode-bits): the primary finding for NFS_ACL enumeration
    - [F-1.1: UID/GID Spoofing](../../security/identity/F-1.1-uid-gid-spoofing.md): ACL-discovered UIDs are direct spoofing targets
    - [F-1.3: Auxiliary Group Injection](../../security/identity/F-1.3-auxiliary-group-injection.md): ACL-discovered GIDs are injection targets
    - [F-5.2: READDIRPLUS Handle Harvesting](../../security/info-disclosure/F-5.2-readdirplus-handle-harvesting.md): provides the file handles needed for GETACL calls
