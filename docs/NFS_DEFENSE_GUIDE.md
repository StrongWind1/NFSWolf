# NFS Defense Guide

A practical reference for defending NFS exports against the attacks nfswolf demonstrates. Every claim in this document was verified live against 6 servers running kernels 2.6.32 through 6.12, across NFSv2, v3, and v4.

---

## How NFS Authentication Works (and Why It Doesn't)

NFS uses AUTH_SYS by default. The client sends its UID and GID in every RPC call, and the server trusts them without verification.

```
  Client                           Server
  ┌──────────┐                     ┌──────────┐
  │ uid=0    │ ── AUTH_SYS ──────> │ "ok, you │
  │ gid=0    │    I am root!       │  are root"│
  │ hostname │                     │          │
  └──────────┘                     └──────────┘
       ↑                                ↑
   Attacker picks                  Server trusts
   any UID/GID                     blindly (RFC 5531 §14)
```

There is no password, no ticket, no signature. The server applies POSIX permission checks using whatever UID the client claims. This is the fundamental weakness that enables every attack in this guide.

---

## The Three Attacks

### 1. Export Escape (Handle Construction)

NFS file handles are bearer tokens. If you can guess the byte pattern for a file outside the exported directory, the server hands it over.

```
  Server filesystem:
  /                          ← inode 2 (ext4 root)
  ├── etc/
  │   ├── shadow             ← the prize
  │   └── hostname
  ├── srv/
  │   └── nfs/
  │       └── public/        ← exported via NFS
  │           └── readme.txt
  └── home/

  Attack: construct a handle pointing at inode 2 (the real root)
  instead of the export's inode. The server accepts it.
```

**Works on**: every default NFS export (v2, v3, v4). Tested on kernels 2.6.32 through 6.12. `root_squash` and `all_squash` do not prevent it.

### 2. Cross-Export Lateral Access

When multiple exports share the same filesystem, escaping from ANY one of them gives access to ALL of them -- regardless of per-export security settings.

```
  Same filesystem (ext4 on /dev/sda1):
  ├── /srv/nfs/public   *(rw, no_root_squash)   ← escape from here
  ├── /srv/nfs/private  *(ro, root_squash)       ← read this anyway
  └── /srv/nfs/secret   *(rw, all_squash)        ← and this too

  The escape handle targets inode 2 (FS root). From there,
  navigate to ANY directory on the filesystem -- the server
  checks the escape handle against the FIRST export's policy
  (no_root_squash), not the target export's policy.
```

**Tested**: escaped from `nosquash` export, read `secret.txt` from `rootsquash`, `allsquash`, and `subtree_check` exports. Confirmed on all 6 lab servers.

### 3. UID/GID Spoofing

The attacker claims any UID in the AUTH_SYS credential. The server applies that UID to POSIX permission checks.

```
  /etc/shadow  (mode 0640, owner root:shadow)

  Attacker: uid=0   → DENIED by root_squash (mapped to nobody)
  Attacker: uid=42  → GRANTED (group "shadow" = gid 42 on Debian)
  Attacker: uid=1000 → reads any file owned by uid 1000
```

**Works on**: every AUTH_SYS export. `root_squash` only blocks uid=0. `all_squash` blocks all spoofing for restricted files but not world-readable ones.

---

## Defense Matrix

Tested live on 6 servers (kernels 2.6.32, 3.13, 4.4, 4.15, 6.8, 6.12), every NFS version the server supports.

```
                     ┌─────────┬─────────────┬───────────┬───────────┐
                     │ Export  │Cross-export │ UID/GID   │           │
  Defense            │ escape  │ lateral     │ spoofing  │ Writes    │
  ═══════════════════╪═════════╪═════════════╪═══════════╪═══════════╡
  sec=krb5           │ BLOCKS  │ BLOCKS      │ BLOCKS    │ BLOCKS    │
  (without sec=sys)  │ (v3/v4) │             │           │           │
  ───────────────────┼─────────┼─────────────┼───────────┼───────────┤
  subtree_check      │ BLOCKS  │   no*       │   no      │   no      │
  ───────────────────┼─────────┼─────────────┼───────────┼───────────┤
  Separate FS per    │ BLOCKS  │ BLOCKS      │   no      │   no      │
  export             │         │             │           │           │
  ───────────────────┼─────────┼─────────────┼───────────┼───────────┤
  all_squash         │   no    │   no        │ PARTIAL   │ BLOCKS    │
  (anonuid=65534)    │         │             │ (0600 ok, │           │
                     │         │             │ 0644 leak)│           │
  ───────────────────┼─────────┼─────────────┼───────────┼───────────┤
  root_squash        │   no    │   no        │ uid=0     │ uid=0     │
                     │         │             │ only      │ only      │
  ───────────────────┼─────────┼─────────────┼───────────┼───────────┤
  readonly (ro)      │   no    │   no        │   no      │ BLOCKS    │
  ───────────────────┼─────────┼─────────────┼───────────┼───────────┤
  secure port        │   no    │   no        │   no      │   no      │
  (no insecure flag) │         │             │           │           │
  ───────────────────┴─────────┴─────────────┴───────────┴───────────┘

  * subtree_check on export B is defeated by escaping from export A
    on the same filesystem (the handle is evaluated against A's policy)
```

---

## Defense Details

### subtree_check

The only export option that blocks handle escape.

**How it works**: on every NFS operation, the kernel walks from the file's inode up through parent directories to verify the file lives inside the exported subtree. A constructed handle targeting inode 2 (filesystem root) fails this walk because inode 2 is not a child of the export directory.

**The catch**: disabled by default since kernel 2.6.x. Causes `ESTALE` errors when files are renamed while open (the parent walk fails after the rename). This is why `no_subtree_check` is the default and the recommendation in `exports(5)`.

```
  /etc/exports:
  /srv/nfs/data  *(rw,sync,subtree_check)

  What happens:
  1. Client sends escape handle (inode 2, gen=0)
  2. Server resolves inode 2 to /
  3. Server walks: / → is / a child of /srv/nfs/data? NO
  4. Server returns NFS3ERR_STALE
```

**Confirmed**: blocks escape on all 6 lab servers, all NFS versions. Does NOT block UID spoofing within the export.

### root_squash

Maps uid=0 to nobody (65534). Does NOT affect any other UID.

```
  /etc/exports:
  /srv/nfs/data  *(rw,sync,root_squash)

  uid=0  → mapped to 65534 (nobody) → DENIED reading 0600 root files
  uid=42 → passes through unchanged  → GRANTED if file is gid=42
  uid=1000 → passes through unchanged → GRANTED if file is uid=1000
```

**The weakness**: an attacker who knows the file owner's UID simply claims that UID. `root_squash` only protects against the attacker claiming to be root -- it does nothing against targeted UID spoofing.

**Confirmed**: on all 6 servers, `uid=1000` reads `0600` files owned by `uid=1000` even with `root_squash` enabled.

### all_squash

Maps ALL UIDs to a single anonymous identity (default: nobody/65534).

```
  /etc/exports:
  /srv/nfs/data  *(rw,sync,all_squash,anonuid=65534,anongid=65534)

  uid=0    → 65534 → DENIED reading 0600 root files
  uid=1000 → 65534 → DENIED reading 0600 uid=1000 files
  uid=65534 → 65534 → CAN READ 0644 files (world-readable)
```

**The strength**: blocks all targeted UID spoofing for files with restrictive permissions (0600, 0640).

**The weakness**: world-readable files (0644, 0755) are still accessible because the squashed identity has "other" read permission. Also, `all_squash` does NOT prevent handle escape -- the attacker still reaches the filesystem root, they just can't read protected files there.

**Danger**: `all_squash,anonuid=0` maps everyone to root. This is worse than `no_root_squash`.

### sec=krb5 (Kerberos)

The only defense that blocks ALL attacks.

```
  /etc/exports:
  /srv/nfs/data  *(rw,sync,sec=krb5)    ← AUTH_SYS rejected

  Without sec=sys in the list, the server rejects ALL AUTH_SYS
  operations with NFS3ERR_WRONGSEC / NFS4ERR_WRONGSEC.
```

**What it blocks**:
- UID/GID spoofing (AUTH_SYS not accepted)
- Handle escape probing (GETATTR on escape handle returns WRONGSEC)
- Cross-export lateral access (all operations blocked)
- Writes (all operations blocked)

**What it does NOT block**:
- MOUNT v3 still leaks the export handle before the krb5 check kicks in (the MOUNT protocol itself uses AUTH_SYS). The handle is useless without krb5 credentials, but its structure reveals the filesystem type and fsid.
- NFSv2 downgrade: if the server still accepts v2, an attacker can bypass krb5 entirely because NFSv2 has no security negotiation mechanism. Always disable v2 alongside krb5.

**Caveat**: listing `sec=krb5:sys` (both flavors) allows the attacker to choose AUTH_SYS and bypass krb5 entirely. The `sec=` list must contain ONLY krb5/krb5i/krb5p.

### Separate Filesystem Per Export

Not an export option -- an architectural decision. When each export is on its own filesystem (separate partition, LVM volume, or loop device), escape handles from one export cannot reach files on another export because the fsid differs.

```
  /dev/sda1 → /srv/nfs/public   (ext4, fsid=0x0001)
  /dev/sda2 → /srv/nfs/private  (ext4, fsid=0x0002)

  Escape from /public targets inode 2 on fsid 0x0001.
  That handle reaches the root of /dev/sda1 -- which IS /srv/nfs/public.
  It cannot reach /dev/sda2 because the fsid doesn't match.
```

**The catch**: the attacker still reaches the root of the export's filesystem. If the export is a subdirectory of a larger filesystem, escape reaches the filesystem root (which may contain other data outside the export). The defense only works when the export IS the entire filesystem.

### Secure Port (no insecure flag)

Requires the client to use a source port below 1024, which typically requires root on the client.

**Why it doesn't help**: any attacker running nfswolf already has root on their attack machine (or CAP_NET_BIND_SERVICE). nfswolf binds privileged ports by default.

### readonly (ro)

Prevents all write operations (CREATE, WRITE, MKDIR, REMOVE, etc.).

**What it blocks**: SUID binary creation, device node creation, symlink attacks, data modification.

**What it doesn't block**: all read-based attacks (escape, UID spoofing, file reads, metadata leaks).

---

## UID/GID Spoofing In Depth

### What Each Defense Blocks

Tested with 4 UIDs against 3 file types across all 6 servers:

```
  File permissions tested:
    secret.txt     0600 root:root    (only root can read)
    user_file.txt  0600 1000:1000   (only uid 1000 can read)
    testfile.txt   0644 root:root    (world-readable)

  ┌────────────────┬───────────────┬───────────────┬───────────────┐
  │                │ no_root_squash│ root_squash   │ all_squash    │
  ├────────────────┼───────────────┼───────────────┼───────────────┤
  │ uid=0          │ reads ALL     │ DENIED (→65534│ DENIED (→65534│
  │ (root spoof)   │               │ on 0600 root) │ on 0600 root) │
  ├────────────────┼───────────────┼───────────────┼───────────────┤
  │ uid=1000       │ reads ALL     │ reads 0600    │ DENIED (→65534│
  │ (owner spoof)  │               │ user file     │ on 0600 user) │
  ├────────────────┼───────────────┼───────────────┼───────────────┤
  │ uid=65534      │ reads 0644    │ reads 0644    │ reads 0644    │
  │ (nobody)       │               │               │ (IS nobody)   │
  ├────────────────┼───────────────┼───────────────┼───────────────┤
  │ mid-session    │ works         │ works         │ no effect     │
  │ uid change     │               │ (0→1000 reads)│ (still 65534) │
  └────────────────┴───────────────┴───────────────┴───────────────┘
```

### Mid-Session UID Change

nfswolf can change UID/GID mid-session without reconnecting (v3/v4) or with a quick reconnect (v2). This means an attacker can:

1. Connect as uid=1000
2. Read files owned by uid=1000
3. Switch to uid=42 (shadow group on Debian)
4. Read `/etc/shadow` via group permission
5. Switch to uid=0 (if `no_root_squash`)
6. Write SUID binaries

`root_squash` only blocks step 5. Steps 1-4 work regardless.

### NFS Version Differences

UID spoofing works identically on v2, v3, and v4 when using AUTH_SYS. The protocol version makes no difference to the credential trust model.

The only version-specific defense is `sec=krb5`, which is available on v3 and v4 but not v2. NFSv2 has no security negotiation mechanism at all.

```
  NFSv2: no sec= option, AUTH_SYS always accepted
         → disable v2 entirely if using krb5

  NFSv3: sec=krb5 enforced at NFS operation level
         → MOUNT still leaks handle via AUTH_SYS

  NFSv4: sec=krb5 enforced, no MOUNT protocol
         → cleanest krb5 enforcement, no handle leak
```

---

## Recommended Configurations

### Maximum Security (Kerberos available)

```
/srv/nfs/data  *(rw,sync,sec=krb5p,no_subtree_check)
```

Plus: disable NFSv2 (`echo "-2" > /proc/fs/nfsd/versions`), use separate filesystem per export, enforce `xprtsec=tls` (kernel 6.5+).

This blocks every attack nfswolf can perform.

### Practical Security (no Kerberos)

```
/srv/nfs/data  *(ro,sync,all_squash,anonuid=65534,anongid=65534,subtree_check)
```

This blocks: handle escape (`subtree_check`), UID spoofing for 0600 files (`all_squash`), writes (`ro`). Does NOT block: reading world-readable files, metadata enumeration.

### Minimum Viable Hardening

```
/srv/nfs/data  *(rw,sync,root_squash,no_subtree_check)
```

This is the kernel default. It only blocks uid=0. An attacker with nfswolf can still escape the export, read files as any non-root UID, and navigate to other exports on the same filesystem.

---

## What Does NOT Work

| "Defense" | Why it fails |
|-----------|-------------|
| `root_squash` alone | Only blocks uid=0. Attacker claims uid=1000 instead. |
| `secure` (privileged port) | nfswolf binds port <1024 by default. Any root attacker can. |
| IP-based ACLs (`10.0.0.0/24`) | Attacker on the allowed subnet bypasses this. UDP is spoofable. |
| `sec=krb5:sys` (both listed) | Attacker chooses AUTH_SYS and bypasses krb5 entirely. |
| `all_squash,anonuid=0` | Maps everyone to root. Worse than no_root_squash. |
| `xprtsec=tls` (default config) | Default allows plaintext alongside TLS. Must explicitly exclude `none`. |
| Client-side `nosuid,nodev` | Server has no control over client mount options. Attacker omits them. |

---

## Quick Reference: What Blocks What

```
  Need to block escape?       → subtree_check or separate FS
  Need to block UID spoofing? → sec=krb5 (only option)
  Need to block cross-export? → separate FS per export
  Need to block writes?       → ro
  Need to block everything?   → sec=krb5p + subtree_check + separate FS
```
