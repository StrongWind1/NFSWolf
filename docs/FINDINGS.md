# Security Findings Catalog

All findings that nfswolf detects, grouped by attack category. Each finding traces to a specific RFC section explaining WHY the vulnerability exists at the protocol level.

---

## Category 1: Identity Attacks (AUTH_SYS Trust Model)

The NFS security model trusts client-supplied credentials without verification.

> "There is no verifier, so credentials can easily be faked."
> -- RFC 1057 §9.3

### F-1.1: UID/GID Spoofing

| Field | Value |
|-------|-------|
| Severity | Critical |
| RFC Basis | RFC 5531 §14, RFC 1057 §9.2, RFC 1813 §4.4 |
| Precondition | Server accepts AUTH_SYS (default) |
| Detection | Attempt ACCESS/READ with forged credentials |

**Why the RFC allows this**: AUTH_SYS credentials use AUTH_NONE as verifier (RFC 5531 Appendix A). The RPC layer treats credentials as opaque pass-through (RFC 5531 §8.2). The server "gets the client's effective uid, effective gid, and groups on each call and uses them to check access" (RFC 1813 §4.4) with no verification step.

**What nfswolf tests**: UID spray (0-65535), targeted UID based on file ownership, auxiliary GID combinations (up to 16 per RFC 1057 §9.2).

### F-1.2: Root Squash Bypass via Non-Root UID

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1813 §4.4, RFC 2623 §2.5 |
| Precondition | root_squash enabled (default) |
| Detection | Create test file as arbitrary non-root UID |

**Why the RFC allows this**: Root squash ONLY maps uid 0 to nobody. "A UNIX server by default maps uid 0 to a distinguished value (UID_NOBODY)" (RFC 1813 §4.4). Any non-zero UID is trusted. An attacker claiming uid=owner of a file gets full access because "the server's permission checking algorithm should allow the owner of a file to access it regardless of the permission setting" (RFC 1813 §4.4).

**What nfswolf tests**: Squash probe (write as uid 0, write as uid 99999, compare resulting ownership).

### F-1.3: Auxiliary Group Injection

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1057 §9.2 |
| Precondition | Files protected by group permissions |
| Detection | ACCESS with target file's GID in aux groups |

**Why the RFC allows this**: The `gids<16>` array in AUTH_SYS is client-asserted. A client can include any GID values (e.g., the `shadow` group GID 42) without verification. The server uses these to check group access bits.

**What nfswolf tests**: Test file readability with shadow GIDs (42, 15), then spray GIDs 0-65535.

### F-1.4: Machine Name Spoofing / Log Poisoning

| Field | Value |
|-------|-------|
| Severity | Low |
| RFC Basis | RFC 1057 §9.2, RFC 9289 §A.1 |
| Precondition | Server logs client machine name |
| Detection | Set machinename to arbitrary value |

**Why the RFC allows this**: The `machinename<255>` field is "an unprotected domain name" (RFC 9289 §A.1). It is never verified against DNS or any other source. Attackers can set it to any string (including log injection payloads, impersonation of other hosts, or null bytes).

**What the spoof actually does on Linux knfsd**: the `machinename` field is *logged*, not *authorised against*. Export ACLs on Linux knfsd match on the source IP (resolved to a hostname via reverse DNS), not on the value of `auth_unix.machinename`. Setting `--hostname victim.example.com` therefore does **not** bypass a host-based export ACL on its own; it poisons log entries and gives false attribution. See F-3.3 for the related but distinct IP-based trust issue.

### F-1.5: Credential Replay from Wire

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1094 §3.4, RFC 5531 §9 |
| Precondition | Network access to observe NFS traffic |
| Detection | N/A (passive attack) |

**Why the RFC allows this**: AUTH_SYS has no nonce, timestamp, or sequence number. The 32-bit XID is "only used for clients matching reply messages with call messages" (RFC 5531 §9), not for replay prevention. Any captured RPC message can be replayed indefinitely.

### F-1.6: NFSv2 Downgrade (Auth Bypass)

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 2623 §2.7 |
| Precondition | Server supports NFSv2 alongside v3/v4 |
| Detection | rpcinfo shows program 100003 version 2 |

**Why the RFC allows this**: "NFS Version 2 had no support for security flavor negotiation. It was up to the client to guess, or depend on prior knowledge." (RFC 2623 §2.7). A client explicitly requesting v2 bypasses any v3+ sec=krb5 requirements because the v2 code path has no mechanism to enforce them.

### F-1.7: RPCSEC_GSS Flavor Downgrade (Mixed-Flavor Export)

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 2203 §5.2.1, RFC 7530 §19, RFC 2623 §5 |
| Precondition | Server exports with both AUTH_SYS and krb5 flavors |
| Detection | MOUNT auth-flavor list or NFSv4 SECINFO returns both AUTH_SYS and krb5 |

**Why the RFC allows this**: When an export advertises multiple security flavors (e.g., `sec=krb5:sys`), a client may freely choose AUTH_SYS even though krb5 is available. The server does not enforce the strongest available flavor. An attacker who cannot obtain Kerberos credentials simply selects AUTH_SYS and proceeds with forged credentials (F-1.1).

**What nfswolf tests**: `analyze` checks the auth-flavor list returned by MOUNT EXPORT and flags exports that accept AUTH_SYS alongside any RPCSEC_GSS flavor.

### F-1.8: AUTH_TOOWEAK Oracle (Kerberos Enforcement Detection)

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 5531 §7.4, RFC 2623 §2.3.2 |
| Precondition | Export requires sec=krb5 (or krb5i/krb5p) |
| Detection | Send GETATTR with AUTH_SYS after MOUNT succeeds; observe AUTH_TOOWEAK error |

**Why the RFC allows this**: When no configured security flavor matches the request, the server returns `nfserr_wrongsec` (wire: `AUTH_TOOWEAK`, RFC 5531 §7.4). This is a definitive oracle: it tells the attacker the export exists but requires stronger authentication. Combined with the RFC 2623 §2.3.2 GSS bypass for root directory operations, MOUNT still succeeds with AUTH_SYS and leaks the root handle — only subsequent operations fail with AUTH_TOOWEAK.

**What nfswolf tests**: NFSv4 SECINFO scanner and MOUNT auth-flavor list analysis detect whether AUTH_TOOWEAK is returned. The scanner's v4 SECINFO probing enumerates all per-directory security flavors. The MOUNT MNT auth_flavors list reveals which flavors the export accepts.

---

## Category 2: Access Control Bypass (File Handle Exploitation)

File handles are bearer tokens -- possession is authorization.

> "An attacker can circumvent the MOUNT server's access control by either stealing a file handle or guessing a file handle."
> -- RFC 2623 §2.6

### F-2.1: Export Escape via Filesystem Root Handle

| Field | Value |
|-------|-------|
| Severity | Critical |
| RFC Basis | RFC 1813 §3.3.3, RFC 1094 §2.3.3 |
| Precondition | Export is a subdirectory, subtree_check disabled |
| Detection | Construct handle for inode 2 (root), issue READDIRPLUS |

**Why the RFC allows this**: File handles are opaque to the client but contain filesystem-specific data (typically: fsid + inode + generation). The RFC says "The file handle can contain whatever information the server needs" (RFC 1094 §2.3.3) but does NOT require the server to confine access to the exported subtree. "A server will not allow a LOOKUP operation to cross a mountpoint" (RFC 1813 §3.3.3) but says nothing about constructed handles pointing outside the export within the SAME filesystem.

**What nfswolf tests**: Fingerprint handle structure (ext4/xfs/btrfs), construct root inode handle, confirm escape via READDIRPLUS child count comparison.

### F-2.2: File Handle Guessing / Brute Force

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1094 §2.3.3, RFC 1813 §2.6, RFC 2623 §2.6 |
| Precondition | Predictable handle structure (sequential inodes) |
| Detection | Entropy analysis of observed handles |

**Why the RFC allows this**: Neither RFC 1094 nor RFC 1813 requires handles to be cryptographically random or unpredictable. The oracle problem (NFS3ERR_BADHANDLE vs NFS3ERR_STALE) confirms when the attacker has guessed the correct format (RFC 1813 §2.6).

**What nfswolf tests**: Handle entropy analysis, inode-based candidate generation, filesystem fingerprinting for known handle layouts.

### F-2.3: Windows File Handle Signing Disabled

| Field | Value |
|-------|-------|
| Severity | Critical |
| RFC Basis | Implementation-specific (no RFC coverage) |
| Precondition | Windows NFS server with signing disabled |
| Detection | Examine last 10 bytes (v3) or 16 bytes (v4.1) of handle for null/constant |

**Why this exists**: Windows NFS server adds HMAC to file handles as a non-standard extension. When signing is disabled (default in some configs), the HMAC field is zeroed, making handles trivially constructible.

### F-2.4: BTRFS Subvolume Handle Construction

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1094 §2.3.3 (handles are server-specific) |
| Precondition | BTRFS filesystem, export on subvolume |
| Detection | fileid_type 0x4d-0x4f in handle structure |

**Why this exists**: BTRFS uses fileid_type encodings that include subvolume IDs. By constructing handles with different subvol IDs (256+), an attacker can access other subvolumes on the same filesystem -- escaping the intended export boundary.

### F-2.5: Stale Handle After Permission Revocation

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 1094 §1.3, RFC 1094 Appendix A |
| Precondition | Client previously had legitimate access |
| Detection | Use handle after export ACL change |

**Why the RFC allows this**: The stateless design means "The mount list information is not critical for the correct functioning of either the client or the server. It is intended for advisory use only." (RFC 1094 Appendix A). UMNT removes the list entry but does NOT invalidate the file handle.

### F-2.6: Bind Mount Export Escape

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1094 §2.3.3 (handles are filesystem-scoped) |
| Precondition | Bind mount used as NFS export, subtree_check disabled |
| Detection | Construct filesystem root handle from bind mount's fsid |

**Why this exists**: Bind mounts are an alternative view of the same underlying filesystem -- they share the same filesystem ID. When `subtree_check` is disabled, the NFS server only validates that a handle's fsid matches the export's filesystem. A handle for any inode on that filesystem is accepted, regardless of the bind mount boundary.

### F-2.7: NFS Daemon Export ACL Blindness (Bearer Token Property)

| Field | Value |
|-------|-------|
| Severity | Critical |
| RFC Basis | RFC 2623 §2.6, RFC 1094 §2.3.3 |
| Precondition | Possession of a valid file handle (obtained by any means) |
| Detection | Use handle from export A against port 2049 from an IP not authorized for that export |

**Why this is the root cause**: The NFS daemon (port 2049) never calls back to mountd to verify that the requesting client was authorized to receive the handle it presents. The kernel checks `(client_auth_domain, fsid)` in the export cache -- if any wildcard export exists on the same filesystem, the handle resolves. MOUNT is the only gate, and it issues permanent bearer tokens with no binding, no MAC, no expiry, and no revocation.

**What nfswolf tests**: The `shell --handle <hex>` path demonstrates this directly -- connects to port 2049 without MOUNT, and the handle works from any IP.

### F-2.8: Sibling Export Lateral Access (Cross-Export Handle Reuse)

| Field | Value |
|-------|-------|
| Severity | Critical |
| RFC Basis | RFC 1813 §3.3.3, RFC 2623 §2.6 |
| Precondition | Access to any export on the same filesystem; no_subtree_check (default) |
| Detection | Mount wildcard export, escape-root, cd to restricted export directory |

**Why this works**: When two exports share a physical filesystem (same fsid) and `subtree_check` is disabled, the kernel does not verify that a handle's inode is within the export's directory tree. After escaping to the filesystem root (F-2.1), standard LOOKUP operations reach any directory on the filesystem -- including IP-restricted peer exports. No handle construction is needed for the lateral movement step.

**What nfswolf tests**: `escape-root` + `cd /path/to/restricted` + `ls`/`cat` demonstrates the full chain.

### F-2.9: WebNFS Public File Handle (MOUNT Bypass)

| Field | Value |
|-------|-------|
| Severity | Critical |
| RFC Basis | RFC 2054 §5, RFC 2055 §5, RFC 2224 §9, RFC 2623 §2.6 |
| Precondition | Server has WebNFS enabled (Solaris `public` share, NetApp `nfs.webnfs.enable`) |
| Detection | Issue NFS LOOKUP with the all-zeros public file handle (RFC 2055 §5) |

**Why the RFC allows this**: WebNFS defines a well-known "public" file handle (all zeros) that any client can use to access the server's public export without going through MOUNT. This bypasses the MOUNT protocol's host-based ACLs entirely. If WebNFS is enabled, the zero handle grants immediate access to the public export from any IP.

**What nfswolf tests**: `analyze` probes for the WebNFS public handle on each target and flags the finding when the server responds to the zero-handle LOOKUP.

### F-2.10: SIGN_FH Root Handle Exemption (FILEID_ROOT MAC Bypass)

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | Implementation-specific (SIGN_FH is a Linux-only extension) |
| Precondition | Export has `sign_fh` enabled with a valid `fh_key` |
| Detection | Construct a root handle (fileid_type=0x00) and send GETATTR |

**Why this exists**: Linux knfsd's handle signing (NFSEXP_SIGN_FH) appends a SipHash-2-4 MAC to non-root file handles. However, root handles (FILEID_ROOT, type 0) are explicitly exempt: `nfsd_set_fh_dentry()` at line 294-296 of `fs/nfsd/nfsfh.c` says "We don't sign or verify the root, no per-file identity" and returns the export root dentry directly, skipping all MAC verification.

**Attack**: An attacker who knows the export's fsid (discoverable via GETATTR or MOUNT) can construct `{version=1, auth_type=0, fsid_type=N, fileid_type=0, fsid=known_value}` — no MAC needed. Combined with `shell --handle` (F-2.7), this bypasses MOUNT host ACLs even when `sign_fh` is deployed. From the root, standard LOOKUP operations return legitimately signed child handles, enabling full directory traversal.

**What nfswolf tests**: `shell --handle <constructed_root_hex>` demonstrates the bypass. `sign_fh` still blocks handle construction for non-root inodes (F-2.1, F-2.2).

---

### F-2.11: NFSv4 LOOKUPP Export Escape

| Field | Value |
|-------|-------|
| Severity | Critical |
| RFC Basis | RFC 7530 §16.14 (LOOKUPP), RFC 7530 §7.3 (pseudo-FS) |
| Precondition | NFSv4 export of a subdirectory (not the filesystem mount point), `no_subtree_check` (Linux default) |
| Detection | LOOKUPP from export root, GETATTR on parent directory |

**Why this exists**: NFSv4's LOOKUPP operation returns the parent directory of any file handle. When a server exports a subdirectory (e.g., `/srv/nfs/data/exported`), LOOKUPP from the export root reaches the filesystem root -- escaping the export boundary without any handle construction or filesystem fingerprinting. This is the NFSv4 equivalent of F-2.1 but requires zero protocol-level sophistication: a single `cd ..` is sufficient.

**Attack**: `cd ..` from any NFSv4 export subdirectory. Read `secret.txt`, `shadow`, or any file outside the exported path. Confirmed on ext4, ZFS, BTRFS, f2fs, and all other filesystem types with subdirectory exports. The pseudo-root boundary stops upward traversal at the top of the export tree (cannot reach host `/`), but within any individual filesystem the escape is complete.

**What nfswolf tests**: `escape-root` in the v4 shell uses LOOKUPP as the primary escape mechanism. `cd ..` in the v4 shell issues LOOKUPP automatically. The `escape` subcommand's `try_nfs4_escape()` performs LOOKUPP traversal as a fallback.

---

### F-2.12: NFSv4 LOOKUPP Cross-Export Lateral Access

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 7530 §7.3 (pseudo-FS namespace), RFC 7530 §16.14 (LOOKUPP), RFC 7530 §16.13 (LOOKUP) |
| Precondition | NFSv4 access to any export, multiple exports sharing a pseudo-FS parent |
| Detection | LOOKUPP to pseudo-root parent, READDIR, LOOKUP into sibling exports |

**Why this exists**: The NFSv4 pseudo-filesystem connects all exports under a shared namespace tree. A client with access to any one export can LOOKUPP to the shared parent directory (e.g., `/srv/nfs/`) and then LOOKUP into any sibling export. No MOUNT protocol is involved -- the entire traversal happens over a single TCP connection. This bypasses MOUNT-level IP ACLs entirely because NFSv4 does not use MOUNT.

**Attack**: From `/srv/nfs/public` (open to everyone), issue `cd ..` to reach `/srv/nfs/`, then `cd data/etc` to enter a different export, then `cat passwd` to read credentials. Confirmed: starting from `public`, traversed to `data/etc/passwd` in 3 operations. The pseudo-root READDIR also reveals the names of ALL exports (F-5.5), including IP-restricted ones.

**What nfswolf tests**: The `exports` shell command enumerates reachable sibling exports via LOOKUPP. Standard `cd ..` + `cd <sibling>` demonstrates the lateral movement manually.

---

## Category 3: Network-Level Attacks

### F-3.1: Plaintext Traffic Interception

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1813 §8, RFC 1094 §3.4 |
| Precondition | Network access between client and server |
| Detection | Check if TLS/krb5p is in use |

**Why the RFC allows this**: "NFS version 3 defers to the authentication provisions of the supporting RPC protocol, and assumes that data privacy and integrity are provided by underlying transport layers" (RFC 1813 §8). No transport layer protection is specified or required.

### F-3.2: Portmapper UDP Amplification (DDoS)

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 1057 Appendix A |
| Precondition | UDP port 111 reachable |
| Detection | Send 68-byte DUMP, measure response size |

**Why the RFC allows this**: The portmapper has no authentication on any operation (RFC 1057 Appendix A). DUMP returns all registered services (~486-1930 bytes) in response to a small request over UDP, where source addresses are trivially spoofed.

### F-3.3: IP Spoofing Against Host-Based ACLs

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 2623 §2.6, RFC 7530 §19 |
| Precondition | Export restricted to specific IPs |
| Detection | Check if export uses IP-based restrictions without krb5 |

**Why the RFC allows this**: "NFS has historically used a model where, from an authentication perspective, the client was the entire machine, or at least the source IP address of the machine." (RFC 7530 §19). With UDP transport, IP addresses are trivially spoofable. Even TCP requires only SYN prediction.

**What nfswolf does for this finding**: detection only. `nfswolf analyze` reports whether an export is restricted by IP/hostname and whether Kerberos is in use. Active spoofing is out of scope because it requires privileged network positioning and is not reproducible across lab environments; the `--hostname` flag manipulates `auth_unix.machinename` (F-1.4), which is NOT the same as source-IP spoofing.

### F-3.6: UDP MOUNT Handle Theft via Source IP Spoofing

| Field | Value |
|-------|-------|
| Severity | Critical |
| RFC Basis | RFC 2623 §2.1, RFC 2623 §2.6, RFC 1057 §10 |
| Precondition | mountd UDP listener; attacker on same L2 segment; knowledge of allowed IP |
| Detection | Check if mountd serves over UDP (rpcinfo/scanner --scan-udp) |

**Why this works**: `rpc.mountd` trusts the source address from `recvfrom()` on its UDP socket. UDP is connectionless -- no handshake, no sequence numbers. An attacker on the same broadcast domain adds the allowed IP to their NIC, sends a single UDP MNT datagram with that source, and receives the file handle in the reply. The handle is then usable indefinitely over TCP from any IP (F-2.7).

**What nfswolf tests**: Scanner reports mountd UDP availability. The attack itself is a one-packet operation documented in the finding write-up.

### F-3.4: STRIPTLS Downgrade (RFC 9289)

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 9289 §6.1.1 |
| Precondition | Server supports TLS but client doesn't require it |
| Detection | Check for DANE/TLSA records, probe TLS support |

**Why the RFC allows this**: "The initial AUTH_TLS probe occurs in cleartext. An on-path attacker can alter a cleartext handshake to make it appear as though TLS support is not available." (RFC 9289 §6.1.1).

### F-3.5: Filtered Portmapper Bypass

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 1057 Appendix A (portmapper is convenience, not security) |
| Precondition | Port 111 filtered, NFS ports open |
| Detection | Scan 2049 directly when 111 is filtered |

**Why this works**: The portmapper is a service directory, not a security gate. NFS can be contacted directly on port 2049 without going through portmapper. Mount ports can be guessed or scanned.

### F-3.7: AUTH_DH Advertised (Cryptographically Broken)

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 5531 §14, RFC 2695 |
| Precondition | Server advertises AUTH_DH (flavor 3) in MOUNT auth_flavors or NFSv4 SECINFO |
| Detection | Check MOUNT MNT auth_flavors and NFSv4 SECINFO for flavor value 3 |

**Why the RFC flags this**: RFC 5531 §14: "AUTH_DH [...] is considered obsolete and insecure; see [RFC2695]." AUTH_DH uses 192-bit Diffie-Hellman key exchange and 56-bit DES encryption. Both are trivially factorable by modern standards.

**What nfswolf tests**: Checks `auth_flavors.contains(&3)` in both `check_auth_methods()` (MOUNT flavor list) and `check_nfs4_secinfo()` (NFSv4 SECINFO response).

### F-3.8: RPC-with-TLS Supported (RFC 9289)

| Field | Value |
|-------|-------|
| Severity | Info |
| RFC Basis | RFC 9289 §4.1 (AUTH_TLS STARTTLS), RFC 9289 §6.3 |
| Precondition | Server accepts AUTH_TLS NULL probe |
| Detection | Send NULL RPC with auth_flavor=7 and STARTTLS verifier |

**Why this matters**: RPC-with-TLS encrypts the wire but AUTH_SYS inside TLS still allows UID/GID credential forging (RFC 9289 §6.3). Mutual TLS is RECOMMENDED but not required. The presence of TLS is a positive security indicator, but does not eliminate AUTH_SYS spoofing.

**What nfswolf tests**: Sends a NULL RPC to NFS program (100003 v3 proc 0) with `auth_flavor=AUTH_TLS` (7) and a verifier containing the STARTTLS token. If accepted, emits an informational finding.

### F-3.9: AUTH_SHORT Session Credentials

| Field | Value |
|-------|-------|
| Severity | Info |
| RFC Basis | RFC 5531 §14, RFC 1057 §9.3 |
| Precondition | NFS server issues AUTH_SHORT verifiers in replies |
| Detection | Check MOUNT MNT auth_flavors and NFSv4 SECINFO for flavor value 2 |

**Why this exists**: AUTH_SHORT (flavor 2) allows servers to return abbreviated session tokens as verifiers, which clients then use for subsequent requests instead of full AUTH_SYS credentials. Linux knfsd defines `RPC_AUTH_SHORT=2` at `include/linux/sunrpc/msg_prot.h:19` but never issues or accepts AUTH_SHORT credentials — the `authtab[2]` slot is NULL.

**What nfswolf tests**: `analyze` checks for AUTH_SHORT in MOUNT auth_flavors and NFSv4 SECINFO responses. Finding is informational — relevant only for non-Linux NFS server implementations that may use AUTH_SHORT session tokens.

---

## Category 4: Privilege Escalation

### F-4.1: no_root_squash Exploitation

| Field | Value |
|-------|-------|
| Severity | Critical |
| RFC Basis | RFC 1813 §4.4, RFC 2623 §2.5 |
| Precondition | no_root_squash enabled on export |
| Detection | Create file as uid=0, check ownership |

**Why the RFC allows this**: "This superuser permission may not be allowed on the server, since anyone who can become superuser on their client could gain access to all remote files." (RFC 1813 §4.4). When no_root_squash is set, uid=0 credentials are not remapped -- full root access.

**Kernel capability escalation**: NFS root gets `CAP_NFSD_SET` (`capability.h:69`), which includes `CAP_FS_MASK | CAP_SYS_RESOURCE`. `CAP_FS_MASK` grants `CAP_MAC_OVERRIDE`, meaning NFS root bypasses ALL mandatory access controls (SELinux, AppArmor, SMACK) — a file labeled `system_u:object_r:shadow_t:s0` is fully readable over NFS. `CAP_SYS_RESOURCE` lets NFS root bypass disk quotas that even local root cannot override, making NFS root strictly more powerful than local root in the quota dimension.

**What nfswolf tests**: Write test file as uid=0, verify it's owned by root on server.

### F-4.2: SUID/SGID Binary Creation

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1094 §2.3.5 |
| Precondition | Writable export with no_root_squash (or no nosuid mount) |
| Detection | Create file with mode 04755, verify SUID bit persists |

**Why the RFC allows this**: CREATE accepts an `sattr` structure including mode bits. The mode bits include "0004000 Set user id on execution" (RFC 1094 §2.3.5). An attacker with write access + uid=0 can create setuid-root binaries.

### F-4.3: Device Node Creation via MKNOD

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1813 §3.3.11 |
| Precondition | Writable export, no nodev mount on client |
| Detection | Attempt MKNOD with NF3CHR/NF3BLK type |

**Why the RFC allows this**: "Creates a special file of the type, specdata..." (RFC 1813 §3.3.11). MKNOD can create character and block device nodes with arbitrary major/minor numbers -- potentially providing raw disk access from the client side.

### F-4.4: Symlink Escape

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1094 §2.2.14, RFC 1813 §3.3.5, §3.3.10 |
| Precondition | Writable directory, application follows symlinks |
| Detection | Create symlink pointing outside export, test if apps follow it |

**Why the RFC allows this**: "The data is not necessarily interpreted by the server, just stored in the file." (RFC 1813 §3.3.5). Symlink targets are not validated against export boundaries. "Note that this procedure does not follow symbolic links. The client is responsible for all parsing of filenames." (RFC 1813 §3.3.3). An application on the client that follows server-stored symlinks can be directed outside the intended export.

### F-4.5: SELinux/MAC Label Bypass via NFS

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 7861 §4 (residual limitation) |
| Precondition | SELinux/Smack enforcing, NFS-mounted files |
| Detection | Check if NFS-created files get default labels instead of intended labels |

**Why this exists**: "RPCSEC_GSSv3 is not a complete solution for labeling: it conveys the labels of actors but not the labels of objects." (RFC 7861 §4). Without labeled NFS (extremely rare), NFS-created files get default SELinux contexts, bypassing mandatory access control. Worse, NFS root on `no_root_squash` exports receives `CAP_MAC_OVERRIDE` via `CAP_NFSD_SET` (`fs/nfsd/auth.c:80`), which bypasses SELinux/AppArmor enforcement entirely — even files with restrictive security labels (e.g., `shadow_t`) are fully accessible. See F-4.1 for the capability chain.

### F-4.6: Unrestricted chown (Any User Can Change File Ownership)

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1094 §3.3, RFC 1813 §4.4 |
| Precondition | PATHCONF chown_restricted=false on the exported filesystem |
| Detection | Call PATHCONF per export, check chown_restricted field |

**Why this exists**: When `_POSIX_CHOWN_RESTRICTED` is not enforced, any user can change file ownership via SETATTR. An attacker can write a file, then chown it to root to create a SUID binary. Most modern UNIX systems restrict chown to root, but some NFS servers or older systems do not enforce this.

**What nfswolf tests**: Calls PATHCONF on the export root and checks `chown_restricted`. False = any user can chown = ownership hijacking possible.

---

## Category 5: Information Disclosure

### F-5.1: Export List Enumeration

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 1094 Appendix A §5.6, RFC 1813 §5.2.5 |
| Precondition | Mountd reachable |
| Detection | Call MNTPROC_EXPORT |

**Why the RFC allows this**: EXPORT "returns a variable number of export list entries" (RFC 1094 Appendix A) without requiring authentication. Full export topology is revealed.

### F-5.2: READDIRPLUS File Handle Harvesting

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1813 §3.3.17 |
| Precondition | Any directory handle |
| Detection | Single READDIRPLUS call returns all child handles |

**Why the RFC allows this**: READDIRPLUS returns "name, fileid, attributes (including the fileid), and file handle" for every entry (RFC 1813 §3.3.17). A single call harvests bearer tokens for all files in a directory without per-file access checks.

### F-5.3: NIS Credential Extraction

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | Related RPC service (programs 100004/100007) |
| Precondition | NIS (ypserv) co-hosted with NFS |
| Detection | Check portmapper for program 100004/100007 |

**Why this exists**: NIS is an unauthenticated RPC directory service. When co-hosted with NFS (common on legacy systems), `ypcat passwd.byname` dumps password hashes without authentication. Discovered via the same portmapper scan.

### F-5.4: RPC Service Enumeration

| Field | Value |
|-------|-------|
| Severity | Low |
| RFC Basis | RFC 1057 Appendix A (DUMP procedure) |
| Precondition | Portmapper reachable |
| Detection | PMAPPROC_DUMP returns all registered services |

**Why the RFC allows this**: No authentication on DUMP. Returns program number, version, protocol, and port for all registered services -- revealing the full RPC service topology.

### F-5.5: NFSv4 Pseudo-Filesystem Structure Leakage

| Field | Value |
|-------|-------|
| Severity | Low |
| RFC Basis | RFC 7530 §7.8 |
| Precondition | NFSv4 server |
| Detection | Browse from PUTROOTFH |

**Why the RFC allows this**: The pseudo-filesystem "provides a view of exported directories" (RFC 7530 §7.3). The server SHOULD hide existence via ancestor security policies, but this is only SHOULD -- the directory structure between exports is often visible.

### F-5.6: Metadata Disclosed on Access Denial

| Field | Value |
|-------|-------|
| Severity | Low |
| RFC Basis | RFC 1813 §3.3 (post_op_attr on failure) |
| Precondition | Server returns fattr3 in NFS3ERR_ACCES/PERM responses |
| Detection | Harvest post_op_attr from denied LOOKUP and READ operations |

**Why the RFC allows this**: RFC 1813 "strongly encourages" servers to return as much attribute data as possible on failure. Linux knfsd always returns post_op_attr on access denial (fs/nfsd/nfs3xdr.c). This discloses uid, gid, mode, and size of files the caller cannot read.

**What nfswolf tests**: Extracts `post_op_attr` from NFS3ERR_ACCES and NFS3ERR_PERM failure responses in `probe_file_access()`. Deduplicates by (operation, path) and reports all leaked metadata.

**NFSv4 ACL dimension**: On NFSv4 servers, `NFS4_ANYONE_MODE` (`fs/nfsd/nfs4acl.c:54`) unconditionally includes `READ_ATTRIBUTES | READ_ACL | SYNCHRONIZE` in every ALLOW ACE. Even `mode 0000` files leak their ACL contents and attributes via NFSv4 GETATTR, because the ACL grants everyone read-attribute access by design.

### F-5.7: Case-Insensitive Filesystem (Windows NFS / NTFS Fingerprint)

| Field | Value |
|-------|-------|
| Severity | Low |
| RFC Basis | RFC 1813 §3.3.20 (PATHCONF), RFC 7530 §12 |
| Precondition | Server filesystem is case-insensitive |
| Detection | Call PATHCONF, check case_insensitive field |

**Why this matters**: PATHCONF `case_insensitive=true` indicates a Windows NFS server or NetApp NTFS volume. Case-insensitive lookups enable filename collision attacks and path-based access control bypasses (RFC 7530 §12 security concerns).

**What nfswolf tests**: Calls PATHCONF per export and checks the `case_insensitive` flag. Also reports `case_preserving` in evidence.

### F-5.8: Export Root Attributes Leaked via AUTH_NONE

| Field | Value |
|-------|-------|
| Severity | Low |
| RFC Basis | RFC 2623 §2.3.2 (automounter AUTH_NONE support) |
| Precondition | Server allows GETATTR with AUTH_NONE on valid file handles |
| Detection | Send GETATTR with AUTH_NONE credentials on the export root handle |

**Why this exists**: RFC 2623 §2.3.2 permits AUTH_NONE for GETATTR at mount time to support automounters that lack Kerberos credentials. This leaks uid, gid, mode, size, and timestamps to any unauthenticated client who possesses a valid file handle.

**What nfswolf tests**: Creates a temporary NFS client with AUTH_NONE credentials (DirectTransport default) and sends GETATTR against the export root handle.

### F-5.9: Execute-Only File Content Disclosure (Read-If-Exec Fallback)


| Field | Value |
|-------|-------|
| Severity | Low |
| RFC Basis | Implementation-specific (no RFC requires this behavior) |
| Precondition | File has execute permission but no read permission (e.g., mode 0111) |
| Detection | Attempt NFS READ on an execute-only file; observe success |

**Why this exists**: When `nfsd_permission()` denies a READ request (`-EACCES`) and the file is regular and the request carries `NFSD_MAY_READ_IF_EXEC`, the server retries the permission check with `MAY_EXEC` instead of `MAY_READ` (`fs/nfsd/vfs.c:2894-2898`). If any execute bit is set, the read succeeds. This is intentional — the server allows downloading executables for local execution — but it violates the POSIX permission model where mode 0111 means "execute but not read."

**Practical impact**: Limited. Few files are deliberately set to execute-only. Affects hardened environments that use execute-only permissions on proprietary binaries or license-protected software.

### F-5.10: pNFS Flex-File Layout Security Downgrade

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 8435 (Flexible File Layout), RFC 5661 §12.9 |
| Precondition | Export has `pnfs` flag set; client has NFSv4.1 session |
| Detection | Issue LAYOUTGET on a pNFS-enabled export; check for NFSv3 handle in response |

**Why this exists**: Linux knfsd's flex-file layout driver responds to LAYOUTGET by handing the client the raw NFS file handle (`flexfilelayout.c:64-65`) plus instructions to contact the data server via NFSv3 AUTH_SYS (`da->version = 3`, line 95). This downgrades the security model from NFSv4.1 (sessions, RPCSEC_GSS) to NFSv3 AUTH_SYS on the data path. Device IDs are sequential from 1 (`nfsd_devid_seq`, `nfs4layouts.c:48`), enabling enumeration of all pNFS exports. The `.disable_recalls = true` flag (`flexfilelayout.c:138`) means granted layouts cannot be recalled or fenced.

**Attack chain**: A client authenticated via krb5p on the MDS obtains a layout containing an NFSv3 file handle and DS address. The client (or attacker) then contacts the DS directly via NFSv3 AUTH_SYS with forged UID/GID credentials (F-1.1), bypassing all Kerberos enforcement. The layout and handle are irrevocable.

### F-5.11: Filesystem Lacks Link/Symlink Support (Reduced Attack Surface)

| Field | Value |
|-------|-------|
| Severity | Info |
| RFC Basis | RFC 1813 §3.3.18 (FSINFO properties) |
| Precondition | Server returns FSINFO with properties field |
| Detection | Call FSINFO, check FSF3_LINK and FSF3_SYMLINK bits |

**Why this matters**: When the filesystem does not support hard links or symbolic links (FSINFO `properties` field lacks `FSF3_LINK` or `FSF3_SYMLINK`), symlink escape (F-4.4) and hardlink attacks are inapplicable. This is informational -- it narrows the effective attack surface.

### F-5.12: Near Inode Exhaustion (DoS Risk)

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 1813 §3.3.18 (FSSTAT) |
| Precondition | Writable export with low available inodes |
| Detection | Call FSSTAT, check avail_files < 1000 |

**Why this matters**: FSSTAT reports total, free, and available file slots. When fewer than 1000 inodes remain, an attacker with write access can exhaust remaining capacity to deny file creation for all users.

### F-5.13: NFSv4 Named Attributes (xattrs) Exposed on Export Root

| Field | Value |
|-------|-------|
| Severity | Low |
| RFC Basis | RFC 7530 §5.3 (named attributes) |
| Precondition | Server supports OPENATTR operation |
| Detection | OPENATTR + READDIR on export root enumerates named attributes |

**Why this matters**: Named attributes (xattrs) may carry sensitive metadata: POSIX ACLs (`system.posix_acl_access`), SELinux labels (`security.selinux`), file capabilities (`security.capability`), or application-specific data. Enumerating them reveals the MAC/DAC enforcement posture.

### F-5.14: POSIX ACL Entries Expose Access Beyond Mode Bits

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | NFS_ACL sideband protocol (program 100227, NFSACL_GETACL) |
| Precondition | NFS_ACL program reachable on port 2049 |
| Detection | GETACL on the export root returns named USER or GROUP ACL entries |

**Why this matters**: The NFS_ACL sideband protocol returns POSIX ACL entries that grant access to specific UIDs/GIDs invisible to standard mode-bit analysis. Named USER and GROUP ACL entries may grant read/write access that does not appear in file ownership or READDIRPLUS results, revealing UIDs and GIDs with access paths invisible to mode-bit analysis and feeding the credential ladder for targeted escalation.

**What nfswolf tests**: Calls NFSACL_GETACL (program 100227, procedure 2) on the export root file handle. Reports any named USER, GROUP, or DEFAULT ACL entries with their permission masks.

### F-5.15: rquotad Exposes UID Activity via Quota Queries

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | Sun rquota.x (program 100011, no RFC; de facto standard) |
| Precondition | rquotad reachable via portmapper |
| Detection | GETQUOTA returns non-zero curblocks/curfiles for probed UIDs |

**Why this matters**: rquotad (program 100011 v1) returns per-UID disk usage without authentication. GETQUOTA with a specific UID reveals whether that UID has disk activity (file and block counts), confirming UID existence on the server. The `bsize` field leaks the filesystem block size (ext4=4096, XFS=512, ZFS=1024), narrowing escape strategy before running NFS operations. Active UIDs feed the credential ladder for targeted spraying.

**What nfswolf tests**: Resolves rquotad via portmapper GETPORT, then probes UIDs 0, 1000, and 65534 with GETQUOTA v1. Reports any UIDs with non-zero block or file counts, plus the filesystem block size.

---

## Category 6: Denial of Service (out of scope)

NLM/NSM lock attacks (F-6.1), NFSv4 grace-period blocking (F-6.2), and
SETCLIENTID state destruction (F-6.3) were initially scoped but are
intentionally not implemented. The lock-DoS module was removed along with
the NLM and NSM clients, and grace-period / SETCLIENTID DoS were never
implemented.

**F-6.3 kernel detail**: The `same_creds()` check at `fs/nfsd/nfs4state.c:2689` compares `cr_uid`, `cr_gid`, `cr_group_info`, and `cr_principal`. Under AUTH_SYS, the attacker controls all of these fields. Most NFS clients run as root (uid=0), so passing the credential check is trivial. At line 4784-4794, confirming a new client with matching name and credentials destroys all of the old client's open state, locks, and delegations via `expire_client()`. The kernel comment "XXX: check that cr_targ_princ fields match?" (line 2696) confirms the developers' own uncertainty about this check.

Detailed write-ups remain in `docs/findings/F-6.1-*.md`,
`F-6.2-*.md`, and `F-6.3-*.md` for completeness, but no nfswolf
subcommand exercises these findings.

---

## Category 7: Configuration Weaknesses

### F-7.1: Wildcard/Broad Subnet Exports

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 2623 §2.6 |
| Precondition | Export allows * or large CIDR |
| Detection | Parse MNTPROC_EXPORT response for wildcards |

**Why this matters**: "Host-based access control" is the primary authorization mechanism (RFC 2623 §2.6). Wildcard exports make it accessible to any host on the network.

### F-7.2: `insecure` Export Option (Unprivileged Ports)

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 2623 §2.1 |
| Precondition | Server accepts connections from ports ≥ 1024 |
| Detection | Connect from unprivileged port, attempt mount |

**Why this matters**: While port monitoring is "at best an inconvenience" (RFC 2623 §2.1), removing even this minimal check means any unprivileged process (no root needed) can connect to NFS.

### F-7.3: `nohide`/`crossmnt` Sub-Mount Exposure

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 1813 §3.3.3, §4.2 |
| Precondition | nohide or crossmnt set on export |
| Detection | Traverse past filesystem boundaries |

**Why this matters**: RFC 1813 §3.3.3 states "A server will not allow a LOOKUP operation to cross a mountpoint." The `nohide`/`crossmnt` options override this, exposing sub-mounted filesystems that may contain more sensitive data than the parent export.

### F-7.4: Missing `nosuid`/`nodev` on Client Mount

| Field | Value |
|-------|-------|
| Severity | High |
| RFC Basis | RFC 1094 §2.3.5 (SUID bits in mode) |
| Precondition | Client mounts without nosuid/nodev |
| Detection | Server-side: check export options; client-side: check mount flags |

**Why this matters**: NFS allows creating files with SUID bits (RFC 1094 §2.3.5) and device nodes (RFC 1813 §3.3.11). Without client-side nosuid/nodev, these are executable/usable as privilege escalation vectors.

### F-7.5: all_squash with anonuid=0

| Field | Value |
|-------|-------|
| Severity | Critical |
| RFC Basis | RFC 1813 §4.4, RFC 2623 §2.5 |
| Precondition | all_squash enabled with anonuid=0 |
| Detection | Squash probe (create file, check ownership) |

**Why this matters**: all_squash maps ALL clients to the anonymous UID. If anonuid is set to 0, every client operation runs as root -- worse than no_root_squash because no UID even needs to be forged.

### F-7.6: Absence of Audit Logging

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | Implementation limitation (knfsd bypasses auditd) |
| Precondition | Linux NFS kernel server |
| Detection | N/A (operational gap, not a remotely testable finding) |

**Why this matters**: The Linux NFS kernel server processes file operations in kernel space, bypassing the auditd framework. No file access logs are generated for NFS operations regardless of audit rules. All NFS attacks operate in a detection blind spot.

### F-7.7: xprtsec Permissive Default (TLS/Plaintext Coexistence)

| Field | Value |
|-------|-------|
| Severity | Medium |
| RFC Basis | RFC 9289 §1 (opt-in nature), §6.1.1 (STRIPTLS) |
| Precondition | Export configured with `xprtsec=tls` or `xprtsec=mtls` |
| Detection | Connect without TLS; observe that NFS operations succeed |

**Why this matters**: The default value for `ex_xprtsec_modes` is `NFSEXP_XPRTSEC_ALL` (`export.c:647`), which sets all three bits: `NFSEXP_XPRTSEC_NONE | NFSEXP_XPRTSEC_TLS | NFSEXP_XPRTSEC_MTLS`. The `check_xprtsec_policy()` function (`export.c:1100-1118`) accepts the connection if ANY one of the enabled modes matches. Because `NFSEXP_XPRTSEC_NONE` is enabled by default, adding `xprtsec=tls` to an export doesn't remove plaintext acceptance — an attacker simply connects without TLS and proceeds in plaintext. No active STRIPTLS attack (F-3.4) is needed. This is the transport-layer equivalent of F-1.7 (RPCSEC_GSS flavor downgrade). To actually require TLS, the admin must explicitly set `xprtsec=tls` and NOT include `xprtsec=none`.

---

## Finding ID Cross-Reference

| Finding | Detail Doc | Severity | Detected by |
|---------|-----------|----------|-------------|
| F-1.1 | [UID/GID Spoofing](findings/F-1.1-uid-gid-spoofing.md) | Critical | `uid-spray`, `shell uid/impersonate`, `mount --uid` |
| F-1.2 | [Root Squash Bypass](findings/F-1.2-root-squash-bypass.md) | High | `analyze` (squash probe), `shell uid 0` once `escape` returns a handle |
| F-1.3 | [Auxiliary Group Injection](findings/F-1.3-auxiliary-group-injection.md) | High | `analyze` (shadow GID 42/15), `shell gid`, `mount --aux-gids` |
| F-1.4 | [Machine Name Spoofing](findings/F-1.4-machine-name-spoofing.md) | Low | `--hostname` global flag (every subcommand), `shell hostname` |
| F-1.5 | [Credential Replay](findings/F-1.5-credential-replay.md) | High | Passive only -- precondition detected via F-3.1 |
| F-1.6 | [NFSv2 Downgrade](findings/F-1.6-nfsv2-downgrade.md) | High | `scan` (portmapper version matrix), `analyze` |
| F-1.7 | [RPCSEC_GSS Flavor Downgrade](findings/F-1.7-rpcsec-gss-flavor-downgrade.md) | High | `analyze` (mixed auth flavor detection) |
| F-1.8 | [AUTH_TOOWEAK Oracle](findings/F-1.8-auth-tooweak-kerberos-enforced.md) | High | `analyze` (NFSv4 SECINFO scanner, MOUNT auth-flavor list) |
| F-2.1 | [Export Escape](findings/F-2.1-export-escape.md) | Critical | `escape`, `analyze`, `shell escape-root` |
| F-2.2 | [File Handle Guessing](findings/F-2.2-file-handle-guessing.md) | High | `analyze` (entropy), `brute-handle` |
| F-2.3 | [Windows Handle Signing](findings/F-2.3-windows-handle-signing.md) | Critical | `analyze` (`FileHandleAnalyzer::check_windows_signing`) |
| F-2.4 | [BTRFS Subvolume Escape](findings/F-2.4-btrfs-subvolume-escape.md) | High | `escape` (subvol 5 + 256+), `shell escape-root` |
| F-2.5 | [Stale Handle Persistence](findings/F-2.5-stale-handle-persistence.md) | Medium | `shell --handle <hex>`, `mount --handle <hex>`, `shell mount-handle` |
| F-2.6 | [Bind Mount Escape](findings/F-2.6-bind-mount-escape.md) | High | `escape` (fsid-based handle). `analyze` detection removed: the old handle-fsid vs fattr3-fsid equality test compared two differently-encoded values and false-positived on normal exports; no sound oracle is available from a single GETATTR |
| F-2.7 | [NFS Daemon ACL Blindness](findings/F-2.7-nfsd-acl-blindness.md) | Critical | `shell --handle <hex>` / `mount --handle <hex>` (port 2049, no MOUNT -- handle resolves from any IP) |
| F-2.8 | [Sibling Export Lateral Access](findings/F-2.8-sibling-export-lateral-access.md) | Critical | `escape` + `shell` (`escape-root`, then `cd` to a peer export, `ls`/`cat`) |
| F-2.9 | [WebNFS Public File Handle](findings/F-2.9-webnfs-public-handle.md) | Critical | `analyze` (WebNFS public handle probe) |
| F-2.10 | [SIGN_FH Root Handle Exemption](findings/F-2.10-sign-fh-root-exemption.md) | Medium | `shell --handle <constructed_root_hex>` |
| F-2.11 | [NFSv4 LOOKUPP Export Escape](findings/F-2.11-nfsv4-lookupp-export-escape.md) | Critical | `escape-root` (v4 shell), `cd ..` from subdirectory export |
| F-2.12 | [NFSv4 LOOKUPP Cross-Export Lateral](findings/F-2.12-nfsv4-lookupp-cross-export-lateral.md) | High | `cd ..` + `cd <sibling>` in v4 shell, `exports` command (planned) |
| F-3.1 | [Plaintext Wire Protocol](findings/F-3.1-plaintext-wire-protocol.md) | High | `analyze` (Info: flags exports that advertise no RPCSEC_GSS; RFC 9289 TLS itself is not actively probed) |
| F-3.2 | [Portmapper Amplification](findings/F-3.2-portmapper-amplification.md) | Medium | `scan` (UDP DUMP amplification factor), `analyze` |
| F-3.3 | [IP Spoofing](findings/F-3.3-ip-spoofing-host-trust.md) | High | `analyze` (host-based ACL detection; no active exploit) |
| F-3.4 | [STRIPTLS Downgrade](findings/F-3.4-striptls-downgrade.md) | High | `analyze` (AUTH_TLS probe); NFSv4 SECINFO |
| F-3.5 | [Portmapper Tunnel Bypass](findings/F-3.5-portmapper-tunnel-bypass.md) | Medium | `scan` (direct port 2049 probe when 111 filtered) |
| F-3.6 | [UDP MOUNT Handle Theft](findings/F-3.6-udp-mount-handle-theft.md) | Critical | `scan --scan-udp` (mountd UDP availability) |
| F-3.7 | [AUTH_DH Advertised (Cryptographically Broken)](findings/F-3.7-auth-dh-broken.md) | Medium | `analyze` (MOUNT auth_flavors + NFSv4 SECINFO flavor 3 detection) |
| F-3.8 | [RPC-with-TLS Supported (RFC 9289)](findings/F-3.8-rpc-with-tls.md) | Info | `analyze` (AUTH_TLS NULL probe on NFS program) |
| F-3.9 | [AUTH_SHORT Session Credentials](findings/F-3.9-auth-short-session-credentials.md) | Info | `analyze` (MOUNT auth_flavors + NFSv4 SECINFO flavor 2 detection) |
| F-4.1 | [no_root_squash](findings/F-4.1-no-root-squash.md) | Critical | `analyze`, `mount --uid 0 --allow-write`, `shell uid 0` |
| F-4.2 | [SUID/SGID Escalation](findings/F-4.2-suid-sgid-escalation.md) | High | `shell suid-scan`, `mount` + `chmod u+s` via regular tools |
| F-4.3 | [Device Node Creation](findings/F-4.3-device-node-creation.md) | High | `shell mknod` |
| F-4.4 | [Symlink Escape](findings/F-4.4-symlink-escape.md) | High | `analyze` (writable parent detection), `shell symlink` |
| F-4.5 | [SELinux Label Bypass](findings/F-4.5-selinux-label-bypass.md) | Medium | Not implemented -- documented for awareness (no SELinux/MAC check in `analyze`) |
| F-4.6 | [Unrestricted chown](findings/F-4.6-unrestricted-chown.md) | High | `analyze` (PATHCONF `chown_restricted` check per export) |
| F-5.1 | [Export List Enumeration](findings/F-5.1-export-list-enumeration.md) | Medium | `scan` (MNTPROC_EXPORT), `analyze` |
| F-5.2 | [READDIRPLUS Harvesting](findings/F-5.2-readdirplus-handle-harvesting.md) | High | `shell ls`, `shell find`, `mount` (transparent via FUSE) |
| F-5.3 | [NIS Credential Extraction](findings/F-5.3-nis-credential-extraction.md) | High | `scan` / `analyze` (portmapper 100004/100007 detect) |
| F-5.4 | [RPC Service Enumeration](findings/F-5.4-rpc-service-enumeration.md) | Low | `scan` (PMAPPROC_DUMP full dump) |
| F-5.5 | [NFSv4 Pseudo-FS Leakage](findings/F-5.5-nfsv4-pseudo-fs-leakage.md) | Low | `scan` (pseudo-root READDIR via `Nfs4DirectClient`) |
| F-5.6 | Metadata Disclosed on Access Denial | Low | `analyze` (harvests `post_op_attr` from NFS3ERR_ACCES/PERM responses) |
| F-5.7 | [Case-Insensitive Filesystem](findings/F-5.7-case-insensitive-filesystem.md) | Low | `analyze` (PATHCONF `case_insensitive` check per export) |
| F-5.8 | [Export Root Attributes Leaked via AUTH_NONE](findings/F-5.8-auth-none-attr-leak.md) | Low | `analyze` (GETATTR with AUTH_NONE on export root handle) |
| F-5.9 | [Execute-Only File Content Disclosure](findings/F-5.9-read-if-exec-content-disclosure.md) | Low | Not implemented -- documented for awareness |
| F-5.10 | [pNFS Layout Security Downgrade](findings/F-5.10-pnfs-layout-security-downgrade.md) | Medium | Not implemented -- documented for awareness |
| F-6.1 | [NLM Lock Attacks](findings/F-6.1-nlm-lock-attacks.md) | Medium | Out of scope -- lock-DoS module removed |
| F-6.2 | [Grace Period DoS](findings/F-6.2-grace-period-dos.md) | Medium | Out of scope -- never implemented |
| F-6.3 | [SETCLIENTID State Destruction](findings/F-6.3-setclientid-state-destruction.md) | Medium | Out of scope -- never implemented |
| F-7.1 | [Wildcard Exports](findings/F-7.1-wildcard-export-policy.md) | High | `scan` + `analyze` (ACL pattern match on EXPORT output) |
| F-7.2 | [Privileged Port Bypass](findings/F-7.2-privileged-port-bypass.md) | Medium | `analyze` probe removed (was tautological -- MNTPROC_EXPORT is not source-port gated, so it reported `insecure` on secure servers); a sound test needs an MNT from an unprivileged source port |
| F-7.3 | [nohide/crossmnt Exposure](findings/F-7.3-nohide-crossmnt-exposure.md) | Medium | `analyze` (crossmnt LOOKUP traversal), `shell` |
| F-7.4 | [Missing nosuid/nodev](findings/F-7.4-missing-nosuid-nodev.md) | High | Not server-observable -- `nosuid`/`nodev` are client-side mount options, absent from MNTPROC_EXPORT, so `analyze` cannot detect them remotely (documented gap, no detection) |
| F-7.5 | [Squash Misconfiguration](findings/F-7.5-squash-misconfiguration.md) | Critical | `analyze` (all_squash + anonuid=0 detection) |
| F-7.6 | [No Audit Logging](findings/F-7.6-no-audit-logging.md) | Medium | Not remotely detectable -- documented for awareness |
| F-7.7 | [xprtsec Permissive Default](findings/F-7.7-xprtsec-permissive-default.md) | Medium | Not implemented -- documented for awareness |
