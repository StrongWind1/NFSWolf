# Glossary

Key terms used across nfswolf documentation, NFS protocol references, and security findings.

ACL
:   Access Control List. A list of rules that define which users or groups can access a file or directory, and what operations they can perform. NFS supports both POSIX ACLs (via the NFS_ACL sideband protocol) and NFSv4 rich ACLs (built into the protocol).

AUTH_DH
:   Diffie-Hellman authentication, RPC flavor 3. A deprecated authentication mechanism that used DES encryption with Diffie-Hellman key exchange. Replaced by RPCSEC_GSS. See [F-3.7](../security/network/F-3.7-auth-dh-obsolete.md).

AUTH_NONE
:   No authentication, RPC flavor 0. The client provides no identity information. Used for NULL procedure pings and some informational calls. See [F-5.8](../security/info-disclosure/F-5.8-auth-none-metadata-leak.md).

AUTH_SHORT
:   Abbreviated credential token, RPC flavor 2. An opaque token the server returns in a reply verifier that the client can reuse instead of sending full AUTH_SYS credentials on every call. See [F-3.9](../security/network/F-3.9-auth-short-session-credentials.md).

AUTH_SYS
:   The default NFS authentication mechanism, RPC flavor 1. The client includes its UID, GID, and supplemental groups in every RPC call. The server trusts these values without cryptographic verification. Also called AUTH_UNIX. See [Authentication model](../nfs/authentication.md) and [F-1.1](../security/identity/F-1.1-uid-gid-spoofing.md).

AUTH_TLS
:   TLS upgrade negotiation, RPC flavor 7, defined in RFC 9289. The client sends a NULL RPC with AUTH_TLS credentials; if the server supports TLS, it replies with a "STARTTLS" verifier, and both sides upgrade the connection to TLS. See [NFS over TLS](../security/defense/hardening/tls.md).

bearer token
:   A credential that grants access to whoever holds it, with no proof of identity required. NFS file handles are bearer tokens: anyone who has the handle bytes can access the file, regardless of how they obtained the handle. See [File handles](../nfs/file-handles.md).

COMPOUND
:   The single RPC procedure in NFSv4 that batches multiple sub-operations (PUTFH, LOOKUP, GETATTR, READ, etc.) into one network round trip. Replaces the per-operation RPC calls used in NFSv2 and NFSv3. See [COMPOUND operations](../nfs/protocols/nfsv4/compound.md).

credential ladder
:   nfswolf's strategy for escalating file access by trying different UIDs in sequence. The ladder is ordered by evidence: file owner first, then UIDs seen in directory listings, then common service accounts. See the `shell` subcommand's auto-escalation behavior.

DAC
:   Discretionary Access Control. The standard UNIX permission model based on owner/group/other mode bits. NFS uses DAC exclusively unless Labeled NFS (NFSv4.2) is deployed.

DRC
:   Duplicate Request Cache. A server-side cache that detects and suppresses retried RPC calls (same XID from same client). The DRC is why AUTH_SYS stamps must be unique per call in nfswolf.

export
:   A directory that an NFS server makes available to remote clients over the network. Configured in `/etc/exports` on Linux. Each export has its own security settings (squash mode, allowed hosts, authentication flavors).

file handle
:   A chunk of server-internal data that identifies a file on disk. Contains a filesystem identifier (fsid), an inode number, and a generation counter. Handles are bearer tokens. See [File handles](../nfs/file-handles.md).

fsid
:   Filesystem identifier. The portion of an NFS file handle that identifies which filesystem the file lives on. The fsid encoding varies by `fsid_type` (device number, UUID, or a combination). See [File handles](../nfs/file-handles.md).

FUSE
:   Filesystem in Userspace. A Linux kernel interface that lets user-space programs implement filesystem operations. nfswolf uses FUSE for its `mount` subcommand.

GID
:   Group ID. A numeric identifier for a UNIX group. NFS transmits the GID in AUTH_SYS credentials; the server uses it for group-permission checks.

GSS-API
:   Generic Security Services Application Programming Interface. The framework that RPCSEC_GSS uses to plug in different authentication mechanisms (Kerberos, SPNEGO, etc.).

HMAC
:   Hash-based Message Authentication Code. A keyed hash that provides both integrity and authentication. NFS file handles on Linux are NOT HMAC-protected (they use predictable structure), which is why export escape works.

inode
:   A file's unique number on disk. Every file and directory on a UNIX filesystem has an inode number. NFS file handles contain the inode number as part of the fileid. The root directory's inode is typically 2 on ext2/3/4, 128 on XFS, and 256 on BTRFS.

KDC
:   Key Distribution Center. The Kerberos server that issues tickets. Required for `sec=krb5` NFS exports. Typically runs MIT Kerberos or Heimdal.

knfsd
:   The Linux kernel NFS server daemon. The in-kernel implementation of the NFS server, as opposed to user-space NFS servers. All nfswolf findings are tested against knfsd.

LOOKUPP
:   An NFSv4 operation that returns the parent directory of the current filehandle. The trailing "P" stands for "parent." Used by nfswolf for export escape on NFSv4 without needing to construct handles. See [F-2.11](../security/access-control/F-2.11-nfsv4-lookupp-export-escape.md).

MAC
:   Mandatory Access Control. A security model where access decisions are enforced by the system regardless of file ownership. Includes SELinux, AppArmor, and SMACK. NFS root with `no_root_squash` bypasses MAC via `CAP_MAC_OVERRIDE`.

MKNOD
:   An NFS operation that creates a device node (character or block device) with specified major/minor numbers. Used in privilege escalation attacks to create fake devices pointing at the server's raw disk. See [F-4.3](../security/privesc/F-4.3-device-node-creation.md).

MNT
:   The MOUNT protocol procedure that converts an export path into a file handle. The entry point for NFS access on NFSv2 and NFSv3.

mountd
:   The MOUNT protocol daemon (`rpc.mountd`). Runs as a separate service from the NFS daemon, typically on a dynamic port registered with portmapper. Handles MNT, UMNT, DUMP, and EXPORT requests.

NFS_ACL
:   A sideband RPC program (number 100227) that provides POSIX ACL queries over NFS. Not defined in any RFC. See [NFS_ACL protocol](../nfs/protocols/nfs-acl.md) and [F-5.14](../security/info-disclosure/F-5.14-posix-acl-entries.md).

NIS
:   Network Information Service. A legacy Sun directory service for distributing system configuration data (passwords, groups, hosts). When co-hosted with NFS, NIS password maps can be dumped without authentication. See [F-5.3](../security/info-disclosure/F-5.3-nis-credential-extraction.md).

NLM
:   Network Lock Manager. A separate RPC program (100021) that provides file locking for NFSv2 and NFSv3. Cannot be secured with Kerberos. Removed from nfswolf in v0.2.0.

NSM
:   Network Status Monitor. A companion to NLM that tracks lock state across server reboots. RPC program 100024.

ONC RPC
:   Open Network Computing Remote Procedure Call. The transport protocol underneath NFS. Defines message framing, program/version/procedure dispatching, and authentication flavors. See [ONC RPC](../nfs/protocols/rpc.md).

pNFS
:   Parallel NFS. An NFSv4.1 extension that separates metadata operations from data operations, allowing clients to read/write data directly from storage devices.

POSIX
:   Portable Operating System Interface. The family of standards that defines UNIX-like operating system behavior, including file permissions, ACLs, and process semantics.

portmapper
:   An RPC service directory that runs on port 111 (TCP and UDP). Maps RPC program numbers to the ports where those programs are listening. The first target in NFS reconnaissance. See [Portmapper](../nfs/protocols/portmapper.md).

READDIRPLUS
:   An NFSv3 operation that returns directory entries along with their file handles and attributes. A single call reveals handles, UIDs, GIDs, and permissions for every file in a directory. See [F-5.2](../security/info-disclosure/F-5.2-readdirplus-handle-harvesting.md).

rpcbind
:   The modern replacement for portmapper. Runs on the same port (111) but adds IPv6 support and additional operations (GETTIME, GETSTAT). See [Portmapper and rpcbind](../nfs/protocols/portmapper.md).

RPCSEC_GSS
:   Kerberos-based RPC authentication, RPC flavor 6. The only NFS authentication mechanism that provides cryptographic identity verification. Three service levels: `krb5` (authentication only), `krb5i` (+ integrity), `krb5p` (+ encryption). See [Authentication model](../nfs/authentication.md) and [Kerberos hardening](../security/defense/hardening/kerberos.md).

RQUOTA
:   Remote Quota protocol, RPC program 100011. Returns per-UID disk usage without authentication, enabling user enumeration. See [RQUOTA protocol](../nfs/protocols/rquota.md) and [F-5.15](../security/info-disclosure/F-5.15-rquotad-uid-oracle.md).

SECINFO
:   An NFSv4 operation that queries the server for the authentication flavors accepted on a given export or directory. Enables in-band security negotiation. See [Security negotiation](../nfs/protocols/nfsv4/security.md).

seed handle
:   The initial file handle obtained from MOUNT MNT (or NFSv4 PUTROOTFH + LOOKUP). nfswolf uses the seed handle's fsid to construct escape handles targeting the filesystem root inode.

SUID
:   Set User ID on execution. A permission bit (mode 04xxx) that causes a program to run with the file owner's privileges instead of the caller's. An attacker with write access to a `no_root_squash` export can create SUID-root binaries. See [F-4.2](../security/privesc/F-4.2-suid-sgid-escalation.md).

UID
:   User ID. A numeric identifier for a UNIX user. NFS transmits the UID in AUTH_SYS credentials; the server uses it for owner-permission checks.

UMNT
:   The MOUNT procedure to remove a client from the mount list. Does NOT invalidate the file handle — the handle continues to work after unmounting.

VFS
:   Virtual File System. The Linux kernel's abstraction layer over different filesystem implementations. NFS permission checks (`nfsd_permission`) operate at the VFS layer.

writeverf3
:   An 8-byte verifier returned by the NFSv3 COMMIT procedure. The server generates a new verifier on each reboot. A change between two COMMIT calls proves the server restarted. See [F-5.17](../security/info-disclosure/F-5.17-write-verifier-changed.md).

XDR
:   External Data Representation, defined in RFC 4506. The serialization format used by ONC RPC to encode all NFS messages. Big-endian, 4-byte aligned, with length-prefixed variable data. See [ONC XDR](../nfs/protocols/xdr.md).

XID
:   Transaction Identifier. A 4-byte value in every RPC message that matches replies to calls. Not a security mechanism — XIDs are predictable and reusable.
