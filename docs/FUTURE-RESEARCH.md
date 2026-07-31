# Future research — sideband protocols and adjacent attack surface

Research notes for protocols NFSWolf does not yet implement but that share the AUTH_SYS trust model and are reachable from the same network position as NFS. Every protocol below is callable with AUTH_SYS (or AUTH_NONE) and leaks something NFS itself will not. Organized by security value: data access and code execution first, then recon and DoS, then detection-only.

Spec reference: X/Open CAE C702 "XNFS, Version 3W" is at `ref/xopen-c702.pdf` (352 pages, February 1998). HTML version at `ref/pubs.opengroup.org/onlinepubs/009629799/`. X/Open D030 "(PC)NFS" is at `ref/archive.opengroup.org/archive/CDROM/d030.pdf` (164 pages, 1990).

## Contents

- [WebNFS — filesystem access bypassing MOUNT](#webnfs--filesystem-access-bypassing-mount)
- [PCNFSD — password oracle and code execution](#pcnfsd--password-oracle-and-code-execution)
- [NLM — lock manipulation enabling writes](#nlm--lock-manipulation-enabling-writes)
- [NSM — reboot spoofing and callback coercion](#nsm--reboot-spoofing-and-callback-coercion)
- [RQUOTA — user enumeration](#rquota--user-enumeration)
- [NIS — credential store dump](#nis--credential-store-dump)
- [NFS_ACL — permission bypass beyond mode bits](#nfs_acl--permission-bypass-beyond-mode-bits)
- [RPCSEC_GSS — auth negotiation recon](#rpcsec_gss--auth-negotiation-recon)
- [C702 insights for existing NFS implementation](#c702-insights-for-existing-nfs-implementation) — permission model quirks, DRC, write verifier oracle, portmapper CALLIT, external citations
- [Cross-protocol attack chains](#cross-protocol-attack-chains) — multi-protocol sequences combining sideband RPC programs with NFS for compound exploitation
- [Crate inventory](#crate-inventory)
- [Detection without implementation](#detection-without-implementation)

---

## WebNFS — filesystem access bypassing MOUNT

**Spec:** C702 Appendix E (pp. 299–319). RFC 2054 §5, §6. RFC 2055.

**Why it matters:** Direct read/write of files without going through MOUNT. The public filehandle is a well-known constant — no portmapper query, no MOUNT exchange, no export ACL check. If the server only gates access at MOUNT time (which the spec itself flags as the common broken implementation), this is unrestricted filesystem access via a single LOOKUP.

**The public filehandle:**
- NFSv2: fixed all-zero 32-byte handle (`[0u8; 32]`)
- NFSv3: zero-length opaque (empty `nfs_fh3`)
- NFSv4: `PUTPUBFH` (already implemented in NFSWolf)

**Multi-component LOOKUP (MCL):** WebNFS servers accept a full slash-delimited path in one LOOKUP call against the public handle. Two encodings:
- Canonical: escaped ASCII, leading `/` = absolute from server root
- Native: `0x80` prefix, raw server pathname syntax, bypasses escaping entirely

**Path traversal:** The spec's own worked example is a `../` cross-export escape. It says only that MOUNT-only-checking servers "must return an error" for cross-export spans — no canonicalization algorithm is mandated. Explicit security note (p. 308): a WebNFS server "must not check the originating port" — waives the reserved-port heuristic AUTH_SYS deployments rely on.

**Attack chain:**
1. Send LOOKUP against the public handle with path `../../../etc/shadow`
2. If the server returns a file handle, READ the file
3. If `--allow-write`, WRITE to files outside the export

**NFSWolf integration:** Fits into the `escape` subcommand as a first-try before handle forging. Cheaper than `FileHandleAnalyzer` — no filesystem fingerprinting, no inode guessing, one RPC call. Fall back to the existing ext4/xfs/btrfs escape if the server rejects the public handle. `Nfs2Client` and `Nfs3Client` already have LOOKUP — the only new thing is constructing the public handle constant.

**What NFSWolf has today:** `PUTPUBFH` for NFSv4 (already in `crates/nfswolf-nfs4/src/wire.rs`). No v2/v3 public handle probe. The `check_webnfs_public_handle` function in `src/engine/analyzer.rs` exists but has a proxy bypass bug (documented in CRATE-DESIGN.md's SOCKS5 section).

### Wire format (C702 Appendix E, pp 307-316; RFC 2054/2055)

WebNFS does not define new RPC procedures or a new program number. It extends the existing NFSv2 and NFSv3 LOOKUP procedures with two mechanisms: (1) well-known public filehandle constants that replace the MOUNT protocol's role of providing an initial handle, and (2) multi-component path encoding in the LOOKUP filename argument when that argument is directed at the public filehandle. Everything runs over the standard NFS program (100003) on port 2049 (C702 ssE.3, p. 307).

**Transport (C702 ssE.2, p. 307):** TCP first, UDP fallback. The spec mandates that a WebNFS client "must first attempt to connect to its server with a TCP connection" and fall back to UDP only if the TCP connection is refused (p. 307). The client assumes port 2049 for both transports and must not contact the portmapper unless port 2049 is unresponsive on both TCP and UDP (C702 ssE.3, p. 307).

**Authentication:** The spec does not mandate a specific auth flavor for public handle operations. AUTH_SYS (AUTH_UNIX) is the default. AUTH_NONE is valid for public handle access on some implementations -- the spec's security model is weaker than standard NFS because it explicitly waives the reserved-port check (see below), and the public handle is designed for unauthenticated browser access. The spec says nothing to prevent AUTH_NONE from being used with public filehandle LOOKUPs.

#### Public filehandle constants (C702 ssE.5, pp 308)

The public filehandle is a reserved filehandle value with well-known encoding per NFS version. The server recognizes it as a signal to enable MCL semantics rather than treating it as a normal directory handle (C702 ssE.5, p. 308).

**NFSv2 (C702 ssE.5.1, p. 308):** 32 bytes, all zero. On the wire this is the fixed `fhandle` opaque -- 32 bytes of `0x00`, no length prefix (NFSv2 handles are fixed-size):

```
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

**NFSv3 (C702 ssE.5.2, p. 308):** Zero-length `nfs_fh3`. The wire encoding is just the 4-byte XDR length field set to zero, with no data bytes following:

```
00 00 00 00
```

This is distinct from the v2 encoding: a v2 public handle is 32 zero bytes (a valid-looking handle that happens to be all zeros), while a v3 public handle is a zero-length opaque (an explicitly empty handle). This distinction matters for version detection -- see error semantics below.

**NFSv4 (RFC 7530 ss16.21):** `PUTPUBFH` (op 23) in a COMPOUND request. No wire-level handle constant -- the operation itself semantically places the public filehandle in the current filehandle slot. Already implemented in NFSWolf's `nfswolf-nfs4` crate.

#### Multi-component LOOKUP encoding (C702 ssE.6, pp 309-310)

MCL is supported *only* for LOOKUP requests directed at the public filehandle (p. 309). A standard LOOKUP against a non-public handle must still use single-component filenames. The MCL path is carried in the normal LOOKUP `filename` argument (NFSv2: the `name` field of `diropargs`; NFSv3: the `name` field of `diropargs3`).

Two path encodings are defined, distinguished by the first byte of the filename:

**Canonical path (first byte is ASCII, C702 ssE.6.1, p. 309):** A hierarchical slash-separated path using printable US-ASCII. The escaping rules are:

| Character | Encoding | Notes |
|-----------|----------|-------|
| `/` within a component | `%2f` | literal slash in a filename, not a path separator (p. 309) |
| non-ASCII byte | `%xx` | 2-digit hex code, same as RFC 1738 percent-encoding (p. 309) |
| literal `%` not introducing a hex code | `%25` | disambiguates from escape sequences (p. 309) |

Path evaluation depends on the first character:

- **Leading `/` = absolute from server root** (p. 309): The canonical path is evaluated starting from the server's filesystem root directory, not from the public filehandle's directory. Example: `LOOKUP FH=0x0 "/etc/shadow"` resolves `/etc/shadow` from the server root.
- **No leading `/` = relative to public filehandle's directory** (p. 309): The path is evaluated relative to whatever directory the server administrator attached the public filehandle to. Example: if the public filehandle points to `/export/data`, then `LOOKUP FH=0x0 "secrets/key"` resolves `/export/data/secrets/key`.
- **Empty path = lookup for "."** (p. 309): If the url-path is omitted, the client must send an MCL for the pathname `"."` (dot), which returns the filehandle for the public filehandle's directory itself.

**Native path (first byte is 0x80, C702 ssE.6.1, pp 309-310):** The byte `0x80` (non-ASCII) is a prefix flag; the remaining bytes are a path in the server's native pathname syntax, bypassing canonical escaping entirely. This is designed for servers whose native path separator is not `/`. The spec's example (p. 310):

```
Canonical:  LOOKUP FH=0x0 "/a/b/c"      (slash-separated)
Native:     LOOKUP FH=0x0 0x80 "a:b:c"  (server uses : as separator)
```

The `0x80` prefix is the first byte of the LOOKUP `filename` argument. The server strips it and interprets the remainder as a raw server pathname. For UNIX-like servers, native and canonical forms are equivalent (both use `/`), but the native form skips percent-decoding.

**`..` traversal in MCL (C702 ssE.7.3, pp 312-313):** The spec's own worked example shows cross-export traversal using `..` in an MCL path:

```
LOOKUP 0x0  "../that/file"
LOOKUP 0x0  "/export/that/file"
```

Both paths attempt to reach a file in `/export/that` when the public filehandle is associated with `/export/this`. The spec states that MOUNT-only-checking servers "cannot return a filehandle without an assurance that the client's use of this filehandle will be authorized" and therefore "must return an error" (p. 313). However, servers that check client access per-request (rather than relying solely on MOUNT) "can return filehandles for paths that span exports" (p. 313) -- these servers are explicitly permitted to resolve cross-export `..` traversals. No canonicalization algorithm is mandated by the spec; the server is free to resolve `..` however it sees fit.

#### Error semantics (C702 ssE.9, p. 315; ssE.10, p. 316)

**Public handle rejection (p. 315):** If the server returns `NFS3ERR_STALE`, `NFS3ERR_INVAL`, or `NFS3ERR_BADHANDLE` in response to a LOOKUP with the public filehandle, the server does not support WebNFS. The client must fall back to the portmapper + MOUNT protocol path. For NFSWolf, these three errors on a public-handle LOOKUP are a negative fingerprint: the server definitely does not support WebNFS.

- `NFS3ERR_STALE` (70): The server treated the public handle as a real handle lookup and found no matching inode/generation. Common response from servers that have never heard of WebNFS.
- `NFS3ERR_BADHANDLE` (10001): The server recognized the handle format as invalid. This is the expected response from NFSv3 servers that reject the zero-length handle outright.
- `NFS3ERR_INVAL` (22): The server considered the LOOKUP arguments invalid. Some servers return this instead of BADHANDLE for a zero-length handle.

**Version fallback (p. 315):** If the server returns `RPC PROG_MISMATCH`, the client should retry with a v2 public filehandle (32 zero bytes). The first LOOKUP attempt should always be NFSv3.

**Cross-export errors (pp 312-313):** When a multi-component path or embedded symlink crosses into a different exported filesystem, the behavior depends on the server's access-checking model:

- MOUNT-only servers: must return an error (the spec does not specify which `nfsstat` code; in practice, `NFS3ERR_ACCES` or `NFS3ERR_STALE`).
- Per-request-checking servers: may return a valid filehandle for the cross-export destination. The client can then use that handle for subsequent operations, subject to per-call access checks.

**Non-exported path errors (p. 309, p. 311):** If the path identifies a file or directory that is not in any exported filesystem, the server "must return an error" (p. 311). The spec does not specify the error code. If the path reaches an exported filesystem through an unexported intermediate directory, the behavior is implementation-defined: the spec's example (p. 314) shows that `LOOKUP 0x0 "export"` returns an error (unexported dir) while `LOOKUP 0x0 "export/foo"` returns a valid handle (the destination `/export/foo` is exported, even though `/export` is not).

#### Security notes from the spec (C702 ssE.4, p. 308; ssE.7.3, pp 312-313)

**Reserved-port waiver (C702 ssE.4, p. 308):** "WebNFS clients are not required to use reserved ports. This means that a WebNFS server must not check the originating port for requests to filesystems which are made available to WebNFS clients." This explicitly waives the reserved-port check (`insecure` in Linux export options, `resvport` in Solaris) for WebNFS-enabled exports. The security implication: any unprivileged user process on any machine can send NFS requests to a WebNFS-enabled export, removing the weak-but-nonzero barrier that port < 1024 checks provide against credential spoofing.

**MOUNT-only-checking admission (C702 ssE.7.3, pp 312-313):** The spec explicitly acknowledges the broken implementation pattern: "Many NFS server implementations rely on the MOUNT protocol for checking access to exported filesystems, and their NFS server does no access checking. The NFS server assumes that the filehandle does double duty: identifying a file as well as being a security token." WebNFS bypasses MOUNT entirely, so on these servers, obtaining a filehandle via the public handle + MCL gives unrestricted access -- the filehandle *is* the authorization, and no MOUNT ACL check ever ran.

**No portmapper required (C702 ssE.3, p. 307):** WebNFS clients connect directly to port 2049 without querying the portmapper. This means WebNFS access works even when the portmapper (port 111) is firewalled, making it harder to detect and harder to filter. A firewall rule blocking port 111 does not prevent WebNFS access.

#### NFSv2 WebNFS procedure: no new procedure number (RFC 2054 ss5-6; C702 ssE.6, p. 309)

RFC 2054 (WebNFS Client Specification for NFSv2) does **not** define a new `NFSPROC_LOOKUP_MULTI` or any other new procedure. WebNFS reuses the existing `NFSPROC_LOOKUP` (procedure 4, program 100003, version 2) unchanged. The multi-component behavior is triggered by the *filehandle*, not the procedure number: when the server receives a LOOKUP with the public filehandle (32 zero bytes), it interprets the filename argument as a multi-component path. When the same LOOKUP is used with any other filehandle, it expects a single component as usual. The same applies to NFSv3 per RFC 2055: `NFSPROC3_LOOKUP` (procedure 3) is reused unchanged.

This means NFSWolf does not need to implement any new RPC procedure to probe for WebNFS. The existing `Nfs2Client::lookup()` and `Nfs3Client` LOOKUP are sufficient -- the only new wire-level construct is the public filehandle constant itself.

#### Implementation variations

| Server | WebNFS support | Notes |
|--------|---------------|-------|
| **Solaris** (2.6+, 1997) | Full | Canonical implementation. Sun developed WebNFS. `share -F nfs -o public` sets the public filehandle root. Supports MCL (canonical and native), export-spanning paths (per-request access checks), and `..` traversal. The reference implementation for all C702 Appendix E semantics. |
| **Linux knfsd** | None | Never implemented. No `CONFIG_NFSD_WEBNFS` kernel option was ever merged. The kernel NFS server does not recognize the all-zero v2 handle or zero-length v3 handle as public filehandle constants. v3 zero-length handle returns `NFS3ERR_BADHANDLE`; v2 all-zero handle returns `NFS3ERR_STALE` (or `NFSERR_STALE` in v2 terms). This makes a WebNFS probe a reliable negative fingerprint: if the public handle is rejected, the server is almost certainly Linux. |
| **NetApp ONTAP** | Optional | ONTAP supports WebNFS public handles. Controlled via `nfs.webnfs.enable` (7-mode) or `vserver nfs modify -v3-webnfs-enabled` (C-mode). Default is disabled. When enabled, the public filehandle root is configurable. |
| **FreeBSD** | None | FreeBSD's kernel NFS server (`nfsd`) does not implement WebNFS public handles. Same rejection behavior as Linux -- zero-length v3 handle returns `NFS3ERR_BADHANDLE`. |
| **OpenBSD / NetBSD** | None | No WebNFS support in either kernel NFS server. |
| **illumos** (OpenSolaris derivatives) | Full | Inherited from Solaris. Same `share -o public` configuration. SmartOS, OmniOS, and other illumos distributions retain full WebNFS support. |

**Fingerprinting value:** Since Linux and FreeBSD (the two most common NFS server platforms today) both reject public handles with distinctive error codes, a WebNFS probe doubles as an OS/platform fingerprint. A successful public-handle LOOKUP strongly suggests Solaris/illumos or a NetApp filer with WebNFS explicitly enabled -- both high-value targets in enterprise environments.

---

## PCNFSD — password oracle and code execution

**Spec:** D030 "Protocols for X/Open PC Interworking: (PC)NFS" (1990), pp. 88–108.

**Program:** 150001, version 1. 4 procedures. UDP only. Registered through portmapper — surfaces in a plain `PMAPPROC_DUMP`.

### `PCNFSD_AUTH` (proc 1) — password oracle

Takes username (≤32 bytes) + password (≤64 bytes), "obfuscated" via XOR 0x5b + AND 0x7f. The spec says this is "not [intended] to be secure but to defeat 'browsers'" — the algorithm is published in-spec and trivially reversible. Returns:

- `AUTH_RES_OK` + real uid/gid — successful authentication
- `AUTH_RES_FAKE` + synthesized uid/gid — spec-sanctioned **fail-open** mode, hands back a usable identity even on failed auth
- `AUTH_RES_FAIL` — authentication failed

No rate limiting, no lockout, no replay protection, no audit. Credentials restricted to 7-bit ASCII, narrowing brute-force keyspace. Combined with AUTH_SYS credential forging, a successful `PCNFSD_AUTH` gives you a legitimate uid/gid to assert on NFS operations.

### `PCNFSD_PR_START` (proc 3) — code execution

Accepts a bare client-supplied username with zero cryptographic link to whatever `PCNFSD_AUTH` verified. The spec's reference implementation "changes effective user identity to that given by `user` if possible" and spawns a subprocess. The spool filename is asserted to be "a simple name, not a path" with no described validation — path traversal is plausible in period implementations. The `r` (raw) option passes client bytes unfiltered into the local print pipeline.

**On a server running pcnfsd, this is unauthenticated command execution under an arbitrary user identity.** Rare on modern systems but legacy SunOS/Solaris PC-NFS gateways persist in enterprise environments.

**NFSWolf integration:** Detection is trivial — portmapper DUMP for program 150001. Full exploitation (auth brute-force, print spool code execution) is a bigger scope call, best treated like `uid-spray` — explicit opt-in, not automatic.

### Wire format (D030 ss6.3-6.4, pp 93-101)

**Authentication (D030 ss6.4, p. 94):** AUTH_UNIX style authentication only.

**Transport (D030 ss6.4, p. 94):** UDP/IP only. Port number obtained from portmapper.

#### PCNFSD v1 procedure table (D030 ss6.4.3, p. 97)

Program 150001, version 1. 4 procedures.

| # | Procedure | Args | Result | Notes |
|---|-----------|------|--------|-------|
| 0 | `PCNFSD_NULL` | `void` | `void` | liveness probe (p. 98) |
| 1 | `PCNFSD_AUTH` | `auth_args` | `auth_results` | password oracle (p. 98) |
| 2 | `PCNFSD_PR_INIT` | `pr_init_args` | `pr_init_results` | initialize print spool directory (p. 99) |
| 3 | `PCNFSD_PR_START` | `pr_start_args` | `pr_start_results` | print a spooled file (p. 100) |

#### PCNFSD v1 XDR type declarations (D030 ss6.4.1-6.4.2, pp 94-97)

**Constants (p. 94):**

```xdr
const IDENTLEN       = 32;              /* max bytes in a user name argument */
const PASSWORDLEN    = 64;              /* max bytes in a password argument */
const CLIENTLEN      = 64;              /* max bytes in a print client name argument */
const PRINTERNAMELEN = 64;              /* max bytes in a printer name argument */
const USERNAMELEN    = 64;              /* max bytes in a print user name argument */
const SPOOLNAMELEN   = 64;              /* max bytes in a print spool file name argument */
const OPTIONSLEN     = 64;              /* max bytes in a print options argument */
const SPOOLDIRLEN    = 255;             /* max bytes in a print spool directory path */
```

**String types (pp 94-95):**

```xdr
typedef string ident<IDENTLEN>;                       /* p. 94, encoded user name */
typedef string password<PASSWORDLEN>;                 /* p. 95, encoded password */
typedef string client<CLIENTLEN>;                     /* p. 95, client hostname for printing */
typedef string printername<PRINTERNAMELEN>;            /* p. 95, printer name */
typedef string username<USERNAMELEN>;                  /* p. 95, print job user name */
typedef string spoolname<SPOOLNAMELEN>;                /* p. 95, spool file name (simple, not path) */
typedef string options<OPTIONSLEN>;                    /* p. 95, print options */
typedef string spooldir<SPOOLDIRLEN>;                  /* implied from SPOOLDIRLEN constant, p. 94 */
```

**`arstat` -- PCNFSD_AUTH status codes (p. 96):**

```xdr
enum arstat {                                          /* p. 96 */
    AUTH_RES_OK   = 0,     /* uid/gid verified and valid */
    AUTH_RES_FAKE = 1,     /* auth failed, but server synthesized acceptable uid/gid */
    AUTH_RES_FAIL = 2      /* authentication failed */
};
```

`AUTH_RES_OK` confirms the credential is valid and the returned uid/gid are real. `AUTH_RES_FAIL` is a hard denial. `AUTH_RES_FAKE` is the spec-sanctioned fail-open mode (p. 96): "the server has synthesised acceptable values for uid and gid which the client may use if it wishes." A server returning `AUTH_RES_FAKE` hands back a usable identity even on authentication failure.

**`pirstat` -- PCNFSD_PR_INIT status codes (pp 96-97):**

```xdr
enum pirstat {                                         /* p. 96 */
    PI_RES_OK              = 0,   /* spool directory created, dir is valid */
    PI_RES_NO_SUCH_PRINTER = 1,   /* printer name not recognized */
    PI_RES_FAIL            = 2    /* spool directory could not be created */
};
```

**`psrstat` -- PCNFSD_PR_START status codes (p. 97):**

```xdr
enum psrstat {                                         /* p. 97 */
    PS_RES_OK      = 0,   /* printing started, file responsibility transferred */
    PS_RES_ALREADY = 1,   /* file already being printed (lost reply, client retransmitted) */
    PS_RES_NULL    = 2,   /* spool file was empty, server deleted it */
    PS_RES_NO_FILE = 3,   /* spool file not found */
    PS_RES_FAIL    = 4    /* unspecified failure */
};
```

#### PCNFSD_AUTH XDR (D030 ss6.4.5, p. 98)

```xdr
struct auth_args {                                     /* p. 98 */
    ident    id;          /* user name (encoded) */
    password pw;          /* user password (encoded) */
};

struct auth_results {                                  /* p. 98 */
    arstat       stat;
    unsigned int uid;
    unsigned int gid;
};
```

**v1 vs v2 note:** D030 defines only PCNFSD v1. The `auth_args` struct has only `id` and `pw`; the `auth_results` struct has only `stat`, `uid`, and `gid`. Sun's later pcnfsd v2 implementation (not part of D030) extended `auth_args` with `system` and `comment` fields, and extended `auth_results` with `gids<>`, `homedir`, and `def_umask`. NFSWolf should target v1 first since it matches D030 and is the baseline all implementations support.

#### Password obfuscation algorithm (D030 ss6.4.2.1, pp 95, 98-99)

Both the `ident` (username) and `password` fields in `auth_args` are obfuscated before transmission. The spec describes the decoding formula (p. 95):

> "The server should decode the string by replacing each octet with the value formed by performing an exclusive-or of the octet value with the value 0x5b, and *and*ing the result with 0x7f."

The formula per byte:

```
decoded_byte = (encoded_byte XOR 0x5b) AND 0x7f
```

Since XOR 0x5b is its own inverse and the AND 0x7f mask is idempotent on 7-bit ASCII, the encoding formula is the same:

```
encoded_byte = (plaintext_byte XOR 0x5b) AND 0x7f
```

The spec notes (p. 99): "the username and password are restricted to 7 bit ASCII characters" -- the AND 0x7f strips the high bit, confining the character space to printable ASCII. This narrows brute-force keyspace to 95 printable characters per position.

**Worked example -- encoding "root":**

| Plaintext | Hex | XOR 0x5b | AND 0x7f | Encoded | Char |
|-----------|-----|----------|----------|---------|------|
| `r` | 0x72 | 0x29 | 0x29 | 0x29 | `)` |
| `o` | 0x6f | 0x34 | 0x34 | 0x34 | `4` |
| `o` | 0x6f | 0x34 | 0x34 | 0x34 | `4` |
| `t` | 0x74 | 0x2f | 0x2f | 0x2f | `/` |

The string "root" encodes as ")44/" on the wire. Decoding reverses identically: `(0x29 ^ 0x5b) & 0x7f = 0x72` = `r`.

The spec explicitly says this is "not [intended] to be secure but to defeat 'browsers'" (p. 93). The algorithm is published in the spec, trivially reversible, and uses no key material. Any network observer who knows the fixed constant 0x5b can decode credentials in real time.

#### PCNFSD_PR_INIT XDR (D030 ss6.4.6, p. 99)

```xdr
struct pr_init_args {                                  /* p. 99 */
    client      system;   /* client hostname */
    printername pn;        /* printer to initialize spool for */
};

struct pr_init_results {                               /* p. 99 */
    pirstat  stat;
    spooldir dir;          /* full pathname of spool directory */
};
```

The server creates a spool directory "which the client can mount using NFS" (p. 99) and returns its full pathname as `dir`. The return codes are `PI_RES_OK` (directory created, `dir` is valid), `PI_RES_NO_SUCH_PRINTER` (printer name not recognized), and `PI_RES_FAIL` (directory creation failed, p. 100).

#### PCNFSD_PR_START XDR (D030 ss6.4.7, p. 100)

```xdr
struct pr_start_args {                                 /* p. 100 */
    client      system;   /* client hostname (same as PR_INIT) */
    printername pr;        /* printer name (same as PR_INIT) */
    username    user;      /* user name for identity switch */
    spoolname   file;      /* spool file name (simple name, not a path) */
    options     opts;      /* print control options */
};

struct pr_start_results {                              /* p. 100 */
    psrstat stat;
};
```

**Spool file name assertion (p. 100):** The spec states that `file` "is a simple name (not a path) which identifies a file *within* this directory." No validation algorithm is described -- the assertion that the name is "simple" is a prose constraint with no specified enforcement. The reference implementation (pp. 100-101) uses `file` directly in file operations within the spool directory. Period implementations that fail to validate this field are vulnerable to path traversal via `../` sequences in the spool name.

**Identity switch in reference implementation (pp. 100-101):** The spec's reference implementation for `PCNFSD_PR_START` includes step 6: "In the sub-process, change effective user identity to that given by `user` if possible." The `user` field is a bare client-supplied string with no cryptographic binding to whatever `PCNFSD_AUTH` verified. The server trusts the client to supply the correct username -- an attacker can pass any `user` value to execute the print job under an arbitrary identity.

**Print options (p. 95):** The `opts` string's first character is reserved for client use (server ignores it). The second character specifies data type: `p` (PostScript), `d` (Diablo 630), `x` (generic printable ASCII), `r` (raw -- client performs no filtering). The `r` option passes client bytes unfiltered into the local print pipeline.

#### PCNFSD v1 program definition (D030 ss6.4.3, p. 97)

```xdr
/*
 * Protocol description for the PCNFSD program
 */
program PCNFSDPROG {
    /*
     * Version 1 of the PCNFSD protocol.
     */
    version PCNFSDVERS {
        void           PCNFSD_NULL(void) = 0;
        auth_results   PCNFSD_AUTH(auth_args) = 1;
        pr_init_results PCNFSD_PR_INIT(pr_init_args) = 2;
        pr_start_results PCNFSD_PR_START(pr_start_args) = 3;
    } = 1;
} = 150001;
```

---

## NLM — lock manipulation enabling writes

**Spec:** C702 ch. 10 (NLM v1/v3, pp. 127–159), ch. 14 (NLM v4, pp. 263–269).

**Program:** 100021, version 3 (24 procedures), version 4 (64-bit offsets for NFSv3 handles). AUTH_UNIX only (C702 §10.2, p. 128). NLM v4 also accepts AUTH_NONE/DES/KERB, but AUTH_UNIX remains legal, so the trust model is unchanged. UDP and TCP. No MOUNT prerequisite — operates purely on file handles as bearer tokens.

**NLM locks are advisory only** (C702 §9.1, p. 117): "strongly encouraged but not mandatory." NLM locks are never a filesystem-enforced boundary — a client using raw NFS READ/WRITE instead of the NLM client is completely unconstrained by any lock. NLM only matters as attack surface against *other* clients that honor advisory locking. No file-permission (mode-bit) check is documented anywhere in any lock/share procedure — possession of a file handle (a bearer token) is sufficient to lock, query, or share any file.

### `NLM_FREE_ALL` (proc 23) — unauthenticated bulk lock release

Takes `nlm_notify { name, state }` where `name` is a `caller_name` string (up to 1024 bytes) and `state` is unused (should be 0). Returns void — no status code, no acknowledgment. Releases **every** lock and share held on behalf of that hostname.

No binding between `name` and the caller's RPC source address or AUTH_UNIX identity. Over UDP (the default for PC clients per C702 §9.3), this is a single spoofable datagram that evicts all locks belonging to an arbitrary hostname.

**Attack value for writes:** If an application relies on advisory locking for write coordination (databases, config management, log aggregators), releasing the legitimate client's locks enables concurrent writes. The attack chain:
1. `NLM_TEST` on known files to discover lock holders (`caller_name`, PID, byte range)
2. `MNTPROC_DUMP` (already in NFSWolf) to harvest client hostnames
3. `NLM_FREE_ALL` with the victim's `caller_name`
4. Write to the now-unlocked file via NFS

### `NLM_TEST` (proc 1) — lock holder enumeration

No prior lock or MOUNT needed. On `LCK_DENIED`, returns `nlm_holder { exclusive, uppid, oh, l_offset, l_len }` — leaks whether the lock is exclusive, the holder's PID, an opaque owner handle identifying the host/process, and the exact byte range. Pure recon against any file handle.

### `NLM_TEST` → `NLM_UNLOCK` spoofing chain

`NLM_CANCEL`/`NLM_UNLOCK` match on `caller_name + fh + oh + uppid`, and the spec explicitly permits granting even when `alock.oh` doesn't match the outstanding lock holder (C702 pp. 140–141). Since `NLM_TEST` leaks a victim's `oh`/`uppid`, the full chain is:
1. `NLM_TEST` against a file handle to harvest the lock holder's `caller_name`, `oh`, `uppid`, and byte range
2. `NLM_UNLOCK` with the victim's `caller_name` and the leaked `oh`/`uppid` to release their lock
3. Write to the now-unlocked file via NFS

This is a more targeted variant of `NLM_FREE_ALL` — it releases a specific lock rather than all locks for a hostname.

### `NLM_GRANTED` (proc 5) — callback injection via blocked locks

When a blocking lock request (`NLM_LOCK` with `block=true`) cannot be granted immediately, the server calls back to the client via `NLM_GRANTED` when the lock becomes available. The callback target is derived from the `caller_name` in the original lock request. This is a second callback-injection angle distinct from NSM's `SM_MON` — if `caller_name` can be used to redirect where the callback lands, it becomes another outbound-connection coercion primitive.

### Grace-period DoS

Triggering (or spoofing a notification of) a server NLM restart forces a ~45-second window (C702 §10.1.2, p. 127) where all new lock requests return `LCK_DENIED_GRACE_PERIOD`. This is a DoS against every locking client on that server and a timing oracle to fingerprint a recent server reboot.

### `NLM_SHARE` (proc 20) — persistent DoS via unmonitored share reservations

DOS-compatible share reservations keyed on `fh + oh + caller_name`. Share modes: `fsm_DN` (deny none), `fsm_DR` (deny read), `fsm_DW` (deny write), `fsm_DRW` (deny read/write). Explicitly non-monitored (C702 §10.1.3) — "the lock manager will make no attempt to verify that the reservation is still valid." A single `NLM_SHARE` with `fsm_DRW` against a target handle permanently denies read/write to other DOS-aware clients. Release requires a matching `NLM_UNSHARE` (needs the attacker's own `oh`/`caller_name`) or `NLM_FREE_ALL`. Persistent single-packet DoS.

### `NLM_NM_LOCK` (proc 22) — non-monitored lock

Same as `NLM_LOCK` but explicitly non-monitored. Recovery depends solely on the client calling `NLM_FREE_ALL`. If the client dies without doing so, the lock leaks forever on the server.

### NLM v4 delta (ch. 14)

64-bit `l_offset`/`l_len` (pairs with NFSv3 handles up to 64 bytes). New status codes: `NLM4_ROFS`, `NLM4_STALE_FH`, `NLM4_FBIG`, `NLM4_FAILED`. Same disclosure and abuse surface as v1/v3 — no new auth or callback mechanism.

### Async `_MSG` procedures (procs 6–15)

Fire-and-forget over UDP — the server does not send an RPC-layer reply. Instead, it sends a separate RPC call back via the `_RES` procedure. Spoofed-source UDP abuse leaves no ack to correlate.

### `caller_name` identity model

`caller_name` in `nlm_lock`/`nlm_share` and `name` in `nlm_notify` are raw client-supplied strings (max 1024 bytes), used as the sole bookkeeping key for lock ownership. Never validated against RPC source address or AUTH_UNIX `machinename`. An attacker can frame a real hostname in lock ownership records and later release those locks with `NLM_FREE_ALL`.

### Wire format (C702 ch 10, pp 127-159; ch 14, pp 263-269)

**Authentication (C702 ss10.2, p. 128):** NLM v1/v3 uses AUTH_UNIX only. NLM v4 (C702 ss14.2, p. 264) accepts AUTH_NONE for the NULL procedure; AUTH_UNIX, AUTH_DES, or AUTH_KERB for all other procedures. AUTH_UNIX remains legal in v4, so the trust model is unchanged.

**Transport (C702 ss10.2, p. 128):** UDP/IP and TCP/IP. Client implementations may choose to only generate requests over UDP. PC clients "will always use UDP" (C702 ss9.3, p. 121).

#### NLM v3 procedure table (C702 ss10.3, p. 134)

Program 100021, version 3. 24 procedures (numbers 16-19 are a gap -- not defined).

| # | Procedure | Args | Result | Notes |
|---|-----------|------|--------|-------|
| 0 | `NLM_NULL` | `void` | `void` | liveness probe |
| 1 | `NLM_TEST` | `nlm_testargs` | `nlm_testres` | synchronous lock test |
| 2 | `NLM_LOCK` | `nlm_lockargs` | `nlm_res` | synchronous monitored lock |
| 3 | `NLM_CANCEL` | `nlm_cancargs` | `nlm_res` | cancel outstanding blocked lock |
| 4 | `NLM_UNLOCK` | `nlm_unlockargs` | `nlm_res` | release lock |
| 5 | `NLM_GRANTED` | `nlm_testargs` | `nlm_res` | **callback: server -> client** (blocked lock granted) |
| 6 | `NLM_TEST_MSG` | `nlm_testargs` | `void` | async _MSG -- no RPC reply |
| 7 | `NLM_LOCK_MSG` | `nlm_lockargs` | `void` | async _MSG |
| 8 | `NLM_CANCEL_MSG` | `nlm_cancargs` | `void` | async _MSG |
| 9 | `NLM_UNLOCK_MSG` | `nlm_unlockargs` | `void` | async _MSG |
| 10 | `NLM_GRANTED_MSG` | `nlm_testargs` | `void` | async callback _MSG (server -> client) |
| 11 | `NLM_TEST_RES` | `nlm_testres` | `void` | async _RES (server -> client response) |
| 12 | `NLM_LOCK_RES` | `nlm_res` | `void` | async _RES |
| 13 | `NLM_CANCEL_RES` | `nlm_res` | `void` | async _RES |
| 14 | `NLM_UNLOCK_RES` | `nlm_res` | `void` | async _RES |
| 15 | `NLM_GRANTED_RES` | `nlm_res` | `void` | async _RES (client -> server ack) |
| 20 | `NLM_SHARE` | `nlm_shareargs` | `nlm_shareres` | v3 only, DOS file-sharing, non-monitored |
| 21 | `NLM_UNSHARE` | `nlm_shareargs` | `nlm_shareres` | v3 only, release share reservation |
| 22 | `NLM_NM_LOCK` | `nlm_lockargs` | `nlm_res` | v3 only, non-monitored lock |
| 23 | `NLM_FREE_ALL` | `nlm_notify` | `void` | v3 only, bulk release all locks/shares for a hostname |

**Spec erratum (p. 150):** The `NLM_LOCK_RES` individual reference page lists its procedure number as 11, but the program definition on p. 134 assigns it procedure 12 (and `NLM_TEST_RES` is already 11). The program definition is authoritative.

**Async procedures (procs 6-15, C702 ss10.3, pp 135, 143-153):** The `_MSG` procedures send no RPC-layer reply. The receiving NLM queues the request and delivers the result via the corresponding `_RES` procedure as a separate RPC call. Most NLM implementations do not send RPC-layer replies to async procedures -- clients must not expect an RPC reply with the matching XID but instead must expect a separate `_RES` RPC call from the server (p. 135).

#### NLM v3 XDR type declarations (C702 ss10.2, pp 128-133)

**Constants (p. 128):**

```xdr
/* The maximum length of the string identifying the caller. */
const LM_MAXSTRLEN = 1024;

/* The maximum number of bytes in the nlm_notify name argument. */
const LM_MAXNAMELEN = LM_MAXSTRLEN+1;

const MAXNETOBJ_SZ = 1024;
```

**Locking types (pp 128-131):**

```xdr
opaque netobj<MAXNETOBJ_SZ>;                          /* p. 128 */

enum nlm_stats {                                      /* p. 128 */
    LCK_GRANTED          = 0,
    LCK_DENIED           = 1,
    LCK_DENIED_NOLOCKS   = 2,
    LCK_BLOCKED          = 3,
    LCK_DENIED_GRACE_PERIOD = 4
};

struct nlm_stat {                                     /* p. 129 */
    nlm_stats stat;
};

struct nlm_res {                                      /* p. 129 */
    netobj cookie;
    nlm_stat stat;
};

struct nlm_holder {                                   /* p. 129 */
    bool exclusive;
    int uppid;
    netobj oh;
    unsigned l_offset;
    unsigned l_len;
};

union nlm_testrply switch (nlm_stats stat) {          /* p. 130 */
    case LCK_DENIED:
        struct nlm_holder holder;    /* holder of the lock */
    default:
        void;
};

struct nlm_testres {                                  /* p. 130 */
    netobj cookie;
    nlm_testrply test_stat;
};

struct nlm_lock {                                     /* p. 130 */
    string caller_name<LM_MAXSTRLEN>;
    netobj fh;          /* identify a file    */
    netobj oh;          /* identify owner of a lock */
    int uppid;          /* Unique process identifier */
    unsigned l_offset;  /* File offset (for record locking) */
    unsigned l_len;     /* Length (size of record) */
};

struct nlm_lockargs {                                 /* p. 130 */
    netobj cookie;
    bool block;          /* Flag to indicate blocking behaviour. */
    bool exclusive;      /* If exclusive access is desired. */
    struct nlm_lock alock; /* The actual lock data (see above) */
    bool reclaim;        /* used for recovering locks  */
    int state;           /* specify local NSM state */
};

struct nlm_cancargs {                                 /* p. 131 */
    netobj cookie;
    bool block;
    bool exclusive;
    struct nlm_lock alock;
};

struct nlm_testargs {                                 /* p. 131 */
    netobj cookie;
    bool exclusive;
    struct nlm_lock alock;
};

struct nlm_unlockargs {                               /* p. 131 */
    netobj cookie;
    struct nlm_lock alock;
};
```

**DOS file-sharing types (v3 only, pp 131-133):**

```xdr
enum fsh_mode {                                       /* p. 131 */
    fsm_DN  = 0,          /* deny none       */
    fsm_DR  = 1,          /* deny read       */
    fsm_DW  = 2,          /* deny write      */
    fsm_DRW = 3           /* deny read/write */
};

enum fsh_access {                                     /* p. 132 */
    fsa_NONE = 0,         /* for completeness */
    fsa_R    = 1,         /* read-only        */
    fsa_W    = 2,         /* write-only       */
    fsa_RW   = 3          /* read/write       */
};

struct nlm_share {                                    /* p. 132 */
    string caller_name<LM_MAXSTRLEN>;
    netobj fh;
    netobj oh;
    fsh_mode mode;
    fsh_access access;
};

struct nlm_shareargs {                                /* p. 132 */
    netobj cookie;
    nlm_share share;       /* actual share data */
    bool reclaim;          /* used for recovering shares */
};

struct nlm_shareres {                                 /* p. 132 */
    netobj cookie;
    nlm_stats stat;
    int sequence;
};

struct nlm_notify {                                   /* p. 133 */
    string name<LM_MAXNAMELEN>;
    long state;
};
```

**`nlm_notify.state` type discrepancy:** The type definition on p. 133 declares `long state` but the `NLM_FREE_ALL` procedure reference page on p. 159 declares `unsigned int state`. Functionally the field is unused (spec says "should be set to 0"), so the discrepancy is inconsequential for implementation -- encode as `unsigned int` (XDR `unsigned`) for interoperability since that is what the procedure page specifies.

#### NLM v3 program definition (C702 ss10.3, p. 134)

```xdr
/*
 * NLM procedures
 */
program NLM_PROG {
    version NLM_VERSX {
        /*
         * synchronous procedures
         */
        void        NLM_NULL(void) = 0;
        nlm_testres NLM_TEST(struct nlm_testargs) = 1;
        nlm_res     NLM_LOCK(struct nlm_lockargs) = 2;
        nlm_res     NLM_CANCEL(struct nlm_cancargs) = 3;
        nlm_res     NLM_UNLOCK(struct nlm_unlockargs) = 4;

        /*
         * server NLM call-back procedure to grant lock
         */
        nlm_res     NLM_GRANTED(struct nlm_testargs) = 5;

        /*
         * asynchronous requests and responses
         */
        void        NLM_TEST_MSG(struct nlm_testargs) = 6;
        void        NLM_LOCK_MSG(struct nlm_lockargs) = 7;
        void        NLM_CANCEL_MSG(struct nlm_cancargs) = 8;
        void        NLM_UNLOCK_MSG(struct nlm_unlockargs) = 9;
        void        NLM_GRANTED_MSG(struct nlm_testargs) = 10;
        void        NLM_TEST_RES(nlm_testres) = 11;
        void        NLM_LOCK_RES(nlm_res) = 12;
        void        NLM_CANCEL_RES(nlm_res) = 13;
        void        NLM_UNLOCK_RES(nlm_res) = 14;
        void        NLM_GRANTED_RES(nlm_res) = 15;

        /*
         * synchronous non-monitored lock and DOS file-sharing
         * procedures (not defined for version 1 and 2)
         */
        nlm_shareres NLM_SHARE(nlm_shareargs) = 20;
        nlm_shareres NLM_UNSHARE(nlm_shareargs) = 21;
        nlm_res      NLM_NM_LOCK(nlm_lockargs) = 22;
        void         NLM_FREE_ALL(nlm_notify) = 23;
    } = 3;
} = 100021;
```

#### NLM v4 deltas (C702 ch 14, pp 263-269)

NLM v4 is used exclusively with NFSv3 (NLM v3 is used with NFSv2). Same program number (100021), version 4. Same 24 procedures with `NLMPROC4_` prefix. The semantic differences are:

**Widened offset/length fields (pp 265-266):** `l_offset` and `l_len` in `nlm4_holder`, `nlm4_lock`, and related structs are `uint64` (XDR `unsigned hyper`) instead of `unsigned` (32-bit). This supports NFSv3's 64-bit file offsets.

**Renamed process ID field:** `uppid` (NLM v3) is renamed to `svid` (NLM v4) with type `int32` instead of `int`. Same semantics.

**File handle encoding change (p. 266):** In NLM v3 the `fh` netobj carries a fixed 32-byte NFSv2 fhandle. In NLM v4 the `fh` netobj carries a variable-length NFSv3 `nfs_fh3`: the first 4 bytes are the byte count, followed by the handle bytes (identical to the `nfs_fh3` wire encoding). The lock manager must distinguish v2 and v3 handles when both NLM v3 and v4 clients coexist.

**New status codes (p. 264):**

```xdr
enum nlm4_stats {                                     /* p. 264 */
    NLM4_GRANTED              = 0,
    NLM4_DENIED               = 1,
    NLM4_DENIED_NOLOCKS       = 2,
    NLM4_BLOCKED              = 3,
    NLM4_DENIED_GRACE_PERIOD  = 4,
    NLM4_DEADLCK              = 5,  /* new: would cause a deadlock */
    NLM4_ROFS                 = 6,  /* new: read-only file system */
    NLM4_STALE_FH             = 7,  /* new: invalid file handle */
    NLM4_FBIG                 = 8,  /* new: offset/length exceeds range */
    NLM4_FAILED               = 9   /* new: catch-all, strong hint not to retry */
};
```

**v4 key struct definitions (pp 265-266):**

```xdr
typedef unsigned hyper uint64;                        /* p. 264 */
typedef hyper int64;
typedef unsigned long uint32;
typedef long int32;

struct nlm4_holder {                                  /* p. 265 */
    bool exclusive;
    int32 svid;
    netobj oh;
    uint64 l_offset;
    uint64 l_len;
};

struct nlm4_lock {                                    /* p. 266 */
    string caller_name<LM_MAXSTRLEN>;
    netobj fh;
    netobj oh;
    int32 svid;
    uint64 l_offset;
    uint64 l_len;
};

struct nlm4_share {                                   /* p. 266 */
    string caller_name<LM_MAXSTRLEN>;
    netobj fh;
    netobj oh;
    fsh4_mode mode;
    fsh4_access access;
};
```

**v4 procedure definition (C702 ss14.3, p. 267):**

```xdr
version NLM4_VERS {
    void         NLMPROC4_NULL(void) = 0;
    nlm4_testres NLMPROC4_TEST(nlm4_testargs) = 1;
    nlm4_res     NLMPROC4_LOCK(nlm4_lockargs) = 2;
    nlm4_res     NLMPROC4_CANCEL(nlm4_cancargs) = 3;
    nlm4_res     NLMPROC4_UNLOCK(nlm4_unlockargs) = 4;
    nlm4_res     NLMPROC4_GRANTED(nlm4_testargs) = 5;
    void         NLMPROC4_TEST_MSG(nlm4_testargs) = 6;
    void         NLMPROC4_LOCK_MSG(nlm4_lockargs) = 7;
    void         NLMPROC4_CANCEL_MSG(nlm4_cancargs) = 8;
    void         NLMPROC4_UNLOCK_MSG(nlm4_unlockargs) = 9;
    void         NLMPROC4_GRANTED_MSG(nlm4_testargs) = 10;
    void         NLMPROC4_TEST_RES(nlm4_testres) = 11;
    void         NLMPROC4_LOCK_RES(nlm4_res) = 12;
    void         NLMPROC4_CANCEL_RES(nlm4_res) = 13;
    void         NLMPROC4_UNLOCK_RES(nlm4_res) = 14;
    void         NLMPROC4_GRANTED_RES(nlm4_res) = 15;
    nlm4_shareres NLMPROC4_SHARE(nlm4_shareargs) = 20;
    nlm4_shareres NLMPROC4_UNSHARE(nlm4_shareargs) = 21;
    nlm4_res     NLMPROC4_NM_LOCK(nlm4_lockargs) = 22;
    void         NLMPROC4_FREE_ALL(nlm4_notify) = 23;
} = 4;
```

**v4 NULL procedure (C702 ss14.3, p. 268):** `NLMPROC4_NULL` accepts AUTH_NONE and never requires authentication. The spec notes it "should never require any authentication" by convention (p. 268). All other v4 procedures require AUTH_UNIX, AUTH_DES, or AUTH_KERB.

---

## NSM — reboot spoofing and callback coercion

**Spec:** C702 ch. 11 (pp. 161–174).

**Program:** 100024, version 1. 7 procedures. AUTH_UNIX only. Required to support UDP; TCP optional.

### `SM_MON` (proc 2) — attacker-controlled callback registration

The caller specifies `my_id { my_name, my_prog, my_vers, my_proc }` — the RPC program/version/procedure to call back when the monitored host's state changes. An attacker registers a callback to their own address; when the target reboots, the server's NSM issues an `SM_NOTIFY` RPC to the attacker's chosen endpoint.

This is an outbound-connection coercion primitive — same class as NFSv4's `SETCLIENTID` callback but available on v2/v3 servers via the NSM sideband. Useful for relay attacks through firewalls, NTLM coercion on dual-homed Windows NFS servers, and confirming internal network topology from an external position.

### `SM_NOTIFY` (proc 6) — spoofable reboot notification

Takes `stat_chge { mon_name, state }`. Matching is pure string comparison on `mon_name` — no monotonicity check on the state number, no correlation secret, no privileged-port requirement. A spoofed `SM_NOTIFY` claiming a legitimate client has rebooted triggers the receiving NLM to release all locks held by that client name.

Combined with `NLM_FREE_ALL`, gives two independent paths to lock release: direct via NLM, or indirect via spoofed NSM reboot notification.

### `SM_SIMU_CRASH` (proc 5) — simulate local crash

Takes no arguments, returns void. Forces the local NSM to act as if the local host crashed — increments the state number and sends `SM_NOTIFY` to every host in its notify list. An attacker who can reach the local NSM can trigger a cascade of lock-recovery activity across every server the host has locks on.

### `SM_STAT` (proc 1) — host knowledge oracle

Returns `STAT_SUCC`/`STAT_FAIL` plus the NSM's own state number (even = down, odd = up). The state number encodes reboot count. Many implementations stub this to always return `STAT_FAIL` (spec says "implementations should not rely on this procedure"). When it works, confirms whether the NSM has been tracking a given hostname.

### NSM state model (C702 §9.1.2)

State is a bare monotonically-increasing integer per host — no crypto binding. NSM is purely passive and trusts each host to self-report its own crash via `SM_NOTIFY`. No independent verification that a host actually crashed. Recovery runs on the honor system.

### Wire format (C702 ch 11, pp 161-174)

**Authentication (C702 ss11.2, p. 162):** AUTH_UNIX only. No procedure requires stronger authentication.

**Transport (C702 ss11.2, p. 162):** Required to support UDP/IP (to support the NLM). TCP/IP support is optional for implementors. Most NSM implementations use TCP for local NLM<->NSM communication and for inter-NSM SM_NOTIFY exchanges, but must accept requests on either transport (C702 ss9.3, p. 121).

#### NSM procedure table (C702 ss11.3, p. 165)

Program 100024, version 1. 7 procedures.

| # | Procedure | Args | Result | Notes |
|---|-----------|------|--------|-------|
| 0 | `SM_NULL` | `void` | `void` | liveness probe |
| 1 | `SM_STAT` | `sm_name` | `sm_stat_res` | check if NSM agrees to monitor a host |
| 2 | `SM_MON` | `mon` | `sm_stat_res` | register monitoring + callback for a host |
| 3 | `SM_UNMON` | `mon_id` | `sm_stat` | stop monitoring a specific host |
| 4 | `SM_UNMON_ALL` | `my_id` | `sm_stat` | stop monitoring all hosts |
| 5 | `SM_SIMU_CRASH` | `void` | `void` | simulate a local crash -- triggers SM_NOTIFY cascade |
| 6 | `SM_NOTIFY` | `stat_chge` | `void` | notify that a monitored host's state changed |

#### NSM XDR type declarations (C702 ss11.2, pp 162-164)

**Constants (p. 162):**

```xdr
/*
 * This defines the maximum length of the string
 * identifying the caller.
 */
const SM_MAXSTRLEN = 1024;
```

**Data types (pp 162-164):**

```xdr
struct sm_name {                                      /* p. 162 */
    string mon_name<SM_MAXSTRLEN>;
};

enum res {                                            /* p. 162 */
    STAT_SUCC = 0,    /* NSM agrees to monitor.   */
    STAT_FAIL = 1     /* NSM cannot monitor.       */
};

struct sm_stat_res {                                  /* p. 163 */
    res  res_stat;
    int  state;
};

struct sm_stat {                                      /* p. 163 */
    int  state;       /* state number of NSM */
};

struct my_id {                                        /* p. 163 */
    string my_name<SM_MAXSTRLEN>;  /* hostname         */
    int    my_prog;                /* RPC program number  */
    int    my_vers;                /* program version number */
    int    my_proc;                /* procedure number    */
};

struct mon_id {                                       /* p. 163 */
    string mon_name<SM_MAXSTRLEN>; /* name of the host to be monitored */
    struct my_id my_id;
};

struct mon {                                          /* p. 163 */
    struct mon_id mon_id;
    opaque priv[16];              /* private information */
};

struct stat_chge {                                    /* p. 164 */
    string mon_name;
    int    state;
};
```

**SM_NOTIFY callback parameter (p. 173):** When an NSM receives an SM_NOTIFY and finds a matching host in its notify list, it calls the RPC specified in the original SM_MON's `my_id` field. The callback is made with this parameter:

```xdr
struct status {                                       /* p. 173 */
    string mon_name<SM_MAXSTRLEN>;
    int    state;
    opaque priv[16];              /* for private information */
};
```

Where `mon_name` and `state` are copied from the SM_NOTIFY parameters, and `priv` is the 16-byte opaque supplied in the original SM_MON call that registered the host `mon_name`. This is the mechanism by which the NLM receives crash notifications.

#### NSM program definition (C702 ss11.3, p. 165)

```xdr
/*
 * Protocol description for the NSM program.
 */
program SM_PROG {
    version SM_VERS {
        void            SM_NULL(void) = 0;
        struct sm_stat_res SM_STAT(struct sm_name) = 1;
        struct sm_stat_res SM_MON(struct mon) = 2;
        struct sm_stat  SM_UNMON(struct mon_id) = 3;
        struct sm_stat  SM_UNMON_ALL(struct my_id) = 4;
        void            SM_SIMU_CRASH(void) = 5;
        void            SM_NOTIFY(struct stat_chg) = 6;
    } = 1;
} = 100024;
```

**`stat_chg` vs `stat_chge` naming:** The program definition on p. 165 uses `stat_chg` (no trailing `e`) as the parameter type for SM_NOTIFY, while the type definition on p. 164 declares the struct as `stat_chge` (with trailing `e`). The two names refer to the same type. This appears to be a typo -- the type definition is the authoritative declaration.

#### State number semantics (C702 ss11.2, p. 163; ss9.1.2, p. 118)

The NSM state number is a bare integer with these properties:
- Monotonically increasing: incremented on every state change (crash and recovery cycle).
- **Even = host is down**, **odd = host is up** (C702 ss9.1.2, p. 118; ss11.2, p. 163).
- Stored on stable storage: survives crashes. On restart, the NSM reads the last value, increments to the next odd number, and writes it back (C702 ss9.4.1, p. 122).
- No cryptographic binding: the state number is a bare counter with no HMAC, nonce, or correlation secret. Any host that knows (or guesses) a plausible state number can forge an SM_NOTIFY.
- `SM_STAT` returns the local NSM's own state number, not the remote host's -- it reveals the local host's reboot count to any AUTH_UNIX caller.
- `SM_MON` returns the remote NSM's state number in `sm_stat_res.state` on success (p. 169), confirming reachability and leaking the remote host's reboot count.
- The NLM's `nlm_lockargs.state` field (p. 130) carries the client NSM's state number. The server NLM stores this and compares it against the state in a future SM_NOTIFY to determine whether locks should be discarded. Since neither field is authenticated, a spoofed SM_NOTIFY with any state number different from the stored value triggers lock release.

---

## RQUOTA — user enumeration

**Spec:** Sun `rquota.x`, XNFS. No RFC.

**Program:** 100011, versions 1 and 2.

`GETQUOTA` takes a path and a UID, returns disk usage and quota limits for that UID. If the UID exists, you get a real answer; if not, you get an error. This is a per-UID existence oracle — sweep a UID range and see which ones have quota entries. Returns `bsize`, `bhardlimit`, `bsoftlimit`, `curblocks`, `fhardlimit`, `fsoftlimit`, `curfiles` — disk usage that reveals which UIDs are active and how much data they own.

**NFSWolf integration:** Same UID-sweep pattern as `uid-spray`, but via RQUOTA instead of NFSv3 ACCESS. Useful on servers where NFS denies everything but RQUOTA is unrestricted.

### Security analysis

#### UID enumeration oracle mechanics

GETQUOTA's response discriminates between existing and non-existing UIDs through three distinct signals:

**Status code oracle.** The `qr_status` return value is the primary discriminant. `Q_OK` confirms the UID has a quota entry. `Q_NOQUOTA` is ambiguous -- it can mean the UID does not exist or that quotas are simply not configured for it. `Q_EPERM` is a weak positive: the server recognized the UID as meaningful enough to deny the request, which on most implementations means the UID exists in the local password database or NSS chain. The combination of `Q_OK` with `rq_curblocks > 0` or `rq_curfiles > 0` is the strongest confirmation that a UID exists and is actively using disk resources.

**Field-level information leaks.** When `Q_OK` is returned, every field in the `rquota` struct leaks something:

- `rq_curblocks` reveals the UID's current disk usage. A non-zero value proves the user is actively storing data. Large values (relative to `rq_bhardlimit`) indicate power users or service accounts with heavy I/O -- higher-priority targets for credential escalation because their files are more likely to contain sensitive data.
- `rq_curfiles` reveals the inode count. A UID with thousands of files is likely running a service (database, web app, mail spool) or has a deep home directory tree. Both patterns correlate with credentials, config files, and keys.
- `rq_bsize` leaks filesystem type. ext4 uses 4096. XFS uses 512 (block accounting in 512-byte sectors). ZFS uses 1024. BTRFS uses 4096. This narrows the escape strategy in `FileHandleAnalyzer` before even running the NFS escape: if RQUOTA says `bsize=512`, it is almost certainly XFS, and the XFS handle format should be tried first.
- `rq_bhardlimit` and `rq_bsoftlimit` reveal administrator intent. A UID with very high limits (or no limits, reported as 0) is likely a service account or privileged user. A UID with tight limits is likely a regular user.
- `rq_btimeleft` and `rq_ftimeleft` are non-zero only when the UID is currently over soft quota. This is a real-time activity indicator -- the user is actively writing data right now.

**Timing analysis.** On Linux `rpc.rquotad`, response time does not meaningfully differ between existing and non-existing UIDs. The quota lookup is a direct `quotactl(Q_GETQUOTA)` syscall regardless of UID existence -- the kernel checks the on-disk quota file (or in-memory cache) and returns `ESRCH` (mapped to `Q_NOQUOTA`) for missing entries at roughly the same speed as a cache-hit lookup. There is no observable timing side-channel in practice. Solaris behaves similarly -- the quota subsystem is synchronous and the lookup cost is dominated by disk I/O for the first access, then cached. Timing-based enumeration is not viable against current implementations.

**Rate limiting.** No known `rpc.rquotad` implementation enforces rate limiting on GETQUOTA calls. Linux `rpc.rquotad` dispatches every request synchronously with no per-client throttling, no connection tracking, and no request counter. The RPC layer (rpcbind/portmapper) does not rate-limit either. A UID sweep of the full 16-bit range (65536 queries) completes in seconds over TCP. The only practical limit is the portmapper's `securenets` or firewall rules blocking access to the RQUOTA port entirely.

#### Interaction with NFS

**Prioritizing UIDs for uid-spray.** RQUOTA results directly feed the credential ladder. Instead of blindly sweeping UIDs 0-65535, RQUOTA lets NFSWolf build a ranked list: UIDs with `Q_OK` and `rq_curblocks > 0` are confirmed active. Sorting by `rq_curblocks` descending puts the most active users first -- these are the UIDs most likely to own readable files on the NFS export. This is strictly better than the current `uid-spray` approach of linear UID scanning, which wastes time on system accounts and dormant users.

**curblocks/curfiles as activity ranking.** The most active users (highest `rq_curblocks` and `rq_curfiles`) are the best targets for credential escalation because: (a) they have the most files, increasing the probability of finding sensitive data; (b) they are more likely to have recently-modified files with credentials, SSH keys, or application secrets; (c) their GID memberships are more likely to grant access to shared directories. NFSWolf's `credential_ladder_with()` should accept RQUOTA-derived rankings as an input source alongside READDIRPLUS-harvested identities.

**RQUOTA on exports where NFS ACCESS is denied.** RQUOTA operates on a filesystem path, not on an NFS file handle. The `rpc.rquotad` daemon is a separate process from `nfsd` with its own access control (or lack thereof). In practice, `rpc.rquotad` performs no export-level ACL check -- it accepts any path that names a local filesystem with quotas enabled, regardless of whether the caller has NFS mount access to the export containing that path. This means RQUOTA can enumerate UIDs on filesystems the attacker cannot mount via NFS. The path argument in `getquota_args.gqa_pathp` is interpreted locally by `rpc.rquotad`, so the attacker needs to guess (or know from `showmount -e`) the server-side mount point (e.g., `/home`, `/export`). The NFS export path usually matches or is a subdirectory of the quota-enabled filesystem, so the export path from MOUNT EXPORT is a reasonable guess for the RQUOTA path argument.

#### v2 group quota: group membership without NIS

RQUOTA v2's `RQUOTA_GRPQUOTA` type extends the oracle to GIDs. The same sweep pattern applies: iterate GIDs 0-65535 with `gqa_type = RQUOTA_GRPQUOTA` and look for `Q_OK` responses. This reveals which GIDs have quota entries, meaning which groups exist and are actively used.

The security value is that group existence and activity is leaked without needing NIS access. On a system where NIS is not running (or is firewalled), RQUOTA v2 is an alternative path to group enumeration. Combined with v2 user quota results, an attacker can build a partial map of user-to-group relationships: if UID 1000 and GID 100 both have active quotas on the same filesystem, and READDIRPLUS on the NFS export shows files owned by uid=1000/gid=100, the UID is a member of that GID. This feeds directly into `uid-spray`'s GID parameter -- instead of guessing GIDs, the attacker can assert known-valid GIDs in AUTH_SYS credentials.

### Wire format (Sun rquota.x)

No RFC exists. The canonical source is Sun's `rquota.x` XDR file, distributed with SunOS/Solaris and adopted unchanged by Linux (`include/uapi/linux/sunrpc/` and `fs/nfsd/`) and FreeBSD. The wire format has been stable since the original Sun publication and is identical across all known implementations.

**Authentication:** AUTH_UNIX or AUTH_NONE. No implementation is known to require stronger auth. Linux `rpc.rquotad` accepts AUTH_UNIX for GETQUOTA and AUTH_NONE for NULL.

**Transport:** UDP and TCP. Most deployments register on both via portmapper.

#### RQUOTA v1 procedure table

Program 100011, version 1. 3 procedures.

| # | Procedure | Args | Result | Notes |
|---|-----------|------|--------|-------|
| 0 | `RQUOTAPROC_NULL` | `void` | `void` | liveness probe |
| 1 | `RQUOTAPROC_GETQUOTA` | `getquota_args` | `getquota_rslt` | return quota for a UID on a given path |
| 2 | `RQUOTAPROC_GETACTIVEQUOTA` | `getquota_args` | `getquota_rslt` | same but only if quotas are enabled |

`GETQUOTA` returns quota data whether or not quotas are enforced (the `rq_active` field indicates enforcement state). `GETACTIVEQUOTA` returns `Q_NOQUOTA` if quotas are disabled on the filesystem, making it a tighter oracle for active quota enforcement.

#### RQUOTA v2 procedure table

Program 100011, version 2. 3 procedures (same numbers, extended args).

| # | Procedure | Args | Result | Notes |
|---|-----------|------|--------|-------|
| 0 | `RQUOTAPROC_NULL` | `void` | `void` | liveness probe |
| 1 | `RQUOTAPROC_GETQUOTA` | `ext_getquota_args` | `getquota_rslt` | UID or GID quota by type field |
| 2 | `RQUOTAPROC_GETACTIVEQUOTA` | `ext_getquota_args` | `getquota_rslt` | same, active-only |

v2 adds a `gqa_type` field to distinguish user quotas from group quotas, and renames `gqa_uid` to `gqa_id` since the identifier may be a GID.

#### RQUOTA XDR type declarations (Sun rquota.x)

**Constants:**

```xdr
const RQ_PATHLEN = 1024;             /* max path length */
```

**Argument types:**

```xdr
struct getquota_args {                /* v1 only */
    string gqa_pathp<RQ_PATHLEN>;     /* export path (e.g. "/export") */
    int gqa_uid;                      /* uid to query */
};

/* v2 quota type selectors */
const RQUOTA_USRQUOTA = 0;           /* user quota */
const RQUOTA_GRPQUOTA = 1;           /* group quota */

struct ext_getquota_args {            /* v2 only */
    string gqa_pathp<RQ_PATHLEN>;     /* export path */
    int gqa_type;                     /* RQUOTA_USRQUOTA or RQUOTA_GRPQUOTA */
    int gqa_id;                       /* uid or gid */
};
```

**Quota data:**

```xdr
struct rquota {
    int rq_bsize;                     /* block size for interpreting block counts */
    bool rq_active;                   /* whether quotas are enforced */
    unsigned int rq_bhardlimit;       /* absolute limit on disk blocks allocated */
    unsigned int rq_bsoftlimit;       /* preferred limit on disk blocks */
    unsigned int rq_curblocks;        /* current block count */
    unsigned int rq_fhardlimit;       /* absolute limit on files allocated */
    unsigned int rq_fsoftlimit;       /* preferred file limit */
    unsigned int rq_curfiles;         /* current number of allocated files */
    unsigned int rq_btimeleft;        /* time remaining for excessive disk use (seconds) */
    unsigned int rq_ftimeleft;        /* time remaining for excessive file count (seconds) */
};
```

**Status codes and result union:**

```xdr
enum qr_status {
    Q_OK      = 1,                    /* quota returned successfully */
    Q_NOQUOTA = 2,                    /* no quota set for this uid/gid */
    Q_EPERM   = 3                     /* permission denied */
};

union getquota_rslt switch (qr_status status) {
    case Q_OK:
        rquota gqr_rquota;           /* quota data */
    default:
        void;                         /* no data on failure */
};
```

**Oracle behavior:** `Q_OK` with `rq_curblocks > 0` or `rq_curfiles > 0` confirms the UID/GID exists and is active. `Q_NOQUOTA` means no quota entry -- the UID may or may not exist (quotas may just not be configured for it). `Q_EPERM` confirms the server has an opinion about the queried identity (the request was meaningful enough to deny). For UID enumeration, `Q_OK` is the strong positive signal; `Q_EPERM` is a weaker positive (identity exists but access is denied).

#### RQUOTA v1 program definition (Sun rquota.x)

```xdr
program RQUOTAPROG {
    version RQUOTAVERS {
        void          RQUOTAPROC_NULL(void) = 0;
        getquota_rslt RQUOTAPROC_GETQUOTA(getquota_args) = 1;
        getquota_rslt RQUOTAPROC_GETACTIVEQUOTA(getquota_args) = 2;
    } = 1;
    version EXT_RQUOTAVERS {
        void          RQUOTAPROC_NULL(void) = 0;
        getquota_rslt RQUOTAPROC_GETQUOTA(ext_getquota_args) = 1;
        getquota_rslt RQUOTAPROC_GETACTIVEQUOTA(ext_getquota_args) = 2;
    } = 2;
} = 100011;
```

---

## NIS — credential store dump

**Spec:** Sun `yp.x`. No RFC.

**Program:** 100004 (ypserv), 100007 (ypbind). Version 2.

`YPPROC_ALL` on `passwd.byname` dumps the credential store outright, given the domain name. NIS maps are unauthenticated — `ypserv` is callable with AUTH_SYS from any host. If NIS is running on the same server as NFS (common in legacy Sun environments), the credential store is a portmapper query away.

Other useful maps: `group.byname` (group membership), `hosts.byname` (network topology), `netgroup` (export ACL groups), `mail.aliases`.

**NFSWolf integration:** Detection via portmapper DUMP (programs 100004, 100007). Domain name discovery via `ypbind` or from NIS domain in RPC broadcast responses. Full map dump as an explicit opt-in command.

### Security analysis

#### Domain name discovery methods

The NIS domain name is the single gatekeeper to every map in the credential store. Without it, `YPPROC_ALL` returns `YP_NODOM`. Four independent discovery methods exist:

**ypbind DOMAIN procedure.** `YPBINDPROC_DOMAIN` (program 100007, proc 1) takes a `domainname` argument and returns either a binding (ypserv IP + port) or failure. This is a domain-name oracle: iterate candidate domain names and check which ones return `YPBIND_SUCC_VAL`. Common candidates: the hostname's domain component, the DNS domain, short company names, "nis", "yp", lowercase variants of the FQDN. A successful response also leaks the ypserv IP and port, which may be on a different host than the one running ypbind.

**RPC broadcast for ypbind.** Sending an RPC broadcast (via portmapper `CALLIT` or direct broadcast to the ypbind port) with `YPPROC_DOMAIN_NONACK` reveals the domain name indirectly: `DOMAIN_NONACK` replies only on success, so any host that answers a broadcast for a given domain name confirms that domain exists on the network. This is noisier than unicast but discovers the domain without knowing it in advance -- the attacker broadcasts a list of guesses and collects which ones get responses. The responding hosts' IP addresses also reveal which machines are NIS clients.

**/etc/defaultdomain on NFS-exported filesystems.** On systems where NFS exports include `/etc` (or the root filesystem), the NIS domain name is stored in plaintext in `/etc/defaultdomain` (Solaris, illumos) or `/etc/yp.conf` (Linux, contains `domain <name> server <addr>`). If the attacker already has NFS read access to the target's `/etc`, the domain name is a single file read away. This is common in environments where the NFS server is also the NIS server -- the same machine exports its own `/etc`.

**NIS domain in portmapper DUMP output.** Some older ypserv implementations (notably SunOS 4.x) register their NIS program with the portmapper using a service name that includes the domain name. This is not standard behavior and modern implementations do not do it, but legacy systems may leak the domain in the `DUMP` output. More reliably, the ypserv source address in a `DUMP` response narrows the search: if ypserv is registered, the domain name is on that host, and `/var/yp/` (or the `ypwhich -m` output) contains the active domain name.

#### Map exploitation beyond passwd.byname

`passwd.byname` is the obvious target, but NIS serves dozens of maps, many with direct value for NFS attacks:

**group.byname** returns entries in the format `groupname:x:gid:member1,member2,...`. This gives the attacker a complete GID-to-membership mapping. For `uid-spray`, this is transformative: instead of asserting arbitrary GIDs in AUTH_SYS credentials, the attacker knows exactly which GIDs to pair with which UIDs. A file owned by `gid=100` with mode `0640` is readable by any UID that appears in group 100's member list. Dumping `group.byname` and cross-referencing with `passwd.byname` produces a complete credential matrix for AUTH_SYS forging.

**hosts.byname** maps hostnames to IP addresses. This reveals internal network topology: which hosts exist, their naming conventions, and their IP ranges. For NFS attacks, the hostnames in NFS export ACLs (from `showmount -e`) may reference NIS hostnames. If an export is restricted to `rw=fileserver.internal`, dumping `hosts.byname` reveals that `fileserver.internal` is `10.1.2.3`, and the attacker knows which source IP to spoof (or which machine to compromise) to satisfy the ACL.

**netgroup** is the most NFS-relevant map after `passwd.byname`. NFS exports using `@netgroup` ACLs (e.g., `/export -access=@trusted`) delegate membership to the NIS netgroup map. Dumping `netgroup` reveals exactly which `(host, user, domain)` triples are authorized for each netgroup. This directly maps to which hostnames and users can mount which exports, without needing to brute-force the export ACL. If the attacker can add themselves to a netgroup (via `YPPROC_XFR` poisoning on a compromised master, or via NFS write access to the NIS map files on a co-located server), they gain access to every export that references that netgroup.

**mail.aliases** maps alias names to recipient addresses. Service account aliases (e.g., `root: admin@corp.com`, `oracle: dba-team@corp.com`) reveal which human accounts map to which service identities. An alias like `backup: backupuser` confirms that `backupuser` exists as a local account and is the identity behind the `backup` service -- a credential target.

**services.byname** maps service names to port numbers. While mostly informational, it reveals which services the NIS domain expects to run, confirming attack surface. A `services.byname` entry for `nfsd 2049/tcp` on a host that does not appear in `showmount -e` output may indicate a misconfigured or secondary NFS server.

**protocols.byname** maps protocol names to numbers. Purely informational in most cases, but exotic protocol entries may indicate unusual network configurations.

**ethers.byaddr** maps MAC addresses to hostnames. This is layer-2 topology information: which physical or virtual NICs correspond to which hosts. On networks where MAC-based filtering exists, this information is directly actionable. Even without MAC filtering, it reveals which hosts are on the same broadcast domain.

#### YPPROC_ALL vs YPPROC_FIRST/NEXT

Both methods produce the same result (every key/value pair in the map), but their network profiles differ:

**YPPROC_ALL** sends one RPC request and receives a single streaming response containing all entries. For `passwd.byname` on a domain with 500 users, this is 1 outbound packet and one TCP stream in response. It is faster (one round trip, no per-entry latency) and simpler to implement. The downside is that the single large response is conspicuous: a bulk transfer of `passwd.byname` is a distinctive network signature, and IDS rules for NIS map theft specifically look for `YPPROC_ALL` calls against credential maps.

**YPPROC_FIRST/NEXT** sends one `FIRST` call followed by N-1 `NEXT` calls, each returning one key/value pair. For 500 users, this is 500 RPC exchanges. Each individual call is small and looks like a normal NIS client lookup. The aggregate traffic is higher, but each packet is indistinguishable from a legitimate `ypcat`-style enumeration or a client performing normal name resolution.

**Stealth tradeoff:** `YPPROC_FIRST/NEXT` is stealthier per-call but generates far more RPC traffic. If the target monitors per-source RPC call counts (as `rpcbind --getstat` tracks), 500 calls from one source in rapid succession is itself suspicious. With NFSWolf's `StealthConfig` delays between calls, `FIRST/NEXT` can be spread over time to look like organic lookups, but this increases total enumeration time from seconds to minutes. `YPPROC_ALL` is faster but creates a single unmistakable event. The right choice depends on the target's monitoring: against a system with NIS-specific IDS signatures, `FIRST/NEXT` with stealth delays; against a system with only aggregate traffic monitoring, `YPPROC_ALL` is fine.

#### NIS+ vs NIS

NIS+ (program 100300, `rpc.nisd`) is the successor to NIS, deployed primarily on Solaris 2.x through Solaris 10. It does have real authentication via RPCSEC_GSS (specifically Diffie-Hellman key exchange using `AUTH_DES`, later Kerberos via `AUTH_KERB`). NIS+ tables are individually access-controlled: each table, column, and entry has an owner, group, and permission bits (analogous to file permissions). Reading `passwd.org_dir` (the NIS+ equivalent of `passwd.byname`) requires credentials that satisfy the table's ACL.

In practice, NIS+ deployments are vanishingly rare today. Sun deprecated NIS+ in Solaris 9 (2002) and removed it entirely in Solaris 11 (2011). No other vendor ever adopted it. The authentication model, while superior to NIS, was complex enough that many Solaris administrators ran NIS+ in "NIS compatibility mode" (`niscompat`), which accepted unauthenticated NIS protocol queries against NIS+ tables -- defeating the authentication entirely. If NFSWolf encounters program 100300 in a portmapper dump, it should flag the presence and note the `niscompat` risk, but full NIS+ client implementation is not worth the effort given the extinct deployment base.

### Wire format (Sun yp.x)

No RFC exists. The canonical source is Sun's `yp.x` XDR file, distributed with SunOS/Solaris and adopted by all NIS implementations (Linux `ypserv`/`ypbind`, FreeBSD, AIX, HP-UX). The wire format has been frozen since the Sun publication and is identical across all known implementations.

**Authentication:** AUTH_UNIX or AUTH_NONE. No NIS implementation is known to require stronger auth. The entire security model is network-level: if you can reach the ypserv port, you can dump every map. `securenets` (source-IP filtering) is the only access control mechanism deployed in practice, and it is not part of the protocol -- it is an implementation-side configuration convention.

**Transport:** UDP and TCP. `ypserv` registers on both via portmapper. `ypbind` also registers on both. `YPPROC_ALL` (bulk map transfer) typically uses TCP due to response size, but the protocol does not mandate it.

#### ypserv procedure table (program 100004, version 2)

12 procedures.

| # | Procedure | Args | Result | Notes |
|---|-----------|------|--------|-------|
| 0 | `YPPROC_NULL` | `void` | `void` | liveness probe |
| 1 | `YPPROC_DOMAIN` | `domainname` | `bool` | check if server serves this domain; returns TRUE or FALSE |
| 2 | `YPPROC_DOMAIN_NONACK` | `domainname` | `bool` | same but returns only TRUE; no reply on FALSE (client uses timeout as negative) |
| 3 | `YPPROC_MATCH` | `ypreq_key` | `ypresp_val` | look up a single key in a map |
| 4 | `YPPROC_FIRST` | `ypreq_nokey` | `ypresp_key_val` | return the first key/value pair in a map |
| 5 | `YPPROC_NEXT` | `ypreq_key` | `ypresp_key_val` | return the next key/value pair after the given key |
| 6 | `YPPROC_XFR` | `ypreq_xfr` | `ypresp_xfr` | initiate map transfer to a slave server |
| 7 | `YPPROC_CLEAR` | `void` | `void` | flush server's internal map cache |
| 8 | `YPPROC_ALL` | `ypreq_nokey` | `ypresp_all` | bulk dump of entire map (stream of key/value pairs) |
| 9 | `YPPROC_MASTER` | `ypreq_nokey` | `ypresp_master` | return hostname of the master server for a map |
| 10 | `YPPROC_ORDER` | `ypreq_nokey` | `ypresp_order` | return map's order number (last-modified timestamp) |
| 11 | `YPPROC_MAPLIST` | `domainname` | `ypresp_maplist` | list all maps served for a domain |

`YPPROC_ALL` is the primary attack procedure -- it streams every key/value pair from a map in a single RPC exchange. Against `passwd.byname`, this dumps the entire credential store. `YPPROC_FIRST`/`YPPROC_NEXT` achieve the same result iteratively but are slower and noisier.

`YPPROC_DOMAIN_NONACK` is designed for ypbind's broadcast-based domain discovery: it never sends a negative reply, so a client broadcasting to the network only receives responses from servers that actually serve the requested domain. The timeout-as-negative design means a domain-name guessing attack produces no network traffic on miss.

`YPPROC_XFR` and `YPPROC_CLEAR` are administrative procedures. `XFR` triggers a full map transfer from master to slave -- an attacker who can reach the server could trigger unnecessary map transfers (DoS) or, on a compromised master, push poisoned map data to slaves. `CLEAR` flushes the server's map cache, forcing it to re-read from disk on the next query.

#### ypbind procedure table (program 100007, version 2)

3 procedures.

| # | Procedure | Args | Result | Notes |
|---|-----------|------|--------|-------|
| 0 | `YPBINDPROC_NULL` | `void` | `void` | liveness probe |
| 1 | `YPBINDPROC_DOMAIN` | `domainname` | `ypbind_resp` | return binding (IP + port) for the domain's ypserv |
| 2 | `YPBINDPROC_SETDOM` | `ypbind_setdom` | `void` | override the domain binding (privileged, usually loopback-only) |

`YPBINDPROC_DOMAIN` is the recon procedure -- it returns the IP address and port of the ypserv the client should contact. This leaks the NIS server's address even if portmapper queries to the server itself are filtered. `YPBINDPROC_SETDOM` is a server-poisoning primitive: if the ypbind accepts SETDOM from remote callers (misconfiguration, but historically common), an attacker can redirect all NIS clients on that host to a rogue ypserv.

#### NIS/YP XDR type declarations (Sun yp.x)

**Constants:**

```xdr
const YPMAXDOMAIN  = 64;             /* max NIS domain name length */
const YPMAXMAP     = 64;             /* max map name length */
const YPMAXRECORD  = 1024;           /* max key or value length */
const YPMAXPEER    = 256;            /* max master server hostname length */
```

**Base types:**

```xdr
typedef string domainname<YPMAXDOMAIN>;
typedef string mapname<YPMAXMAP>;
typedef opaque datum<YPMAXRECORD>;    /* key or value payload */
```

**Status codes:**

```xdr
enum ypstat {
    YP_TRUE     =  1,                /* operation succeeded, value returned */
    YP_NOMORE   =  2,                /* no more entries in map (end of iteration) */
    YP_FALSE    =  0,                /* generic failure */
    YP_NOMAP    = -1,                /* no such map in this domain */
    YP_NODOM    = -2,                /* server does not serve this domain */
    YP_NOKEY    = -3,                /* no such key in the map */
    YP_BADOP    = -4,                /* invalid operation */
    YP_BADDB    = -5,                /* database error (corrupt map file) */
    YP_YPERR    = -6,                /* internal ypserv error */
    YP_BADARGS  = -7,                /* bad arguments to procedure */
    YP_VERS     = -8                 /* version mismatch (YP version skew) */
};
```

**Request types:**

```xdr
struct ypreq_key {                   /* keyed lookup (MATCH, NEXT) */
    domainname domain;
    mapname map;
    datum key;
};

struct ypreq_nokey {                 /* keyless request (FIRST, ALL, MASTER, ORDER) */
    domainname domain;
    mapname map;
};

struct ypreq_xfr {                   /* map transfer request */
    mapname map;
    domainname domain;
    unsigned int ordernum;            /* minimum order number to accept */
    string owner<YPMAXPEER>;          /* requesting slave's hostname */
};
```

**Response types:**

```xdr
struct ypresp_val {                  /* single-value response (MATCH) */
    ypstat stat;
    datum val;
};

struct ypresp_key_val {              /* key+value response (FIRST, NEXT) */
    ypstat stat;
    datum key;
    datum val;
};

struct ypresp_master {               /* master server response */
    ypstat stat;
    string peer<YPMAXPEER>;          /* hostname of the master ypserv */
};

struct ypresp_order {                /* map order response */
    ypstat stat;
    unsigned int ordernum;            /* last-modified timestamp of the map */
};

struct ypmaplist_entry {             /* linked list of map names */
    mapname map;
    ypmaplist_entry *next;
};

struct ypresp_maplist {              /* map listing response */
    ypstat stat;
    ypmaplist_entry *maps;           /* linked list, NULL-terminated */
};
```

**YPPROC_ALL streaming response:** `YPPROC_ALL` returns a sequence of `ypresp_all` records, each indicating whether more data follows:

```xdr
union ypresp_all switch (bool more) {
    case TRUE:
        ypresp_key_val val;           /* next key/value pair */
    case FALSE:
        void;                         /* end of stream */
};
```

The server sends `more=TRUE` with each key/value pair, then a final record with `more=FALSE` to terminate the stream. On error, the server may terminate early with a `ypresp_key_val` whose `stat` field carries the error code.

**Transfer response:**

```xdr
struct ypresp_xfr {
    unsigned int transid;             /* transaction ID for the transfer */
    unsigned int status;              /* 0 = success, nonzero = error */
};
```

**ypbind types:**

```xdr
struct ypbind_binding {
    opaque ypbind_binding_addr[4];    /* IPv4 address of ypserv, network byte order */
    opaque ypbind_binding_port[2];    /* port of ypserv, network byte order */
};

enum ypbind_resptype {
    YPBIND_SUCC_VAL = 1,             /* binding found */
    YPBIND_FAIL_VAL = 2              /* no binding available */
};

union ypbind_resp switch (ypbind_resptype resp) {
    case YPBIND_SUCC_VAL:
        ypbind_binding ypbind_bindinfo;   /* ypserv address + port */
    case YPBIND_FAIL_VAL:
        unsigned int ypbind_error;         /* error code (implementation-defined) */
};

struct ypbind_setdom {
    domainname ypsetdom_domain;
    ypbind_binding ypsetdom_binding;  /* new ypserv to bind to */
    unsigned int ypsetdom_vers;       /* YP protocol version (always 2) */
};
```

#### ypserv program definition (Sun yp.x)

```xdr
program YPPROG {
    version YPVERS {
        void             YPPROC_NULL(void) = 0;
        bool             YPPROC_DOMAIN(domainname) = 1;
        bool             YPPROC_DOMAIN_NONACK(domainname) = 2;
        ypresp_val       YPPROC_MATCH(ypreq_key) = 3;
        ypresp_key_val   YPPROC_FIRST(ypreq_nokey) = 4;
        ypresp_key_val   YPPROC_NEXT(ypreq_key) = 5;
        ypresp_xfr       YPPROC_XFR(ypreq_xfr) = 6;
        void             YPPROC_CLEAR(void) = 7;
        ypresp_all       YPPROC_ALL(ypreq_nokey) = 8;
        ypresp_master    YPPROC_MASTER(ypreq_nokey) = 9;
        ypresp_order     YPPROC_ORDER(ypreq_nokey) = 10;
        ypresp_maplist   YPPROC_MAPLIST(domainname) = 11;
    } = 2;
} = 100004;
```

#### ypbind program definition (Sun yp.x)

```xdr
program YPBINDPROG {
    version YPBINDVERS {
        void         YPBINDPROC_NULL(void) = 0;
        ypbind_resp  YPBINDPROC_DOMAIN(domainname) = 1;
        void         YPBINDPROC_SETDOM(ypbind_setdom) = 2;
    } = 2;
} = 100007;
```

#### Well-known NIS map names

These are the maps with direct security value for NFS attacks. Map names are case-sensitive.

| Map name | Content | Security value |
|----------|---------|----------------|
| `passwd.byname` | username -> `user:x:uid:gid:gecos:home:shell` | credential store dump; UID/GID for AUTH_SYS forging |
| `passwd.byuid` | uid -> same passwd entry | reverse lookup from UID found on NFS files |
| `group.byname` | groupname -> `group:x:gid:member1,member2,...` | group membership for GID-based access escalation |
| `group.bygid` | gid -> same group entry | reverse lookup from GID found on NFS files |
| `hosts.byname` | hostname -> IP address | internal network topology discovery |
| `hosts.byaddr` | IP -> hostname | reverse DNS for NFS export ACL hostnames |
| `netgroup` | netgroup name -> `(host,user,domain)` triples | NFS `@netgroup` export ACL membership |
| `netgroup.byhost` | `host.domain` -> netgroup names | which netgroups a host belongs to |
| `netgroup.byuser` | `user.domain` -> netgroup names | which netgroups a user belongs to |
| `mail.aliases` | alias -> recipient list | mail routing, sometimes reveals service accounts |
| `shadow.byname` | username -> shadow password entry | password hashes (rare -- most deployments exclude this map) |
| `ethers.byname` | hostname -> MAC address | layer-2 topology (rare) |
| `protocols.byname` | protocol name -> number | informational only |
| `services.byname` | service/proto -> port | informational only |

`passwd.byname` is the primary target. A single `YPPROC_ALL` against it returns every username, UID, GID, home directory, and login shell on the NIS domain. Combined with AUTH_SYS credential forging, this gives a complete list of identities to try against NFS exports.

`netgroup` is the secondary target for NFS-specific attacks. NFS exports using `@netgroup` ACLs (e.g., `rw=@trusted`) rely on the NIS netgroup map for membership resolution. Dumping this map reveals which hosts and users are authorized for each export, without needing to brute-force the export ACL.

---

## NFS_ACL — permission bypass beyond mode bits

**Spec:** Sun — no public specification at all.

**Program:** 100227, versions 2 and 3.

`GETACL` returns POSIX ACLs (access control lists) beyond the traditional mode bits. If a file has mode 0600 (owner-only) but an ACL grants read to `gid=42`, the mode bits lie about who can access the file. NFSv3 ACCESS (advisory) may also not reflect ACL grants.

Every constant in this protocol would be an observed deviation — documented as such, with the reverse-engineering method recorded in the crate.

**NFSWolf integration:** Detection via portmapper. `GETACL` against files the mode bits say should be inaccessible — any ACL entry granting access beyond the mode bits is a finding.

### Security analysis

#### Specific bypass scenarios

POSIX ACLs can grant access that mode bits deny. These are the concrete cases where NFSWolf's current mode-bit-only analysis produces false negatives:

**File with mode 0600 but ACL grants read to gid=42.** The mode bits say only the owner can read/write. But an ACL entry `ACL_GROUP gid=42 perm=r--` grants read access to any process whose supplementary groups include GID 42. The `ACL_MASK` entry limits the effective permission: `effective = entry.perm & mask.perm`. If the mask is `rwx` (common when the administrator used `setfacl -m g:42:r`), the full read permission applies. NFSWolf currently sees mode 0600 and skips this file during `secrets-scan` unless the current credential is the owner. With GETACL, NFSWolf would discover that GID 42 also has read access, and the credential ladder could try a UID with GID 42 as a supplementary group.

**Directory with mode 0700 but ACL grants traverse to gid=100.** A directory with mode 0700 is owner-only by mode bits. But `ACL_GROUP gid=100 perm=--x` grants execute (traverse) permission to GID 100 members. Traverse permission on a directory allows `LOOKUP` into it, which is the prerequisite for accessing any file inside. NFSWolf's recursive `secrets-scan` and `suid-scan` stop at directories where mode bits deny traverse to the current credential. With GETACL data, NFSWolf would know to try GID 100's credentials to enter this directory and scan its contents.

**Default ACL inheritance.** When a directory has a default ACL (`NFS_DFACL`), every new file and subdirectory created inside it inherits the default ACL as its access ACL. The inheriting file's creator may not be aware that the default ACL grants wider access than they intended. For example: a directory `/export/shared` has default ACL `ACL_GROUP gid=200 perm=rw-`. A user creates `/export/shared/secrets.txt` with `umask 077`, expecting mode 0600 (owner-only). The file gets mode 0600 in its mode bits, but the inherited ACL grants read/write to GID 200. The creator sees `0600` in `ls -l` and believes the file is protected. This is a systemic false sense of security: every file created in a directory with a permissive default ACL is wider-open than its mode bits indicate. NFSWolf should flag directories with default ACLs that grant access beyond `ACL_OTHER` as a finding, because every file created inside them silently inherits that access.

#### Interaction with NFSv3 ACCESS

**Does ACCESS reflect ACL entries or only mode bits?** The answer is implementation-dependent, and the gap between implementations is itself the vulnerability.

**Linux knfsd: ACCESS checks POSIX ACLs.** On Linux, the NFSv3 ACCESS procedure calls `nfsd_permission()` in `fs/nfsd/vfs.c`, which calls `inode_permission()`, which calls `generic_permission()` in `fs/namei.c`. `generic_permission()` calls `posix_acl_permission()` (via `check_acl`), which evaluates the full POSIX ACL if one exists. This means on Linux, ACCESS results do reflect ACL entries -- if an ACL grants read to GID 42, ACCESS with GID 42 in supplementary groups returns `ACCESS3_READ`. NFSWolf's current ACCESS-based probing catches ACL-granted access on Linux servers, even without explicit GETACL support.

**Solaris: ACCESS checks ACLs natively.** Solaris NFS server evaluates ACLs as part of the standard VFS access check. Like Linux, ACCESS results on Solaris reflect ACL grants. The behavior is the same: ACCESS is ACL-aware.

**The gap: NFSWolf's current analysis misses the intelligence.** Even though ACCESS on Linux/Solaris reflects ACL-granted permissions, NFSWolf currently cannot distinguish between "ACCESS succeeded because mode bits allow it" and "ACCESS succeeded because an ACL entry grants it." Without GETACL data, NFSWolf cannot report which specific UID or GID has been granted an exception. This matters because: (a) the credential ladder cannot target ACL-granted UIDs/GIDs specifically -- it has to discover them by brute-force through `uid-spray`; (b) the analyzer cannot report "mode bits say 0600 but ACL grants read to GID 42" as a finding, because it never learns about GID 42; (c) the `secrets-scan` output cannot distinguish owner access from ACL-granted access, so the user cannot assess which credentials are alternatives vs requirements.

#### GETACL as a reconnaissance tool

GETACL reveals identity information that no other NFS procedure exposes:

**ACL entries reference UIDs/GIDs that may not own any files.** READDIRPLUS harvests UIDs and GIDs from file ownership (`uid` and `gid` fields in `fattr3`). The credential ladder and `uid-spray` use these as candidate identities. But an ACL can grant access to a UID or GID that owns zero files on the export. For example, an administrator grants `ACL_USER uid=5000 perm=r--` on `/export/finance/reports/` so that the auditor (UID 5000) can read financial reports. The auditor never creates files, so READDIRPLUS never sees UID 5000 in any file's owner field. `uid-spray` scanning the range 0-65535 would eventually try UID 5000, but without RQUOTA or GETACL data, there is no way to prioritize it. GETACL reveals UID 5000 as a specifically-privileged identity worth trying immediately.

**ACL entries reveal high-value credential targets.** The presence of an `ACL_USER` or `ACL_GROUP` entry means an administrator deliberately granted an exception. These exceptions are rarely random -- they represent specific access requirements. A file with `ACL_USER uid=3001 perm=rwx` on a directory containing deployment scripts strongly implies UID 3001 is a deployment service account. A directory with `ACL_GROUP gid=500 perm=r-x` on a configuration directory implies GID 500 is an operations group. These identities are higher-value targets than the file owners themselves, because the ACL entries represent intentional trust relationships that are likely replicated across the system.

**Comprehensive GETACL sweep.** The optimal reconnaissance pattern is: (a) READDIRPLUS to enumerate all files and their owner UIDs/GIDs; (b) GETACL on every file and directory to extract ACL-referenced UIDs/GIDs; (c) merge both sets, deduplicate, and rank by frequency of appearance; (d) feed the ranked list into the credential ladder. This produces a strictly better candidate set than READDIRPLUS alone, because it captures identities that have been granted access but do not own files. The cost is one additional RPC call (GETACL) per file, which doubles the enumeration traffic but requires no credential escalation -- GETACL typically succeeds with the same credentials as GETATTR.

### Wire format (observed, no spec)

**No public specification exists for the NFS_ACL protocol.** The wire format below is reconstructed from two independent implementations: the Linux kernel NFS server (`fs/nfsd/nfs2acl.c`, `fs/nfsd/nfs3acl.c`, `include/uapi/linux/nfsacl.h`, `include/uapi/linux/posix_acl.h`) and the Solaris/illumos NFS ACL implementation. Every constant and type is marked with its source. Where Linux and Solaris diverge, both behaviors are documented.

**Authentication:** AUTH_UNIX. Same as the NFS program it extends -- NFS_ACL v2 pairs with NFSv2, NFS_ACL v3 pairs with NFSv3. No implementation is known to require AUTH_NONE or stronger auth.

**Transport:** TCP and UDP. Shares the NFS transport -- typically the same port (2049) or a nearby dynamically-assigned port registered via portmapper.

**Binding to NFS version:** NFS_ACL program 100227 version 2 operates on NFSv2 file handles (fixed 32-byte `fhandle`). Version 3 operates on NFSv3 file handles (variable-length `nfs_fh3`). The version number tracks the NFS version, not an independent protocol revision.

#### NFS_ACL v2 procedure table (observed from Linux knfsd)

Program 100227, version 2. 5 procedures.

| # | Procedure | Args | Result | Source | Notes |
|---|-----------|------|--------|--------|-------|
| 0 | `ACLPROC2_NULL` | `void` | `void` | observed from Linux `fs/nfsd/nfs2acl.c` | liveness probe |
| 1 | `ACLPROC2_GETACL` | `GETACL2args` | `GETACL2res` | observed from Linux `fs/nfsd/nfs2acl.c` | return POSIX ACLs for a file |
| 2 | `ACLPROC2_SETACL` | `SETACL2args` | `SETACL2res` | observed from Linux `fs/nfsd/nfs2acl.c` | set POSIX ACLs on a file |
| 3 | `ACLPROC2_GETATTR` | `GETATTR2args` | `GETATTR2res` | observed from Linux `fs/nfsd/nfs2acl.c` | get file attributes (like NFSv2 GETATTR) |
| 4 | `ACLPROC2_ACCESS` | `ACCESS2args` | `ACCESS2res` | observed from Linux `fs/nfsd/nfs2acl.c` | check access rights (backport of NFSv3 ACCESS to v2) |

`ACCESS` at procedure 4 is significant: NFSv2 has no ACCESS procedure, so NFS_ACL v2 backports it. This gives NFSv2 clients an advisory access check that considers ACLs, not just mode bits.

#### NFS_ACL v3 procedure table (observed from Linux and Solaris)

Program 100227, version 3. Linux and Solaris implement different procedure sets.

| # | Procedure | Args | Result | Source | Notes |
|---|-----------|------|--------|--------|-------|
| 0 | `ACLPROC3_NULL` | `void` | `void` | observed from Linux `fs/nfsd/nfs3acl.c`, Solaris | liveness probe |
| 1 | `ACLPROC3_GETACL` | `GETACL3args` | `GETACL3res` | observed from Linux `fs/nfsd/nfs3acl.c`, Solaris | return POSIX ACLs for a file |
| 2 | `ACLPROC3_SETACL` | `SETACL3args` | `SETACL3res` | observed from Linux `fs/nfsd/nfs3acl.c`, Solaris | set POSIX ACLs on a file |
| 3 | `ACLPROC3_GETATTR` | `GETATTR3args` | `GETATTR3res` | observed from Solaris only, no spec citation | get file attributes |
| 4 | `ACLPROC3_ACCESS` | `ACCESS3args` | `ACCESS3res` | observed from Solaris only, no spec citation | ACL-aware access check |
| 5 | `ACLPROC3_GETXATTR` | `GETXATTR3args` | `GETXATTR3res` | observed from Solaris only, no spec citation | get extended attributes |

**Linux vs Solaris divergence:** Linux knfsd v3 implements only NULL, GETACL, and SETACL (3 procedures). Solaris implements all 6 procedures (NULL through GETXATTR). Procedures 3-5 in v3 are Solaris-only -- Linux omits them because NFSv3 already provides GETATTR and ACCESS natively. An implementation must probe the server to determine which procedures are supported; calling an unimplemented procedure returns an RPC `PROC_UNAVAIL` error.

#### NFS_ACL XDR type declarations (observed, no spec)

**ACL request mask constants (observed from Linux `include/uapi/linux/nfsacl.h`):**

```xdr
/* Bitmask for which ACL data to request/return.             */
/* observed from Linux include/uapi/linux/nfsacl.h, no spec citation */
const NFS_ACL      = 0x0001;          /* access ACL entries */
const NFS_ACLCNT   = 0x0002;          /* access ACL entry count */
const NFS_DFACL    = 0x0004;          /* default ACL entries (directories only) */
const NFS_DFACLCNT = 0x0008;          /* default ACL entry count */
```

The `mask` field in GETACL args specifies which ACL components to retrieve. A mask of `NFS_ACL | NFS_ACLCNT | NFS_DFACL | NFS_DFACLCNT` (0x000f) requests everything. The result carries a corresponding mask indicating which components are actually present -- a regular file returns 0 for `NFS_DFACL`/`NFS_DFACLCNT` since default ACLs apply only to directories.

**ACL entry type constants (observed from Linux `include/uapi/linux/posix_acl.h`):**

```xdr
/* POSIX.1e ACL entry type tags.                              */
/* observed from Linux include/uapi/linux/posix_acl.h, no spec citation */
const ACL_USER_OBJ  = 0x01;          /* file owner permissions */
const ACL_USER      = 0x02;          /* named user permissions */
const ACL_GROUP_OBJ = 0x04;          /* file group permissions */
const ACL_GROUP     = 0x08;          /* named group permissions */
const ACL_MASK      = 0x10;          /* maximum effective permissions for USER/GROUP entries */
const ACL_OTHER     = 0x20;          /* other (world) permissions */
```

**Permission bit constants (observed from Linux `include/uapi/linux/posix_acl.h`):**

```xdr
/* POSIX.1e ACL permission bits.                              */
/* observed from Linux include/uapi/linux/posix_acl.h, no spec citation */
const ACL_READ    = 0x04;            /* read permission */
const ACL_WRITE   = 0x02;            /* write permission */
const ACL_EXECUTE = 0x01;            /* execute permission */
```

These match the traditional Unix permission bits (r=4, w=2, x=1) and are stored in the low 3 bits of each ACL entry's `perm` field.

**ACL entry structure (observed from Linux/Solaris wire captures and kernel source):**

```xdr
/* Single POSIX ACL entry.                                    */
/* observed from Linux fs/nfsd/nfs2acl.c XDR encoding, no spec citation */
struct aclent {
    unsigned int type;                /* ACL_USER_OBJ, ACL_USER, etc. */
    unsigned int id;                  /* uid or gid (meaningful only for ACL_USER/ACL_GROUP) */
    unsigned int perm;                /* permission bits (ACL_READ | ACL_WRITE | ACL_EXECUTE) */
};
```

For `ACL_USER_OBJ`, `ACL_GROUP_OBJ`, `ACL_MASK`, and `ACL_OTHER` entries, the `id` field is unused and typically set to `ACL_UNDEFINED_ID` (0xffffffff, observed from Linux `include/uapi/linux/posix_acl.h`, no spec citation). For `ACL_USER` entries, `id` is a UID. For `ACL_GROUP` entries, `id` is a GID.

**GETACL argument and result types (v2, observed from Linux `fs/nfsd/nfs2acl.c`):**

```xdr
/* ACLPROC2_GETACL args                                       */
/* observed from Linux fs/nfsd/nfs2acl.c, no spec citation    */
struct GETACL2args {
    fhandle fh;                       /* NFSv2 32-byte file handle */
    unsigned int mask;                /* bitmask: NFS_ACL | NFS_ACLCNT | ... */
};

/* ACLPROC2_GETACL result                                     */
/* observed from Linux fs/nfsd/nfs2acl.c, no spec citation    */
struct GETACL2res {
    nfsstat status;                   /* NFSv2 status code */
    /* on NFS_OK: */
    fattr attributes;                 /* NFSv2 file attributes */
    unsigned int mask;                /* which components are present */
    unsigned int aclcnt;              /* number of access ACL entries */
    aclent aclent<>;                  /* access ACL entries */
    unsigned int dfaclcnt;            /* number of default ACL entries */
    aclent dfaclent<>;                /* default ACL entries (directories only) */
};
```

**GETACL argument and result types (v3, observed from Linux `fs/nfsd/nfs3acl.c`):**

```xdr
/* ACLPROC3_GETACL args                                       */
/* observed from Linux fs/nfsd/nfs3acl.c, no spec citation    */
struct GETACL3args {
    nfs_fh3 fh;                       /* NFSv3 variable-length file handle */
    unsigned int mask;                /* bitmask: NFS_ACL | NFS_ACLCNT | ... */
};

/* ACLPROC3_GETACL result                                     */
/* observed from Linux fs/nfsd/nfs3acl.c, no spec citation    */
struct GETACL3res {
    nfsstat3 status;                  /* NFSv3 status code */
    /* on NFS3_OK: */
    post_op_attr attr;                /* NFSv3 post-operation attributes */
    unsigned int mask;                /* which components are present */
    unsigned int aclcnt;              /* number of access ACL entries */
    aclent aclent<>;                  /* access ACL entries */
    unsigned int dfaclcnt;            /* number of default ACL entries */
    aclent dfaclent<>;                /* default ACL entries (directories only) */
};
```

**SETACL types (observed from Linux kernel):**

```xdr
/* ACLPROC2_SETACL args                                       */
/* observed from Linux fs/nfsd/nfs2acl.c, no spec citation    */
struct SETACL2args {
    fhandle fh;
    unsigned int mask;                /* which ACL components to set */
    unsigned int aclcnt;
    aclent aclent<>;
    unsigned int dfaclcnt;
    aclent dfaclent<>;
};

/* ACLPROC2_SETACL result                                     */
/* observed from Linux fs/nfsd/nfs2acl.c, no spec citation    */
struct SETACL2res {
    nfsstat status;
    fattr attributes;                 /* updated attributes on success */
};

/* ACLPROC3_SETACL args                                       */
/* observed from Linux fs/nfsd/nfs3acl.c, no spec citation    */
struct SETACL3args {
    nfs_fh3 fh;
    unsigned int mask;
    unsigned int aclcnt;
    aclent aclent<>;
    unsigned int dfaclcnt;
    aclent dfaclent<>;
};

/* ACLPROC3_SETACL result                                     */
/* observed from Linux fs/nfsd/nfs3acl.c, no spec citation    */
struct SETACL3res {
    nfsstat3 status;
    post_op_attr attr;                /* updated attributes on success */
};
```

**ACL entry count limits (observed from Linux, no spec citation):** Linux knfsd enforces a maximum of 1024 ACL entries per file (`NFS_ACL_MAX_ENTRIES`, observed from `include/linux/nfsacl.h`). Solaris enforces a similar limit. A minimal ACL has 3 entries (`USER_OBJ`, `GROUP_OBJ`, `OTHER`) which are equivalent to the traditional mode bits. Any ACL with more than 3 entries (specifically, any ACL containing `ACL_USER` or `ACL_GROUP` entries) grants access beyond what mode bits express -- these are the entries NFSWolf should flag.

**MASK interaction:** When an ACL contains `ACL_USER` or `ACL_GROUP` entries, an `ACL_MASK` entry must also be present. The effective permissions for any `ACL_USER` or `ACL_GROUP` entry are `entry.perm & mask.perm`. `ACL_USER_OBJ` and `ACL_OTHER` are not affected by the mask. This means the raw `perm` field in a `ACL_USER`/`ACL_GROUP` entry may overstate the actual granted access -- always intersect with the mask entry to compute effective permissions.

---

## RPCSEC_GSS — auth negotiation recon

**Spec:** RFC 2203, 5403, 7861.

The only auth flavour that authenticates. The recon half matters more than the client half for NFSWolf — `SECINFO` (NFSv3 via MOUNT, NFSv4 as an operation) reports which flavours a server accepts per export. Parsing that answer tells you whether an export is AUTH_SYS-only, which is the precondition for every other finding NFSWolf produces.

Full context establishment pulls a Kerberos implementation into the dependency graph. Separate crate (`onc-rpcsec-gss`) so `onc-rpc-client` consumers that only speak AUTH_SYS don't compile a GSSAPI stack.

The `SECINFO`/`SECINFO_NO_NAME` interpretation needed for recon can live in `nfs-v4` until this crate exists.

### Wire format (RFC 2203, 5403, 7861)

RFC 2203 defines the base RPCSEC_GSS protocol (v1). RFC 5403 adds channel bindings (v2). RFC 7861 adds multi-principal authentication, security labels, and structured privileges (v3). The credential structure is identical across all three versions; only the set of control procedures and service values grows. **Note:** RFC 2203 is not in `ref/rfc/`; the XDR below is reproduced from RFC 5403 ss3.2 and RFC 7861 ss2.4, which include the complete updated definitions.

#### Credential structure (RFC 2203 ss5.3.1, reproduced in RFC 5403 ss3.2, RFC 7861 ss2.4)

The RPCSEC_GSS credential is carried in the RPC call header's `opaque_auth cred` field with `auth_flavor = RPCSEC_GSS (6)`. The credential body is XDR-encoded as `rpc_gss_cred_t`:

```xdr
union rpc_gss_cred_t switch (unsigned int rgc_version) {    /* RFC 5403 ss3.2 */
    case RPCSEC_GSS_VERS_1:                                  /* = 1 */
    case RPCSEC_GSS_VERS_2:                                  /* = 2 */
    case RPCSEC_GSS_VERS_3:                                  /* = 3, RFC 7861 ss2.4 */
        rpc_gss_cred_vers_1_t rgc_cred_v1;
};

struct rpc_gss_cred_vers_1_t {                               /* RFC 5403 ss3.2 */
    rpc_gss_proc_t    gss_proc;   /* control procedure selector */
    unsigned int      seq_num;    /* sequence number (anti-replay) */
    rpc_gss_service_t service;    /* integrity/privacy/none */
    opaque            handle<>;   /* context handle from INIT exchange */
};
```

The version discriminant selects which features are available but does not change the credential layout -- all three versions use `rpc_gss_cred_vers_1_t`. For recon purposes, `rgc_version` in an observed credential tells you whether the client and server negotiated v1 (base GSS), v2 (channel bindings), or v3 (labels/privileges/multi-principal).

#### `rpc_gss_service_t` values (RFC 2203 ss5.3.1, RFC 5403 ss3.4, RFC 7861 ss2.4)

```xdr
enum rpc_gss_service_t {                                     /* RFC 7861 ss2.4 */
    /* 0 is reserved */
    rpc_gss_svc_none         = 1,   /* authentication only, no per-message protection */
    rpc_gss_svc_integrity    = 2,   /* authentication + integrity (MIC on every message) */
    rpc_gss_svc_privacy      = 3,   /* authentication + integrity + confidentiality (wrap) */
    rpc_gss_svc_channel_prot = 4    /* v2+: channel provides protection, no per-message MIC */
};
```

`rpc_gss_svc_none` means the GSS context authenticates the caller but individual RPC payloads are unprotected -- equivalent in confidentiality to AUTH_SYS. `rpc_gss_svc_integrity` adds a MIC (message integrity code) to every request/reply. `rpc_gss_svc_privacy` additionally encrypts the payload. `rpc_gss_svc_channel_prot` (v2+, RFC 5403 ss3.4) delegates protection to a secure channel (e.g., IPsec) after a successful `RPCSEC_GSS_BIND_CHANNEL` exchange.

For NFS exports, these map to the Linux `sec=` option: `sec=krb5` = `svc_none`, `sec=krb5i` = `svc_integrity`, `sec=krb5p` = `svc_privacy`.

#### `rpc_gss_proc_t` values (RFC 2203 ss5.2, RFC 5403 ss3.3, RFC 7861 ss2.7)

```xdr
enum rpc_gss_proc_t {                                        /* RFC 7861 ss2.4 */
    RPCSEC_GSS_DATA          = 0,   /* normal data request/reply */
    RPCSEC_GSS_INIT          = 1,   /* context establishment (first token) */
    RPCSEC_GSS_CONTINUE_INIT = 2,   /* context establishment (subsequent tokens) */
    RPCSEC_GSS_DESTROY       = 3,   /* destroy context */
    RPCSEC_GSS_BIND_CHANNEL  = 4,   /* v2: bind channel (not used in v3, RFC 7861 ss2.5) */
    RPCSEC_GSS_CREATE        = 5,   /* v3: create child handle with assertions */
    RPCSEC_GSS_LIST          = 6    /* v3: query supported assertions */
};
```

`RPCSEC_GSS_INIT` and `RPCSEC_GSS_CONTINUE_INIT` carry GSS-API tokens (opaque blobs from `gss_init_sec_context` / `gss_accept_sec_context`). These are the only procedures that exchange GSS tokens -- once context establishment completes, all subsequent calls use `RPCSEC_GSS_DATA` with MICs derived from the established context. `RPCSEC_GSS_BIND_CHANNEL` (v2, RFC 5403 ss3.3) is explicitly "Not used" in v3 (RFC 7861 ss2.5); v3 replaces it with a channel-binding assertion in `RPCSEC_GSS_CREATE`.

#### Well-known GSS mechanism OIDs

The mechanism OID identifies which GSS-API mechanism is used for context establishment. It appears in GSS-API `gss_init_sec_context` calls and in NFSv4 SECINFO responses. The OIDs relevant to NFS:

| Mechanism | OID (dotted) | ASN.1 DER encoding (hex) | Source |
|-----------|-------------|--------------------------|--------|
| Kerberos 5 | 1.2.840.113554.1.2.2 | `06 09 2a 86 48 86 f7 12 01 02 02` | RFC 1964 ss1, RFC 4121 |
| SPNEGO | 1.3.6.1.5.5.2 | `06 06 2b 06 01 05 05 02` | RFC 4178 |
| Kerberos 5 (Microsoft) | 1.2.840.48018.1.2.2 | `06 09 2a 86 48 82 f7 12 01 02 02` | Microsoft SPNEGO, pre-RFC |

The DER encoding is tag 0x06 (OID), length byte, then the OID value octets. The first two arcs are combined: `40 * arc1 + arc2`. Subsequent arcs use base-128 variable-length encoding with high-bit continuation.

**Kerberos 5** (1.2.840.113554.1.2.2) is the standard mechanism for NFS Kerberos authentication. SPNEGO (1.3.6.1.5.5.2) wraps mechanism negotiation and is used by Windows NFS clients. The Microsoft variant OID (1.2.840.48018.1.2.2) appears in SPNEGO `NegTokenInit` from older Windows clients; it identifies the same krb5 mechanism but predates the RFC standardization of the OID.

**Integrity and privacy are not separate OIDs.** The distinction between `sec=krb5`, `sec=krb5i`, and `sec=krb5p` is encoded in the `rpc_gss_service_t` field of the RPCSEC_GSS credential, not in different mechanism OIDs. All three use the same mechanism OID (1.2.840.113554.1.2.2) with service values `rpc_gss_svc_none` (1), `rpc_gss_svc_integrity` (2), and `rpc_gss_svc_privacy` (3) respectively.

#### SECINFO / SECINFO_NO_NAME mechanism list encoding

Servers advertise supported security flavors per export via two mechanisms:

**MOUNT v3 `auth_flavors` (RFC 1813 Appendix III):** The `mountres3_ok` response includes `int auth_flavors<>` -- an array of integer flavor values. For AUTH_SYS and AUTH_NONE, the raw flavor values (1 and 0) appear directly. For RPCSEC_GSS, Linux uses pseudo-flavor integers that encode the mechanism + service combination:

| Pseudo-flavor | Value | Meaning |
|---------------|-------|---------|
| `AUTH_NONE` | 0 | no authentication |
| `AUTH_SYS` | 1 | AUTH_UNIX / AUTH_SYS |
| `RPCSEC_GSS` | 6 | base RPCSEC_GSS (not used as pseudo-flavor) |
| `RPC_AUTH_GSS_KRB5` | 390003 | krb5, `svc_none` |
| `RPC_AUTH_GSS_KRB5I` | 390004 | krb5, `svc_integrity` |
| `RPC_AUTH_GSS_KRB5P` | 390005 | krb5, `svc_privacy` |

These pseudo-flavor values are defined in the Linux kernel (`include/linux/sunrpc/auth.h`) and are not formally standardized in an RFC. They are, however, the de facto wire encoding used by Linux knfsd and recognized by all Linux NFS clients. An export configured with `sec=krb5:sys` returns `[390003, 1]` in `auth_flavors`.

**NFSv4 SECINFO (RFC 7530 ss16.31):** Returns `secinfo4<>` -- an array of tagged unions. Each entry is either a simple flavor (`AUTH_NONE`, `AUTH_SYS`) or a full `rpcsec_gss_info` struct:

```xdr
struct rpcsec_gss_info {                                     /* RFC 7530 ss16.31 */
    sec_oid4       oid;       /* GSS mechanism OID (opaque<>) */
    qop4           qop;       /* quality of protection (0 = default) */
    rpc_gss_svc_t  service;   /* none=1, integrity=2, privacy=3 */
};

union secinfo4 switch (uint32_t flavor) {                    /* RFC 7530 ss16.31 */
    case RPCSEC_GSS:
        rpcsec_gss_info flavor_info;
    default:
        void;
};

typedef secinfo4 SECINFO4resok<>;
```

`SECINFO_NO_NAME` (RFC 5661 ss18.45.3, NFSv4.1+) returns the same `secinfo4<>` array but operates on the current filehandle's filesystem rather than a named object. Both procedures provide the complete mechanism + service + QOP tuple per flavor, which is strictly more informative than MOUNT v3's pseudo-flavor integers.

#### Recon-only requirements (no context establishment)

NFSWolf's immediate need is parsing security flavor advertisements, not establishing GSS contexts. What this requires:

1. **Parse MOUNT v3 `auth_flavors`**: decode the integer array from `mountres3_ok`. Match against the pseudo-flavor table above. If any value equals 1 (`AUTH_SYS`), the export is AUTH_SYS-accessible -- precondition for every finding NFSWolf produces. If only `390003`/`390004`/`390005` appear, the export requires Kerberos and AUTH_SYS attacks will fail at the server.

2. **Parse NFSv4 SECINFO responses**: decode the `secinfo4<>` array. Extract the `sec_oid4` OID and `rpc_gss_service_t` from each `rpcsec_gss_info` entry. Match OIDs against the well-known table above.

3. **No GSS context establishment needed**: parsing the server's security advertisement is a read-only operation on the MOUNT/SECINFO response. No `gss_init_sec_context` call, no Kerberos tickets, no GSSAPI library dependency. The `sec_oid4` field is a raw opaque that can be compared byte-for-byte against known OID encodings.

4. **XDR types already available**: `nfswolf-nfs3` has the MOUNT v3 response types; `nfswolf-nfs4` has the NFSv4 COMPOUND types including SECINFO. The only missing piece is the OID constant table and the pseudo-flavor mapping.

#### v2 additions (RFC 5403)

RFC 5403 adds channel bindings to RPCSEC_GSS, allowing the RPC layer to verify that both endpoints are using the same underlying secure channel (e.g., IPsec, TLS). The changes are:

- **New version number**: `RPCSEC_GSS_VERS_2 = 2` (RFC 5403 ss3.2). Setting `rgc_version = 2` signals channel binding support.
- **New control procedure**: `RPCSEC_GSS_BIND_CHANNEL = 4` (RFC 5403 ss3.3). Binds the RPCSEC_GSS context to a secure channel via a MIC exchange over the channel bindings data.
- **New security service**: `rpc_gss_svc_channel_prot = 4` (RFC 5403 ss3.4). Once channel binding succeeds, requests use `svc_channel_prot` instead of `svc_integrity`/`svc_privacy`, delegating protection to the channel and eliminating per-message MIC overhead.
- **Channel binding verification types** (RFC 5403 ss3.3):

```xdr
enum rgss2_bind_chan_status {                                 /* RFC 5403 ss3.3 */
    RGSS2_BIND_CHAN_OK           = 0,   /* channel binding accepted */
    RGSS2_BIND_CHAN_PREF_NOTSUPP = 1,   /* channel prefix not supported */
    RGSS2_BIND_CHAN_HASH_NOTSUPP = 2    /* hash algorithm not supported */
};
```

**Recon relevance:** If a server accepts `rgc_version = 2` without error, it supports channel bindings. If it rejects with an RPC error per RFC 2203 ss5.1, it only supports v1. This is a version fingerprinting signal, not a direct attack surface.

**Label awareness is NOT in v2.** RFC 5403 is exclusively about channel bindings. Security label assertions were added in v3 (RFC 7861).

#### v3 additions (RFC 7861)

RFC 7861 adds three assertion types and replaces the v2 channel binding mechanism. The changes are:

- **New version number**: `RPCSEC_GSS_VERS_3 = 3` (RFC 7861 ss2.2).
- **New control procedures**: `RPCSEC_GSS_CREATE = 5` and `RPCSEC_GSS_LIST = 6` (RFC 7861 ss2.7). `CREATE` binds assertions to a new child context handle. `LIST` queries the server for supported assertion types.
- **`RPCSEC_GSS_BIND_CHANNEL` deprecated in v3** (RFC 7861 ss2.5): returns `PROC_UNAVAIL` on v3 handles. Channel binding in v3 uses a field in `RPCSEC_GSS_CREATE` args instead.
- **New reply verifier** (RFC 7861 ss2.3): v3 computes the reply verifier MIC over the same header fields as the request verifier (with `mtype` changed to `REPLY`), fixing a man-in-the-middle weakness where child and parent handles sharing a GSS context could have colliding sequence numbers.

**Multi-principal authentication** (RFC 7861 ss2.7.1.1): binds two RPCSEC_GSS handles -- a "parent" (client host principal) and an "inner" (user principal) -- into a single child handle. The server verifies both principals before granting authority. This prevents cache-poisoning attacks on multi-user clients and enables per-user+per-host authorization decisions.

```xdr
struct rgss3_gss_mp_auth {                                   /* RFC 7861 ss2.7.1.1 */
    opaque rgmp_handle<>;            /* inner RPCSEC_GSS handle (user principal) */
    opaque rgmp_rpcheader_mic<>;     /* MIC of RPC header using inner context */
};
```

**Security label assertions** (RFC 7861 ss2.7.1.3): client processes assert MLS/MAC subject labels to the server, enabling Full Mode MAC when combined with Labeled NFS (RFC 7862 ss9). The Label Format Specifier (LFS) identifies the label syntax and semantics.

```xdr
struct rgss3_lfs {                                           /* RFC 7861 ss2.7.1.3 */
    unsigned int rlf_lfs_id;         /* Label Format Specifier identifier */
    unsigned int rlf_pi_id;          /* Policy Identifier */
};

struct rgss3_label {                                         /* RFC 7861 ss2.7.1.3 */
    rgss3_lfs rl_lfs;
    opaque    rl_label<>;            /* opaque label, interpreted by MAC policy */
};
```

**Structured privilege assertions** (RFC 7861 ss2.7.1.4): application-defined capabilities bound to a context handle. Used by NFSv4.2 inter-server copy (`copy_to_auth`, `copy_from_auth`, `copy_confirm_auth` per RFC 7862 ss4.9.1.1).

```xdr
struct rgss3_privs {                                         /* RFC 7861 ss2.7.1.4 */
    utf8str_cs rp_name<>;           /* privilege identifier (registered with IANA) */
    opaque     rp_privilege<>;      /* application-defined privilege data */
};
```

**New `auth_stat` error codes** (RFC 7861 ss2.6):

```xdr
enum auth_stat {                                             /* RFC 7861 ss2.6 */
    /* ... existing values ... */
    RPCSEC_GSS_INNER_CREDPROBLEM = 15,   /* inner handle invalid (multi-principal) */
    RPCSEC_GSS_LABEL_PROBLEM     = 16,   /* label/LFS not supported */
    RPCSEC_GSS_PRIVILEGE_PROBLEM = 17,   /* structured privilege not supported */
    RPCSEC_GSS_UNKNOWN_MESSAGE   = 18    /* unknown structured privilege name */
};
```

**Recon relevance of v3:** If a server returns `RPCSEC_GSS_LABEL_PROBLEM` (16) on an `RPCSEC_GSS_CREATE` with a label assertion, it recognizes v3 but does not support labeled security. If it returns `RPCSEC_GSS_UNKNOWN_MESSAGE` (18) on a privilege assertion, it recognizes v3 but not the specific privilege. `RPCSEC_GSS_LIST` (proc 6) enumerates which labels and privileges the server supports without needing to attempt assertions. These are fingerprinting signals for server capability, but exercising them requires an established GSS context.

---

## C702 insights for existing NFS implementation

Findings from C702 that apply to NFSWolf's already-implemented protocols — not new sideband protocols, but spec-level details the RFCs don't cover or that the XNFS spec states more explicitly. Each claim is verified against the Linux kernel 7.1.5 NFS server source (`fs/nfsd/`).

### NFSv3 permission model (C702 §12.3.3, pp. 190–191)

Confirmed verbatim from the spec and verified against Linux knfsd:

**Owner override — CONFIRMED in Linux 7.1.5 knfsd.** "The server's permission checking algorithm should allow the owner of a file to access it regardless of the permission setting." Linux implements this in `nfsd_permission()` (`fs/nfsd/vfs.c`): when `NFSD_MAY_OWNER_OVERRIDE` is set and `inode->i_uid == current_fsuid()`, access is granted unconditionally. `NFSD_MAY_OWNER_OVERRIDE` is auto-ORed onto every file-open access check via `nfsd_file_do_acquire()` in `fs/nfsd/filecache.c`. The owner can always read/write their own files even with mode 0000. NFSWolf's credential ladder should try the file's owner UID even when mode bits show no access.

**Execute-implies-read — CONFIRMED in Linux 7.1.5 knfsd.** "The server allows reading of files if the user ID given in the call has either execute or read permission on the file." Linux implements this in `nfsd_permission()` (`fs/nfsd/vfs.c`): when a READ is denied on a regular file and `NFSD_MAY_OWNER_OVERRIDE` is set, the code falls back to checking `MAY_EXEC` — if execute permission exists, READ is allowed. Since `NFSD_MAY_OWNER_OVERRIDE` is unconditionally added to every file-open check, this applies to every NFSv3 READ, not just owner reads. A file with mode 0111 (execute-only) is readable via NFS by anyone with execute permission. Relevant for `secrets-scan` — binaries and scripts with execute-only permissions are still readable via NFS.

**Root squash — CONFIRMED in Linux 7.1.5 knfsd, no diskless-boot exception.** Linux implements root squash in `nfsd_setuser()` (`fs/nfsd/auth.c`): when `NFSEXP_ROOTSQUASH` is set, UID 0 is mapped to the export's anonymous UID. The spec mentioned an exception for "diskless client root filesystems" — Linux has no such exception in the code. The diskless-boot case is an administrative convention (setting `no_root_squash` on those exports), not a kernel-level carve-out.

### NFSv3 attributes on failure (C702 §12.2.3, p. 188)

**CONFIRMED in Linux 7.1.5 knfsd.** Failed operations "may contain the pre-operation attributes of the object or object's parent directory" in `post_op_attr`/`wcc_data`, and "implementors are strongly encouraged to return as much attribute data as possible upon failure." Linux's NFSv3 XDR encoders (`fs/nfsd/nfs3xdr.c`) encode `post_op_attr`/`wcc_data` on both success and error paths for READ, WRITE, ACCESS, READLINK, and most other procedures — `NFS3ERR_ACCES` responses carry file attributes. LOOKUP on failure encodes only the directory's `post_op_attr` (not the target object's), which matches RFC 1813's `LOOKUP3resfail` structure. This means access-denied responses can leak file size, mtime, ctime, uid, gid — metadata disclosure on denial. This is the wire-level justification for CRATE-DESIGN.md's two-layer convention: the failure arm's `dir_attributes` that `flatten()` discards is exactly this data.

### NFSv3 duplicate request cache (C702 §12.3.4, pp. 191–192)

**DRC wipe on reboot — CONFIRMED in Linux 7.1.5 knfsd.** "Most servers store the duplicate request cache in RAM, so the contents are lost if the server crashes." Linux's DRC (`fs/nfsd/nfscache.c`) is allocated via `kvzalloc()` and `KMEM_CACHE()` — pure RAM, no backing store. The hash table is allocated fresh every time `nfsd_startup_net()` runs. A reboot wipes the DRC completely, opening a replay window for previously-deduplicated destructive calls (REMOVE, RENAME, RMDIR).

"A network partition can cause a cache entry to be reused before a client receives a reply... the duplicate request will be processed as a new one, possibly with destructive side effects" — partition-induced replay window.

**DRC key is a compound key, not XID alone — VERIFIED in Linux 7.1.5 knfsd.** C702 §4.1.3 says DRC keying is on the RPC XID. Linux's actual implementation uses a compound key: `xid + proc + client_addr + version + arg_len + arg_checksum`. XID selects the hash bucket; the full match uses `memcmp` over the entire key struct. The AUTH_UNIX stamp is NOT part of the key — the comment in `src/proto/auth.rs` attributing DRC-avoidance to fresh stamps is citing the wrong field. Fresh stamps don't hurt, but they don't help with DRC avoidance either. XID uniqueness is what matters, and NFSWolf already uses `fastrand` for XID generation in the RPC crate.

### NFSv3 write verifier as reboot oracle (C702 §12.3.11, pp. 193–194)

**CONFIRMED in Linux 7.1.5 knfsd.** Linux generates the write verifier in `nfsd_reset_write_verifier_locked()` (`fs/nfsd/nfssvc.c`) as a SipHash of the current timestamp keyed with a per-namespace random key. It is regenerated on every nfsd (re)start and on any non-transient write-commit failure (`fs/nfsd/vfs.c`, `fs/nfsd/filecache.c`). The write verifier changing between WRITE and COMMIT signals server data loss/reboot. Also documents a lost-update race: if client A writes async and client B reads-and-rewrites before A commits, then the server crashes, A's COMMIT returns a different verifier — A "will need to retransmit the buffers," potentially clobbering B's changes. HA caveat: non-shared-memory failover *must* change `verf`; shared-memory failover "would not need to" — verifier stability alone isn't proof against a redundant server pair.

### NFSv3 null-string filename fingerprinting (C702 §12.2.4, pp. 188–189)

**NOT CONFIRMED in Linux 7.1.5 knfsd — Linux behaves differently.** C702 says a null-string filename must return `NFS3ERR_ACCES`. Linux rejects it during XDR argument decoding (`svcxdr_decode_filename3()` in `fs/nfsd/nfs3xdr.c`: `if (size == 0) return false`), which produces an RPC-level `GARBAGE_ARGS` rejection before any NFS procedure runs. The response is never an NFS status code at all — `NFS3ERR_ACCES` is never assigned. This is a clean spec divergence: the 1998 spec mandated an NFS-level error, the modern implementation rejects at the wire layer. Not useful as a fingerprinting signal on Linux knfsd — but may still work against other implementations (Solaris, NetApp, FreeBSD) that follow the spec's original language.

Overlong filenames are either silently truncated to `name_max` or rejected with `NFS3ERR_NAMETOOLONG`, controlled by `PATHCONF.no_trunc`.

### C702 portmapper omits CALLIT

C702 ch. 6 (pp. 61–68) defines only NULL/SET/UNSET/GETPORT/DUMP for the portmapper — `PMAPPROC_CALLIT` is absent entirely. No mention anywhere, not even as deprecated. This likely reflects the committee dropping it once CALLIT-based reflection abuse was known.

**Linux kernel status:** The kernel contains no portmapper/rpcbind server — it's entirely userspace (`rpcbind` daemon). The kernel only has a client-side enum constant (`RPCBPROC_CALLIT` in `net/sunrpc/rpcb_clnt.c`). Modern `rpcbind` has NOT removed CALLIT — it had crash-class CVEs (CVE-2013-1950, CVE-2015-7236) that were patched, but the procedure itself remains. Only `SET`/`UNSET` are loopback-restricted by default; CALLIT has no documented restriction beyond operational guidance to firewall port 111. CALLIT-based amplification testing cites RFC 1057 and empirical rpcbind behavior, not C702.

### E403 external corroboration (1994)

X/Open's own "Security in Interworking Specifications" (E403, `ref/archive.opengroup.org/archive/CDROM/e403.pdf`) scores NFS/XNFS "Authentication: N/A" with the note "No API is defined." NFS is the only communications spec in the entire document with no defined security API. Citable as an external, industry-consortium corroboration of the "AUTH_SYS isn't real authentication" premise that underpins every finding NFSWolf reports.

### P521 `exportfs` defaults (1995)

X/Open's "File System and Scheduling Utilities" (P521, `ref/archive.opengroup.org/archive/CDROM/p521.pdf`) documents:
- Default is **read-write-to-everyone** if neither `ro` nor `rw` is specified
- `access=` default is **allow-all** — "The default value allows any machine to mount the given directory"
- `root=` default is **empty** (root-squash by default)
- Removing a client from `access=` is **not retroactive** — already-mounted clients keep access until unmount. Only `exportfs -u` triggers STALE.
- Narrowing `root=`/`rw=` membership takes effect **immediately** — no grace period.

### Write verifier as reboot oracle — exploitation details (C702 ss12.3.11, pp. 193-194; ss12.4.0 NFSPROC3_WRITE, pp. 212-214; ss12.4.0 NFSPROC3_COMMIT, pp. 251-253)

The existing subsection confirms the `writeverf3` changes on server reboot and documents the HA failover distinction. This subsection adds practical exploitation techniques.

**Polling for verifier changes.** The `verf` field is an 8-byte opaque cookie returned by both WRITE and COMMIT (C702 ss12.4.0, pp. 213, 251). C702 states: "This cookie must be consistent during a single instance of the NFS Version 3 protocol server and must be unique between instances of the NFS Version 3 protocol server, where uncommitted data may be lost" (p. 213). The cheapest probe is a zero-byte COMMIT: `COMMIT(file, offset=0, count=0)` flushes everything and returns `verf` in `COMMIT3resok.verf` (p. 251). C702 explicitly says "It is not an error for there to be nothing to flush on the server" (p. 252), so this probe succeeds even when no prior UNSTABLE WRITE was issued. Alternatively, a zero-count WRITE (`WRITE(file, offset=0, count=0, stable=FILE_SYNC)`) also returns `verf` and "will succeed and return a count of zero, barring errors due to permission checking" (p. 212). Both probes require only a valid file handle and appropriate permissions -- no data is written.

**HA failover detection.** C702 ss12.3.11 (pp. 193-194) explicitly documents the two HA cases: "If the high availability server implementation does not use a shared-memory scheme, then the *verf* must change on failover, since the unsynchronised data is not available to the second processor." Conversely, "In a shared-memory high availability server implementation, the *verf* would not need to change because the server would still have the cached data available to it to be flushed." This is a binary fingerprint: stable verifier across failover = shared-memory HA (active-active or shared-storage active-passive). Changed verifier = non-shared failover (the standby has no access to cached data). An attacker polling `verf` can distinguish these architectures without any other recon -- the verifier transition pattern during a failover event is definitive.

**Verifier-based uptime estimation.** C702 suggests the `verf` value should be "the time that the server was booted or the time the server was last started (if restarting the server without a reboot results in lost buffers)" (p. 214). Linux knfsd uses a SipHash of the timestamp, so the raw value is not a readable timestamp. However, verifier *stability* is the signal: a stable `verf` across multiple polling intervals proves the NFS server process has not restarted. A change proves it has. Periodic polling (e.g., once per minute) establishes a lower bound on uptime and detects restarts within the polling interval. Combined with `rpcbind GETTIME` (which returns the server's epoch clock), the polling interval brackets the reboot time.

**NFSWolf integration.** The `verf` value is already available in `WRITE3resok` and `COMMIT3resok` via the `nfswolf-nfs3` crate. A reboot oracle would store the baseline `verf` on first COMMIT and compare on subsequent calls. The zero-count COMMIT probe is the preferred polling method -- it requires `--allow-write` for the initial WRITE that establishes the baseline, but the polling COMMITs themselves are read-only (they flush already-committed data). The HA fingerprint is a side effect of the same comparison logic.

### DRC replay window — practical exploitation (C702 ss12.3.4, pp. 191-192; ss7.1.3, p. 70)

The existing subsection documents the DRC wipe on reboot and the partition-induced replay. This subsection adds the mechanics of triggering and exploiting the replay window.

**Replay matching requirements.** C702 ss4.1.3 (p. 44) describes the DRC key as the RPC transaction ID (XID). Linux's actual implementation uses a compound key (xid + proc + client_addr + version + arg_len + arg_checksum), as documented in the existing subsection. For a replay to match a previous DRC entry, the retransmitted request must arrive from the same source address with the same XID and procedure number. After a reboot, however, there are no DRC entries to match at all -- the cache is empty (`kvzalloc` in `fs/nfsd/nfscache.c`), so every request with a previously-used XID is processed as new.

**Which operations are dangerous to replay.** C702 ss12.3.4 (p. 191) distinguishes idempotent from non-idempotent operations and explicitly names the destructive cases. Non-idempotent operations whose replay has destructive side effects include: REMOVE (proc 12, p. 228 -- "this is generally a non-idempotent operation"; a replayed REMOVE after the target was recreated deletes the new file), RENAME (proc 14, p. 232 -- "this is possibly a non-idempotent operation"; a replayed RENAME after the destination was recreated overwrites it), RMDIR (proc 13, p. 230 -- same as REMOVE for directories), and CREATE with `UNCHECKED` mode (proc 8, p. 216 -- replaying truncates the recreated file). WRITE (proc 7) with `stable=FILE_SYNC` or `DATA_SYNC` is technically idempotent (same data at same offset), but a replayed WRITE after the file contents changed overwrites the new data with old data -- destructive in practice. C702 warns of "a truncate operation causing lost writes" (p. 191) as an explicit example.

**Network partition scenario.** C702 ss12.3.4 (pp. 191-192) documents this explicitly: "A network partition can cause a cache entry to be reused before a client receives a reply for the corresponding request. If this happens, the duplicate request will be processed as a new one, possibly with destructive side effects." The scenario: client sends REMOVE, the reply is lost due to partition, the DRC entry is evicted to make room for new entries, the client retransmits, and the "duplicate" REMOVE is processed as new -- potentially deleting a file that was recreated in the interim. No reboot is needed for this case; the DRC simply needs to cycle through enough entries to evict the original.

**DRC fill timing.** The post-reboot replay window closes when the DRC fills with new entries. Linux's DRC size defaults to `num_drc_entries` (scaled to available memory; typically 1024-16384 entries on modern systems). Under normal NFS load, the cache fills within seconds to minutes depending on client activity. Under light load (e.g., a single dormant mount), the window may persist for hours. An attacker who detects a reboot via the write verifier oracle has a time-bounded window: the fewer active clients, the longer the window stays open. Replaying a captured REMOVE/RENAME/RMDIR XID from before the reboot within this window processes it as a new destructive operation.

**Interaction with the write verifier oracle.** The write verifier change (ss12.3.11) and the DRC wipe (ss12.3.4) are two effects of the same event (server restart). Detecting one confirms the other. The attack sequence from Chain 7 (Cross-protocol attack chains) uses the verifier as the trigger: poll COMMIT, detect verifier change, immediately replay captured destructive XIDs before the DRC refills.

### Locking architecture security implications (C702 ch. 9, pp. 117-125; ch. 10, pp. 127-128)

C702 Chapter 9 describes how NFS file locking works through the cooperation of two sideband protocols (NLM and NSM) that are entirely separate from NFS itself. The security implications arise from this separation and from the advisory-only nature of the locks.

**Advisory-only model: locks are suggestions, not enforcement.** C702 ss9.1.1 (p. 117) defines NLM locking as "advisory X/Open CAE file and record locking" whose use is "strongly encouraged but not mandatory." The NLM section header (ss10, p. 127, already cited in the NLM section of this document) confirms: NLM locks are never enforced by the filesystem. An NFS client that issues READ or WRITE directly -- bypassing the local NLM entirely -- is completely unconstrained by any lock held by any other client. NFSWolf's shell `read`/`write` commands use raw NFS procedures, never NLM, so they inherently bypass all advisory locks on the target file. No additional implementation is needed to exploit this; it is the default behavior.

**NFS operations ignore locks entirely.** The NFS protocol (programs 100003 v2/v3) and the NLM protocol (program 100021) are separate RPC programs with separate procedure namespaces. There is no cross-reference: NFSPROC3_WRITE does not check whether an NLM lock exists on the target byte range, and NLM_LOCK does not prevent a subsequent NFS WRITE. C702 ss9.2 (p. 119) describes the interaction as being between "the user process" and "the local NLM" via "a user-level API or system call such as the XSI fcntl()." The NFS server has no involvement in the locking decision. Appendix D ss D.2 (p. 302) confirms that `fcntl()` F_SETLK triggers NLM_LOCK to "the remote NLM" -- not to the NFS server. The lock and the I/O travel through completely independent protocol paths.

**Grace period exploitation.** C702 ss9.2.1 (p. 119) describes the grace period: "The grace period is an implementation-dependent time during which the NLM implementation will only accept requests to re-establish locks or shares that were in effect at the time of the crash. During this period any other lock or share requests will be returned with a status indicating that the NLM is in the grace period and is not accepting new requests." C702 ss10.1.2 (p. 127) specifies this as approximately 45 seconds. During this window: (1) new lock requests from legitimate clients are denied with `LCK_DENIED_GRACE_PERIOD`, breaking write coordination, (2) NFS READ/WRITE operations continue unimpeded because NFS ignores NLM entirely, and (3) an attacker who detects the reboot (via write verifier change or NSM notification) knows the exact window during which legitimate clients cannot establish new locks. Files that were previously protected by advisory locks are accessible without coordination for the duration of the grace period.

**Lock authentication: caller_name is the only identity.** C702 ss9.2.1 (p. 119) describes the locking interaction: the NLM_LOCK request "includes the name of the host to be monitored" via `caller_name` in the `nlm_lock` structure (ss10.2, p. 130). This `caller_name` is the sole identity key for lock ownership -- it is a self-asserted string up to 1024 bytes (ss10.2, p. 128, `LM_MAXSTRLEN`). No binding exists between `caller_name` and the RPC source address, AUTH_SYS `machinename`, or any cryptographic identity. C702 ss9.2.2 (p. 120) for non-monitored locks makes this worse: "the personal computer client must inform the server NLM when it has been rebooted so it can discard all locks and file shares held for the client" via NLM_FREE_ALL -- with the hostname as the only credential. An attacker who knows (or guesses) a legitimate client's hostname can release all its locks with a single NLM_FREE_ALL call.

### Server-side implementation guidelines with security impact (C702 ss12.3, pp. 189-194; Appendix A, pp. 271-283)

C702 ss12.3 provides implementation guidance for NFSv3 servers. Several guidelines have direct security implications for NFSWolf's attack surface.

**Silly rename reveals active files (C702 ss12.3.1, p. 189; Appendix A ss A.8, pp. 275-276).** When a client deletes a file that is still open, the NFS client "can do some tricks such as renaming the file on remove (to a hidden name), and only physically deleting it on close" (ss12.3.1, p. 189). Appendix A ss A.8 (pp. 275-276) elaborates: "the client will rename the file to a temporary file" and "it is common practice for the client to pick a name starting with a period (.) in the same directory as the original file." The Linux NFS client uses the naming convention `.nfsXXXXXXXXXXXXXXXX` (hex-encoded inode number + generation counter). These files are visible in READDIR/READDIRPLUS output and reveal three things to an attacker: (1) which files are actively in use (the original was deleted but a process still has it open), (2) the inode number of the original file (encoded in the `.nfs` name on Linux clients), and (3) which directories have active write operations (silly-renamed files only appear when a delete races with an open). NFSWolf's `secrets-scan` could flag `.nfs*` entries as indicators of active file usage. The silly-renamed file is still readable via its handle -- the rename is a namespace operation, not a permission change.

**Caching policies are undefined (C702 ss12.3.10, p. 193).** "The NFS Version 3 protocol does not define a policy for caching on the client or server. In particular, there is no support for strict cache consistency between a client and server, nor between different clients." This means attribute caches (mode bits, uid, gid) on the server have no mandated expiration. NFSWolf's `credential_ladder()` makes decisions based on file attributes (mode bits from GETATTR/READDIRPLUS). If the server returns cached attributes, the ladder may operate on stale mode bits -- e.g., a file whose permissions were recently tightened may still appear world-readable in the server's attribute cache. C702 Appendix A ss A.5 (p. 273) confirms: "Information in a client's attribute and access caches becomes inaccurate when the attributes of a file on the server are changed." The MountedFileSystem attributes `ACRegMin`, `ACRegMax`, `ACDirMin`, `ACDirMax` (ss2.4.2, p. 15) control client-side cache timeouts, but the *server's* internal attribute cache is not bounded by these parameters. On the server side, Linux knfsd does not cache attributes independently -- it reads them from the VFS on each call -- but other implementations (NetApp, Solaris) may cache aggressively.

**Filesystem ID stability and handle invalidation (C702 ss12.3.1, pp. 189-190).** C702 notes that "both NFS Version 2 protocol and NFS Version 3 protocol implementations do not typically let clients cross a server's mount point" (p. 190). When a server re-exports a filesystem or the underlying storage changes, the `fsid` in `fattr3` may change. An `fsid` change invalidates all cached handles for that filesystem -- the client must re-MOUNT and re-LOOKUP from the export root. For NFSWolf, an unexpected `fsid` change in a GETATTR response (compared to the value received at MOUNT time) is a signal that the server's storage topology changed. This could indicate a failover event, a filesystem re-export, or administrative intervention. The `FileHandleAnalyzer` already uses `fsid` for OS/FS fingerprinting; tracking `fsid` stability over time adds a change-detection capability.

**Filename character handling and path traversal (C702 ss12.3.5, p. 192; ss12.2.4, pp. 188-189; Appendix A ss A.15.6, p. 281).** C702 ss12.3.5 (p. 192) states: "Server implementations of NFS Version 3 protocol will frequently impose restrictions on the names that can be created. Many servers will also forbid the use of names that contain certain characters, such as the path component separator used by the server operating system." Appendix A ss A.15.6 (p. 281) adds: "A server may have an implementation-specific set of characters that it does not allow in file names." Case handling is also implementation-defined: "some server implementations do not preserve character case when creating an object" and "some server implementations may ignore case distinctions for lookup operations" (p. 281). This means LOOKUP with mixed-case names may succeed on case-insensitive servers (Windows NFS, NetApp NTFS volumes) when it would fail on case-sensitive ones (Linux ext4). For path traversal: the NFS protocol transmits filenames as raw opaque byte strings. The interpretation of bytes above 0x7F is server-specific -- there is no mandated charset. A filename containing bytes that decode to `../` in one encoding but are treated as a single multibyte character in another could traverse directories on charset-mismatched servers. C702 provides no guidance on charset normalization; the risk is entirely implementation-dependent.

**Server access control model divergence (C702 Appendix A ss A.15.7, pp. 281-282).** "The server may use an access model other than the traditional UNIX mode bits, for example, Access Control Lists. In this case the mode bits reported by the client need not accurately represent the permissions on a file" (p. 281). With NFSv2, "the client relies on the mode bits to determine whether a given process has access to a given file. If the mode bits are sufficiently inaccurate, the client may deny access to a process even though the request would succeed on the server" (p. 281). Conversely, "the client may grant access based on the mode bits, only to have the request denied by the server" (p. 282). With NFSv3, "the client can ask the server whether a particular access request should be granted" via ACCESS (p. 282). This directly validates NFSWolf's existing design rule (CLAUDE.md rule 5): "ACCESS is advisory" -- but C702 goes further by documenting that even the mode bits returned by GETATTR may be a lossy projection of the actual server access model. The credential ladder's mode-bit pruning (`mode & 0o007 == 0` skips service accounts) can be wrong in both directions: overly aggressive (ACLs grant access that mode bits don't show) and insufficiently aggressive (mode bits show access that ACLs deny). The NFS_ACL sideband protocol (program 100227, documented earlier in this file) is the only way to get the real access model.

### Client-side vulnerabilities documented by C702 (Appendix A ss A.5-A.9, pp. 273-277; ss12.3.1, p. 189)

C702 Appendix A catalogs semantic differences between local and NFS filesystems that create exploitable client-side behaviors. These affect legitimate NFS clients, not NFSWolf itself -- but they are attack surface NFSWolf can exploit against clients mounted on the same export.

**Client attribute caching: stale permissions (C702 Appendix A ss A.5, pp. 273-274).** "Functions such as stat() may return incorrect information if the client's attribute cache is inaccurate" (p. 274). The attribute cache holds mode, uid, gid, size, and timestamps. C702 ss A.5.1 (p. 274) documents two failure modes: (1) "Access to a file on the server may be denied because the attributes in the client caches are more restrictive than the attributes on the server" -- a recently chmod'd file stays inaccessible to the client until the cache expires, and (2) "If the attributes in the client caches are less restrictive than the attributes on the server, functions such as open() may succeed, but functions like read() or write() may fail" -- the client grants access based on stale permissive attributes, only to get `NFS3ERR_ACCES` from the server. For an attacker who can write to the export (`--allow-write`): changing a file's permissions via SETATTR takes effect on the server immediately, but other clients' attribute caches may continue showing the old permissions for seconds to minutes. This means a privilege escalation via SETATTR (e.g., `chmod 0777`) is invisible to other clients' access-check caches, reducing the detection window.

**Client handle caching: stale handles (C702 Appendix A ss A.6.2, p. 275).** "Another function of the stateless behaviour of NFS is that the server cannot prevent the deletion of a file that is open by a process on a client system and is not open by a process on the server. When this occurs, the next client request which refers to the file will be rejected with the XNFS-specific error [ESTALE]." If a client has a cached handle for a file that was deleted and recreated (with a new inode number), the stale handle returns `NFS3ERR_STALE`, forcing the client to re-LOOKUP. The security implication: an attacker who deletes and recreates a file (e.g., `/etc/cron.d/job`) controls the new file's content. Clients with stale handles get ESTALE, re-LOOKUP, and then operate on the attacker's replacement file. The timing window is the client's LOOKUP cache timeout.

**Silly rename reveals file activity (C702 ss12.3.1, p. 189; Appendix A ss A.8, pp. 275-276).** Already detailed in the server-side section above. From the client-side perspective: "It is common practice to have an entry in the XNFS server's crontab database to regularly delete these lingering temporary files" (p. 276). This means: (1) the crontab entry itself is a target (modifying it via NFS WRITE disables cleanup), (2) `.nfs*` files that persist after their creating client disconnects indicate a client crash (the client failed to clean up), and (3) reading the `.nfs*` file's content recovers the data the original process was working with at the time of deletion -- potentially including credentials, database records, or configuration being edited.

**Data caching: read of old data (C702 Appendix A ss A.9.2, p. 276).** "The information in the buffer cache may be inaccurate and not reflect the latest changes to a file. Therefore, the read() function may not get the latest contents of a file." An attacker who writes to a file via NFS (using a different UID or from a different source) may find that other clients continue reading the old cached version for a bounded period. This cuts both ways: a defender's monitoring scripts running on NFS may not see an attacker's modifications until the cache expires, and an attacker reading a recently-modified file (e.g., a password change) may get stale data. C702 ss A.9.3 (p. 276) adds: "it is impossible to guarantee that any arbitrary multi-byte read or write will be atomic" -- no atomicity guarantee means TOCTOU races are inherent in the protocol.

**No protection for in-use executables (C702 Appendix A ss A.7, p. 275).** "If an executable file stored on an XNFS server is being executed on a client system, there is no mechanism that prevents the file from being deleted, truncated, or overwritten (for example, via remove(), fopen(), truncate() or write()). The execution of the program may be terminated if this occurs." The error `[ETXTBSY]` is "never returned by a function operating on a remote file over NFS" (p. 275). An attacker with write access to an export can overwrite a binary that is being executed by another client -- the executing client may crash or, depending on the paging model, start executing attacker-controlled code as new pages are faulted in from the now-modified file. This is a code execution primitive on any client executing binaries from an NFS export.

---

## Cross-protocol attack chains

These chains combine sideband protocols with NFS operations. Each chain is an ordered sequence of steps across multiple RPC programs, exploiting the AUTH_SYS trust model that all of them share. Every step uses an existing NFSWolf capability or a Tier 3 protocol documented elsewhere in this file. The chains are ordered by attack impact: credential theft and write access first, then recon amplification and evasion.

### Chain 1: NIS -> NFS credential theft

Turns a portmapper DUMP into a fully targeted NFS attack with real credentials instead of brute-force guessing.

1. Detect NIS via portmapper DUMP (program 100004 `ypserv` / program 100007 `ypbind`). NFSWolf's scanner already enumerates portmapper — NIS surfaces as a side effect.
2. Discover the NIS domain name. Two paths: (a) `YPBINDPROC_DOMAIN` (program 100007, proc 1) returns the bound domain, or (b) read `/etc/defaultdomain` via an already-accessible NFS export.
3. `YPPROC_ALL` (program 100004, proc 8) on map `passwd.byname` dumps the full credential store: username, uid, gid, home directory, login shell. AUTH_NONE is sufficient on most deployments — NIS has no per-map access control.
4. `YPPROC_ALL` on map `group.byname` dumps group memberships: group name, gid, member list. This gives the exact supplementary groups each uid belongs to.
5. `YPPROC_ALL` on map `netgroup` reveals which hostnames belong to which netgroup names. NFS exports using `@netgroup` syntax in their ACLs (e.g., `/etc/exports: /data @trusted_hosts(rw)`) are now crackable — the attacker knows which hostnames to spoof.
6. Feed the real uid/gid pairs into NFSWolf's `credential_ladder` as observed identities. `uid-spray` becomes a targeted dictionary attack (dozens of real uids) instead of a blind sweep across 0-65535.
7. With netgroup membership known, `--hostname` spoofing targets the exact netgroup name needed to pass the export ACL. Even though knfsd checks TCP source IP (not `auth_unix.machinename`) for export ACLs, the netgroup data reveals which *machines* to pivot through.

**Prerequisites:** Network access to portmapper (TCP/UDP 111) and the NIS server port. No NFS export access needed for steps 1-5.
**Detection difficulty:** Low. NIS queries are logged by few deployments. `YPPROC_ALL` is indistinguishable from a legitimate NIS client sync.
**NFSWolf implementation status:** Step 1 is implemented (portmapper DUMP). Steps 2-7 require NIS client procedures (Tier 3, program 100004). The `credential_ladder` integration point (step 6) is implemented and accepts external identity lists via `credential_ladder_with()`.

### Chain 2: NSM -> NLM -> NFS write access

Weaponizes the statd/lockd trust relationship to release locks and write to coordinated files.

1. `MNTPROC_DUMP` (program 100005, proc 2) to harvest connected client hostnames and their mounted exports. Already implemented in NFSWolf (`NfsMountClient::dump_clients()`).
2. `NLM_TEST` (program 100021, proc 1) against file handles on the target export. On `LCK_DENIED`, the response leaks `nlm_holder { exclusive, uppid, oh, l_offset, l_len }` — the lock holder's PID, owner handle, and exact byte range. No prior lock or MOUNT needed; file handle possession is sufficient.
3. Two lock-release paths, choose based on stealth requirements:
   - **Targeted:** `SM_NOTIFY` (program 100024, proc 6) with a spoofed `mon_name` matching the target client's hostname and a changed `state` value. The NFS server's local statd receives the notification and tells lockd the client rebooted, triggering lock release for that client only. One UDP datagram, no authentication.
   - **Bulk:** `NLM_FREE_ALL` (program 100021, proc 23) with the target client's `caller_name`. Releases every lock and share reservation held by that hostname. Also one UDP datagram, no authentication, returns void.
4. NFS `WRITE` (program 100003, proc 7 for v3) to the now-unlocked files. Requires `--allow-write` in NFSWolf. The advisory locks are gone; the legitimate client's write coordination is broken.
5. Optional cleanup: `NLM_LOCK` (proc 2) with the attacker's own `caller_name` to re-establish a lock, preventing the legitimate client from detecting the gap via its next lock attempt.

**Prerequisites:** Network access to NFS, NLM, and NSM ports. File handle for the target file (via MOUNT or handle forging). `--allow-write` flag.
**Detection difficulty:** Medium. `SM_NOTIFY` is a normal part of statd recovery — a single spoofed notification blends with legitimate reboots. `NLM_FREE_ALL` is more distinctive but logged by few deployments. The subsequent NFS WRITE is indistinguishable from any other write.
**NFSWolf implementation status:** Step 1 is implemented (`dump_clients`). Steps 2-5 require NLM and NSM client procedures (Tier 3, programs 100021 and 100024). NFS WRITE is implemented.

### Chain 3: RQUOTA -> targeted uid-spray

Uses the quota subsystem as a faster UID enumeration oracle than NFS ACCESS-based spraying.

1. `RQUOTAPROC_GETQUOTA` (program 100011, proc 1) sweep across a UID range. Each call returns `rquota { bsize, rq_active, rq_bhardlimit, rq_bsoftlimit, rq_curblocks, rq_fhardlimit, rq_fsoftlimit, rq_curfiles }` or `Q_NOQUOTA`. The sweep is faster than NFS ACCESS-based uid-spray because RQUOTA is a single RPC call per UID with no file handle needed — no MOUNT, no LOOKUP chain.
2. UIDs with `rq_active=TRUE` and `rq_curblocks > 0` are confirmed active users with data on the filesystem. These are high-priority targets for credential escalation.
3. `rq_curfiles` count reveals which users have the most files — a proxy for "most interesting target" when prioritizing uid-spray order.
4. Feed the discovered UIDs into `credential_ladder_with()` as observed identities. The ladder now tries real, active UIDs first instead of walking common service accounts or brute-forcing.
5. For UIDs with quotas near their limits (`rq_curblocks` close to `rq_bhardlimit`), the attacker knows a WRITE as that UID will fail with `NFS3ERR_DQUOT` — skip those UIDs for write operations.

**Prerequisites:** Network access to the RQUOTA service port (obtained via portmapper). No NFS export access needed.
**Detection difficulty:** Low. RQUOTA queries are rarely logged. A sweep looks like a quota management tool checking allocations.
**NFSWolf implementation status:** None. RQUOTA is Tier 3 (program 100011). The `credential_ladder_with()` integration point is implemented.

### Chain 4: NFS_ACL -> hidden permission discovery

Reveals access paths that NFSWolf's current mode-bit analysis cannot see.

1. NFS `ACCESS` (program 100003, proc 4 for v3) on a target file reports "denied" based on mode bits — the file appears inaccessible to the current uid/gid.
2. `GETACL` (program 100227, proc 1) on the same file retrieves the POSIX ACL. The ACL may contain entries like `group:developers:rw-` that grant access to a specific GID not visible in the file's mode bits. ACLs are a superset of mode bits — the mode bits show only the owning user, owning group, and other; ACLs can grant access to arbitrary additional users and groups.
3. `uid-spray` with the GID from the ACL entry (via `credential_ladder_with()` seeded with the discovered GID) grants access to the file despite mode bits saying denied.
4. This bypasses NFSWolf's current mode-bit-based pruning in `credential_ladder()`. The ladder's optimization that skips service-account rungs when `mode & 0o007 == 0` is wrong in the presence of ACLs — the file may have no "other" access but an ACL granting access to a specific group. The chain exposes a real gap in the current credential escalation logic.

**Prerequisites:** File handle for the target file. Network access to the NFS_ACL service (program 100227, usually co-located with NFS on port 2049).
**Detection difficulty:** Low. `GETACL` is a normal administrative operation. The subsequent `uid-spray` is the detectable step.
**NFSWolf implementation status:** NFS ACCESS is implemented. GETACL requires the NFS_ACL protocol (Tier 3, program 100227). The credential ladder gap (mode-bit pruning ignoring ACLs) is a real limitation of the current `credential_ladder()` implementation.

### Chain 5: WebNFS -> MOUNT bypass -> full filesystem

Combines the WebNFS public filehandle with AUTH_SYS credential forging to access exports without ever touching the MOUNT protocol.

1. Construct the public filehandle: zero-length `nfs_fh3` for v3, all-zero 32 bytes for v2. Send `NFSPROC3_LOOKUP` (proc 3) with the public handle and a multi-component path (MCL) like `../../../etc/passwd`. NFSWolf's existing `Nfs3Client` LOOKUP is sufficient — the only new construct is the handle constant.
2. If the server returns a valid file handle: the server supports WebNFS, and the export ACL check that MOUNT enforces was never executed. The file handle is a bearer token — it works with any AUTH_SYS credential.
3. Combine with `uid-spray`: try the public handle LOOKUP under multiple AUTH_SYS identities. Even if the initial LOOKUP succeeds only for uid 0, the returned handle works with any uid (bearer token property, RFC 1094 ss2.3.3).
4. No MOUNT means no `auth_flavors` negotiation. On servers that only check auth flavor at MOUNT time (the "MOUNT-only-checking" pattern C702 ssE.7.3 explicitly warns about), AUTH_SYS works even on exports configured with `sec=krb5`. The server never ran the MOUNT procedure that would have enforced Kerberos.
5. If step 1 fails with `NFS3ERR_STALE`, `NFS3ERR_BADHANDLE`, or `NFS3ERR_INVAL`: WebNFS is not supported. Fall back to the existing `escape` subcommand (ext4/xfs/btrfs handle forging via `FileHandleAnalyzer`).

**Prerequisites:** Network access to NFS port 2049. No portmapper needed (WebNFS spec mandates direct port 2049 connection). No MOUNT access needed.
**Detection difficulty:** Medium. The zero-length/all-zero handle is distinctive in packet captures, but no standard NFS monitoring tool flags it. The MCL path with `..` components is more suspicious but only visible in deep packet inspection.
**NFSWolf implementation status:** The v4 `PUTPUBFH` is implemented in `nfswolf-nfs4`. The v2/v3 public handle probe is not implemented. `check_webnfs_public_handle` exists in `src/engine/analyzer.rs` but has a proxy bypass bug (documented in CRATE-DESIGN.md). The existing LOOKUP procedures in `Nfs2Client` and `Nfs3Client` are sufficient for the wire-level probe — only the handle constant and MCL path construction are missing.

### Chain 6: PCNFSD -> authenticated NFS access

Turns a legacy print server into a password oracle that feeds NFS credential forging.

1. Detect PCNFSD via portmapper DUMP (program 150001). NFSWolf's scanner already enumerates portmapper.
2. `PCNFSD_AUTH` (program 150001, proc 1) with candidate username/password. The password is "obfuscated" with XOR 0x5b + AND 0x7f — trivially reversible, published in-spec (D030 ss6.4.2.1). On success (`AUTH_RES_OK`), the server returns the real uid/gid for that user.
3. Fail-open mode: even on authentication failure, `AUTH_RES_FAKE` returns a synthesized but usable uid/gid. The spec explicitly sanctions this as a valid response — the server hands back an identity the client "may use if it wishes" (D030 p. 96). Some deployments always return `AUTH_RES_FAKE` instead of `AUTH_RES_FAIL`.
4. Use the obtained uid/gid as the AUTH_SYS credential for NFS operations. The uid/gid from `PCNFSD_AUTH` is a real, verified identity — not a guess. Set it via `AuthSys::with_groups()` and proceed with normal NFS operations.
5. Combine with NIS `passwd.byname` dump (Chain 1): the username list from NIS feeds a `PCNFSD_AUTH` brute-force. NIS gives the usernames; PCNFSD validates which passwords are weak. The uid/gid from either source feeds NFS.
6. `PCNFSD_PR_INIT` (proc 2) returns a spool directory path as a bonus — it reveals the server's filesystem layout, which helps target `escape` path traversal.

**Prerequisites:** Network access to portmapper and the PCNFSD service port (UDP). The target must be running pcnfsd (rare on modern systems, persistent on legacy SunOS/Solaris/illumos PC-NFS gateways).
**Detection difficulty:** Low. PCNFSD has no audit logging in any known implementation. The XOR obfuscation defeats casual packet sniffing but not any real monitoring. Brute-force attempts are limited only by UDP round-trip time.
**NFSWolf implementation status:** Step 1 is implemented (portmapper DUMP for program 150001 detection). Steps 2-6 require PCNFSD client procedures (Tier 3, program 150001). The AUTH_SYS credential injection point (step 4) is fully implemented.

### Chain 7: Write verifier -> DRC replay window

Uses the NFSv3 write verifier as a reboot oracle, then exploits the empty duplicate request cache after a reboot.

1. Issue NFS `WRITE` (program 100003, proc 7, `UNSTABLE` stability) followed by `COMMIT` (proc 21) with `--allow-write`. Record the write verifier from the COMMIT response. The write verifier is a server-generated 8-byte value that changes on reboot (C702 ss12.3.11; Linux generates it via SipHash of current timestamp in `nfsd_reset_write_verifier_locked()`).
2. Periodically re-issue COMMIT and compare the returned verifier to the saved value. A changed verifier means the server rebooted — the write verifier is a reboot oracle.
3. During the post-reboot window: the DRC (duplicate request cache) is wiped. Linux's DRC is pure RAM (`kvzalloc` + `KMEM_CACHE` in `fs/nfsd/nfscache.c`), reallocated fresh on every `nfsd_startup_net()`. No backing store, no persistence.
4. Previously-deduplicated destructive calls (`REMOVE` proc 12, `RENAME` proc 14, `RMDIR` proc 13) can now be replayed. Before the reboot, the DRC would have returned the cached result for a retransmitted XID. After the reboot, the DRC is empty — the server processes the "retransmission" as a new request with destructive side effects.
5. Combine with NSM (Chain 2): `SM_SIMU_CRASH` (program 100024, proc 4 — a debugging procedure that most statd implementations leave enabled) triggers the local NSM to send `SM_NOTIFY` to all monitored peers, cascading lock recovery across the cluster. This creates a window of lock-free access (NLM grace period, ~45 seconds per C702 ss10.1.2) alongside the DRC replay window — two independent coordination mechanisms are disrupted simultaneously.

**Prerequisites:** `--allow-write` flag. Active NFS session with at least one prior WRITE+COMMIT (to establish the verifier baseline). For step 5: network access to the target's NSM port.
**Detection difficulty:** High. The write verifier check is an ordinary COMMIT call. DRC replay is indistinguishable from a legitimate client retransmission after a network partition. `SM_SIMU_CRASH` is the most detectable step — it is a debugging procedure with no legitimate production use.
**NFSWolf implementation status:** NFS WRITE and COMMIT are implemented. The write verifier comparison logic is not implemented as a reboot oracle. DRC replay exploitation is not implemented. NSM `SM_SIMU_CRASH` requires the NSM client (Tier 3, program 100024).

### Chain 8: Metadata leak -> targeted file discovery

Exploits the NFSv3 spec requirement that failed operations return attributes, turning access denials into a full directory map.

1. NFS `LOOKUP` (program 100003, proc 3) or `ACCESS` (proc 4) on guessed paths. When the target exists but access is denied, the response carries `post_op_attr` in the failure arm: `fattr3 { type, mode, nlink, uid, gid, size, used, rdev, fsid, fileid, atime, mtime, ctime }`. C702 ss12.2.3 (p. 188) mandates this: "implementors are strongly encouraged to return as much attribute data as possible upon failure." Linux knfsd (`fs/nfsd/nfs3xdr.c`) encodes `post_op_attr` on both success and error paths.
2. The denied response leaks: file size (`size`), modification time (`mtime`), owner (`uid`, `gid`), inode number (`fileid`), file type (`type`). This is full `stat()` output on a file the attacker cannot read.
3. Systematically probe common paths (`/etc/shadow`, `/etc/krb5.keytab`, `/root/.ssh/id_rsa`, database data directories) to map the directory structure and file ownership. `NFS3ERR_NOENT` means the file does not exist; `NFS3ERR_ACCES` means it exists and the attributes are in the response.
4. Feed the discovered owner UIDs into `credential_ladder_with()` for targeted escalation. The file's `uid` from the denied response tells the ladder exactly which identity to try first.
5. File sizes reveal which files are worth targeting. A `/etc/shadow` of 2KB vs a database file of 500MB drives prioritization. `mtime` reveals recency — recently modified files are more likely to contain current credentials.

**Prerequisites:** File handle for a parent directory (via MOUNT or handle forging). The target files must exist on the export.
**Detection difficulty:** Low. LOOKUP and ACCESS are the most common NFS operations. The access-denied responses are never logged by standard NFS server configurations. The attacker's probing is indistinguishable from a misconfigured client.
**NFSWolf implementation status:** LOOKUP and ACCESS are fully implemented. The `post_op_attr` extraction from failure responses is partially implemented — the `Nfs3Result::Err` arm carries the failure data, but `flatten()` in the domain API discards it. Recovering the attributes from the failure arm is a code change in `nfswolf-nfs3`, not a new protocol. The `credential_ladder_with()` integration point is implemented.

---

## Crate inventory

| # | Crate | Program | Versions | Spec | Layers | Security value |
|---|---|---|---|---|---|---|
| — | (WebNFS) | 100003 | v2, v3 | C702 App. E, RFC 2054/2055 | — (uses existing NFS clients) | filesystem access bypassing MOUNT |
| — | (PCNFSD) | 150001 | v1 | D030 | fused | password oracle, code execution |
| 10 | `nfs-nlm` | 100021 | v1, v3, v4 | C702 ch. 10, 14 — no RFC | both | lock manipulation → write access, holder enumeration |
| 11 | `nfs-nsm` | 100024 | v1 | C702 ch. 11 — no RFC | fused | callback coercion, lock release via reboot spoofing |
| 12 | `nfs-rquota` | 100011 | v1, v2 | Sun `rquota.x` — no RFC | fused | UID enumeration via quota oracle |
| 13 | `nfs-acl` | 100227 | v2, v3 | Sun — no public spec | fused | permission bypass beyond mode bits |
| 14 | `nfs-nis` | 100004, 100007 | v2 | Sun `yp.x` — no RFC | fused | credential store dump |
| — | `onc-rpcsec-gss` | — | — | RFC 2203, 5403, 7861 | both | auth negotiation recon |

WebNFS and PCNFSD do not need their own crates — WebNFS uses existing NFS clients with a well-known handle constant, and PCNFSD detection is a portmapper check. Full PCNFSD exploitation would be a module in the binary, not a published crate.

---

## Detection without implementation

Several of these protocols can be detected and reported in NFSWolf's scanner today without implementing the protocol itself:

| Protocol | Program | Detection method | What to report |
|---|---|---|---|
| NLM | 100021 | portmapper DUMP | "NLM registered — lock state may be queryable/manipulable via AUTH_SYS" |
| NSM | 100024 | portmapper DUMP | "NSM registered — reboot notification spoofable, callback coercion possible" |
| RQUOTA | 100011 | portmapper DUMP | "RQUOTA registered — UID enumeration via quota queries" |
| NFS_ACL | 100227 | portmapper DUMP | "NFS_ACL registered — POSIX ACLs may grant access beyond mode bits" |
| NIS (ypserv) | 100004 | portmapper DUMP | "NIS registered — credential maps may be dumpable without authentication" |
| NIS (ypbind) | 100007 | portmapper DUMP | "NIS bind registered — domain name discoverable" |
| PCNFSD | 150001 | portmapper DUMP | "PCNFSD registered — password oracle (PCNFSD_AUTH) and print spool code execution (PR_START)" |

NFSWolf's existing `PortmapClient::dump()` already returns all registered programs. The scanner currently names only NFS (100003), ypserv (100004), and ypbind (100007). Adding the remaining program numbers to the `program_name` table and flagging their security implications is a Phase 1 task (see TASKLIST.md).

---

## Source documents in `ref/`

| Document | Path | Pages | Content |
|---|---|---|---|
| C702 — XNFS 3W | `ref/xopen-c702.pdf` | 352 | NLM (ch 10, 14), NSM (ch 11), WebNFS (app E), plus XDR, RPC, portmapper, NFSv2, NFSv3, MOUNT |
| D030 — (PC)NFS | `ref/archive.opengroup.org/archive/CDROM/d030.pdf` | 164 | PCNFSD protocol (auth, print spool) |
| E403 — Security in Interworking | `ref/archive.opengroup.org/archive/CDROM/e403.pdf` | 92 | NFS/XNFS has "no defined security API" — external corroboration of AUTH_SYS weakness |
| P521 — FSSU | `ref/archive.opengroup.org/archive/CDROM/p521.pdf` | 60 | `exportfs` defaults (rw-to-everyone, access=allow-all), `showmount` info disclosure |
| C702 HTML | `ref/pubs.opengroup.org/onlinepubs/009629799/` | 128 files | Same content as C702 PDF, browsable HTML |
