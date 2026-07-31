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
