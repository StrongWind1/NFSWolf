# NFSv4.0 Crate Completion Plan

Phased plan to bring `crates/nfs-v4` to full RFC 7530 spec compliance. Each phase is independently shippable — later phases build on earlier ones but earlier ones are useful alone.

Current state: 37/37 ops sendable, ~17 fully decoded, 25/49 status codes named, no stateful infrastructure. 48 tests passing.

---

## Phase 1 — Status codes and typed enums (1 day)

Add the 24 missing `Nfs4Status` named variants. Pure additive, no behavioral change — `Unknown(u32)` already catches them on the wire, this just enables pattern matching.

### 1.1 Add missing `Nfs4Status` variants

| Variant | Wire Value | RFC 7530 Section |
|---------|-----------|-----------------|
| `Xdev` | 18 | S13.1.4.14 |
| `Mlink` | 31 | S13.1.4.7 |
| `Dquot` | 69 | S13.1.4.2 |
| `TooSmall` | 10005 | S13.1.1.7 |
| `ServerFault` | 10006 | S13.1.1.6 |
| `BadType` | 10007 | S13.1.4.1 |
| `Delay` | 10008 | S13.1.1.3 |
| `Same` | 10009 | S13.1.11.4 |
| `Grace` | 10013 | S13.1.9.1 |
| `FhExpired` | 10014 | S13.1.2.2 |
| `ShareDenied` | 10015 | S13.1.8.10 |
| `ClidInuse` | 10017 | S13.1.10.1 |
| `Resource` | 10018 | S13.1.3.4 |
| `NoFilehandle` | 10020 | S13.1.2.5 |
| `MinorVersMismatch` | 10021 | S13.1.3.2 |
| `StaleClientid` | 10022 | S13.1.10.2 |
| `StaleStateid` | 10023 | S13.1.5.6 |
| `OldStateid` | 10024 | S13.1.5.5 |
| `BadStateid` | 10025 | S13.1.5.2 |
| `BadSeqid` | 10026 | S13.1.8.2 |
| `NotSame` | 10027 | S13.1.11.3 |
| `LockRange` | 10028 | S13.1.8.8 |
| `Symlink` | 10029 | S13.1.2.8 |
| `RestoreFh` | 10030 | S13.1.4.12 |
| `LeaseMoved` | 10031 | S13.1.5.4 |
| `AttrNotSupp` | 10032 | S13.1.11.1 |
| `NoGrace` | 10033 | S13.1.9.2 |
| `ReclaimBad` | 10034 | S13.1.9.3 |
| `ReclaimConflict` | 10035 | S13.1.9.4 |
| `LocksHeld` | 10037 | S13.1.8.6 |
| `Openmode` | 10038 | S13.1.8.9 |
| `BadOwner` | 10039 | S13.1.11.2 |
| `BadChar` | 10040 | S13.1.7.1 |
| `BadName` | 10041 | S13.1.7.2 |
| `BadRange` | 10042 | S13.1.8.1 |
| `LockNotSupp` | 10043 | S13.1.8.7 |
| `OpIllegal` | 10044 | S13.1.3.3 |
| `Deadlock` | 10045 | S13.1.8.3 |
| `FileOpen` | 10046 | S13.1.4.5 |
| `AdminRevoked` | 10047 | S13.1.5.1 |
| `CbPathDown` | 10048 | S13.1.12.1 |

Update `from_u32`, `as_u32`, `Display`, and add classification methods:

```rust
pub const fn is_transient(self) -> bool {
    matches!(self, Self::Io | Self::Delay | Self::Resource | Self::ServerFault)
}
pub const fn is_stateid_error(self) -> bool {
    matches!(self, Self::StaleStateid | Self::OldStateid | Self::BadStateid | Self::Expired | Self::AdminRevoked)
}
pub const fn is_lease_error(self) -> bool {
    matches!(self, Self::StaleClientid | Self::Expired | Self::LeaseMoved)
}
```

### 1.2 Add wire constants

```rust
pub const NFS4_FHSIZE: usize = 128;
pub const NFS4_VERIFIER_SIZE: usize = 8;
pub const NFS4_OTHER_SIZE: usize = 12;
pub const NFS4_OPAQUE_LIMIT: usize = 1024;
```

### 1.3 Add `stable_how4` and `open_delegation_type4` enums

These are referenced by multiple ops and should be proper types:

```rust
pub enum StableHow4 { Unstable = 0, DataSync = 1, FileSync = 2 }
pub enum OpenDelegationType4 { None = 0, Read = 1, Write = 2 }
pub enum CreateMode4 { Unchecked = 0, Guarded = 1, Exclusive = 2 }
pub enum OpenType4 { NoCreate = 0, Create = 1 }
pub enum OpenClaimType4 { Null = 0, Previous = 1, DelegateCur = 2, DelegatePrev = 3 }
pub enum LockType4 { ReadLt = 1, WriteLt = 2, ReadwLt = 3, WritewLt = 4 }
```

---

## Phase 2 — Supporting wire types (2–3 days)

Add the shared types that multiple operations need. These are prerequisites for typed OPEN/LOCK/CREATE encode and decode.

### 2.1 `stateid4` as a proper type

Replace bare `[u8; 16]` throughout with a named struct:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stateid4 {
    pub seqid: u32,
    pub other: [u8; 12],
}
```

With constants for the special stateids:

```rust
impl Stateid4 {
    pub const ANONYMOUS: Self = Self { seqid: 0, other: [0; 12] };
    pub const READ_BYPASS: Self = Self { seqid: 0xFFFFFFFF, other: [0xFF; 12] };
}
```

Derive `XdrCodec` or hand-implement Pack/Unpack (4 + 12 = 16 bytes, no padding).

### 2.2 `change_info4`

```rust
#[derive(Debug, Clone, Copy)]
pub struct ChangeInfo4 {
    pub atomic: bool,
    pub before: u64,
    pub after: u64,
}
```

20 bytes on the wire (4 bool + 8 before + 8 after). Used by CREATE, LINK, OPEN, REMOVE, RENAME responses.

### 2.3 `nfs_ftype4`

```rust
pub enum NfsFtype4 {
    Reg = 1, Dir = 2, Blk = 3, Chr = 4, Lnk = 5, Sock = 6, Fifo = 7,
    AttrDir = 8, NamedAttr = 9,
}
```

### 2.4 Owner types

```rust
#[derive(Debug, Clone)]
pub struct OpenOwner4 { pub clientid: u64, pub owner: Vec<u8> }

#[derive(Debug, Clone)]
pub struct LockOwner4 { pub clientid: u64, pub owner: Vec<u8> }
```

### 2.5 `nfsace4`

```rust
#[derive(Debug, Clone)]
pub struct NfsAce4 {
    pub ace_type: u32,
    pub flag: u32,
    pub access_mask: u32,
    pub who: String,
}
```

### 2.6 `fattr4` encode/decode helpers

The current GETATTR decoder only extracts `fsid` and `sec_label`. Generalize to a `Fattr4` builder/decoder that handles the bitmap + attrvals encoding for the key attributes:

| Attr ID | Name | Type | Word | Bit |
|---------|------|------|------|-----|
| 1 | type | `NfsFtype4` | 0 | 1 |
| 3 | change | `u64` | 0 | 3 |
| 4 | size | `u64` | 0 | 4 |
| 8 | fsid | `(u64, u64)` | 0 | 8 |
| 10 | lease_time | `u32` | 0 | 10 |
| 20 | fileid | `u64` | 0 | 20 |
| 33 | mode | `u32` | 1 | 1 |
| 35 | numlinks | `u32` | 1 | 3 |
| 36 | owner | `String` | 1 | 4 |
| 37 | owner_group | `String` | 1 | 5 |
| 47 | time_access | `(i64, u32)` | 1 | 15 |
| 52 | time_metadata | `(i64, u32)` | 1 | 20 |
| 53 | time_modify | `(i64, u32)` | 1 | 21 |

Design: `Fattr4` struct with `Option<T>` fields, a `to_bitmap() -> AttrRequest` method, and `pack_attrvals()` / `unpack_attrvals(bitmap)` methods. The bitmap tells the decoder which fields are present and in what order.

---

## Phase 3 — Type all 10 opaque-payload operations (1 week)

Replace `Vec<u8>` payloads with typed structs for all 10 remaining `ArgOp` variants. Each needs typed encode (Pack) and the response decoder updated.

### 3.1 `CREATE` (op 6)

**Typed args:**
```rust
ArgOp::Create {
    objtype: CreateType4,  // enum: Lnk(String), Blk(u32,u32), Chr(u32,u32), Sock, Fifo, Dir
    objname: String,
    createattrs: Fattr4,
}
```

**Response decode:** `ChangeInfo4` + `bitmap4` (attrset) -> `ResOpData::Create { cinfo: ChangeInfo4, attrset: Vec<u32> }`

### 3.2 `LOCK` (op 12)

**Typed args:**
```rust
ArgOp::Lock {
    locktype: LockType4,
    reclaim: bool,
    offset: u64,
    length: u64,
    locker: Locker4,  // enum: NewLockOwner { open_seqid, open_stateid, lock_seqid, lock_owner } | ExistLockOwner { lock_stateid, lock_seqid }
}
```

**Response decode:** on OK -> `Stateid4` (lock stateid); on DENIED -> `Lock4Denied { offset, length, locktype, owner }`

New `ResOpData` variant:
```rust
ResOpData::Lock { lock_stateid: Stateid4 }
ResOpData::LockDenied { offset: u64, length: u64, locktype: LockType4, owner: LockOwner4 }
```

Or a combined variant with an enum.

### 3.3 `LOCKT` (op 13)

**Typed args:**
```rust
ArgOp::Lockt {
    locktype: LockType4,
    offset: u64,
    length: u64,
    owner: LockOwner4,
}
```

**Response decode:** on OK -> void; on DENIED -> `Lock4Denied`

### 3.4 `LOCKU` (op 14)

**Typed args:**
```rust
ArgOp::Locku {
    locktype: LockType4,
    seqid: u32,
    lock_stateid: Stateid4,
    offset: u64,
    length: u64,
}
```

**Response decode:** Already skips the 16-byte stateid. Change to extract it: `ResOpData::Stateid(Stateid4)`

### 3.5 `NVERIFY` (op 17)

**Typed args:**
```rust
ArgOp::Nverify { obj_attributes: Fattr4 }
```

Response is void — no decode change needed.

### 3.6 `OPEN` (op 18)

The most complex operation. Typed args:

```rust
ArgOp::Open {
    seqid: u32,
    share_access: u32,
    share_deny: u32,
    owner: OpenOwner4,
    openhow: OpenFlag4,    // enum: NoCreate | Create(CreateHow4)
    claim: OpenClaim4,     // enum: Null(String) | Previous(OpenDelegationType4) | DelegateCur { stateid, file } | DelegatePrev(String)
}
```

**Response decode** — the big one. `OPEN4resok`:

```rust
ResOpData::Open {
    stateid: Stateid4,
    cinfo: ChangeInfo4,
    rflags: u32,
    attrset: Vec<u32>,
    delegation: OpenDelegation4,  // enum: None | Read { stateid, recall, ace } | Write { stateid, recall, space_limit, ace }
}
```

### 3.7 `SETATTR` (op 34)

**Typed args:**
```rust
ArgOp::Setattr {
    stateid: Stateid4,
    obj_attributes: Fattr4,
}
```

**Response decode:** Currently skips bitmap. Change to: `ResOpData::Setattr { attrsset: Vec<u32> }`

### 3.8 `SETCLIENTID` (op 35)

**Typed args:**
```rust
ArgOp::Setclientid {
    client: NfsClientId4,  // { verifier: [u8;8], id: Vec<u8> }
    callback: CbClient4,  // { cb_program: u32, cb_location: ClientAddr4 }
    callback_ident: u32,
}
```

**Response decode:**
```rust
ResOpData::Setclientid {
    clientid: u64,
    setclientid_confirm: [u8; 8],
}
```

On `NFS4ERR_CLID_INUSE`, the response includes `clientaddr4` — decode or skip.

### 3.9 `VERIFY` (op 37)

Same structure as NVERIFY:
```rust
ArgOp::Verify { obj_attributes: Fattr4 }
```

### 3.10 `RELEASE_LOCKOWNER` (op 39)

**Typed args:**
```rust
ArgOp::ReleaseLockowner { lock_owner: LockOwner4 }
```

Response is void — no decode change.

### 3.11 Update `decode_op_result_data`

For each of the 5 ops that currently cause COMPOUND parsing to stop (CREATE, LOCK, LOCKT, OPEN, SETCLIENTID), add proper result decoding so subsequent ops in the COMPOUND are accessible.

### 3.12 Update existing result decoders

- REMOVE, LINK: decode `ChangeInfo4` instead of skipping 20 bytes -> `ResOpData::ChangeInfo(ChangeInfo4)`
- RENAME: decode two `ChangeInfo4` -> `ResOpData::RenameInfo { source: ChangeInfo4, target: ChangeInfo4 }`
- CLOSE, OPEN_CONFIRM, OPEN_DOWNGRADE, LOCKU: decode `Stateid4` instead of skipping 16 bytes -> `ResOpData::Stateid(Stateid4)`
- SETATTR: decode `bitmap4` -> `ResOpData::Setattr { attrsset: Vec<u32> }`

---

## Phase 4 — Generalized GETATTR decode (3–5 days)

The current GETATTR decoder only extracts `fsid` and `sec_label`. Generalize it to decode any combination of the key attributes listed in Phase 2.6.

### 4.1 `Fattr4Decoded` struct

```rust
#[derive(Debug, Clone, Default)]
pub struct Fattr4Decoded {
    pub ftype: Option<NfsFtype4>,
    pub change: Option<u64>,
    pub size: Option<u64>,
    pub fsid: Option<(u64, u64)>,
    pub lease_time: Option<u32>,
    pub fileid: Option<u64>,
    pub mode: Option<u32>,
    pub numlinks: Option<u32>,
    pub owner: Option<String>,
    pub owner_group: Option<String>,
    pub time_access: Option<(i64, u32)>,
    pub time_metadata: Option<(i64, u32)>,
    pub time_modify: Option<(i64, u32)>,
    pub sec_label: Option<SecLabel4>,
}
```

### 4.2 Decoder

Walk the bitmap word by word. For each set bit, decode the corresponding attribute from `attrvals` in order. Skip unknown attributes by tracking cumulative size.

### 4.3 Update `ResOpData::Getattr`

Replace `{ fsid: Option<(u64, u64)>, sec_label: Option<SecLabel4> }` with `Fattr4Decoded`. This is a breaking change to the `ResOpData` enum — update all match sites in `src/` (scanner, analyzer, shell).

### 4.4 READDIR entry attributes

Currently `DirEntry4` has only `cookie` and `name`. Extend to optionally carry decoded attributes when the READDIR request included an `attr_request`.

---

## Phase 5 — CompoundBuilder completeness (2 days)

Add builder methods for every typed operation. Currently only 15 ops have builder methods.

### Missing builder methods

| Op | Method signature |
|----|-----------------|
| `access` | `.access(mask: u32)` |
| `close` | `.close(seqid: u32, stateid: Stateid4)` |
| `commit` | `.commit(offset: u64, count: u32)` |
| `create_dir` | `.create_dir(name: &str, attrs: Fattr4)` |
| `create_symlink` | `.create_symlink(name: &str, linkdata: &str, attrs: Fattr4)` |
| `delegpurge` | `.delegpurge(clientid: u64)` |
| `delegreturn` | `.delegreturn(stateid: Stateid4)` |
| `link` | `.link(newname: &str)` |
| `lock` | `.lock(locktype: LockType4, reclaim: bool, offset: u64, length: u64, locker: Locker4)` |
| `lockt` | `.lockt(locktype: LockType4, offset: u64, length: u64, owner: LockOwner4)` |
| `locku` | `.locku(locktype: LockType4, seqid: u32, stateid: Stateid4, offset: u64, length: u64)` |
| `nverify` | `.nverify(attrs: Fattr4)` |
| `open` | `.open(seqid: u32, share_access: u32, share_deny: u32, owner: OpenOwner4, openhow: OpenFlag4, claim: OpenClaim4)` |
| `openattr` | `.openattr(createdir: bool)` |
| `open_confirm` | `.open_confirm(stateid: Stateid4, seqid: u32)` |
| `open_downgrade` | `.open_downgrade(stateid: Stateid4, seqid: u32, share_access: u32, share_deny: u32)` |
| `read` | `.read(stateid: Stateid4, offset: u64, count: u32)` |
| `readdir` | `.readdir(cookie: u64, cookieverf: u64, dircount: u32, maxcount: u32, attrs: AttrRequest)` |
| `readlink` | `.readlink()` |
| `remove` | `.remove(target: &str)` |
| `rename` | `.rename(oldname: &str, newname: &str)` |
| `renew` | `.renew(clientid: u64)` |
| `restorefh` | `.restorefh()` |
| `savefh` | `.savefh()` |
| `setattr` | `.setattr(stateid: Stateid4, attrs: Fattr4)` |
| `setclientid_confirm` | `.setclientid_confirm(clientid: u64, verifier: [u8; 8])` |
| `verify` | `.verify(attrs: Fattr4)` |
| `write` | `.write(stateid: Stateid4, offset: u64, stable: StableHow4, data: Vec<u8>)` |
| `release_lockowner` | `.release_lockowner(owner: LockOwner4)` |

---

## Phase 6 — Client API methods (3–5 days)

Add higher-level `Nfs4Client` methods for common operations. These compose COMPOUND sequences and return domain types.

### 6.1 File operations

```rust
pub async fn getattr(&self, fh: &[u8], attrs: AttrRequest) -> Result<Fattr4Decoded, ...>
pub async fn read_file(&self, fh: &[u8]) -> Result<Vec<u8>, ...>  // read entire file
pub async fn write(&self, fh: &[u8], stateid: Stateid4, offset: u64, data: &[u8]) -> Result<WriteRes, ...>
pub async fn setattr(&self, fh: &[u8], stateid: Stateid4, attrs: Fattr4) -> Result<Vec<u32>, ...>
pub async fn readlink(&self, fh: &[u8]) -> Result<String, ...>
pub async fn access(&self, fh: &[u8], mask: u32) -> Result<(u32, u32), ...>
pub async fn commit(&self, fh: &[u8], offset: u64, count: u32) -> Result<[u8; 8], ...>
```

### 6.2 Directory operations

```rust
pub async fn create_dir(&self, dir_fh: &[u8], name: &str) -> Result<(Vec<u8>, ChangeInfo4), ...>
pub async fn remove(&self, dir_fh: &[u8], name: &str) -> Result<ChangeInfo4, ...>
pub async fn rename(&self, src_fh: &[u8], oldname: &str, dst_fh: &[u8], newname: &str) -> Result<(ChangeInfo4, ChangeInfo4), ...>
pub async fn link(&self, src_fh: &[u8], dir_fh: &[u8], newname: &str) -> Result<ChangeInfo4, ...>
```

### 6.3 Security

```rust
pub async fn secinfo(&self, dir_fh: &[u8], name: &str) -> Result<Vec<SecInfoEntry>, ...>
```

---

## Phase 7 — Stateful infrastructure (2–4 weeks)

The biggest phase. Adds SETCLIENTID lifecycle, stateid tracking, and OPEN/CLOSE/LOCK state management.

### 7.1 Client ID lifecycle

```rust
pub struct Nfs4Session {
    clientid: u64,
    confirm_verifier: [u8; 8],
    confirmed: bool,
    lease_time: Duration,
}
```

Methods:
- `establish(client_name, callback_addr)` — SETCLIENTID + SETCLIENTID_CONFIRM
- `renew()` — RENEW with clientid
- Automatic lease renewal in a background task

### 7.2 Open state tracking

```rust
pub struct OpenState {
    stateid: Stateid4,
    owner: OpenOwner4,
    share_access: u32,
    share_deny: u32,
    delegation: Option<OpenDelegation4>,
    confirmed: bool,
}
```

Methods:
- `open(dir_fh, name, share_access, share_deny)` -> `OpenState`
- OPEN_CONFIRM on first use per open-owner
- `close(open_state)` — CLOSE
- `open_downgrade(open_state, new_access, new_deny)` — OPEN_DOWNGRADE

### 7.3 Lock state tracking

```rust
pub struct LockState {
    lock_stateid: Stateid4,
    lock_owner: LockOwner4,
    ranges: Vec<(u64, u64, LockType4)>,
}
```

Methods:
- `lock(open_state, locktype, offset, length)` -> `LockState`
- `unlock(lock_state, offset, length)` — LOCKU
- `test_lock(fh, locktype, offset, length, owner)` — LOCKT
- `release_lockowner(owner)` — RELEASE_LOCKOWNER

### 7.4 Delegation tracking

Track delegation stateids per file handle. DELEGRETURN method. DELEGPURGE for recovery.

No callback server (CB_RECALL requires a listening RPC service on the client) — this remains out of scope. Delegations can be returned but not recalled.

---

## Phase 8 — Crash recovery and grace period (1 week)

### 8.1 Grace period handling

On `NFS4ERR_GRACE`, wait `lease_time` and retry. Only reclaim-type operations (OPEN with CLAIM_PREVIOUS, LOCK with `reclaim=TRUE`) are allowed during grace.

### 8.2 Stale clientid recovery

On `NFS4ERR_STALE_CLIENTID`, re-establish the client ID (SETCLIENTID + CONFIRM) and retry the operation.

### 8.3 Expired state recovery

On `NFS4ERR_EXPIRED`, all state for this client has been revoked. Re-establish and re-open all files.

---

## Dependency Graph

```
Phase 1 (status codes + enums)
    |
Phase 2 (wire types: Stateid4, ChangeInfo4, owner types, Fattr4)
    |
    +---> Phase 3 (type all 10 opaque ops, decode all responses)
    |         |
    |         +---> Phase 5 (CompoundBuilder methods for all ops)
    |         |         |
    |         |         +---> Phase 6 (client API methods)
    |         |                   |
    |         |                   +---> Phase 7 (stateful infrastructure)
    |         |                             |
    |         |                             +---> Phase 8 (crash recovery)
    |         |
    +---> Phase 4 (generalized GETATTR decode)
```

Phases 3 and 4 are independent of each other. Phases 5-8 are sequential.

---

## Effort Summary

| Phase | Description | Effort | Tests (est.) |
|-------|------------|--------|-------------|
| 1 | Status codes + enums | 1 day | +50 |
| 2 | Supporting wire types | 2–3 days | +30 |
| 3 | Type all 10 opaque ops + decode | 1 week | +60 |
| 4 | Generalized GETATTR decode | 3–5 days | +20 |
| 5 | CompoundBuilder completeness | 2 days | +30 |
| 6 | Client API methods | 3–5 days | +20 |
| 7 | Stateful infrastructure | 2–4 weeks | +40 |
| 8 | Crash recovery | 1 week | +15 |
| **Total** | | **6–10 weeks** | **+265** |

Phases 1–5 bring the crate to full wire-level spec compliance (every type, every op, every status code). Phases 6–8 add the stateful engine for OPEN/LOCK workflows.

---

## What Remains Out of Scope

| Item | Reason |
|------|--------|
| CB_RECALL callback server | Requires a listening RPC service on the client; different architecture |
| NFSv4.1 session management (RFC 8881) | Different protocol version; the 4 v4.1 ops already present are sufficient for recon |
| Full ACL encoding/decoding | Complex attribute with many edge cases; encode as opaque for now |
| All 76 fattr4 attributes | Decode the ~15 key attributes; others remain opaque |
| RPCSEC_GSS integration | Separate crate concern (onc-rpc-client) |
