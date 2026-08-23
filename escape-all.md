# `escape`: Comprehensive Export Escape

## Overview

`nfswolf escape <HOST>` is the default mode. Given just an IP address (no export path required), it discovers every export on the server and attempts every known escape method across all protocol versions. This is a seven-phase operation:

- **Phase 1: Gather seeds** -- discover every export, acquire every reachable file handle from every protocol version and source, walk upward from every handle across every version, output a deduplicated export list and seed pool.
- **Phase 2: Construct escape candidates** -- copy seeds as-is into the candidate pool, then construct every plausible filesystem-top handle from each seed. Pure computation, no network I/O.
- **Phase 3: Probe candidates** -- test every candidate against the server across all protocol versions, confirm tree-tops via LOOKUP ".." == self with credential escalation.
- **Phase 4: Deduplicate and filter** -- dedup tree-tops by handle bytes, remove handles the operator already has (known export boundaries from Phase 1b).
- **Phase 4b: Rootfs detection** -- list each tree-top's directory contents, score against known rootfs directory names, tag `OS-ESCAPE` if score >= 30.
- **Phase 5: Score and annotate** -- score each tree-top for ranking (handle quality + version bonus + rootfs bonus), generate human-readable annotations, sort by score.
- **Phase 6: Report** -- print the final results to the operator. Optionally attempt post-escape reads (`--read-shadow`).

## CLI

```
# Default: comprehensive escape against all exports on the server
nfswolf escape 192.168.1.10

# Optionally scope to a single export (still runs all phases against that export)
nfswolf escape 192.168.1.10:/srv/nfs

# Fast mode: single export, single version, reduced construction, same pipeline
nfswolf escape --fast 192.168.1.10:/srv/nfs

# JSON output for scripting
nfswolf escape 192.168.1.10 --json > escape.json

# Post-escape /etc/shadow read
nfswolf escape 192.168.1.10 --read-shadow
```

**Default mode** (`escape <HOST>`): the operator provides just the IP. Phase 1a discovers all exports automatically. Every export is probed across all versions. The full pipeline runs. Output is a sorted list of every escape handle found.

**Default mode with export** (`escape <HOST>:/export`): same pipeline but Phase 1a force-includes the specified export. Other exports are still discovered and probed. Useful when the operator knows which export they care about but still wants comprehensive coverage.

**Fast mode** (`escape --fast <HOST>:/export`): requires an export path. Single export, single NFS version (v3 first, fallback to v2, then v4). Same pipeline (Phases 1-6) but with reduced seed gathering, no brute-force, and all probing through one version. Minimal RPCs for quick engagements where speed and stealth matter.

## Flags

### Positional

- `TARGET` -- `HOST` or `HOST:/export`. Just HOST for default mode. HOST:/export required for `--fast`.

### Escape-specific

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--fast` | bool | false | Reduced pipeline: one export, one version, no brute-force, no children, no Phase 1a/1c |
| `--json` | bool | false | JSON output to stdout instead of console format |
| `--read-shadow` | bool | false | After reporting, read /etc/shadow from highest OS-ESCAPE handle |
| `--export PATH` | string | none | Alternative to `:/export` in the positional target |
| `--btrfs-subvols N` | u32 | 16 | BTRFS subvolume IDs to try (256..256+N). Fast mode forces 2. |
| `--max-root-scan N` | u32 | 200 | Brute-force inode scan depth (inodes 6..N). Fast mode skips brute-force entirely. |

### Global (inherited, affect escape behavior)

| Flag | Type | Default | How escape uses it |
|------|------|---------|-------------------|
| `--uid N` | u32 | 0 | Initial AUTH_SYS uid for all probes |
| `--gid N` | u32 | 0 | Initial AUTH_SYS gid for all probes |
| `--aux-gids N,N,...` | Vec | [] | Additional groups in AUTH_SYS credential |
| `--hostname NAME` | string | "localhost" | AUTH_SYS machinename (F-1.4 spoofing) |
| `--privileged-port` | bool | false | Force source port < 1024 for MOUNT |
| `--proxy HOST:PORT` | string | none | SOCKS5 proxy for all connections |
| `--nfs-port N` | u16 | 2049 | Direct NFS port (bypass portmapper) |
| `--mount-port N` | u16 | auto | Direct mountd port (bypass portmapper) |
| `--delay MS` | u64 | 0 | Stealth delay between RPCs |
| `--jitter MS` | u64 | 0 | Random jitter added to delay |
| `--timeout MS` | u64 | 5000 | Per-RPC timeout |
| `--no-color` | bool | false | Disable ANSI colors |
| `-v` / `--verbose` | count | 0 | Increase tracing verbosity |
| `--quiet` | bool | false | Suppress progress output |

## `--fast` mode

Fast mode runs the same seven-phase pipeline as default mode, with these reductions:

### Phase 1 reductions

**Phase 1a: SKIPPED.** Operator provides the export path. No export discovery.

**Phase 1b: ONE export, ONE version, export boundary handle only.** Try versions in order, stop at first success:

1. MOUNT v3 MNT → if success, use v3 for everything
2. MOUNT v1 MNT → if success, use v2 for everything
3. NFSv4 LOOKUP → if success, use v4 for everything

One export boundary handle. No children (no READDIRPLUS/READDIR+LOOKUP). The version that succeeded becomes the **active version** for all subsequent phases.

If all three fail, abort with an error: "could not mount export via any NFS version -- verify the export path and server availability."

**Phase 1c: SKIPPED.** No PUTROOTFH, PUTPUBFH, WebNFS, NFSPROC_ROOT.

**Phase 1d: upward traversal using the active version only.**

- If active version is v3: v3 LOOKUP ".." chain only (1 chain, not 4)
- If active version is v2: v2 LOOKUP ".." chain only
- If active version is v4: v4 LOOKUPP chain + v4 LOOKUP ".." chain (2 chains -- both v4 ops, distinct kernel paths)

### Phase 2 reductions

- Step 0 (copy seeds): **keep**
- Step 1 (extract gen): **keep**
- Step 2 (known inodes, 9 entries): **keep** (both fsid variants for compound UUID)
- Step 3 (BTRFS subvols): **reduce to 2** -- subvol 5 (FS_TREE) + subvol 256 (first user subvol)
- Step 4 (FS-specific constructors): **keep** (each is 1-2 candidates, cheap)
- Step 5 (brute-force inode scan): **SKIPPED entirely**

### Phase 3 reductions

Probe every candidate via the **active version only** (not all three). One GETATTR per candidate, not three. Root confirmation (LOOKUP ".." == self) via the active version.

### Phases 4, 4b, 5, 6

**No reductions.** Dedup, filter, rootfs detection, scoring, annotation, and report all run identically to default mode. Rootfs detection is informational -- no OS-ESCAPE tag just means the tree-top isn't confirmed as the server rootfs, not that the handle is invalid.

### RPC cost

| Phase | RPCs |
|-------|------|
| 1b: MOUNT (1 version) | 1 |
| 1d: ".." chain (1-2 chains, ~5 depth) | ~5-10 |
| 3: probing (~42 candidates * 1 version) | ~42 |
| 3: tree-top confirmation | ~5 |
| 4b: rootfs detection | ~1-3 |
| **Total best case** (v3 works, ".." finds tree-top) | **~10** |
| **Total worst case** (v4 fallback, construction needed) | **~80** |

## Terminology

Four terms used throughout this document:

| Term | Meaning | Example |
|------|---------|---------|
| **tree-top** | any directory where LOOKUP ".." == self | Phase 3 output |
| **export boundary** | the directory the server exported (MOUNT handle) | Phase 1b MOUNT handles |
| **filesystem top** | the real top of a disk filesystem | ext4 inode 2, XFS inode 128 -- the escape target |
| **pseudo-root** | NFSv4 virtual namespace root | PUTROOTFH handle |

A tree-top that is NOT an export boundary and NOT a pseudo-root is a **filesystem top** -- an **escape**. The operator reached a directory they were not supposed to access.

## Handle source matrix

Every handle source used across all phases. No handle source exists outside this table.

| #  | Source                      | How obtained                                       | fsid_type   | fileid_type          | Phase | When available                    |
|----|-----------------------------|---------------------------------------------------|-------------|----------------------|-------|-----------------------------------|
| 1  | MOUNT v3 MNT                | MNTPROC3_MNT per export                           | 6 or 7      | 0 (export boundary)  | 1b    | v3 server with mountd             |
| 2  | MOUNT v1 MNT                | MNTPROC1_MNT per export                           | 0, 3, or 4  | 0 (export boundary)  | 1b    | v2 server with mountd             |
| 3  | NFSv4 LOOKUP (export boundary) | PUTROOTFH + LOOKUP chain + GETFH                | 6 or 7      | 0 (export boundary)  | 1b    | v4 server                         |
| 4  | NFSv3 READDIRPLUS children  | READDIRPLUS on v3 export boundary handle, first 10 | same as parent | 1+ (real inode)   | 1b    | v3 server                         |
| 5  | NFSv2 READDIR+LOOKUP children| READDIR on v2 export boundary + LOOKUP each, first 10 | same as parent | varies          | 1b    | v2 server                         |
| 6  | NFSv4 READDIR+LOOKUP children| READDIR on v4 handle + LOOKUP each, first 10      | varies      | 1+ (real inode)      | 1b    | v4 server                         |
| 7  | v3 LOOKUP ".." chain        | resolve(&handle, "..") chained upward, per `is_root` handle | varies | varies        | 1d    | v3 server, subtree_check off      |
| 8  | v2 LOOKUP ".." chain        | lookup(&fh, "..") chained upward, per `is_root` handle | varies | varies              | 1d    | v2 server, subtree_check off      |
| 9  | v4 LOOKUPP chain            | PUTFH + LOOKUPP + GETFH chained upward            | 1 (pseudo) or varies | 0 or varies  | 1d    | v4 server                         |
| 10 | v4 LOOKUP ".." chain        | PUTFH + LOOKUP("..") + GETFH chained upward       | varies      | varies               | 1d    | v4 server, subtree_check off      |
| 11 | PUTROOTFH + GETFH           | NFSv4 COMPOUND: PUTROOTFH + GETFH                 | 1 (pseudo)  | 0                    | 1c    | v4 server (always)                |
| 12 | PUTPUBFH + GETFH            | NFSv4 COMPOUND: PUTPUBFH + GETFH                  | varies      | varies               | 1c    | v4 server with WebNFS             |
| 13 | WebNFS public v3            | zero-length FileHandle, test via LOOKUP            | n/a         | n/a                  | 1c    | v3 server with WebNFS             |
| 14 | WebNFS public v2            | all-zero 32 bytes, test via GETATTR                | n/a         | n/a                  | 1c    | v2 server with WebNFS             |
| 15 | NFSPROC_ROOT v2             | NFSv2 proc 3 (obsolete)                            | varies      | varies               | 1c    | old/embedded servers              |

Sources 7-10 are the upward traversal chains. Each runs on every handle with `is_root = true` in the seed pool across all protocol versions. Source 9 (LOOKUPP) and Source 10 (LOOKUP "..") are distinct NFSv4 operations with different kernel code paths -- LOOKUPP enters the pseudo-root at export boundaries on Linux knfsd, while LOOKUP("..") goes through `nfsd_lookup` which may resolve differently.

---

# Phase 1: Gather Seeds

Phase 1 collects every reachable file handle from every available protocol version and source. No escape probing happens here -- that is Phase 3. Phase 1 outputs three data structures:

1. **Export list** -- deduplicated `Vec<DiscoveredExport>` of export paths with metadata about which discovery channel found each one. Used as the iteration list for Phase 1b and passed to Phase 6 for the report.
2. **Seed pool** -- deduplicated `Vec<EscapeSeed>` of file handles, each tagged with a source label and an `is_root` flag indicating whether it came from an export-boundary-level source (MOUNT/LOOKUP) vs a child source (READDIRPLUS/READDIR). Deduped by handle bytes. Passed to Phase 2.
3. **Known export boundary set** -- `HashSet<Vec<u8>>` of handle bytes for every MOUNT v3, MOUNT v1, and NFSv4 LOOKUP export boundary handle acquired during Phase 1b. Passed to Phase 4 for filtering.

## Phase 1a: Discover exports

Five independent discovery channels, merged into one deduplicated export list. Each channel may return exports the others miss. When the operator specifies an export path (`escape host:/export`), it is always included even if no discovery channel finds it.

### Channel 1: MOUNT v3 EXPORT

Call `list_exports(addr)` (MNTPROC_EXPORT, program 100005, version 3, proc 5).

Returns `Vec<ExportEntry>` with path and allowed_hosts. This is the standard NFSv3 export enumeration -- most servers expose their full export table here.

Failure mode: mountd unreachable (firewalled, no portmapper). Logged as a warning, does not abort Phase 1.

### Channel 2: MOUNT v1 EXPORT

Call `list_exports_v1(addr)` (program 100005, version 1, proc 5).

Same wire format as v3 EXPORT but the RPC header carries version 1. The v1 list can differ from v3: a server may publish v2-only exports in its v1 table that do not appear in v3, or vice versa.

Failure mode: mountd v1 not registered. Logged as a warning.

### Channel 3: NFSv4 pseudo-FS walk

Connect to port 2049, PUTROOTFH, DFS through the pseudo-filesystem. At each directory, GETATTR(fsid). When fsid changes from the parent, the directory is a real export junction -- record its path.

Discovers exports that have no MOUNT representation at all: v4-only servers, pseudo-FS junctions, auto-mounted home directories, nested referrals.

Failure mode: v4 not available on the server. Logged as a warning.

### Channel 4: MOUNT v3 DUMP

Call `dump_clients(addr)` (MNTPROC_DUMP, program 100005, version 3, proc 4). Returns paths other clients currently have mounted. These may include bind-mount children, dynamically added exports, or sub-directory mounts that do not appear in any EXPORT list.

**Cap: 10 novel paths** not already present in the merged export list (combined cap with Channel 5). DUMP reflects other clients' state and can be arbitrarily large; capping prevents wasting time on deep subdirectory mounts that are unlikely to yield different filesystem handles.

Failure mode: mountd unreachable. Logged as a warning.

### Channel 5: MOUNT v1 DUMP

Call DUMP via MOUNT v1 (program 100005, version 1, proc 4). Same wire format as v3 DUMP but the RPC header carries version 1. On Linux knfsd v1 and v3 share rmtab so the results are identical, but on Solaris, NetApp, or embedded servers the v1 mountd may maintain separate client state and return different paths.

*Implemented via `dump_clients_v1` in `proto/mount.rs` (raw RPC with version=1, proc=4, same pattern as `list_exports_v1`).*

**Cap: 10 novel paths** not already present in the merged export list (combined cap with Channel 4 -- the 10-path cap is shared across both DUMP channels).

Failure mode: mountd v1 not registered. Logged as a warning.

### Merge

Collect all paths from channels 1-5 into a single `Vec<DiscoveredExport>`. Deduplicate by path string. Each entry records which channels discovered it.

If the operator specified an export path (`escape host:/export`), force-insert it even if no channel discovered it.

If the operator specified only a host (`escape host`) and all five channels returned zero exports, abort with an error: "no exports discovered on target -- use host:/export to specify an export manually."

```rust
struct DiscoveredExport {
    path: String,
    /// Which channels found this export (for reporting).
    sources: Vec<&'static str>,
}
```

## Phase 1b: Acquire handles from each export

For **every** export path in the merged list (no cap on export count), attempt to acquire handles via three protocol versions, then enumerate children from each successful export boundary handle.

### Per-export boundary handles (3 attempts)

```
MOUNT v3 MNT (mount.mount(addr, &path))
  -> variable-length handle (typically 28-36 bytes)
  -> also captures auth_flavors from MNT response

MOUNT v1 MNT (mount.mount_v1(addr, &path))
  -> fixed 32-byte handle
  -> different wire format, may have different fsid_type/fileid_type

NFSv4 LOOKUP (component-by-component from pseudo-root via acquire_v4_lookup_handle)
  -> v4 handle for the export boundary
```

Each handle is tagged with its source (e.g. `"MOUNT v3 /srv/nfs"`), marked `is_root = true`, and added to the seed pool if its bytes are not already present. The handle bytes are also added to the **known export boundary set** (`HashSet<Vec<u8>>`) which Phase 4 uses to filter out handles the operator already has.

### Per-export children from v3 export boundary handle

If MOUNT v3 MNT succeeded for this export:

Call `list_dir_page()` (READDIRPLUS) on the v3 export boundary handle. Collect the **first 10** child entries that have handles (skipping `.` and `..`). Each child handle has fileid_type=1 (INO32_GEN) with real inode/generation data, vs the export boundary's fileid_type=0.

Tagged as e.g. `"READDIRPLUS v3 child 'etc' from /srv/nfs"`, marked `is_root = false`.

Cap: 10 children per export. Beyond that is diminishing returns -- all children share the same fsid, just different inodes.

### Per-export children from v1 export boundary handle

If MOUNT v1 MNT succeeded for this export:

NFSv2 READDIR returns fileid + name but **no handles**. To get handles, LOOKUP each child name individually against the v2 export boundary handle. Collect the **first 10** children (skipping `.` and `..`), then LOOKUP each to get a 32-byte v2 handle.

Tagged as e.g. `"READDIR+LOOKUP v2 child 'etc' from /srv/nfs"`, marked `is_root = false`.

Cap: 10 children per export (10 LOOKUPs).

### Per-export children from v4 handle

If NFSv4 LOOKUP succeeded for this export:

Call `list_dir()` (READDIR) on the v4 handle. For the **first 10** children (skipping `.` and `..`), LOOKUP each to get a v4 handle.

Tagged as e.g. `"READDIR+LOOKUP v4 child 'etc' from /srv/nfs"`, marked `is_root = false`.

Cap: 10 children per export (10 LOOKUPs).

### Per-export yield

Up to 3 export boundary handles + 30 child handles (10 per version) per export. All deduped by handle bytes into the seed pool.

### Unmount

After acquiring all handles from an export, unmount from both MOUNT v3 and v1 (best-effort) for stealth cleanup.

## Phase 1c: Protocol-specific handle sources

Single-shot sources that don't iterate over exports or chain upward. These test protocol features that may yield handles unavailable through any other method. Runs before upward traversal so these handles are included in the traversal pool.

### NFSv4 pseudo-root handle (PUTROOTFH + GETFH)

Issue NFSv4 COMPOUND: PUTROOTFH + GETFH. PUTROOTFH (op 19, RFC 7530 S16.24) sets the current filehandle to the pseudo-root. GETFH returns the handle bytes.

**Distinct from PUTPUBFH.** PUTROOTFH always returns the pseudo-root. PUTPUBFH returns the server's designated public handle, which may point to a completely different directory (or may not be configured at all). Both must be tried.

The pseudo-root handle is always available on v4 servers, even when all exports reject the client's credentials (sec=krb5, IP ACL denial). It is a valid seed for cross-export navigation and for Phase 1d upward traversal.

Tagged as `"PUTROOTFH v4 (pseudo-root)"`, `is_root = true`.

### WebNFS public handle: NFSv3

The v3 WebNFS public handle is a zero-length opaque (`FileHandle::from_bytes(&[])`), defined by RFC 2054 sec. 6. Test by issuing a LOOKUP of any name (e.g. `"."`) against this handle. If the server processes the LOOKUP (OK, NOENT, or ACCES -- anything except BADHANDLE/PROG_MISMATCH), the handle is valid.

On a WebNFS server, the public handle points at a server-designated directory which may be a different filesystem than any export.

Tagged as `"WebNFS public v3"`, `is_root = true`.

### WebNFS public handle: NFSv2

The v2 WebNFS public handle is all-zero 32 bytes (`[0u8; 32]`), defined by RFC 2054 sec. 5. Test by issuing GETATTR against this handle. If the server accepts (OK or ACCES), the handle is valid and added as a seed.

Tagged as `"WebNFS public v2"`, `is_root = true`.

### WebNFS public handle: NFSv4 (PUTPUBFH)

Issue NFSv4 COMPOUND: PUTPUBFH + GETFH. PUTPUBFH (op 23, RFC 7530 S16.21) sets the current filehandle to the server's public handle. If the server returns a file handle via GETFH, add it as a seed.

Tagged as `"WebNFS public v4 (PUTPUBFH)"`, `is_root = true`.

### NFSPROC_ROOT v2

Single call, not per-export. Call `Nfs2Client::root()` (NFSv2 proc 3, RFC 1094 S2.2.4). This obsolete procedure was supposed to return the server's filesystem top handle. Most modern servers return void, but old or embedded servers (VxWorks, old Solaris, kernel 2.4.x) may respond with a real 32-byte handle.

If the server returns `Some(handle)` and the bytes are non-zero, add as a seed.

Tagged as `"NFSPROC_ROOT v2"`, `is_root = true`.

## Phase 1d: Upward traversal

The most important seed discovery step. Every handle in the pool with `is_root = true` (from Phases 1b AND 1c) is a starting point for upward directory traversal via **four chains across all three protocol versions** (v3 LOOKUP "..", v2 LOOKUP "..", v4 LOOKUPP, v4 LOOKUP ".."). Each chain may resolve differently, and cross-version handle reuse (e.g. a v1 MOUNT handle used with v4 LOOKUPP) can yield handles that same-version traversal misses.

File handles are bearer tokens (RFC 1094 S2.3.3) -- a handle obtained via v3 MOUNT works with v2 GETATTR and v4 PUTFH. This means every handle is a valid starting point for traversal in every version.

### v3 LOOKUP ".." chain on every `is_root` handle

For every handle in the seed pool with `is_root = true`:

1. Call `resolve(&handle, "..")` via NFSv3.
2. If the parent handle differs from the input handle, add parent to seed pool (tagged `"LOOKUP '..' v3 from <source> (depth N)"`, `is_root = true`).
3. Repeat from the parent handle until the handle stabilizes (LOOKUP ".." returns same handle -- reached a tree-top) or the server rejects with NFS3ERR_NOENT/ACCES.
4. Cap: 64 levels deep to prevent infinite loops on misbehaving servers.

Without subtree_check (the kernel default), the first ".." from an export boundary returns a handle **outside** the export. Chaining upward from there yields handles at every directory level between the export boundary and the filesystem top. Each intermediate handle is a valid escape seed with a different inode.

### v2 LOOKUP ".." chain on every `is_root` handle

For every handle in the seed pool with `is_root = true`:

1. Truncate/pad the handle to 32 bytes for v2 wire format (`Nfs2FileHandle::from_bytes`).
2. Call `lookup(&fh, "..")` via NFSv2.
3. If the parent handle differs, add to seed pool (tagged `"LOOKUP '..' v2 from <source> (depth N)"`, `is_root = true`).
4. Repeat until stabilization or rejection.
5. Cap: 64 levels.

v2 uses fixed 32-byte handles. A variable-length v3/v4 handle truncated to 32 bytes may still be accepted by the server (the knfsd kernel parses the internal structure, not the total length). This cross-version probe catches servers where v2 and v3 handle resolution diverge.

### v4 LOOKUPP chain on every `is_root` handle

For every handle in the seed pool with `is_root = true`:

1. Issue NFSv4 COMPOUND: PUTFH(handle) + LOOKUPP + GETFH.
2. If the parent handle differs, add to seed pool (tagged `"LOOKUPP v4 from <source> (depth N)"`, `is_root = true`).
3. Repeat until the handle stabilizes (reached a tree-top) or the server rejects with NFS4ERR_NOENT.
4. Cap: 64 levels.

Structurally different from v3 LOOKUP "..": on Linux knfsd, v3 ".." returns the real parent directory, while v4 LOOKUPP at the export boundary enters the pseudo-root (RFC 7530 S7.3). Both yield useful seeds:

- v3 ".." parent: real filesystem handle above the export boundary, usable across all versions.
- v4 LOOKUPP parent: pseudo-root handle giving cross-export navigation in v4, or the real parent on servers that don't enforce the pseudo-FS boundary.

Every intermediate handle encountered during each chain is added to the pool -- not just the final stabilized handle.

### v4 LOOKUP ".." chain on every `is_root` handle

For every handle in the seed pool with `is_root = true`:

1. Issue NFSv4 COMPOUND: PUTFH(handle) + LOOKUP("..") + GETFH.
2. If the parent handle differs, add to seed pool (tagged `"LOOKUP '..' v4 from <source> (depth N)"`, `is_root = true`).
3. Repeat until stabilization or rejection.
4. Cap: 64 levels.

**Distinct from LOOKUPP.** On Linux knfsd, LOOKUP("..") goes through `nfsd4_lookup` -> `nfsd_lookup` which resolves ".." as a regular name lookup in the directory. LOOKUPP goes through `nfsd4_lookupp` which is a separate handler. At export boundaries these diverge: LOOKUPP enters the pseudo-root, while LOOKUP("..") may resolve the real parent directory (same behavior as v3 LOOKUP "..") or be rejected. On non-Linux servers the divergence can be even wider.

Both must be tried because they exercise different kernel code paths and may yield different handles from the same starting point.

### Why all four traversals on every `is_root` handle

A handle obtained via MOUNT v1 may resolve differently when used with v3 LOOKUP ".." vs v2 LOOKUP ".." vs v4 LOOKUPP vs v4 LOOKUP "..":

- v3 may see a 32-byte v1 handle as a valid variable-length handle and resolve it on the real filesystem.
- v4 LOOKUPP may interpret the same bytes through the pseudo-FS layer and end up in the pseudo-root.
- v4 LOOKUP ".." may follow the real directory tree where LOOKUPP entered the pseudo-root.
- v2 truncation of a longer v3/v4 handle may produce a valid shortened handle that the kernel accepts.

Running all four on every `is_root` handle is the only way to guarantee no traversal path is missed.

### Dedup during traversal

Each chain checks the seed pool before adding. If a parent handle's bytes are already in the pool (from a different chain or a different starting handle), it is skipped and the chain terminates. This prevents redundant work when multiple starting handles converge to the same parent.

### Final dedup

New seeds from 1c and 1d are deduped by handle bytes into the same pool as 1a/1b seeds.

## Phase 1 output

Phase 1 is complete. Three outputs:

1. `Vec<DiscoveredExport>` -- every export path with discovery channel metadata. Passed to Phase 6 for the report.
2. `Vec<EscapeSeed>` -- every unique file handle with its source label and `is_root` flag. Passed to Phase 2.
3. `HashSet<Vec<u8>>` -- known export boundary handle bytes (every MOUNT v3, MOUNT v1, and NFSv4 LOOKUP handle from Phase 1b). Passed to Phase 4 for filtering.

## Error handling

Every source is best-effort. A failure in any single channel, per-export acquisition, or upward traversal step is logged as a warning and does not abort Phase 1. The only hard failure is if the target host is completely unreachable (no TCP connectivity at all), which is caught before Phase 1 begins by the address resolution step.

## RPC cost estimate

For a server with E exports, each exporting a directory with at least 10 children:

| Source | RPCs |
|--------|------|
| Phase 1a: 5 discovery channels | ~5 |
| Phase 1b: 3 root MNTs + 3x10 children per export | 33 * E |
| Phase 1c: 5 single-shot probes | 5 |
| Phase 1d: 4 upward chains per `is_root` handle (3*E + 5 starts, up to 64 deep each) | up to 256 * E (usually much less due to convergence) |

Typical server with 3 exports: ~900 RPCs worst case, ~250 in practice (chains converge quickly, many handles dedup). Stealth delay applies to every RPC when configured.

---

# Phase 2: Construct Escape Candidates

Phase 2 takes the seed pool from Phase 1 and builds the candidate pool: first by copying every seed as-is, then by constructing every plausible filesystem-top handle from each seed. No network probing happens here -- that is Phase 3. Phase 2 outputs a single data structure:

- **Candidate pool** -- `Vec<EscapeCandidate>` of handles (both raw seeds and constructed handles), each tagged with its source, filesystem type, and construction method. Deduped by handle bytes.

```rust
struct EscapeCandidate {
    /// The handle to probe.
    handle: FileHandle,
    /// Which seed produced this candidate (or "seed" if it is the seed itself).
    seed_source: String,
    /// Inferred filesystem type.
    fs_type: FsType,
    /// Human-readable label (e.g. "seed: MOUNT v3 /srv/nfs", "ext4 inode 2 gen=0").
    label: String,
    /// Inode/object number embedded in the handle (0 for raw seeds).
    inode_number: u32,
}
```

## Step 0: Copy seeds into candidate pool

Every seed handle from Phase 1 is copied into the candidate pool as-is. These are server-given handles that may already point above the export boundary (Phase 1d traversal handles that walked to the filesystem top) or at export boundaries, children, public handles, etc.

Phase 3 treats them identically to constructed handles -- probe via v3/v2/v4 GETATTR, confirm tree-top via LOOKUP ".." == self. A Phase 1d traversal handle that IS the filesystem top flows through naturally: Phase 3 confirms it as a tree-top, Phase 4 filters out known export boundaries, and the handle reaches the report. No parallel paths or special cases needed.

Tagged as e.g. `"seed: MOUNT v3 /srv/nfs"`, `"seed: LOOKUP '..' v3 from /srv/nfs (depth 4)"`.

## Step 1: Extract seed generation values

For each seed, extract the generation value embedded in its handle bytes (if the fileid_type carries one):

| fileid_type | Gen location |
|-------------|-------------|
| 0x01 (INO32_GEN) | 4 bytes after the inode field |
| 0x02 (INO32_GEN_PARENT) | 4 bytes after the inode field |
| 0x81 (INO64_GEN) | 4 bytes after the 8-byte inode field |
| 0x4d (BTRFS) | bytes 16-19 of the fileid (gen field in btrfs_fid) |
| 0x00 (FILEID_ROOT) | no gen field -- skip |

Store as `seed_gen: Option<u32>` per seed. This gen value is used as an **additional** generation to try during construction (alongside gen=0 and the static table values). If the seed is a Phase 1d traversal handle that reached the filesystem top, its gen IS the filesystem top inode's generation -- constructing with that gen produces an exact match.

## Construction pipeline

For **each** seed handle in the pool:

### Step 2: Known filesystem-top candidates (INO32_GEN table)

Call `FileHandleAnalyzer::construct_root_candidates(&seed)`.

Produces handles for every (inode, generation) pair in the static table:

| Inode | Gen | Filesystem |
|-------|-----|------------|
| 2     | 0   | ext2/3/4, JFS, squashfs |
| 3     | 0   | f2fs |
| 1     | 0   | VFAT |
| 128   | 0   | XFS v5 |
| 64    | 0   | XFS v4 |
| 32    | 0   | XFS v4 (1024B inodes) |
| 5     | 5   | NTFS3 |
| 2     | 1   | reiserfs |
| 7     | 0   | squashfs |

If `seed_gen` (from Step 1) is available and differs from the table's gen value for a given inode, also construct a variant with the seed's gen. This catches the case where the filesystem-top inode has a non-zero generation (e.g., after fsck, mkfs with non-default options, or when the seed IS the filesystem top from Phase 1d traversal and carries the real gen).

For compound UUID seeds (fsid_type=7), each entry produces both an fsid_type=7 variant (full export context) and an fsid_type=6 variant (UUID-only). Other seed types produce one variant.

### Step 3: BTRFS subvolume handles

Call `FileHandleAnalyzer::construct_btrfs_subvol_handles(&seed, btrfs_subvols)`.

Constructs FILEID_BTRFS_WITHOUT_PARENT (0x4d) handles for:
- FS_TREE_OBJECTID (5) -- the default subvolume on any fresh BTRFS filesystem
- Subvolumes 256 through 256 + `btrfs_subvols` -- user-created subvolumes

Each with objectid=256 (BTRFS_FIRST_FREE_OBJECTID, the top directory of any subvolume) and gen=0.

Both fsid variants for compound UUID seeds.

### Step 4: Filesystem-specific constructors

Each constructor targets a filesystem with a non-standard fileid format that the INO32_GEN table and brute-force scan cannot produce.

**ZFS** -- `construct_zfs_root_handle(&seed)`

ZFS uses zfid_short_t: zf_len(u16) + zf_object(6 bytes) + zf_gen(4 bytes). Filesystem top object is 34 (OBJ_DIR_OBJECTID). Gen=0 accepted as wildcard. Both fsid variants.

**EROFS** -- `construct_erofs_root_handle(&seed, 36)`

EROFS uses FILEID_INO64_GEN (0x81) with a 64-bit nid. Filesystem top nid is commonly 36. Gen ignored (read-only FS). Both fsid variants.

**NILFS2** -- `construct_nilfs2_root_handles(&seed)`

NILFS2 uses FILEID_NILFS_WITHOUT_PARENT (0x61): cno(u64) + ino(u64) + gen(u32). Filesystem top is inode 2, cno=0 (current mount), gen=0 (lenient check). Both fsid variants.

**bcachefs** -- `construct_bcachefs_root_handle(&seed)`

bcachefs uses FILEID_BCACHEFS_WITHOUT_PARENT (0xb1): inum(u64) + subvol(u32) + gen(u32). Filesystem top is inum=4096, subvol=1, gen=0. Both fsid variants.

**UDF** -- `construct_udf_root_candidates(&seed)`

UDF uses FILEID_UDF_WITHOUT_PARENT (0x51) with logical block addressing. Filesystem top block varies per volume. Tries blocks: 66, 130, 258, 2, 64, 128, 256, 512. Gen=0 (lenient). Both fsid variants.

**ISO 9660** -- `construct_iso9660_root_candidates(&seed)`

isofs uses fileid_type=1 with a bit-packed block/offset layout. Filesystem top LBA varies by authoring tool. Tries blocks: 23-30, 20, 22, 18, 19, 21. Gen=0 (lenient). Both fsid variants.

**FAT/VFAT** -- `construct_fat_root_handle(&seed)` *(not yet implemented)*

On modern Linux (3.x+), FAT/VFAT uses `fat_encode_fh` which produces FILEID_FAT_WITHOUT_PARENT (0x71) handles with format: `i_logstart(u32) + i_generation(u32)`. The filesystem top's `i_logstart` is 0 on FAT32 (the top directory's cluster lives in the superblock, not the data area). Gen=0.

This is distinct from the INO32_GEN table entry (inode=1, gen=0, fileid_type=0x01) which goes through `generic_fh_to_dentry` -- a different kernel code path. A server that produced 0x71 handles from `fat_encode_fh` will only accept 0x71 handles via `fat_fh_to_dentry`. Both must be tried.

Both fsid variants for compound UUID seeds.

### Step 5: Brute-force inode scan

Call `FileHandleAnalyzer::construct_candidates_all_variants(&seed, inode, generation)` for:

1. **Dense low-inode sweep**: inodes 1-5 with generations 0-5 (6 * 6 = 36 combinations). Catches reiserfs gen=1, NTFS3 gen=5, and other non-standard filesystem-top inodes with non-zero generations.

2. **Wide inode sweep**: inodes 6 through `max_root_scan` (default 200) with gen=0 only. The filesystem-top inode is always within the first 200 inodes on any Linux filesystem.

3. **Seed gen sweep**: if `seed_gen` is available and > 5 (not already covered by the dense sweep), also try each inode 1-5 with `seed_gen`. For the wide sweep range (6-200), try both gen=0 and `seed_gen`.

Both fsid variants for compound UUID seeds.

### No length variants on constructed handles

Length variants (`derive_handle_variants`: raw, trimmed, pad32, pad64) are NOT applied to constructed handles. Constructed handles have the exact length the kernel expects -- determined by fileid_type and fsid_type. Trimming would strip gen=0 bytes the kernel needs, breaking the handle. Padding to 32 bytes for v2 is already done by Phase 3's v2 probe (`Nfs2FileHandle::from_bytes`). Padding to 64 bytes is ignored by the kernel (trailing bytes past the FID length).

Length variants are useful for **seed** handles (Phase 1) where the original server-produced length may differ from what a different protocol version expects. Constructed handles are correct by construction.

### Per-seed yield

For a compound UUID seed with default settings (16 BTRFS subvols, 200 max inode scan), without seed_gen:

| Source | Candidates |
|--------|------------|
| Raw seed (Step 0) | 1 |
| Known filesystem-top inodes (9 entries * 2 fsid variants) | ~18 |
| BTRFS (17 subvols * 2 fsid variants) | ~34 |
| FS-specific (7 constructors * 2 fsid variants) | ~56 |
| Brute-force (36 dense + 195 wide, * 2 fsid variants) | ~462 |
| **Total** | **~571** |

With seed_gen available and > 5, add ~200 more candidates (seed_gen variants in the brute-force range).

After dedup across seeds (many seeds on the same filesystem produce identical candidates), the candidate pool is typically much smaller than seeds * 571.

### Construction coverage

Phase 2 covers every Linux kernel FILEID type that can encode a filesystem top:

| fileid_type | Name | Constructor | Filesystem top value |
|-------------|------|-------------|----------------------|
| 0x01 | FILEID_INO32_GEN | Step 2 (known inodes) + Step 5 (brute-force) | ext4=2, f2fs=3, VFAT=1, XFS=32/64/128 |
| 0x02 | FILEID_INO32_GEN_PARENT | Step 2 (compound UUID path) | same + parent=self |
| 0x4d | FILEID_BTRFS_WITHOUT_PARENT | Step 3 | subvol 5 + 256..N |
| 0x51 | FILEID_UDF_WITHOUT_PARENT | Step 4 (UDF) | block 66/130/258/... |
| 0x61 | FILEID_NILFS_WITHOUT_PARENT | Step 4 (NILFS2) | inode 2 cno=0 |
| 0x71 | FILEID_FAT_WITHOUT_PARENT | Step 4 (FAT) | logstart=0 |
| 0x81 | FILEID_INO64_GEN | Step 2 (XFS 0x81 path) + Step 4 (EROFS) | XFS=128/64/32, EROFS nid=36 |
| 0xb1 | FILEID_BCACHEFS_WITHOUT_PARENT | Step 4 (bcachefs) | inum=4096 subvol=1 |
| (ZFS) | ZFS zfid_short_t (uses 0x01) | Step 4 (ZFS) | object 34 |
| (ISO) | ISO 9660 (uses 0x01) | Step 4 (ISO 9660) | block 23-30 |

Types intentionally NOT constructed (kernel accepts the WITHOUT_PARENT variant for dentry lookup):
- 0x4e/0x4f (BTRFS WITH_PARENT variants) -- kernel's `btrfs_fh_to_dentry` accepts 0x4d
- 0x52 (UDF_WITH_PARENT), 0x62 (NILFS_WITH_PARENT), 0x72 (FAT_WITH_PARENT), 0xb2 (BCACHEFS_WITH_PARENT) -- kernel accepts the WITHOUT_PARENT form
- 0x82/0x83 (INO32/64_GEN_PARENT variants) -- fh_to_dentry doesn't need parent info
- 0x97 (LUSTRE) -- enterprise distributed FS, rare over NFS
- 0xfe (KERNFS) -- sysfs/cgroup, not exportable via NFS

### Not-yet-implemented constructors

The following server types are fingerprinted by `fingerprint_os` but do not yet have handle constructors. Seeds from these servers currently pass through to Phase 3 as-is (Phase 1d upward traversal may have already walked them above the export boundary) but no new filesystem-top handles are derived from them.

**FreeBSD** *(not yet implemented)*

FreeBSD handles use fsid(8 bytes) + fid_len(2 bytes) + fid_data(variable). UFS filesystem top is inode 2, ZFS filesystem top is object 34. The fsid from the seed is preserved; only the fid needs to be rewritten with the filesystem-top inode. Constructible -- needs a `construct_freebsd_root_handle` function.

TODO: drop FreeBSD kernel source into `ref/` -- need `sys/kern/vfs_export.c`, `sys/ufs/ffs/ffs_vfsops.c` (UFS fhtovp), `sys/contrib/openzfs/module/os/freebsd/zfs/zfs_vnops_os.c` (ZFS fhtovp) to extract exact fid layout, filesystem-top values, and gen handling.

**OpenBSD** *(not yet implemented)*

OpenBSD handles use a similar `fhandle` structure to FreeBSD but may diverge in fid encoding per filesystem. Constructible -- needs a `construct_openbsd_root_handle` function.

TODO: drop OpenBSD kernel source into `ref/` -- need `fhandle` structure + per-FS fid encoding to extract layout, filesystem-top values, and gen handling.

**Windows NFS (unsigned)** *(not yet implemented)*

Windows NFS handles are 32 bytes. When signing is disabled (HMAC bytes at offset 22-31 are zero, detected by `check_windows_signing`), the handle structure is forgeable. The internal format encodes volume ID + file ID. Constructible when signing is disabled -- needs a `construct_windows_root_handle` function. When signing is enabled (non-zero HMAC), construction is not possible without the server's signing key.

**Solaris** *(not yet implemented)*

Solaris NFS handles use a different fid structure documented in Solaris kernel source. Constructible -- needs a `construct_solaris_root_handle` function.

TODO: drop Solaris kernel source or docs into `ref/` -- need `nfs_fhandle_t` / `export_fid` structure, per-FS fid encoding (UFS, ZFS), filesystem-top values, and gen bypass behavior.

### Candidate pool dedup

All candidates across all seeds are deduped by handle bytes into one `Vec<EscapeCandidate>`. When multiple seeds produce the same candidate bytes, the first (highest-quality seed) wins.

## Phase 2 output

`Vec<EscapeCandidate>` -- every unique handle with metadata. This is the sole input to Phase 3.

---

# Phase 3: Probe Candidates

Phase 3 takes the candidate pool from Phase 2 and probes every candidate against the server across all three protocol versions. No fallback ordering -- every candidate is tested through every version. Phase 3 has no checks to remove candidates -- it is pure verification.

Phase 3 outputs:

- **Verified pool** -- `Vec<VerifiedTreeTop>` of handles confirmed to be tree-tops (directories where ".." == self), tagged with which version(s) accepted them and the working credential.

```rust
struct VerifiedTreeTop {
    candidate: EscapeCandidate,
    /// Which versions confirmed this as a tree-top (any combination).
    v3_confirmed: bool,
    v2_confirmed: bool,
    v4_confirmed: bool,
    /// The uid/gid pair that succeeded (from credential ladder escalation).
    /// uid=0/gid=0 if the initial probe succeeded without escalation.
    uid: u32,
    gid: u32,
    /// Rootfs detection score from Phase 4b directory listing.
    /// 0 until Phase 4b runs.
    rootfs_score: u32,
    /// True when rootfs_score >= 30 -- this handle reaches the server's root filesystem.
    /// false until Phase 4b runs.
    os_escape: bool,
}
```

## Probing pipeline

For **each** candidate in the candidate pool:

### Step 1: Probe handle validity via GETATTR

Test the candidate handle against all three protocol versions:

**NFSv3**: call `Nfs3Client::attrs(&candidate.handle)`.

**NFSv2**: truncate/pad to 32 bytes via `Nfs2FileHandle::from_bytes`, call `Nfs2Client::getattr(&fh)`. The v2 code path in the kernel has different handle validation (fixed 32 bytes) -- a candidate that fails on v3 may succeed on v2.

**NFSv4**: call `Nfs4Client::getattr(&candidate.handle)`. v4 PUTFH has its own validation path and the pseudo-FS layer can intercept handles differently.

Result interpretation (same for all three versions):

| Result | Interpretation |
|--------|---------------|
| Ok (directory) | Handle valid, is a directory. Proceed to Step 2 for this version. |
| Ok (non-directory) | Handle valid but not a directory. Not a tree-top. Skip this version. |
| ACCES/PERM | Handle valid, root_squash blocks read. Proceed to Step 2 for this version. |
| STALE | Handle format valid but inode/gen wrong. Skip this version. |
| BADHANDLE / other error | Handle rejected. Skip this version. |

### Step 2: Confirm tree-top via LOOKUP ".." == self

For every version that returned valid (Ok or ACCES) in Step 1, independently confirm this is a tree-top.

**For v3/v2**: call LOOKUP ".." on the candidate handle. If the parent handle's fileid equals the candidate's fileid, the directory is its own parent -- confirmed tree-top.

**For v4**: call both LOOKUPP and LOOKUP("..") on the candidate handle. Either confirming ".." == self is sufficient for that version.

**Credential escalation on ACCES**: if GETATTR or LOOKUP ".." returns ACCES (root_squash blocking uid=0), bootstrap the credential ladder:

1. **Get owner info**: try GETATTR as nobody (uid=65534, gid=65534) -- the filesystem top is typically mode 0755, so nobody can read attrs even under root_squash. If this succeeds, extract the owner uid/gid and mode bits.

2. **Build the ladder**: feed owner info (if obtained) into `credential_ladder_with()`. The full ladder, in order:
   - File owner UID + file owner GID (from step 1, if available)
   - Caller UID with the file's GID
   - Root (uid=0 -- already tried, skipped)
   - Observed identities from Phase 1b READDIRPLUS results (ranked by frequency)
   - Common service accounts (nobody/65534, nfsnobody/65534, daemon/1, bin/2, etc.)
   - If mode bits prove no "other" access (`mode & 0o007 == 0`), service account rungs are skipped.

3. **Try the ladder**: attempt LOOKUP ".." with each credential in order until one succeeds. The first credential that gets Ok gives us both the tree-top confirmation (parent == self) and the working uid/gid to record.

4. **Fallback**: if the entire ladder is exhausted without a successful LOOKUP "..", try LOOKUP of well-known names ("etc", "bin", "usr", "var", "lib") with the same ladder. A successful LOOKUP of any confirms the handle points at a tree-top that contains standard top-level directories. (Note: this overlaps with Phase 4b's rootfs detection, but serves a different purpose -- Phase 3 uses it for tree-top CONFIRMATION when ".." fails; Phase 4b uses a full directory listing for rootfs SCORING. Both are needed.)

If nobody also returns ACCES in step 1, the ladder runs without owner info -- starts from observed identities, then service accounts. The ladder is evidence-driven: it tries the most likely UIDs first and avoids wasting RPCs on identities the mode bits rule out.

### Step 3: Record results

For each confirmed tree-top, record:
- Which versions confirmed it (v3, v2, v4 -- independently, any combination)
- The uid/gid pair that succeeded (uid=0/gid=0 if no escalation was needed, or the credential from the ladder that got through root_squash)

The uid/gid is essential for the report: it tells the operator which identity to use with `shell --handle` or `mount --handle` to access the escaped filesystem.

## Phase 3 output

`Vec<VerifiedTreeTop>` -- every confirmed tree-top with per-version status and working credential. This is the sole input to Phase 4.

---

# Phase 4: Deduplicate and Filter

Phase 4 takes the verified tree-tops from Phase 3, deduplicates them, and filters out handles the operator already has. Pure computation, no network I/O.

The operator can already access any export boundary via `nfswolf shell host:/export` -- showing those handles in the results is noise. Phase 4 removes them so the output contains only handles the operator doesn't already have.

## Inputs

Phase 4 receives two inputs:

1. `Vec<VerifiedTreeTop>` from Phase 3 -- confirmed tree-tops with per-version flags and working credential.
2. **Known export boundary handles** from Phase 1b -- a `HashSet<Vec<u8>>` of handle bytes for every MOUNT v3, MOUNT v1, and NFSv4 LOOKUP export boundary handle acquired during Phase 1b. Phase 1b must retain this set alongside the seed pool for Phase 4's use.

## Deduplication

Dedup tree-tops by handle bytes. When the same handle appears multiple times (from different seeds or different construction methods), merge:
- Version flags: OR together (v3_confirmed, v2_confirmed, v4_confirmed)
- uid/gid: keep the first working credential
- Seed sources: collect all source labels for the report

## Filter

Remove any tree-top whose handle bytes exactly match an entry in the Phase 1b known export boundary set.

This is a direct byte comparison -- no fileid tracking needed. If a constructed handle has different bytes but resolves to the same directory as an export boundary, it is kept. Different bytes means a different wire format that might work in contexts the MOUNT handle doesn't (different NFS version, different server validation path).

## Phase 4 output

`Vec<VerifiedTreeTop>` -- deduped, filtered to only handles the operator doesn't already have. This is the sole input to Phase 4b.

---

# Phase 4b: Rootfs Detection

Phase 4b takes the filtered tree-tops from Phase 4 and probes each to determine whether it points at the server's actual root filesystem (`/`). This is the only phase between filtering and scoring that makes network calls.

## Method

For each tree-top, list its directory contents. When multiple versions confirmed the tree-top in Phase 3, prefer v3 (READDIRPLUS returns child names + handles + attrs in one call). Fall back to v4 READDIR, then v2 READDIR.

- **v3** (preferred): READDIRPLUS on the tree-top handle (single RPC, returns child names + handles)
- **v4** (fallback): READDIR on the tree-top handle (single RPC, returns child names)
- **v2** (last resort): READDIR on the tree-top handle (single RPC, returns child names)

Use the working uid/gid from Phase 3 for the listing. If ACCES, escalate with the credential ladder (same as Phase 3 Step 2).

## Scoring against rootfs name set

Intersect the child names from the directory listing against two tiers of rootfs directory names:

**Tier 1 -- definitive** (only exist at `/`, +15 each):

| Name | Why definitive |
|------|---------------|
| `proc` | procfs mount point, kernel-created at boot |
| `sys` | sysfs mount point, kernel-created at boot |
| `dev` | devtmpfs, kernel-populated device nodes |
| `run` | tmpfs created by systemd at boot |

**Tier 2 -- common** (typically at `/` but can exist elsewhere, +5 each):

| Name | Notes |
|------|-------|
| `boot` | kernel images, initramfs |
| `mnt` | FHS admin mount point |
| `media` | FHS removable media |
| `srv` | FHS service data |
| `bin` | system binaries |
| `sbin` | system admin binaries |
| `lib` | shared libraries |
| `etc` | configuration files |
| `tmp` | temporary files |
| `var` | variable data |
| `usr` | user programs |
| `opt` | optional packages |
| `home` | user home directories |
| `root` | root user home directory |

Maximum possible score: 4 * 15 + 14 * 5 = 130.

**Threshold: 30+ = `OS-ESCAPE` tag.** This requires either two definitive names (proc + sys = 15 + 15 = 30), or one definitive + three common (15 + 3*5 = 30), or six common names (6 * 5 = 30). All of these strongly indicate the server's root filesystem.

Examples:
- `proc` + `sys` = 30 → `OS-ESCAPE` (two kernel mount points = certain)
- `proc` + `etc` + `bin` + `usr` = 15 + 5 + 5 + 5 = 30 → `OS-ESCAPE`
- `etc` + `bin` + `usr` + `var` + `lib` + `home` = 30 → `OS-ESCAPE` (six common = very likely)
- `etc` + `bin` + `usr` = 15 → no tag (could be a chroot or container)
- BTRFS subvolume with only data directories = 0 → no tag (filesystem top but not rootfs)

## Recording

Set `rootfs_score` and `os_escape` on each `VerifiedTreeTop` (fields defined in Phase 3's struct, initialized to 0/false, filled by Phase 4b). Phase 5 uses these for scoring and annotation.

## RPC cost

One directory listing RPC per tree-top in the filtered set. After Phase 4's dedup and filter, this is typically 1-5 handles. Negligible cost.

## Phase 4b output

`Vec<VerifiedTreeTop>` -- same set as Phase 4 output, enriched with rootfs_score and os_escape. This is the sole input to Phase 5.

---

# Phase 5: Score and Annotate

Phase 5 takes the enriched tree-tops from Phase 4b, scores each for ranking, and generates human-readable annotations. Pure computation, no network I/O. Phase 5 outputs:

- **Annotated pool** -- `Vec<AnnotatedTreeTop>` of tree-tops with scores and annotations, sorted by score descending.

```rust
struct AnnotatedTreeTop {
    tree_top: VerifiedTreeTop,
    score: u32,
    annotation: String,
}
```

## Scoring

Score each tree-top for ranking. Higher score = more likely to be useful to the operator:

```
fsid_type score:
  7 (compound UUID)  -> 100  (real filesystem, most complete handle format)
  6 (UUID-only)      -> 50   (real filesystem, less context)
  1 (pseudo)         -> 0    (pseudo-root, not a real filesystem)
  other              -> 25

fileid_type score:
  2 (INO32_GEN_PARENT) -> 20  (most complete, includes parent)
  1 or 0x81            -> 15  (standard inode format)
  0x4d (BTRFS)         -> 10  (BTRFS subvol)
  other                -> 5

version bonus:
  v3_confirmed       -> +10  (usable with shell, FUSE mount, all tools)
  v2_confirmed       -> +5   (usable with v2 shell)
  v4_confirmed       -> +5   (usable with v4 shell)

rootfs bonus:
  os_escape          -> +200  (confirmed server rootfs -- highest priority)

total = fsid_score + fileid_score + version_bonus + rootfs_bonus
```

The rootfs bonus ensures `OS-ESCAPE` handles always sort above non-rootfs filesystem tops. Among multiple `OS-ESCAPE` handles, the fsid/fileid/version scores break ties.

Sort by total score descending (best handles first).

## Annotation

For each tree-top, generate a human-readable annotation:

- **Tag**: `OS-ESCAPE` if `os_escape == true` (rootfs_score >= 30). No tag otherwise.
- **Verdict**: from handle bytes via `annotate_handle` -- "likely the filesystem top, best candidate to try first" / "BTRFS volume top" / "NFSv4 pseudo-root, virtual directory not a real filesystem" / etc.
- **Rootfs detail**: if `OS-ESCAPE`, append which rootfs directories were found (e.g. "proc, sys, dev, etc, bin, usr, var, home")
- **Technical detail**: fsid_type, fileid_type, filesystem UUID prefix (first 4 bytes for grouping handles from the same disk)
- **Seed source**: which Phase 1 source produced the seed that led to this tree-top
- **Version compatibility**: which NFS versions confirmed this tree-top
- **Working credential**: uid/gid that succeeded

## Phase 5 output

`Vec<AnnotatedTreeTop>` -- every tree-top scored and annotated, sorted by score. This is the sole input to Phase 6.

---

# Phase 6: Report

Phase 6 takes the annotated tree-tops from Phase 5 and the export list from Phase 1, and presents the final output to the operator.

## Console output

The default output format. Printed to stdout/stderr using the existing `output.rs` formatting utilities (colored, bold, dimmed).

```
Exports discovered:
  /srv/nfs      [MOUNT v3, MOUNT v1, NFSv4]
  /data         [MOUNT v3, NFSv4]
  /home         [MOUNT v3]

Seeds acquired: 42 unique handles
Candidates constructed: 8,547 (deduped from 23,982)
Tree-tops confirmed: 3 (filtered 2 known export boundaries)

Results:
  [OS-ESCAPE]  ext4 inode 2  via MOUNT v3 /srv/nfs   [v3 v2 v4]  uid=65534
               handle: 0100070200000000...
               likely the filesystem top, best candidate to try first (fsid=compound-UUID, fileid=ino32+gen+parent, fs=a1b2c3d4)
               rootfs dirs: proc, sys, dev, run, etc, bin, sbin, lib, usr, var, tmp, opt, home, root (score: 130)

  [+]  XFS inode 128  via MOUNT v1 /data      [v3]  uid=0
       handle: 0100060181000000...
       likely the filesystem top (fsid=UUID-only, fileid=ino64+gen, fs=e5f6a7b8)

  [+]  NFSv4 pseudo-root                       [v4]  uid=0
       handle: 0100010000000000...
       NFSv4 pseudo-root, virtual directory not a real filesystem (fsid=pseudo)

  3 handle(s) found from 42 seeds. 1 confirmed server rootfs.

Next steps:
  nfswolf shell 192.168.1.10 --handle 0100070200000000... --uid 65534 --gid 65534
  nfswolf mount 192.168.1.10 --handle 0100070200000000... --uid 65534 --gid 65534 /mnt/escape
```

Next-steps commands use the highest-scoring handle's hex and credential. The operator picks the handle that looks most useful and tries it in the shell.

If Phase 4 filtering removed all tree-tops (every confirmed tree-top was a known export boundary), print: "No new handles found -- all tree-tops matched known export boundaries. The server's exports may already be whole-filesystem exports (no boundary to escape)."

## JSON output (`--json`)

When `--json` is passed, Phase 6 writes a single JSON object to stdout instead of console output. No colors, no progress lines (progress goes to stderr). The JSON is the machine-readable equivalent of the console report.

```json
{
  "host": "192.168.1.10",
  "exports": [
    {"path": "/srv/nfs", "sources": ["MOUNT v3", "MOUNT v1", "NFSv4"]},
    {"path": "/data", "sources": ["MOUNT v3", "NFSv4"]},
    {"path": "/home", "sources": ["MOUNT v3"]}
  ],
  "stats": {
    "seeds": 42,
    "candidates": 8547,
    "candidates_before_dedup": 23982,
    "tree_tops_confirmed": 5,
    "tree_tops_filtered": 2,
    "tree_tops_reported": 3
  },
  "results": [
    {
      "handle": "0100070200000000abcdef...",
      "fs_type": "ext4",
      "inode": 2,
      "label": "ext4 inode 2 gen=0",
      "versions": {"v3": true, "v2": true, "v4": true},
      "uid": 65534,
      "gid": 65534,
      "os_escape": true,
      "rootfs_score": 130,
      "rootfs_dirs": ["proc", "sys", "dev", "run", "boot", "etc", "bin", "sbin", "lib", "usr", "var", "tmp", "opt", "home", "root"],
      "score": 335,
      "seed_source": "MOUNT v3 /srv/nfs",
      "annotation": "likely the filesystem top, best candidate to try first (fsid=compound-UUID, fileid=ino32+gen+parent, fs=a1b2c3d4)"
    },
    {
      "handle": "0100060181000000...",
      "fs_type": "xfs",
      "inode": 128,
      "label": "XFS inode 128 gen=0",
      "versions": {"v3": true, "v2": false, "v4": false},
      "uid": 0,
      "gid": 0,
      "os_escape": false,
      "rootfs_score": 0,
      "rootfs_dirs": [],
      "score": 75,
      "seed_source": "MOUNT v1 /data",
      "annotation": "likely the filesystem top (fsid=UUID-only, fileid=ino64+gen, fs=e5f6a7b8)"
    },
    {
      "handle": "0100010000000000...",
      "fs_type": "unknown",
      "inode": 0,
      "label": "seed: PUTROOTFH v4 (pseudo-root)",
      "versions": {"v3": false, "v2": false, "v4": true},
      "uid": 0,
      "gid": 0,
      "os_escape": false,
      "rootfs_score": 0,
      "rootfs_dirs": [],
      "score": 10,
      "seed_source": "PUTROOTFH v4 (pseudo-root)",
      "annotation": "NFSv4 pseudo-root, virtual directory not a real filesystem (fsid=pseudo)"
    }
  ],
  "next_steps": [
    "nfswolf shell 192.168.1.10 --handle 0100070200000000abcdef... --uid 65534 --gid 65534",
    "nfswolf mount 192.168.1.10 --handle 0100070200000000abcdef... --uid 65534 --gid 65534 /mnt/escape"
  ]
}
```

Results are sorted by `score` descending (same ordering as console output). The `next_steps` array contains the same commands shown in console output, ready for copy-paste or programmatic use.

When `--read-shadow` is also passed, the JSON includes an additional `shadow` field:

```json
{
  "shadow": {
    "readable": true,
    "gid_used": 42,
    "gid_label": "Debian/Ubuntu shadow",
    "lines": ["root:$6$...:19000:0:99999:7:::", "..."]
  }
}
```

If /etc/shadow is not readable, `"readable": false` with no `lines` field.

## Post-escape actions (`--read-shadow`, optional)

Only runs when the operator passes `--read-shadow`. Attempts automatic reads from the highest-scoring `OS-ESCAPE` handle (not just any tree-top -- a pseudo-root or non-rootfs filesystem top won't have /etc/shadow).

If no `OS-ESCAPE` handle exists, skip silently.

1. **Read /etc/shadow**: LOOKUP "etc" -> LOOKUP "shadow" -> READ. Try with shadow GIDs (42 for Debian/Ubuntu, 15 for SUSE) to bypass root_squash. Use the working uid/gid from the verified tree-top for the initial connection, then switch to shadow GIDs for the READ.

These are informational -- failure does not affect the report.

## Error handling

Phase 4 and 5-6 are pure computation + local I/O. Phase 4b makes network calls (READDIRPLUS per tree-top) -- same best-effort error handling as Phase 1 and 3: failures are logged and the tree-top gets rootfs_score=0 (no tag).

---

# RPC Cost Estimate

For a server with E exports and S seeds in the pool, with default settings:

| Phase | Source | RPCs |
|-------|--------|------|
| 1a | 5 discovery channels | ~5 |
| 1b | 3 MNTs + 3x10 children per export | 33 * E |
| 1c | 5 single-shot probes | 5 |
| 1d | 4 upward chains per `is_root` handle (up to 64 deep each) | up to 256 * E (usually much less due to convergence) |
| 2 | construction | 0 (pure computation) |
| 3 | probing (~570 candidates per seed * 3 versions) | ~1710 * S |
| 3 | tree-top confirmation (LOOKUP ".." per hit) | ~10 * S (few hits expected) |
| 4 | dedup + filter | 0 (pure computation) |
| 4b | rootfs detection (READDIRPLUS per tree-top) | ~1-5 |
| 5-6 | scoring, annotation, reporting | 0 (pure computation) |
| 6 | post-escape /etc/shadow (optional, `--read-shadow`) | ~10 |

Typical server with 3 exports, 20 seeds: ~35,000 RPCs total. With stealth delay of 50ms, that's ~29 minutes. Without delay (default), seconds on a local network. Many seeds share the same filesystem, so dedup across seeds significantly reduces the actual candidate count.

The brute-force scan (inodes 6-200) dominates the cost. `--max-root-scan` controls this: lowering it to 10 cuts Phase 3 by ~90%.
