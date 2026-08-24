# Comparison

nfswolf replaces 10+ fragmented NFS security tools with one static binary. This page compares nfswolf against every actively maintained offensive NFS tool across 39 capability dimensions.

!!! tip "See also"
    For detailed descriptions of each tool, client libraries, and the historical timeline, see [Related Tools](../nfs/tools.md).

## Full capability matrix

:material-check: = supported | :material-close: = not supported | Partial = limited implementation

### Reconnaissance

| Capability | nfswolf | nfs_analyze | nfscli | niffler | NfSpy | nfsshell | EvilNFSClient | NFSwalker | RPCScan | showmount | nmap NSE |
|------------|---------|-------------|--------|---------|-------|----------|---------------|-----------|---------|-----------|----------|
| Network scan (host/port discovery) | :material-check: | :material-close: | :material-close: | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-check: | :material-close: | :material-check: |
| Export enumeration (MOUNT EXPORT) | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: |
| Auth flavor extraction | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| Portmapper enumeration | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-check: | :material-close: | :material-check: |
| Portmap amplification measurement | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| NIS detection | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| Version probing (PROG_MISMATCH) | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| NFSv4 pseudo-FS mapping | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| NFSv4 SECINFO probing | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| RDMA detection | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| UDP scan fallback | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-check: |

### Analysis

| Capability | nfswolf | nfs_analyze | nfscli | niffler | NfSpy | nfsshell | EvilNFSClient | NFSwalker | RPCScan | showmount | nmap NSE |
|------------|---------|-------------|--------|---------|-------|----------|---------------|-----------|---------|-----------|----------|
| Security analysis (findings catalog) | :material-check: (62) | :material-check: | :material-close: | Partial | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| OS/FS fingerprinting | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| File handle decode (offline) | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| Squash misconfiguration detection | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| AUTH_TLS / STRIPTLS detection | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| Structured reporting (HTML/JSON/CSV) | :material-check: (6 formats) | :material-check: (JSON) | :material-close: | :material-check: (SQLite/Web) | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |

### Exploitation

| Capability | nfswolf | nfs_analyze | nfscli | niffler | NfSpy | nfsshell | EvilNFSClient | NFSwalker | RPCScan | showmount | nmap NSE |
|------------|---------|-------------|--------|---------|-------|----------|---------------|-----------|---------|-----------|----------|
| Export escape (handle construction) | :material-check: (18 FS) | :material-check: (4 FS) | Via `..` | :material-close: | Via handle | Via handle | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| BTRFS subvolume escape | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| NFSv4 LOOKUPP escape | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| Handle brute-force | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| UID/GID spray | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| Auto-UID credential escalation | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| Evidence-driven credential ladder | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |

### Access

| Capability | nfswolf | nfs_analyze | nfscli | niffler | NfSpy | nfsshell | EvilNFSClient | NFSwalker | RPCScan | showmount | nmap NSE |
|------------|---------|-------------|--------|---------|-------|----------|---------------|-----------|---------|-----------|----------|
| Interactive shell | :material-check: (52 cmds) | :material-close: | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: |
| FUSE mount | :material-check: | :material-close: | :material-close: | :material-close: | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| Recursive get/put | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| Tab completion | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| Secret scanning (SUID, world-writable) | :material-check: | :material-close: | :material-close: | :material-check: | :material-close: | :material-close: | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: |

### Protocol support

| Capability | nfswolf | nfs_analyze | nfscli | niffler | NfSpy | nfsshell | EvilNFSClient | NFSwalker | RPCScan | showmount | nmap NSE |
|------------|---------|-------------|--------|---------|-------|----------|---------------|-----------|---------|-----------|----------|
| NFSv2 | :material-check: | :material-close: | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| NFSv3 | :material-check: | :material-check: | :material-check: | :material-check: | :material-check: | :material-check: | :material-check: | :material-check: | :material-check: | N/A | N/A |
| NFSv4 | :material-check: | :material-check: | :material-close: | :material-check: | :material-close: | :material-close: | :material-close: | Partial | :material-close: | N/A | N/A |
| Auto-version detection | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | N/A | N/A |

### Operational

| Capability | nfswolf | nfs_analyze | nfscli | niffler | NfSpy | nfsshell | EvilNFSClient | NFSwalker | RPCScan | showmount | nmap NSE |
|------------|---------|-------------|--------|---------|-------|----------|---------------|-----------|---------|-----------|----------|
| SOCKS proxy support | :material-check: | :material-close: | :material-close: | :material-check: | :material-close: | :material-close: | :material-close: | :material-check: | :material-close: | :material-close: | :material-close: |
| Stealth mode (configurable delays) | :material-check: | :material-close: | :material-close: | :material-close: | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| Single static binary | :material-check: | :material-close: | :material-check: | :material-close: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-check: | :material-close: |
| No C/runtime dependencies | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| AUTH_DH session support | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |
| AUTH_SHORT replay | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: | :material-close: |

## Scorecard

Counting supported capabilities from the matrix above (39 total dimensions):

| Tool | Supported | Coverage |
|------|-----------|----------|
| nfswolf | 39/39 | 100% |
| nfs_analyze | 11/39 | 28% |
| nfscli | 7/39 | 18% |
| niffler | 8/39 | 21% |
| nfsshell | 4/39 | 10% |
| NfSpy | 4/39 | 10% |
| EvilNFSClient | 4/39 | 10% |
| NFSwalker | 3/39 | 8% |
| RPCScan | 4/39 | 10% |
| showmount | 2/39 | 5% |
| nmap NSE | 4/39 | 10% |

!!! note "Counting methodology"
    "Partial" counts as 0. "Via handle" or "Via `..`" counts as 1 (the capability exists, even if the mechanism differs). N/A counts as 0.

## Escape coverage comparison

The export escape capability varies dramatically across tools. nfswolf's escape engine covers 18 of 19 tested Linux filesystem types. The closest competitor, nfs_analyze, covers 4.

| Filesystem | nfswolf | nfs_analyze | nfscli | NfSpy | nfsshell |
|------------|---------|-------------|--------|-------|----------|
| ext2/3/4 | :material-check: | :material-check: | :material-check: (via `..`) | Manual | Manual |
| XFS | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| BTRFS | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| JFS | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: |
| SquashFS | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: |
| f2fs | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: |
| VFAT | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: |
| ZFS | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| EROFS | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: |
| UDF | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: |
| ISO 9660 | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: |
| ReiserFS | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: |
| NILFS2 | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: |

See the [Filesystem Escape Matrix](escape-matrix.md) for per-filesystem test results and kernel `encode_fh` analysis.

## Gaps filled by nfswolf

| Attack Phase | Best Prior Tool | What nfswolf Adds |
|-------------|-----------------|-------------------|
| **Reconnaissance** | nmap + RPCScan | Unified scan with portmap amplification, NIS detection, version probing, RDMA, TLS/STRIPTLS detection, NFSv4 pseudo-FS mapping |
| **Analysis** | nfs_analyze | 62-finding catalog with RFC citations, AUTH_TLS detection, AUTH_NONE metadata leak, portmap amplification measurement, 6 output formats |
| **Export Escape** | nfs_analyze (4 FS types) | 18/19 filesystem types, NFSv4 escape path, multi-source seed gathering, scoring/annotation, seven-phase pipeline |
| **Interactive Access** | nfscli | Auxiliary GID injection, handle construction from within the shell, NFSv4 support, tab completion, recursive get/put, 52 commands |
| **FUSE Mount** | fuse_nfs (Python) | Auto-UID + escape handle + SOCKS proxy + NFSv2/v3/v4 in one binary, no Python runtime |
| **Credential Harvesting** | niffler | Complementary; nfswolf finds the path, niffler scans the files |
| **Reporting** | niffler (SQLite/Web) | HTML + JSON + TXT + CSV + Markdown + console, finding IDs traceable to RFC sections |

## Language and deployment

| Property | nfswolf | nfs_analyze | nfscli | niffler | NfSpy | nfsshell | EvilNFSClient | NFSwalker | RPCScan |
|----------|---------|-------------|--------|---------|-------|----------|---------------|-----------|---------|
| Language | Rust | Python | C | Rust | Python 2 | C | Go | Python | Python |
| Runtime deps | None | Python + pynfs + libfuse3 | None | libnfs (C FFI) | Python 2 | None | None | Python | Python |
| Static binary | Yes (musl) | No | Yes | No | No | Yes | Yes | No | No |
| Cross-platform | Linux | Linux | Linux | Linux | Linux | Linux/BSD | Linux/macOS/Windows | Linux | Linux |
| Last active | 2026 | 2026 | 2026 | 2026 | 2014 (dead) | 2025 | 2025 | 2025 | 2018 (dead) |

!!! info "nfswolf + niffler"
    nfswolf and niffler are designed as companions. Use nfswolf to discover NFS infrastructure (`scan`), identify misconfigurations (`analyze`), break out of exports (`escape`), and gain interactive access (`shell` or `mount`). Then point niffler at the accessible shares for deep credential and secret scanning with its rule engine and web dashboard.

## Prior workflow vs. nfswolf

Before nfswolf, a security researcher assessing NFS infrastructure needed to install, configure, and context-switch between 10+ tools in 5 languages to cover the full attack path:

1. **Find NFS services:** `nmap` or `RPCScan` for host/port discovery.
2. **Enumerate exports:** `showmount -e` or `rpcinfo -p` for service and export lists.
3. **Analyze security:** `nfs_analyze` (requires Python, pynfs, libfuse3-dev) for misconfigurations and escape.
4. **Mount escaped handle:** `fuse_nfs` (Python, same repo as nfs_analyze) for FUSE mount.
5. **Interactive access:** `nfscli` (C) or `nfsshell` (C) for shell commands, raw handle injection.
6. **Scan for secrets:** `niffler` (Rust, requires libnfs C library) for credential scanning.
7. **NFSv4 ACLs:** `NFSwalker` (Python) for v4-specific ACL extraction.

With nfswolf, the same workflow is a single binary:

```bash
nfswolf scan 10.0.0.0/24          # Find and enumerate
nfswolf analyze 10.0.0.5          # Analyze all exports
nfswolf escape 10.0.0.5           # Break out of exports
nfswolf shell 10.0.0.5:/share     # Interactive shell (52 commands)
nfswolf mount 10.0.0.5:/share /mnt # FUSE mount with auto-UID
```
