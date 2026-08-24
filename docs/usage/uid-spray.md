# UID Spray

The `uid-spray` subcommand is a last-resort credential brute-force tool that iterates over UID/GID ranges to discover which identities have access to a specific file or directory on the NFS server. It uses the NFSv3 ACCESS procedure (RFC 1813 S3.3.4) as a permission oracle, testing each UID/GID combination and reporting which ones the server grants access to.

!!! warning "Last resort"
    You should rarely need this. The interactive [shell](shell.md) and [FUSE mount](mount.md) already run an automatic credential escalation ladder on every `NFS3ERR_ACCES`: file owner first, then the file's group, root, observed identities from directory listings, and common service accounts. The [escape](escape.md) subcommand bypasses export-level access checks entirely by constructing handles to the filesystem root. Reach for `uid-spray` only when both of those have failed and you need to enumerate the UID/GID space to confirm whether an export is truly inaccessible or to map which identities the server recognizes.

## Usage

```bash
nfswolf uid-spray <TARGET:/export> [OPTIONS]
```

An export path is required. The tool mounts the export to obtain a root handle, then walks to the target path before spraying.

### Examples

```bash
# Spray UIDs 0-65535 against the export root (gid = uid)
nfswolf uid-spray 10.0.0.1:/srv/nfs

# Narrow the range to common user UIDs
nfswolf uid-spray 10.0.0.1:/srv/nfs --uid-start 1000 --uid-end 2000

# Target a specific file
nfswolf uid-spray 10.0.0.1:/srv/nfs --path /etc/shadow

# Cross-product sweep: every UID x GID combination
nfswolf uid-spray 10.0.0.1:/srv/nfs --uid-start 0 --uid-end 100 --gid-start 0 --gid-end 100

# Inject auxiliary groups into each probe
nfswolf uid-spray 10.0.0.1:/srv/nfs --aux-gids 42,15,100

# Add delay between probes for stealth
nfswolf uid-spray 10.0.0.1:/srv/nfs --attempt-delay 100
```

## How it works

AUTH_SYS (RFC 5531 S14) is trust-based: the server believes whatever UID, GID, and auxiliary group list the client presents. There is no authentication; the client simply declares its identity in the RPC credential. This makes UID spraying trivial: for each candidate identity, the tool constructs a fresh AUTH_SYS credential with a unique stamp (preventing duplicate-request-cache collisions) and calls the NFSv3 ACCESS procedure to check what permissions the server would grant.

The ACCESS procedure returns a bitmask of granted permissions:

| Bit | Name | Meaning |
|-----|------|---------|
| `0x0001` | READ | Read file data or list directory |
| `0x0002` | LOOKUP | Look up names in directory |
| `0x0004` | MODIFY | Rewrite existing data |
| `0x0008` | EXTEND | Write new data / create files |
| `0x0010` | DELETE | Delete entries from directory |
| `0x0020` | EXECUTE | Execute file or search directory |

!!! note "ACCESS is advisory"
    NFSv3 ACCESS results are advisory only (RFC 1813 S3.3.4). A credential reported as having write access may still be denied when attempting an actual WRITE, and vice versa. The authoritative test is to use the credential in a shell session and attempt the operation. However, ACCESS is reliable enough for discovery, and it accurately reflects the server's view of the credential's permissions in the vast majority of cases.

## UID/GID sweep modes

### Paired mode (default)

When neither `--gid-start` nor `--gid-end` is set, each UID is tested with a matching GID (uid=1000 gid=1000, uid=1001 gid=1001, etc.). This follows the Linux per-user-group convention and finds the same access in N probes that the cross-product mode needs N * 65536 to find.

### Cross-product mode

Setting `--gid-start` and/or `--gid-end` sweeps every UID x GID combination. This grows fast: 1000 UIDs x 1000 GIDs = 1,000,000 probes. The `--max-attempts` guard (default 100,000) prevents accidentally launching an unrunnable sweep. Raise it deliberately if the cross-product is what you want.

## Safety guard

The `--max-attempts` flag exists to catch accidental large sweeps, not to limit the tool's capability. If the computed sweep size exceeds the limit, the tool refuses to start and prints the sweep size so you can narrow the range or raise the limit:

```
Error: sweep would issue 4294967296 credential probes, over the 100000 limit.
Narrow --uid-start/--uid-end or --gid-start/--gid-end, or raise --max-attempts if this is intended.
```

## Flags reference

| Flag | Default | Description |
|------|---------|-------------|
| `--uid-start UID` | 0 | Start of the UID range (inclusive). |
| `--uid-end UID` | 65535 | End of the UID range (inclusive). |
| `--gid-start GID` | -- | Start of GID range. Unset = paired mode (gid follows uid). |
| `--gid-end GID` | -- | End of GID range. Unset = paired mode. |
| `--max-attempts N` | 100000 | Refuse to start if the sweep would exceed this many probes. |
| `--path PATH` | `/` | Remote path to test access against (relative to the export root). |
| `--attempt-delay MS` | 0 | Delay between probes in milliseconds (independent of global `--delay`). |
| `-e, --export PATH` | -- | Alternative to the `host:/export` positional syntax. |

## Output

Each credential that receives any access grant is printed with its UID, GID, and the granted permission bits:

??? example "Example output"

    ```
    [*] Spraying UIDs 0-5000 (gid = uid) on 10.0.0.1:/srv/nfs  --  5001 probes
    [+] 3 credential(s) granted access
        uid=0 gid=0 [READ|LOOKUP|MODIFY|EXTEND|DELETE|EXECUTE]
        uid=33 gid=33 [READ|LOOKUP|EXECUTE]
        uid=1000 gid=1000 [READ|LOOKUP|MODIFY|EXTEND|DELETE|EXECUTE]
    ```

## NFSv3 only

UID spray requires NFSv3 because the permission oracle is the NFSv3 ACCESS procedure. NFSv2 has no equivalent; it provides no way to query permissions without attempting the actual operation. If the target only speaks NFSv2, use the [shell](shell.md) with explicit `-u UID -g GID` flags and attempt reads/writes directly.

## Related pages

- [Escape](escape.md) -- bypass export-level access checks entirely (use before UID spray)
- [Shell](shell.md) -- interactive session with auto-credential escalation
- [Brute Handle](brute-handle.md) -- handle-space brute-force (complements UID spray)
- [F-1.1 UID/GID Spoofing](../security/identity/F-1.1-uid-gid-spoofing.md) -- the finding that documents AUTH_SYS identity spoofing
