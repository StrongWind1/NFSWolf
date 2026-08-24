# /etc/exports syntax

`/etc/exports` is the primary configuration file for the Linux NFS server (knfsd). Each line defines one export: a local directory path, one or more client specifications, and the options that control access. The file is parsed by `exportfs(8)`, which loads the entries into the kernel's export table.

This page covers the file format, client specification types, option syntax rules, and the management commands. For the meaning of individual options (`root_squash`, `no_subtree_check`, `sec=`, etc.), see [Export options](export-options.md).

## General format

Each export entry follows this pattern:

```text
/path client1(options) [client2(options) ...]
```

- **Path**: an existing local directory (or file, though directory exports are the norm)
- **Client**: who is allowed to mount this export (hostname, IP, network, wildcard, or netgroup)
- **Options**: comma-separated list inside parentheses, controlling security and behavior

Multiple clients can share one path on the same line, each with their own option set. Blank lines and lines starting with `#` are ignored. Long lines can be continued with a trailing backslash (`\`).

```bash title="/etc/exports"
# Simple export: one directory, one client, read-write
/srv/nfs/data  192.168.1.10(rw,sync,no_subtree_check)

# Same directory exported to two clients with different options
/srv/nfs/shared  10.0.0.0/24(rw,sync) 10.0.1.0/24(ro,sync)
```

## Path rules

The exported path must be an existing directory on the server. It does not need to be a mount point -- you can export any subdirectory. However, exporting a subdirectory of a filesystem (rather than the filesystem root) has security implications:

- With `no_subtree_check` (the default since Linux 2.6.25), the kernel does not verify that file handles fall within the exported subtree. A handle pointing to any inode on the same filesystem is accepted, even if it is outside the exported directory. This is the foundation of export escape attacks ([F-2.1](../../access-control/F-2.1-export-escape.md)).
- With `subtree_check`, the kernel verifies that each file handle resolves to an inode within the exported subtree, but this has performance costs and causes `ESTALE` errors when files are renamed.

!!! danger "Exporting a subdirectory is not a security boundary"
    Exporting `/srv/nfs/share` on an ext4 partition does **not** prevent clients from accessing the rest of the partition. With `no_subtree_check` (the default), any valid file handle on that filesystem is accepted by the kernel. An attacker who constructs a handle pointing to inode 2 (the ext4 root) gains access to the entire filesystem. See [F-2.1](../../access-control/F-2.1-export-escape.md).

## Client specifications

The client field determines which hosts are allowed to mount the export. There are five formats:

### Single host

A hostname or IP address. Only that one machine can mount the export.

```bash
/data  server1.example.com(rw,sync)
/data  192.168.1.50(rw,sync)
/data  2001:db8::1(rw,sync)
```

!!! note "Hostname resolution"
    When you use a hostname, `exportfs` resolves it to IP addresses at load time. If DNS changes after loading, the old IP remains in the export table until you run `exportfs -ra`. For security-sensitive exports, prefer IP addresses to avoid DNS-based attacks.

### Network (CIDR or netmask)

A network range in CIDR notation or with an explicit subnet mask. All hosts in the range can mount.

```bash
/data  192.168.1.0/24(rw,sync)
/data  192.168.1.0/255.255.255.0(rw,sync)
/data  2001:db8::/48(rw,sync)
```

Both forms are equivalent. CIDR notation is more common and less error-prone.

### Wildcard

A pattern with `*` and `?` characters, matched against the client's resolved hostname. Only works with reverse DNS -- if the client's IP does not have a PTR record, the match fails.

```bash
/data  *.example.com(rw,sync)
/data  web?.internal.net(ro,sync)
```

!!! warning "Wildcards depend on reverse DNS"
    Wildcard matching requires the server to reverse-resolve the client's IP address to a hostname. If reverse DNS is misconfigured or unavailable, clients that should match will be denied. If an attacker controls reverse DNS for their IP, they can forge a matching hostname.

### Netgroup

An NIS netgroup, prefixed with `@`. All hosts listed in the netgroup can mount.

```bash
/data  @web_servers(rw,sync)
/data  @trusted_hosts(rw,no_root_squash)
```

Netgroups require a functioning NIS/NIS+ or LDAP-backed `nsswitch.conf` configuration. If the netgroup source is unreachable, `exportfs` may fail silently or deny all access.

### Anonymous (everyone)

A bare `*` matches every client. This is almost never what you want in production.

```bash
/pub  *(ro,sync,all_squash)
```

!!! danger "Anonymous exports are visible to every host on the network"
    An export with `*` as the client is accessible from any IP address that can reach the NFS server. Combined with `rw` or `no_root_squash`, this is a full compromise. Even with `ro,all_squash`, it exposes directory listings and file contents to anyone. See [F-7.1](../../config/F-7.1-wildcard-export-policy.md).

### GSS security prefix

The `gss/krb5p` prefix restricts access to clients using Kerberos privacy-level authentication. The general form is `gss/<mechanism>`, where `<mechanism>` is one of `krb5`, `krb5i`, or `krb5p`. Only clients that authenticate with the specified (or stronger) GSS mechanism can mount the export.

```bash
/export       gss/krb5p(fsid=0,ro,no_subtree_check)
/export/home  gss/krb5p(rw,sec=krb5p,no_subtree_check)
```

This is distinct from the `sec=` option: `gss/krb5p` as a client specifier controls who can mount, while `sec=krb5p` controls which authentication flavors are accepted for file operations. In practice, both are used together for consistent enforcement.

## Options syntax

Options are comma-separated inside parentheses, attached directly to the client specification with **no space** between the client and the opening parenthesis.

```text
client(opt1,opt2,opt3)
```

There are no spaces around commas, no spaces inside the parentheses, and, critically, no space before the opening parenthesis.

### The space-before-paren trap

!!! danger "The most common NFS misconfiguration"
    A space between the client and the opening parenthesis changes the meaning of the line entirely:

    ```bash
    # INTENDED: export /data to 192.168.1.0/24 with rw
    /data  192.168.1.0/24(rw,sync)

    # ACTUAL EFFECT of adding a space before the paren:
    /data  192.168.1.0/24 (rw,sync)
    ```

    The second line does **not** export `/data` to `192.168.1.0/24` with `rw,sync`. It parses as two separate entries:

    1. `/data` exported to `192.168.1.0/24` with **default options** (which include `ro`)
    2. `/data` exported to **everyone** (`*` implied) with `rw,sync`

    The result: the intended network gets read-only access, and every other host on the network gets read-write access. This single space character has caused production data breaches.

You can verify this by checking the effective export table:

```bash
# After: /data  192.168.1.0/24 (rw,sync)
$ exportfs -v
/data  192.168.1.0/24(ro,wdelay,root_squash,no_subtree_check,...)
/data  <world>(rw,wdelay,root_squash,no_subtree_check,...)
```

The `<world>` entry is the giveaway -- it means the orphaned `(rw,sync)` was applied to an anonymous client specification.

!!! tip "Always verify with `exportfs -v`"
    After editing `/etc/exports`, always run `exportfs -v` and look for `<world>` entries. If any appear and you did not intend them, you have the space-before-paren bug.

## Example exports file

```bash title="/etc/exports"
# Read-only public data -- squash all users to anonymous
/srv/nfs/pub  *(ro,sync,all_squash,anonuid=65534,anongid=65534)

# Home directories -- specific subnet, root squashed
/home  192.168.1.0/24(rw,sync,root_squash,no_subtree_check)

# Build artifacts -- two dev teams, different options
/srv/builds  10.10.1.0/24(rw,sync,no_root_squash) 10.10.2.0/24(ro,sync)

# Kerberos-secured export -- require krb5p (privacy)
/srv/secure  *.corp.example.com(rw,sync,sec=krb5p,no_subtree_check)

# Database server -- single host, no root squash for backup agent
/var/backups  db01.internal(rw,sync,no_root_squash,no_subtree_check)

# ISO images -- read-only, all users squashed, world-accessible
/srv/iso  *(ro,sync,all_squash)

# Development -- wide open for lab use (NOT for production)
/srv/dev  10.0.0.0/8(rw,sync,no_root_squash,no_subtree_check,insecure)

# NFSv4-only export with fsid for pseudo-FS root
/export  192.168.0.0/16(rw,sync,fsid=0,no_subtree_check)

# Nested export under the pseudo-FS root
/export/data  192.168.0.0/16(rw,sync,no_subtree_check)

# Restricted: only Kerberos integrity or privacy, no AUTH_SYS
/srv/restricted  10.20.0.0/16(rw,sync,sec=krb5i:krb5p,no_subtree_check)

# Cross-mount visibility: crossmnt exposes nested filesystems
/srv/shared  10.0.0.0/24(rw,sync,crossmnt,no_subtree_check)
```

!!! warning "Security review of the example"
    Several entries above are intentionally insecure for illustration:

    - `/srv/dev` with `no_root_squash` + `insecure` + `/8` network is a full compromise vector
    - `/srv/builds` with `no_root_squash` for `10.10.1.0/24` allows any machine on that subnet to write files as root
    - `/srv/nfs/pub` with `*` is accessible from any host
    - `/srv/shared` with `crossmnt` may expose filesystems mounted under `/srv/shared` that were not intended to be exported

    Run `nfswolf scan` and `nfswolf analyze` against your server to identify these issues automatically.

## Managing exports with exportfs

The `exportfs` command loads, modifies, and inspects the kernel's export table. You never need to restart `nfs-server.service` to apply export changes; `exportfs` updates the kernel table live.

### Common operations

```bash
# Re-read /etc/exports and apply all changes (add new, update changed, remove deleted)
exportfs -ra

# Re-read with verbose output showing what changed
exportfs -rav

# Show the current effective export table (with all defaults expanded)
exportfs -v

# Show exports in /var/lib/nfs/etab format (machine-readable)
exportfs -s

# Unexport a specific entry
exportfs -u 192.168.1.0/24:/srv/nfs/data

# Temporarily add an export without editing /etc/exports
exportfs -o rw,sync,no_subtree_check 192.168.1.50:/tmp/scratch

# Unexport everything
exportfs -ua
```

!!! note "`exportfs -ra` vs restarting the NFS server"
    `exportfs -ra` only updates the export table. It does not drop existing client connections, invalidate file handles, or interrupt in-progress I/O. Restarting `nfs-server.service` does all of those things. In production, always prefer `exportfs -ra` over a full restart.

### Verifying changes

After any change to `/etc/exports`, verify the result:

```bash
# Step 1: Apply changes
exportfs -rav

# Step 2: Check for unintended <world> entries
exportfs -v | grep '<world>'

# Step 3: Confirm specific export options
exportfs -v | grep '/srv/nfs/data'
```

??? example "Sample `exportfs -v` output"
    ```text
    /srv/nfs/pub    <world>(ro,wdelay,root_squash,no_subtree_check,sec=sys,
                    all_squash,anonuid=65534,anongid=65534)
    /home           192.168.1.0/24(rw,wdelay,root_squash,no_subtree_check,
                    sec=sys,anonuid=65534,anongid=65534)
    /srv/builds     10.10.1.0/24(rw,wdelay,no_root_squash,no_subtree_check,
                    sec=sys,anonuid=65534,anongid=65534)
    /srv/builds     10.10.2.0/24(ro,wdelay,root_squash,no_subtree_check,
                    sec=sys,anonuid=65534,anongid=65534)
    ```

    Note how `exportfs -v` fills in defaults you did not specify: `wdelay`, `root_squash` (or `no_root_squash`), `sec=sys`, and the anonymous UID/GID mapping. These defaults are active even though they do not appear in `/etc/exports`.

## Troubleshooting with rpcdebug

When exports are not behaving as expected, kernel-level RPC and NFS debugging can reveal what the server is actually doing with incoming requests.

```bash
# Enable NFS server debug output (appears in dmesg / journalctl -k)
rpcdebug -m nfsd -s all

# Enable only export-related debugging
rpcdebug -m nfsd -s exp

# Enable RPC auth debugging (credential checks)
rpcdebug -m nfsd -s auth

# Disable all NFS server debugging
rpcdebug -m nfsd -c all

# Enable MOUNT daemon debugging (client mount requests)
rpcdebug -m nfsd -s proc

# Watch the debug output live
journalctl -kf | grep nfsd
```

!!! tip "Debug flags for common issues"
    | Issue | Debug flag | What it shows |
    |-------|-----------|---------------|
    | Client denied mount | `exp` | Export lookup, ACL matching |
    | Permission denied on file ops | `auth` | Credential mapping, squash behavior |
    | Stale file handle errors | `fh` | Handle verification, inode resolution |
    | General procedure tracing | `proc` | Every NFS procedure call and result |

??? note "Drop-in export files"
    In addition to `/etc/exports`, the NFS server loads any file matching `/etc/exports.d/*.exports` (note the `.exports` extension requirement). These drop-in files use the same syntax and are processed after the main file. This is useful for configuration management tools that need to add exports without modifying the main file.

    ```bash
    # /etc/exports.d/backups.exports
    /var/backups  backup01.internal(rw,sync,no_root_squash)
    /var/backups  backup02.internal(rw,sync,no_root_squash)
    ```

    Run `exportfs -rav` after adding or modifying drop-in files.

## Quick reference

| Element | Syntax | Example |
|---------|--------|---------|
| Single host | hostname or IP | `server1(rw)` |
| Network (CIDR) | `IP/prefix` | `10.0.0.0/24(rw)` |
| Network (mask) | `IP/mask` | `10.0.0.0/255.255.255.0(rw)` |
| Wildcard | `*.domain` | `*.example.com(ro)` |
| Netgroup | `@name` | `@trusted(rw)` |
| Everyone | `*` | `*(ro,all_squash)` |
| Comment | `# text` | `# This is a comment` |
| Continuation | trailing `\` | `host1(rw) \` |
| Options | `client(opt1,opt2)` | `host(rw,sync,no_root_squash)` |

## Next steps

- [Export options](export-options.md) -- what each option does and its security impact
- [Hardening checklist](../hardening/checklist.md) -- a prioritized list of changes to make
- [Firewall rules](firewall.md) -- network-level controls for NFS services
