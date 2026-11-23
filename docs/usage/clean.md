# Clean

The `clean` subcommand removes your entries from an NFS server's mount list, the advisory record that `showmount -a` reports and that mountd keeps in `/var/lib/nfs/rmtab`. Every successful MOUNT MNT adds an entry for the calling client, so every subcommand that mounts an export (`scan`, `analyze`, `escape`, `shell`, `mount`, `brute-handle`, `uid-spray`) leaves a trail there. `clean` sends MNTPROC_UMNTALL and then a looped MNTPROC_UMNT over MOUNT v3 and v1 until your entries are gone. A `--list` mode prints the current mount list without changing anything.

!!! warning "Changes server state"
    Without `--list`, `clean` asks the server's mountd to delete mount-list entries. It does not touch any exported filesystem, so it is not gated behind `--allow-write`, but it is a state change on the target and mountd may log it. Run `--list` first to see what is there.

!!! note "File handles stay valid"
    UMNT and UMNTALL only remove the advisory mount-list entries. They do not revoke anything: file handles the server already issued keep working after `clean` ([F-2.5](../security/access-control/F-2.5-stale-handle-persistence.md)). A handle captured from `escape` or `mount` remains usable with `shell --handle` and `mount --handle`.

## Usage

```bash
nfswolf clean <TARGET> [--list]
```

`TARGET` is the NFS server: an IP address or hostname. No export is needed; `clean` works on the whole mount list.

### Examples

```bash
# Inspect the mount list (MNTPROC_DUMP), change nothing
nfswolf clean 10.0.0.5 --list

# Remove your entries
nfswolf clean 10.0.0.5

# mountd on a known port, portmapper firewalled
nfswolf clean 10.0.0.5 --skip-rpc --mount-port 20048

# Through a SOCKS5 pivot
nfswolf clean 10.0.0.5 --proxy 127.0.0.1:1080
```

## How it works

### `--list`: read the mount list

`--list` sends MNTPROC_DUMP (RFC 1813 Appendix I sec. 5.2.2) over MOUNT v3 and falls back to MOUNT v1 if the v3 call fails. Each entry is printed as a hostname and the export it mounted. The hostname is whatever the server recorded for the client, usually its IP address or reverse-DNS name.

### Default mode: drain your entries

1. **Snapshot.** `clean` runs DUMP first. If the list is already empty, it stops there.
2. **UMNTALL.** It sends MNTPROC_UMNTALL over MOUNT v3 (RFC 1813 Appendix I sec. 5.2.4) and MOUNT v1 (RFC 1094 Appendix A sec. A.5.5), then runs DUMP again. When the server can reverse-resolve your IP address, this clears every entry of yours in one call. When it cannot (no PTR record), nfs-utils mountd silently skips the deletion, and the list is unchanged.
3. **UMNT loop.** For every export still in the list, `clean` sends MNTPROC_UMNT (sec. 5.2.3) over MOUNT v3 and v1. nfs-utils keeps a reference count per entry, and each UMNT decrements it, so an export you mounted several times needs several rounds: each round takes two references off (one v3, one v1). Because a decrement is invisible in DUMP until the count reaches zero, progress is checked every 10 rounds rather than after each one.
4. **Stall detector.** If three checks in a row (30 rounds) show no further progress, the remaining entries belong to other clients, and `clean` stops and reports how many of yours it cleared.

### Why only your own entries

Linux mountd identifies the caller of UMNT and UMNTALL by the TCP source IP of the request (`host_ntop()` in nfs-utils `rmtab.c`), not by the AUTH_SYS `machinename`. Spoofing `--hostname` does not let you remove another client's entry: you can only clear entries the server stored under the IP address you connect from. `clean` cannot tell which entries are yours (it does not know the source IP the server sees), so the UMNT loop sends UMNT for every listed export and lets the stall detector decide when it is done.

This also means `clean` must run from the same source IP as the earlier mounts. When the assessment went through `--proxy`, clean through the same proxy.

## Flags reference

| Flag | Default | Description |
|------|---------|-------------|
| `<TARGET>` | required | Target NFS server (IP or hostname). |
| `--list` | off | Show the current mount list (MNTPROC_DUMP) without removing anything. |

### Global flags affecting clean

These can be given before or after the subcommand. See [Global Options](global-options.md) for the full list.

| Flag | Effect on clean |
|------|-----------------|
| `--mount-port <PORT>` | Send every MOUNT call to this port instead of asking the portmapper. |
| `--rpc-port <PORT>` | Portmapper/rpcbind port used to look up the MOUNT port (default 111). |
| `--skip-rpc` | Never contact the portmapper. MOUNT uses `--mount-port`, or probes the well-known mountd ports 2049 and 20048. |
| `--privileged-port` | Bind MOUNT calls from a source port below 1024. |
| `--proxy <HOST:PORT>` | Route MOUNT calls through a SOCKS5 proxy. The server sees the proxy's IP, so this only clears entries made through the same proxy. |
| `-q`, `--quiet` | Suppress status lines. |

## Output

Status lines go to stderr; the `--list` table goes to stdout.

??? example "`--list`"

    ```
    [*] 3 mount entries on 10.0.0.5
    ╭──────────────┬──────────────╮
    │ Hostname     │ Export       │
    ├──────────────┼──────────────┤
    │ 10.0.0.20    │ /srv/nfs     │
    │ 10.0.0.20    │ /home        │
    │ 10.0.0.31    │ /srv/nfs     │
    ╰──────────────┴──────────────╯
    ```

??? example "Default mode, server without reverse DNS for the caller"

    ```
    [*] sending UMNTALL
    [*] 3 entries remain -- draining via UMNT loop
    [*] round 10: 1 entries remaining
    [*] round 20: 1 entries remaining
    [*] round 30: 1 entries remaining
    [+] 2 of your entries cleared
    [!] 1 entries remain from other clients (server matches by source IP -- cannot clear entries for other IPs)
    # rerun: nfswolf clean 10.0.0.5
    ```

??? example "Default mode, UMNTALL succeeds"

    ```
    [*] sending UMNTALL
    [+] 2 entries removed via UMNTALL
    # rerun: nfswolf clean 10.0.0.5
    ```

## Related pages

- [Mount](mount.md) -- `--hide` unmounts from the server right after capturing the handle, so no entry is left behind in the first place
- [Global Options](global-options.md) -- port, proxy, and stealth flags
- [F-2.5 Stale Handle Persistence](../security/access-control/F-2.5-stale-handle-persistence.md) -- why unmounting does not revoke a handle
