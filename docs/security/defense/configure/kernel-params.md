# Kernel parameters

Linux exposes NFS server and client tunables through `/proc/fs/nfsd/`, `/proc/sys/sunrpc/`, and kernel module parameters. Most of these control performance and protocol version availability, but several have direct security implications -- disabling vulnerable protocol versions, limiting thread exposure, and controlling identity mapping behavior.

This page covers the tunables relevant to hardening an NFS server. For export-level options, see [Export options reference](export-options.md). For firewall rules, see [Firewall rules](firewall.md).

## NFS server parameters (`/proc/fs/nfsd/`)

The NFS server daemon (`nfsd`) exposes its runtime configuration under `/proc/fs/nfsd/`. These files are writable only while the server is running, and changes take effect immediately unless noted otherwise.

### Protocol version control

The `versions` file controls which NFS versions the server accepts. This is the single most important kernel parameter for NFS security -- disabling NFSv2 and NFSv3 eliminates the MOUNT protocol, the portmapper dependency, and the entire AUTH_SYS identity spoofing surface for those versions.

```bash
# Show currently enabled versions
cat /proc/fs/nfsd/versions

# Disable NFSv2 and NFSv3 (NFSv4-only server)
echo "-2 -3 +4 +4.1 +4.2" > /proc/fs/nfsd/versions
```

!!! danger "Disable NFSv2"
    NFSv2 has no security negotiation mechanism. A server that accepts NFSv2 connections allows attackers to bypass `sec=krb5` enforcement entirely ([F-1.6](../../identity/F-1.6-nfsv2-downgrade.md)). Unless you have legacy clients from the 1990s that cannot be upgraded, disable NFSv2.

The persistent equivalent lives in `/etc/nfs.conf`:

```ini
[nfsd]
vers2 = n
vers3 = n
vers4 = y
vers4.1 = y
vers4.2 = y
```

### Thread count

```bash
cat /proc/fs/nfsd/threads    # Current thread count
echo 64 > /proc/fs/nfsd/threads
```

The thread count determines how many concurrent NFS requests the server processes. Too few threads cause request queuing and timeouts; too many waste memory. The default of 8 is too low for production servers handling more than a handful of clients. A reasonable starting point is 1 thread per CPU core for moderate workloads, scaling up under monitoring.

### Listening ports and addresses

```bash
cat /proc/fs/nfsd/portlist    # Current listeners (protocol, port, address)
```

The server listens on port 2049 by default. The `portlist` file shows which protocol/address combinations are active (TCP, UDP, IPv4, IPv6). To bind to a specific address, configure it in `/etc/nfs.conf`:

```ini
[nfsd]
host = 192.168.1.10
port = 2049
```

!!! tip "Disable UDP for NFSv3"
    UDP NFS is susceptible to source-address spoofing and request amplification. If your clients support TCP, disable UDP by setting `udp = n` under `[nfsd]` in `/etc/nfs.conf`.

### Maximum block size

```bash
cat /proc/fs/nfsd/max_block_size    # Default: 1048576 (1 MiB)
```

Controls the maximum read/write payload per RPC call. Reducing this limits the data an attacker can exfiltrate per request, but also degrades legitimate client performance. Rarely worth changing for security alone.

## NFSv4 identity mapping

NFSv4 maps UIDs and GIDs to `user@domain` strings on the wire, translated back to numeric IDs by `idmapd`. When ID mapping is disabled, the server sends raw numeric IDs instead.

```bash
# Check current state (0 = mapping enabled, 1 = mapping disabled)
cat /proc/sys/fs/nfsd/nfs4_disable_idmapping
```

!!! warning "Security implication"
    With `nfs4_disable_idmapping = 1` (the common setting for AUTH_SYS environments), NFSv4 transmits raw UIDs on the wire just like NFSv3. This means UID spoofing via AUTH_SYS works identically across both versions ([F-1.1](../../identity/F-1.1-uid-gid-spoofing.md)). ID mapping with Kerberos (`sec=krb5`) binds identities to the KDC principal, which is the only configuration where this tunable does not matter.

```bash
# Persistent via sysctl
echo "fs.nfsd.nfs4_disable_idmapping = 0" >> /etc/sysctl.d/nfs.conf
sysctl -p /etc/sysctl.d/nfs.conf
```

## SunRPC parameters (`/proc/sys/sunrpc/`)

The kernel SunRPC layer underpins both the NFS client and server. Its tunables affect connection handling, slot allocation, and transport behavior.

### TCP slot tables

```bash
cat /proc/sys/sunrpc/tcp_slot_table_entries     # Client: max concurrent RPCs per connection
cat /proc/sys/sunrpc/tcp_max_slot_table_entries  # Client: upper bound for slot negotiation
```

The slot table controls how many RPC requests can be in-flight simultaneously on a single TCP connection. The default of 2 is conservative. Increasing it improves throughput for parallel workloads but also increases the server's exposure to a single misbehaving client consuming disproportionate resources.

```ini
# /etc/sysctl.d/nfs.conf — client-side tuning
sunrpc.tcp_slot_table_entries = 128
sunrpc.tcp_max_slot_table_entries = 65536
```

### Transport pool mode

```bash
cat /proc/sys/sunrpc/pool_mode    # auto, global, percpu, pernode
```

Controls how the server distributes incoming connections across thread pools. `percpu` pins each thread to a CPU core, reducing cache contention under high load. `auto` selects `percpu` on NUMA systems and `global` elsewhere. This is a performance tunable with no direct security impact.

### RPC debugging

The `rpcdebug` tool controls kernel-level tracing for NFS and RPC subsystems. It writes to the kernel ring buffer (`dmesg`).

```bash
rpcdebug -m nfsd -s all     # Enable all NFSD debug flags
rpcdebug -m nfsd -c all     # Disable all NFSD debug flags
rpcdebug -m rpc -s auth     # Trace RPC authentication decisions
rpcdebug -m nfs -s all      # Client-side NFS debug (for troubleshooting mounts)
```

Available modules and useful flag combinations:

| Module | Flag | What it traces |
|--------|------|---------------|
| `nfsd` | `proc` | Every NFS procedure call (operation type, file handle, result) |
| `nfsd` | `fileop` | File open, read, write, close at the VFS level |
| `nfsd` | `auth` | Authentication decisions (accept/reject, squash, flavor) |
| `nfsd` | `export` | Export lookups (which export matched, access checks) |
| `rpc` | `auth` | RPC-level credential parsing and verification |
| `rpc` | `call` | Every RPC call/reply (program, version, procedure, XID) |
| `nlm` | `all` | NLM lock manager activity (lock requests, grants, denials) |

!!! tip "Incident response"
    During an active investigation, `rpcdebug -m nfsd -s proc,auth,export` traces every NFS operation with its credential and export match. Combine with `tcpdump -i eth0 port 2049 -w /tmp/nfs.pcap` for wire-level correlation. Disable debug flags after investigation -- they generate substantial kernel log volume.

## Recommended sysctl.conf

A consolidated `/etc/sysctl.d/nfs-hardening.conf` for a production NFS server:

```ini
# Disable NFSv4 numeric ID passthrough — require proper idmapping
fs.nfsd.nfs4_disable_idmapping = 0

# Server-side: increase slot capacity for high-client-count environments
sunrpc.tcp_slot_table_entries = 128
sunrpc.tcp_max_slot_table_entries = 65536

# Disable SunRPC UDP transport (TCP only)
# Note: this is a compile-time / nfs.conf setting, not a sysctl.
# Use /etc/nfs.conf [nfsd] udp=n instead.
```

Apply with:

```bash
sysctl -p /etc/sysctl.d/nfs-hardening.conf
```

!!! note "Version control is not a sysctl"
    NFS version enable/disable is controlled through `/etc/nfs.conf` (persistent) or `/proc/fs/nfsd/versions` (runtime), not through sysctl. The sysctl namespace only covers `fs.nfsd.nfs4_disable_idmapping` and the `sunrpc.*` parameters.

## Kernel module parameters

Some NFS settings are kernel module parameters, set at load time or via `/etc/modprobe.d/`:

```ini
# /etc/modprobe.d/nfs-server.conf
options nfsd nfs4_disable_idmapping=0
options lockd nlm_udpport=32803 nlm_tcpport=32803
```

The `lockd` port pinning is critical for firewall rules -- see [Firewall rules](firewall.md) for the complete port-pinning configuration.
