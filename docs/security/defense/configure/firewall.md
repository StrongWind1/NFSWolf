# Firewall rules

NFS is not a single port. A default NFSv3 deployment uses at least five services across dynamically assigned ports, making firewall configuration error-prone. This page documents every port NFS needs, how to pin the dynamic ones, and complete firewall rulesets for both nftables and iptables. It also explains why firewalling alone cannot secure NFS.

For kernel-level tunables, see [Kernel parameters](kernel-params.md). For export-level hardening, see [Export options reference](export-options.md).

## The port problem

NFSv3 depends on multiple RPC services, each registering a random port with the portmapper at startup. Without explicit configuration, mountd might listen on port 43721 one boot and 51893 the next. Firewalling "the NFS port" means nothing when half the attack surface is on unpredictable ports.

| Service | Program | Default Port | Dynamic? | Purpose |
|---------|---------|-------------|----------|---------|
| Portmapper / rpcbind | 100000 | 111 (TCP+UDP) | No | Service discovery: maps program numbers to ports ([F-5.4](../../info-disclosure/F-5.4-rpc-service-enumeration.md)) |
| NFS | 100003 | 2049 (TCP+UDP) | No | File operations (READ, WRITE, LOOKUP, etc.) |
| mountd | 100005 | random | **Yes** | Export listing, mount handle distribution ([F-5.1](../../info-disclosure/F-5.1-export-list-enumeration.md)) |
| NLM (lockd) | 100021 | random | **Yes** | File locking (NFSv3 only) |
| statd (NSM) | 100024 | random | **Yes** | Lock recovery after crashes |
| rquotad | 100011 | random | **Yes** | Disk quota queries ([F-5.15](../../info-disclosure/F-5.15-rquotad-uid-oracle.md)) |

An attacker only needs to reach portmapper on port 111 to discover every other port. Even without the portmapper, sequential port scanning finds the services quickly.

## Step 1: pin dynamic ports

Before writing firewall rules, assign fixed ports to every dynamic service. Edit `/etc/nfs.conf`:

```ini
[mountd]
port = 20048

[lockd]
port = 32803

[statd]
port = 32765
outgoing-port = 32766
```

For `lockd`, also set kernel module parameters (some distributions ignore `nfs.conf` for lockd):

```ini
# /etc/modprobe.d/lockd.conf
options lockd nlm_udpport=32803 nlm_tcpport=32803
```

Restart NFS services after changing these:

```bash
systemctl restart nfs-server rpc-statd
```

Verify with `rpcinfo -p localhost`; every service should show its assigned port.

!!! warning "rquotad"
    `rquotad` is not always controlled by `/etc/nfs.conf`. On RHEL/CentOS, set `RPCRQUOTADOPTS="-p 32769"` in `/etc/sysconfig/rpc-rquotad`. On Debian/Ubuntu, use `/etc/default/quota` with `RPCRQUOTADOPTS="-p 32769"`. If you do not need quota reporting over NFS, disable `rpc-rquotad.service` entirely, since it leaks per-UID disk usage without authentication.

## Step 2: firewall rules

With ports pinned, the firewall configuration is straightforward. Allow the fixed set of ports from trusted client networks only.

=== "nftables"

    ```bash
    #!/usr/sbin/nft -f
    
    table inet nfs_filter {
        set trusted_clients {
            type ipv4_addr
            flags interval
            elements = { 10.0.1.0/24, 10.0.2.0/24 }
        }

        chain input {
            type filter hook input priority 0; policy drop;

            # Loopback
            iif "lo" accept

            # Established connections
            ct state established,related accept

            # NFS services — TCP only (UDP disabled in nfs.conf)
            ip saddr @trusted_clients tcp dport {
                111,     # portmapper
                2049,    # nfsd
                20048,   # mountd
                32803,   # lockd
                32765    # statd
            } accept

            # Log and drop everything else
            log prefix "nfs-dropped: " counter drop
        }
    }
    ```

=== "iptables"

    ```bash
    #!/usr/bin/env bash
    set -euo pipefail

    TRUSTED="10.0.1.0/24,10.0.2.0/24"

    # Flush existing NFS rules
    iptables -D INPUT -j NFS_FILTER 2>/dev/null || true
    iptables -F NFS_FILTER 2>/dev/null || true
    iptables -X NFS_FILTER 2>/dev/null || true

    # Create NFS chain
    iptables -N NFS_FILTER

    # Allow from trusted clients only — TCP
    for PORT in 111 2049 20048 32803 32765; do
        iptables -A NFS_FILTER -s "${TRUSTED}" -p tcp --dport "${PORT}" -j ACCEPT
    done

    # Drop all other NFS-related traffic
    for PORT in 111 2049 20048 32803 32765; do
        iptables -A NFS_FILTER -p tcp --dport "${PORT}" -j DROP
        iptables -A NFS_FILTER -p udp --dport "${PORT}" -j DROP
    done

    # Insert into INPUT chain
    iptables -I INPUT -j NFS_FILTER
    ```

!!! tip "Disable UDP"
    The examples above only allow TCP. UDP NFS is susceptible to source-address spoofing and amplification attacks ([F-3.2](../../network/F-3.2-portmapper-amplification.md)). Disable UDP in `/etc/nfs.conf` with `udp = n` under `[nfsd]` and omit UDP `dport` rules entirely.

## NFSv4-only simplification

NFSv4 eliminates the MOUNT protocol, the portmapper dependency, and the NLM lock manager. An NFSv4-only server needs exactly one port:

```mermaid
graph LR
    C["NFS Client"] -->|"TCP 2049"| S["NFS Server"]
    style C fill:#1a1a2e,stroke:#e94560,color:#fff
    style S fill:#1a1a2e,stroke:#e94560,color:#fff
```

| Port | Service | Needed? |
|------|---------|---------|
| 111 | portmapper | No. NFSv4 connects directly to 2049. |
| 2049 | nfsd | **Yes** |
| 20048 | mountd | No. NFSv4 uses PUTROOTFH + LOOKUP. |
| 32803 | lockd | No. NFSv4 has built-in locking. |
| 32765 | statd | No. NFSv4 handles state recovery internally. |

The firewall for an NFSv4-only server is minimal:

=== "nftables"

    ```bash
    table inet nfs_filter {
        set trusted_clients {
            type ipv4_addr
            flags interval
            elements = { 10.0.1.0/24 }
        }

        chain input {
            type filter hook input priority 0; policy drop;
            iif "lo" accept
            ct state established,related accept
            ip saddr @trusted_clients tcp dport 2049 accept
            log prefix "nfs-dropped: " counter drop
        }
    }
    ```

=== "iptables"

    ```bash
    iptables -A INPUT -s 10.0.1.0/24 -p tcp --dport 2049 -j ACCEPT
    iptables -A INPUT -p tcp --dport 2049 -j DROP
    iptables -A INPUT -p udp --dport 2049 -j DROP
    ```

!!! note "Disable v2/v3 at the kernel level too"
    Firewalling port 111 prevents clients from discovering mountd, but does not prevent direct connections to port 2049 using NFSv3. Always disable NFSv2/v3 in `/etc/nfs.conf` alongside firewall rules; see [Kernel parameters](kernel-params.md) for the version control settings.

## Blocking the portmapper

The portmapper on port 111 is the primary reconnaissance target. A single `DUMP` call returns every registered RPC service, port, version, and protocol: the complete service topology of the server ([F-5.4](../../info-disclosure/F-5.4-rpc-service-enumeration.md)). On UDP, the same call enables amplification attacks with a ~28x ratio ([F-3.2](../../network/F-3.2-portmapper-amplification.md)).

For NFSv4-only servers, block port 111 entirely. For mixed v3/v4 environments where clients need mountd discovery, restrict port 111 to the trusted client set.

!!! danger "Never expose portmapper to the internet"
    An internet-facing portmapper is exploitable for DDoS amplification, full service enumeration, and NIS credential extraction ([F-5.3](../../info-disclosure/F-5.3-nis-credential-extraction.md)). There is no legitimate reason for port 111 to be reachable from outside the local network.

## Why firewalling is insufficient

Firewall rules restrict which hosts can reach NFS services. They do not address what those hosts can do once connected. Even with a perfectly configured firewall:

- **UID/GID spoofing works from any trusted client.** A compromised or multi-user machine inside the trusted network can claim any identity via AUTH_SYS. Firewall rules cannot distinguish between a legitimate user and an attacker on the same host. ([F-1.1](../../identity/F-1.1-uid-gid-spoofing.md))

- **File handles are bearer tokens.** A handle captured via network sniffing or obtained from a trusted client works from any IP address the server accepts. Firewall rules bind access to IP ranges, but handles bypass this because the NFS daemon never re-checks whether the presenting client was authorized to receive the handle. ([F-2.5](../../access-control/F-2.5-stale-handle-persistence.md))

- **Export escape works from inside the trusted set.** Handle construction and LOOKUPP traversal require only a valid mount point. Any client inside the firewall's trusted set can escape the export and access the entire filesystem. ([F-2.1](../../access-control/F-2.1-export-escape.md))

- **Internal network threats are the common case.** Most NFS attacks originate from hosts that already have network access: lateral movement from a compromised web server, a container breakout, a VPN-connected attacker. Firewalls protect the perimeter but NFS is typically deployed behind it.

!!! warning "Firewalling is necessary but not sufficient"
    Firewall rules are part of defense in depth. They prevent casual external access and reduce the attack surface. But they do not replace [Kerberos authentication](../hardening/kerberos.md), proper [export options](export-options.md), or [per-export filesystem isolation](../hardening/checklist.md). Use all of them together.
