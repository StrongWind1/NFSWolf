# What does not work

Defenses that administrators commonly deploy or believe are effective, but that do not actually prevent the attacks nfswolf demonstrates. Every failure described here was verified live against lab servers running kernels 2.6.32 through 6.12.

If you have not read the [NFS Security Guide](security-guide.md) yet, start there for the full defense matrix and recommended configurations.

## root_squash alone

`root_squash` maps uid=0 to nobody (65534). Administrators often treat this as the primary NFS security control. It is not.

`root_squash` blocks exactly one UID. An attacker who claims uid=1000, uid=42, or any other non-zero UID passes through `root_squash` unchanged. On every lab server tested, `uid=1000` reads `0600` files owned by `uid=1000` with `root_squash` enabled.

!!! danger "root_squash does not prevent"
    - Export escape (the handle is constructed, not authenticated)
    - Cross-export lateral movement (same filesystem, same handles)
    - UID spoofing for any non-root UID
    - Reading world-readable files as any UID

## Secure port requirement (no `insecure` flag)

Without the `insecure` export option, the server requires the client to connect from a source port below 1024. On Unix systems, binding to privileged ports requires root.

This does not help because any attacker running a tool like nfswolf already has root on their attack machine (or `CAP_NET_BIND_SERVICE`). nfswolf binds privileged ports by default. The `secure` requirement stops nothing that was not already stopped by other means.

## IP-based ACLs

```bash title="/etc/exports — IP restriction"
/srv/nfs/data  10.0.0.0/24(rw,sync)
```

IP-based restrictions limit which networks can mount the export. They do not defend against:

- An attacker who has compromised any host on the allowed subnet
- UDP source-IP spoofing (NFS over UDP accepts spoofed source addresses)
- A rogue VM or container on the allowed network

IP ACLs are defense-in-depth: they reduce the attack surface but do not eliminate it. They are worth deploying alongside real defenses, not as a substitute.

!!! note "NFSv4 pseudo-filesystem and IP ACLs"
    IP-restricted ACLs do have one strong property on NFSv4: knfsd removes the export from the pseudo-filesystem entirely for unauthorized clients. The export is not visible, not traversable, not discoverable via LOOKUPP. This is the one scenario where IP ACLs provide a hard block rather than a soft filter.

## sec=krb5:sys (both listed)

```bash title="/etc/exports — WRONG"
/srv/nfs/data  *(rw,sync,sec=krb5:sys)
```

When both `krb5` and `sys` appear in the `sec=` list, the server accepts either authentication flavor. The attacker chooses AUTH_SYS and bypasses Kerberos entirely. The `sec=` list must contain **only** `krb5`, `krb5i`, or `krb5p` -- never `sys` alongside them.

!!! danger "This is the most common Kerberos misconfiguration"
    Administrators add `sys` as a fallback "for testing" or "for legacy clients" and forget to remove it. A single `sys` entry in the `sec=` list nullifies every benefit of Kerberos deployment.

## all_squash with anonuid=0

```bash title="/etc/exports — WRONG"
/srv/nfs/data  *(rw,sync,all_squash,anonuid=0,anongid=0)
```

`all_squash` maps every UID to the anonymous identity. When `anonuid=0`, the anonymous identity IS root. Every client, regardless of claimed UID, operates as root on the export. This is worse than `no_root_squash` because there is no way for any client to operate as a non-root user.

## xprtsec=tls (default configuration)

NFS over TLS (RFC 9289) encrypts the transport layer. The kernel default for `ex_xprtsec_modes` is `NFSEXP_XPRTSEC_ALL` (`export.c:647`), which sets all three bits: `NFSEXP_XPRTSEC_NONE | NFSEXP_XPRTSEC_TLS | NFSEXP_XPRTSEC_MTLS`. Because `NFSEXP_XPRTSEC_NONE` is enabled by default, adding `xprtsec=tls` to an export does not remove plaintext acceptance -- the `check_xprtsec_policy()` function accepts the connection if ANY enabled mode matches. The attacker connects without TLS and the encryption provides no protection.

```bash title="/etc/exports — WRONG (plaintext still accepted)"
/srv/nfs/data  *(rw,sync,xprtsec=tls)
```

There is no `no_xprtsec=none` export option in the Linux kernel. To actually enforce TLS, set `tls-required = 1` in `/etc/nfs.conf`, which rejects plaintext connections at the server level:

```ini title="/etc/nfs.conf — correct (plaintext rejected)"
[nfsd]
tls = 1
tls-required = 1
```

!!! note "TLS does not authenticate"
    Even correctly configured, NFS over TLS encrypts the transport but does not authenticate the client. AUTH_SYS credentials are still trusted blindly -- they are just encrypted in transit. TLS prevents network sniffing and man-in-the-middle attacks, not UID spoofing or export escape. Use TLS for confidentiality, Kerberos for authentication.

## Client-side nosuid,nodev mount options

Administrators sometimes mandate that NFS clients mount with `nosuid,nodev` to prevent SUID binary exploitation and device node attacks.

The server has no control over client mount options. These flags are enforced by the client kernel, not the server. An attacker who controls their own machine simply omits them. The server cannot verify or enforce how the client mounts the export.

!!! tip "Use `ro` on the server side instead"
    If the goal is to prevent SUID binary creation, the server-side `ro` export option blocks all writes regardless of what the client does. Server-side controls are the only controls that matter against a hostile client.

## Hostname-based access control

The `machinename` field in AUTH_SYS credentials (the hostname the client sends) is sometimes checked against export ACLs. On Linux knfsd, this is not how export authorization works. knfsd uses the TCP source IP address, not the `auth_unix.machinename` field, for export ACL decisions. The `machinename` field is attacker-controlled and can be set to any string.

Tested: MOUNT denied both with and without `--hostname` spoofing. knfsd does not consult the hostname field for access decisions.

## Firewall rules (without protocol awareness)

Blocking port 111 (portmapper) prevents service discovery but does not prevent NFS access. NFS typically runs on port 2049 (and is often the only port needed for NFSv4). Blocking mountd prevents MOUNT-based handle acquisition on NFSv3, but NFSv4 obtains handles via PUTROOTFH + LOOKUP without any MOUNT protocol. A firewall that blocks 111 but allows 2049 does not prevent NFSv4 escape.

Effective firewall rules must block port 2049 from untrusted networks -- not just the ancillary services.

## Summary

| "Defense" | Why it fails |
|---|---|
| `root_squash` alone | Only blocks uid=0. Attacker claims uid=1000 instead. |
| Secure port (no `insecure`) | Attacker already has root. nfswolf binds port <1024 by default. |
| IP-based ACLs | Attacker on the allowed subnet bypasses this. UDP is spoofable. |
| `sec=krb5:sys` | Attacker chooses AUTH_SYS and bypasses krb5 entirely. |
| `all_squash,anonuid=0` | Maps everyone to root. Worse than `no_root_squash`. |
| `xprtsec=tls` (default) | Default allows plaintext alongside TLS. Requires `tls-required = 1` in nfs.conf. |
| Client-side `nosuid,nodev` | Server cannot control client mount options. Attacker omits them. |
| Hostname spoofing | knfsd uses TCP source IP, not `machinename`, for ACL decisions. |
| Blocking port 111 only | NFSv4 needs only port 2049. No MOUNT protocol required. |

For defenses that actually work, see the [NFS Security Guide](security-guide.md).
