# RPC/portmapper findings

ONC RPC (RFC 5531) and the portmapper (RFC 1057 Appendix A) form the transport layer beneath NFS. Every NFS call is an RPC call, every credential is an RPC credential, and the portmapper is the service directory that tells clients where to find NFS and MOUNT. This layer has its own set of vulnerabilities independent of the NFS version running above it: unauthenticated service enumeration, UDP amplification, credential replay, and clock leakage. These findings apply regardless of whether the server runs NFSv2, v3, or v4 (though v4 eliminates the portmapper dependency).

## Applicable findings

| Finding | Name | Severity | RPC/Portmapper Detail |
|---------|------|----------|-----------------------|
| [F-3.1](../network/F-3.1-plaintext-wire-protocol.md) | Plaintext Traffic | High | All ONC RPC traffic is cleartext by default. AUTH_SYS credentials, file data, and handle values are visible to any network observer. RPC-with-TLS (RFC 9289) is optional and rarely deployed. The RPC layer itself has no built-in encryption. |
| [F-3.2](../network/F-3.2-portmapper-amplification.md) | Portmapper UDP Amplification | Medium | PMAPPROC_DUMP over UDP returns 486-1930 bytes in response to a 68-byte request. With spoofed source addresses, this is a DDoS amplification vector. The portmapper has no authentication on any operation (RFC 1057 Appendix A). |
| [F-1.5](../identity/F-1.5-credential-replay.md) | AUTH_SYS Credential Replay | High | AUTH_SYS has no nonce, timestamp, or sequence number. The RPC XID (RFC 5531 Section 9) is for matching replies to calls, not for replay prevention. Any captured RPC message can be replayed indefinitely from any network position. |
| [F-3.3](../network/F-3.3-ip-spoofing-host-trust.md) | IP Spoofing Against Host-Based ACLs | High | NFS historically uses source IP as machine identity (RFC 7530 Section 19). Export ACLs restricted to specific IPs can be bypassed via UDP source-address spoofing or TCP SYN prediction. Without Kerberos, IP-based restrictions are the only access control on MOUNT and NFS operations. |
| [F-3.5](../network/F-3.5-portmapper-tunnel-bypass.md) | Filtered Portmapper Bypass | Medium | Firewalling port 111 does not protect NFS. The portmapper is a convenience directory, not a security gate. NFS listens on 2049 independently. MOUNT ports can be guessed or scanned. nfswolf's scanner probes 2049 directly when 111 is filtered, using `--skip-rpc` or `--rpc-port` flags. |
| [F-3.7](../network/F-3.7-auth-dh-obsolete.md) | AUTH_DH Advertised | Medium | AUTH_DH (flavor 3) is an RPC authentication mechanism defined in RFC 2695. It uses 192-bit Diffie-Hellman key exchange and 56-bit DES encryption -- both trivially breakable by modern standards. RFC 5531 Section 14 explicitly marks it as "obsolete and insecure." nfswolf detects AUTH_DH in both MOUNT auth_flavors and NFSv4 SECINFO responses. |
| [F-3.8](../network/F-3.8-rpc-with-tls.md) | RPC-with-TLS Supported | Info | RFC 9289 adds optional TLS to ONC RPC via an AUTH_TLS STARTTLS handshake. Positive security indicator, but AUTH_SYS inside TLS still allows UID forgery (RFC 9289 Section 6.3). Mutual TLS is recommended but not required. nfswolf probes for AUTH_TLS support by sending a NULL RPC with `auth_flavor=7`. |
| [F-3.9](../network/F-3.9-auth-short-session-credentials.md) | AUTH_SHORT Session Credentials | Info | AUTH_SHORT (flavor 2) allows servers to return abbreviated session tokens. Linux knfsd defines the constant but never issues or accepts AUTH_SHORT credentials. Relevant only for non-Linux NFS implementations (Solaris, NetApp). |
| [F-5.4](../info-disclosure/F-5.4-rpc-service-enumeration.md) | RPC Service Enumeration | Low | PMAPPROC_DUMP returns program number, version, protocol, and port for every registered RPC service. No authentication required. Reveals the full service topology: NFS versions, MOUNT ports, NIS, NLM, NSM, rquotad, NFS_ACL, and any other registered programs. nfswolf's scanner uses DUMP as the first reconnaissance step. |
| F-5.14 | POSIX ACL via NFS_ACL Sideband | Medium | The NFS_ACL program (100227) is registered in the portmapper and returns POSIX ACL entries that reveal access grants invisible to standard mode bits. This is an RPC sideband program, not part of the NFS protocol itself. |
| F-5.15 | rquotad UID Oracle | Medium | The RQUOTA program (100011) is an RPC sideband service registered in the portmapper. GETQUOTA returns per-UID disk usage without authentication, confirming UID existence and leaking filesystem block size for escape strategy selection. |

## Protocol-specific exploitation notes

### Portmapper as the first reconnaissance step

The portmapper (program 100000) runs on the well-known port 111 and is a directory of all registered RPC services. nfswolf's scanner sends PMAPPROC_DUMP as its first operation against any target. The response reveals:

- Which NFS versions are available (program 100003 versions 2, 3, 4)
- Where the MOUNT daemon listens (program 100005, version + port + protocol)
- Whether NIS is co-hosted (program 100004 for ypserv, 100007 for ypbind)
- Whether rquotad is available (program 100011)
- Whether NFS_ACL is available (program 100227)
- Whether NLM is running (program 100021 -- out of scope for nfswolf but noted)
- Full IANA program number resolution via the 1251-entry registry built into nfswolf

This single unauthenticated call provides the complete service map for all subsequent attack stages.

### rpcbind v3/v4 extensions

Beyond the v2 portmapper, nfswolf's `RpcbindClient` supports rpcbind v3/v4 operations (RFC 1833):

- **GETTIME** returns the server's clock as epoch seconds. This leaks the server timezone and drift, which feeds NTP-based attacks and Kerberos ticket timing. No authentication required.
- **GETSTAT** returns per-version call counts for every registered RPC program. This reveals which services are actively used (high call counts) versus dormant (zero calls), helping prioritize targets.

### AUTH_SYS is an RPC-layer problem

The AUTH_SYS credential format is defined at the RPC layer (RFC 5531 Section 14), not at the NFS layer. Every NFS version inherits it. The RPC layer treats credentials as opaque pass-through (RFC 5531 Section 8.2) -- it makes no attempt to verify them. This architectural decision is why UID spoofing (F-1.1) works identically across NFSv2, v3, and v4. The fix must come from replacing AUTH_SYS with RPCSEC_GSS (Kerberos) at the RPC layer, not from NFS protocol version upgrades.

The RPC authentication framework defines several flavors, but in practice only three matter for NFS security:

| Flavor | Value | Security | Status |
|--------|-------|----------|--------|
| AUTH_NONE | 0 | None -- no identity asserted | Used for automounter GETATTR (RFC 2623 Section 2.3.2) |
| AUTH_SYS | 1 | None -- client-asserted UID/GID | Default on virtually all NFS deployments |
| AUTH_SHORT | 2 | None -- opaque session token from server | Linux knfsd never issues these; Solaris/NetApp may |
| AUTH_DH | 3 | Weak -- 192-bit DH + 56-bit DES | Obsolete per RFC 5531 Section 14 |
| RPCSEC_GSS | 6 | Strong -- Kerberos v5 or equivalent | Required for real security; rarely deployed |
| AUTH_TLS | 7 | Transport -- TLS channel setup | RFC 9289; does not replace AUTH_SYS credential forgery |

Every flavor below RPCSEC_GSS provides no meaningful authentication. AUTH_SYS and AUTH_NONE are the norm. Upgrading from AUTH_SYS to RPCSEC_GSS requires a Kerberos infrastructure (KDC, keytabs, DNS SRV records), which is why most environments never make the switch.

### UDP vs TCP transport security

ONC RPC supports both UDP and TCP transport. UDP is connectionless with no handshake, making source IP spoofing trivial. The portmapper's DUMP and CALLIT procedures over UDP are the primary amplification vectors (F-3.2). TCP requires a three-way handshake, which makes IP spoofing harder (SYN prediction required) but not impossible. nfswolf's `--scan-udp` flag probes for UDP-accessible RPC services, and the scanner reports mountd UDP availability as a specific risk factor for handle theft (F-3.6).

TCP record marking (RFC 5531 Section 11) adds a 4-byte fragment header to every RPC message. This is the only framing NFS gets -- there is no message authentication, no sequence numbering, and no integrity check at the RPC layer. An on-path attacker who can inject TCP segments can modify RPC messages in transit (F-3.1).

### The CALLIT amplification vector

The portmapper's CALLIT procedure (RFC 1057 Appendix A) forwards an RPC call to a registered service and returns the result. Over UDP with a spoofed source address, an attacker can trigger responses from multiple RPC services through a single portmapper request, multiplying the amplification factor. nfswolf measures both the direct DUMP amplification ratio and reports the CALLIT availability.

### RPC sideband programs

Several RPC programs run alongside NFS and provide additional attack surface. These are not part of the NFS protocol but are registered in the same portmapper and reachable from the same network position:

- **NFS_ACL (100227)**: Returns POSIX ACL entries that reveal access grants invisible to standard mode bits (F-5.14). Named USER and GROUP ACL entries disclose UIDs and GIDs with access paths that cannot be seen via READDIRPLUS attributes alone.
- **RQUOTA (100011)**: Returns per-UID disk usage without authentication (F-5.15). GETQUOTA confirms UID existence on the server and leaks filesystem block size (ext4=4096, XFS=512, ZFS=1024), which feeds the escape strategy before any NFS operation.
- **NIS/YP (100004/100007)**: When co-hosted with NFS, `ypcat passwd.byname` dumps password hashes without authentication (F-5.3). Discovery via portmapper DUMP.
- **NLM (100021)**: Network Lock Manager. Out of scope for nfswolf (lock-DoS module removed), but its presence in the portmapper confirms stateful NFS usage.
- **NSM (100024)**: Network Status Monitor. Tracks NFS client/server crash recovery. Out of scope but noted in DUMP output.

All of these programs share the same lack of authentication as the portmapper itself. Their presence in the DUMP output is part of the reconnaissance value of the initial portmapper probe.
