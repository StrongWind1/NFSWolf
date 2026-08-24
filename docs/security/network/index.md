# Network attacks (F-3.x)

NFS was designed for trusted local networks. The protocol has no built-in encryption, no integrity protection, and no replay prevention. Transport-layer security (TLS, krb5p) exists but is opt-in and rarely deployed. The nine findings in this category exploit the wire protocol, transport assumptions, and network-level trust model.

## Finding summary

| ID | Finding | Severity | RFC Basis | Detection |
|----|---------|----------|-----------|-----------|
| [F-3.1](F-3.1-plaintext-wire-protocol.md) | Plaintext Traffic Interception | High | RFC 1813 sec. 8, RFC 1094 sec. 3.4 | `analyze` (no RPCSEC_GSS detection) |
| [F-3.2](F-3.2-portmapper-amplification.md) | Portmapper UDP Amplification (DDoS) | Medium | RFC 1057 Appendix A | `scan` (UDP DUMP amplification factor) |
| [F-3.3](F-3.3-ip-spoofing-host-trust.md) | IP Spoofing Against Host-Based ACLs | High | RFC 2623 sec. 2.6, RFC 7530 sec. 19 | `analyze` (host-based ACL detection) |
| [F-3.4](F-3.4-striptls-downgrade.md) | STRIPTLS Downgrade (RFC 9289) | High | RFC 9289 sec. 6.1.1 | `analyze` (AUTH_TLS probe) |
| [F-3.5](F-3.5-portmapper-tunnel-bypass.md) | pNFS Metadata Server Detected | Info | RFC 5661 sec. 18.35 | `analyze` (NFSv4.1 EXCHANGE_ID + GETDEVICELIST) |
| [F-3.6](F-3.6-udp-mount-handle-theft.md) | Mixed Security Zones via Per-Path SECINFO | Medium | RFC 7530 sec. 19 | `analyze` (NFSv4 SECINFO per-path probing) |
| [F-3.7](F-3.7-auth-dh-obsolete.md) | AUTH_DH Advertised (Cryptographically Broken) | Medium | RFC 5531 sec. 14, RFC 2695 | `analyze` (flavor 3 in MOUNT/SECINFO) |
| [F-3.8](F-3.8-rpc-with-tls.md) | RPC-with-TLS Supported (RFC 9289) | Info | RFC 9289 sec. 4.1, sec. 6.3 | `analyze` (AUTH_TLS NULL probe) |
| [F-3.9](F-3.9-auth-short-session-credentials.md) | AUTH_SHORT Session Credentials | Info | RFC 5531 sec. 14, RFC 1057 sec. 9.3 | `analyze` (flavor 2 in MOUNT/SECINFO) |

## Findings

### F-3.1: Plaintext Traffic Interception

NFS version 3 "defers to the authentication provisions of the supporting RPC protocol, and assumes that data privacy and integrity are provided by underlying transport layers" (RFC 1813 sec. 8). No transport-layer protection is specified or required. All file contents, credentials (AUTH_SYS UIDs/GIDs), and file handles traverse the wire in cleartext. An attacker with network access can passively capture everything needed to replay operations (F-1.5) or directly read sensitive file data.

### F-3.2: Portmapper UDP Amplification (DDoS)

The portmapper has no authentication on any operation (RFC 1057 Appendix A). A 68-byte DUMP request over UDP returns all registered services in a response typically 7--28 times larger. Because UDP source addresses are trivially spoofable, an attacker can direct amplified traffic at an arbitrary victim. nfswolf's scanner measures the exact amplification factor for both TCP and UDP.

### F-3.3: IP Spoofing Against Host-Based ACLs

NFS "has historically used a model where, from an authentication perspective, the client was the entire machine, or at least the source IP address of the machine" (RFC 7530 sec. 19). Export ACLs that restrict access to specific IPs or hostnames rely on source-address verification. With UDP transport, IP addresses are trivially spoofable. Even TCP requires only SYN sequence prediction or on-path positioning. nfswolf's analyzer reports whether an export uses IP-based restrictions without Kerberos enforcement; active spoofing is out of scope.

### F-3.4: STRIPTLS Downgrade (RFC 9289)

!!! warning
    The AUTH_TLS probe occurs in cleartext. An on-path attacker can alter the handshake to make it appear as though TLS is not available (RFC 9289 sec. 6.1.1).

RPC-with-TLS (RFC 9289) upgrades an existing RPC connection via a STARTTLS-style handshake. Because the initial probe is unencrypted, an active network attacker can strip the TLS negotiation, forcing the connection to remain in plaintext. Without DANE/TLSA records or mutual TLS certificate pinning, the client has no way to detect the downgrade. nfswolf's analyzer sends the AUTH_TLS NULL probe and checks whether the server supports TLS upgrade.

### F-3.5: pNFS Metadata Server Detected

The server's NFSv4.1 EXCHANGE_ID flags indicate pNFS metadata server (MDS) capability (RFC 5661 S18.35). GETDEVICELIST reveals the topology of pNFS data servers, which may reside on separate networks or lack equivalent access controls. This is an informational reconnaissance finding that exposes backend infrastructure without requiring network scanning.

### F-3.6: Mixed Security Zones via Per-Path SECINFO

NFSv4 SECINFO probing on subdirectories reveals different auth flavors than the export root. When the root requires Kerberos but a subdirectory accepts AUTH_SYS, an attacker bypasses the stronger requirement by directly accessing the subdirectory with weaker credentials. SECINFO responses lack integrity protection unless the initial connection uses RPCSEC_GSS (RFC 7530 S19).

### F-3.7: AUTH_DH Advertised (Cryptographically Broken)

AUTH_DH (flavor 3) uses 192-bit Diffie-Hellman key exchange and 56-bit DES encryption. RFC 5531 sec. 14 explicitly marks it as "obsolete and insecure." Both the key exchange and the symmetric cipher are trivially factorable by modern standards. An export advertising AUTH_DH provides a false sense of security -- it is marginally better than AUTH_NONE but offers no meaningful protection. nfswolf checks for flavor 3 in both the MOUNT auth_flavors list and NFSv4 SECINFO responses.

### F-3.8: RPC-with-TLS Supported (RFC 9289)

This is an informational finding. When the server accepts the AUTH_TLS NULL probe with the STARTTLS verifier, it indicates RPC-with-TLS support. TLS encrypts the wire protocol, addressing F-3.1 and F-1.5. However, AUTH_SYS inside TLS still allows UID/GID credential forging (RFC 9289 sec. 6.3). Mutual TLS is recommended but not required. The presence of TLS is a positive security indicator but does not eliminate identity-layer attacks.

### F-3.9: AUTH_SHORT Session Credentials

AUTH_SHORT (flavor 2) allows servers to return abbreviated session tokens as reply verifiers, which clients then use for subsequent requests instead of full AUTH_SYS credentials. Linux knfsd defines `RPC_AUTH_SHORT=2` but never issues or accepts AUTH_SHORT credentials -- the `authtab[2]` slot is NULL. This finding is informational and relevant only for non-Linux NFS implementations (Solaris, NetApp, FreeBSD) that may use AUTH_SHORT session tokens.

## Severity distribution

| Severity | Count | Findings |
|----------|-------|----------|
| High | 3 | F-3.1, F-3.3, F-3.4 |
| Medium | 3 | F-3.2, F-3.6, F-3.7 |
| Info | 3 | F-3.5, F-3.8, F-3.9 |

The three High findings represent fundamental protocol weaknesses (no encryption, IP-based trust, TLS stripping) that are structural to NFS as deployed. The three Medium findings cover amplification, SECINFO zone mismatches, and broken auth. The three Info findings are topology disclosure (pNFS), positive indicators (TLS support), or implementation details (AUTH_SHORT).

## Relationship to other categories

Network-layer findings are preconditions or enablers for identity and access-control attacks:

- **F-3.1 enables F-1.5**: Plaintext wire traffic allows credential replay.
- **F-3.6 enables F-1.1**: Mixed SECINFO zones let an attacker use AUTH_SYS credential forging on subdirectories that accept weaker auth.
- **F-3.3 enables F-1.1**: IP spoofing past export ACLs gives the attacker a session where forged credentials are accepted.
- **F-3.4 undermines F-3.8**: STRIPTLS removes the only transport-layer protection that could prevent F-3.1.

## Attack scenarios

### Passive network attacker

An attacker with read access to the network segment (span port, ARP poisoning, compromised switch) can:

1. Capture AUTH_SYS credentials (UIDs, GIDs, machine names) from any NFS session (F-3.1).
2. Capture file handles and replay them from their own machine (F-1.5, F-2.7).
3. Read file contents directly from captured READ replies (F-3.1).

### Active network attacker (on-path)

An attacker who can inject or modify packets can additionally:

1. Strip TLS negotiation to prevent encryption upgrades (F-3.4).
2. Probe SECINFO on subdirectories to find paths accepting weaker auth (F-3.6).
3. Bypass IP-based export ACLs via source address spoofing (F-3.3).

### Remote attacker (no network positioning)

Even without network access to the NFS segment, an attacker can:

1. Use the portmapper as a DDoS amplifier against third-party targets (F-3.2).
2. Discover pNFS data-server topology via EXCHANGE_ID + GETDEVICELIST (F-3.5).
3. Connect with AUTH_DH credentials that offer no real protection (F-3.7).

## Mitigations

| Mitigation | Findings Addressed |
|------------|--------------------|
| `sec=krb5p` (encryption + integrity) | F-3.1, F-3.3, F-3.4 |
| RPC-with-TLS with mutual TLS and DANE/TLSA | F-3.1, F-3.4, F-3.8 (hardens positive indicator) |
| Disable UDP on mountd (`--no-udp` or `RPCMOUNTDOPTS`) | F-3.2 |
| Firewall portmapper + use fixed NFS/mountd ports | F-3.2 (reduces surface, does not eliminate) |
| Network segmentation (dedicated NFS VLAN) | F-3.1, F-3.3, F-3.5 (limits attacker positioning, hides pNFS topology) |
| Uniform `sec=` across export tree | F-3.6 (eliminates per-path auth flavor mismatches) |
| Remove AUTH_DH from export configurations | F-3.7 |
| Require `xprtsec=tls` without `xprtsec=none` | F-3.1, F-3.4 (see also F-7.7) |
