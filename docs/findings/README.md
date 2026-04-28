# NFS Security Findings

Detailed write-ups for each finding that nfswolf detects. Each finding has a unique ID (e.g., F-1.1) that is the authoritative identifier used across all documentation.

For the summary catalog with RFC rationale, see [FINDINGS.md](../FINDINGS.md).

## Finding Index

### Category 1: Identity Attacks (AUTH_SYS Trust Model)

| ID | Finding | Severity |
|----|---------|----------|
| F-1.1 | [UID/GID Spoofing](F-1.1-uid-gid-spoofing.md) | Critical |
| F-1.2 | [Root Squash Bypass via Non-Root UID](F-1.2-root-squash-bypass.md) | High |
| F-1.3 | [Auxiliary Group Injection](F-1.3-auxiliary-group-injection.md) | High |
| F-1.4 | [Machine Name Spoofing / Log Poisoning](F-1.4-machine-name-spoofing.md) | Low |
| F-1.5 | [Credential Replay from Wire](F-1.5-credential-replay.md) | High |
| F-1.6 | [NFSv2 Downgrade (Auth Bypass)](F-1.6-nfsv2-downgrade.md) | High |

### Category 2: Access Control Bypass (File Handle Exploitation)

| ID | Finding | Severity |
|----|---------|----------|
| F-2.1 | [Export Escape via Filesystem Root Handle](F-2.1-export-escape.md) | Critical |
| F-2.2 | [File Handle Guessing / Brute Force](F-2.2-file-handle-guessing.md) | High |
| F-2.3 | [Windows File Handle Signing Disabled](F-2.3-windows-handle-signing.md) | Critical |
| F-2.4 | [BTRFS Subvolume Handle Construction](F-2.4-btrfs-subvolume-escape.md) | High |
| F-2.5 | [Stale Handle After Permission Revocation](F-2.5-stale-handle-persistence.md) | Medium |
| F-2.6 | [Bind Mount Export Escape](F-2.6-bind-mount-escape.md) | High |

### Category 3: Network-Level Attacks

| ID | Finding | Severity |
|----|---------|----------|
| F-3.1 | [Plaintext Traffic Interception](F-3.1-plaintext-wire-protocol.md) | High |
| F-3.2 | [Portmapper UDP Amplification (DDoS)](F-3.2-portmapper-amplification.md) | Medium |
| F-3.3 | [IP Spoofing Against Host-Based ACLs](F-3.3-ip-spoofing-host-trust.md) | High |
| F-3.4 | [STRIPTLS Downgrade (RFC 9289)](F-3.4-striptls-downgrade.md) | High |
| F-3.5 | [Filtered Portmapper Bypass](F-3.5-portmapper-tunnel-bypass.md) | Medium |

### Category 4: Privilege Escalation

| ID | Finding | Severity |
|----|---------|----------|
| F-4.1 | [no_root_squash Exploitation](F-4.1-no-root-squash.md) | Critical |
| F-4.2 | [SUID/SGID Binary Creation](F-4.2-suid-sgid-escalation.md) | High |
| F-4.3 | [Device Node Creation via MKNOD](F-4.3-device-node-creation.md) | High |
| F-4.4 | [Symlink Escape](F-4.4-symlink-escape.md) | High |
| F-4.5 | [SELinux/MAC Label Bypass via NFS](F-4.5-selinux-label-bypass.md) | Medium |

### Category 5: Information Disclosure

| ID | Finding | Severity |
|----|---------|----------|
| F-5.1 | [Export List Enumeration](F-5.1-export-list-enumeration.md) | Medium |
| F-5.2 | [READDIRPLUS File Handle Harvesting](F-5.2-readdirplus-handle-harvesting.md) | High |
| F-5.3 | [NIS Credential Extraction](F-5.3-nis-credential-extraction.md) | High |
| F-5.4 | [RPC Service Enumeration](F-5.4-rpc-service-enumeration.md) | Low |
| F-5.5 | [NFSv4 Pseudo-FS Structure Leakage](F-5.5-nfsv4-pseudo-fs-leakage.md) | Low |

### Category 6: Denial of Service (out of scope)

The DoS findings are documented for completeness but are **not exercised
by any nfswolf subcommand**. The lock-DoS module that drove F-6.1 was
removed along with the NLM and NSM clients; F-6.2 and F-6.3 were never
implemented.

| ID | Finding | Severity |
|----|---------|----------|
| F-6.1 | [NLM Lock Exhaustion / Lock Theft](F-6.1-nlm-lock-attacks.md) | Medium |
| F-6.2 | [NFSv4 Grace Period Blocking](F-6.2-grace-period-dos.md) | Medium |
| F-6.3 | [SETCLIENTID State Destruction](F-6.3-setclientid-state-destruction.md) | Medium |

### Category 7: Configuration Weaknesses

| ID | Finding | Severity |
|----|---------|----------|
| F-7.1 | [Wildcard/Broad Subnet Exports](F-7.1-wildcard-export-policy.md) | High |
| F-7.2 | [insecure Export Option (Unprivileged Ports)](F-7.2-privileged-port-bypass.md) | Medium |
| F-7.3 | [nohide/crossmnt Sub-Mount Exposure](F-7.3-nohide-crossmnt-exposure.md) | Medium |
| F-7.4 | [Missing nosuid/nodev on Client Mount](F-7.4-missing-nosuid-nodev.md) | High |
| F-7.5 | [all_squash with anonuid=0](F-7.5-squash-misconfiguration.md) | Critical |
| F-7.6 | [Absence of Audit Logging](F-7.6-no-audit-logging.md) | Medium |

## Attack Chain Summary

```
Reconnaissance          Identity / Access           Post-Exploitation
─────────────────       ──────────────────          ─────────────────────
[F-5.4] RPC Enum  ──┐
[F-5.1] Export Enum──┤
[F-7.1] Wildcard  ──┤  [F-1.1] UID Spoofing  ──┬──> [F-4.1] no_root_squash
[F-3.3] IP Spoof  ──┼─>[F-7.2] Port Bypass   ──┤    [F-4.2] SUID Escalation
[F-3.1] Sniffing  ──┤  [F-7.5] Squash Misconf──┤    [F-4.3] Device Nodes
[F-1.4] Name Spoof──┤  [F-1.5] Cred Replay    │    [F-4.4] Symlink Attack
[F-3.2] Portmap Amp──┤  [F-1.6] v2 Downgrade──┤    [F-4.5] SELinux Bypass
[F-5.3] NIS Extract──┤  [F-2.1] Export Escape  │    [F-7.6] No Detection
[F-3.5] Portmap Tun──┤  [F-2.2] Handle Guess  │    [F-6.1] Lock DoS
[F-5.5] Pseudo-FS ──┘  [F-2.3] Win Signing   ┘    [F-2.6] Bind Mount
                        [F-1.2] Squash Bypass        [F-6.2] Grace Period
                        [F-1.3] Group Inject         [F-6.3] State Destroy
                        [F-2.4] BTRFS Subvol
                        [F-3.4] STRIPTLS
```

## Key Insight

NFSv3's security model is fundamentally broken on shared or routable networks. The protocol was designed for trusted LANs in the 1980s and has no cryptographic authentication in its default configuration. The **only** effective remediation is:

1. Kerberos authentication (`sec=krb5p`) — or —
2. Complete network isolation (dedicated VLAN, strict firewalling)

Everything else (root_squash, IP restrictions, subtree_check) is a speed bump, not a barrier.
