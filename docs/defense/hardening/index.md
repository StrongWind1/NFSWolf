# Hardening

NFS was designed in the 1980s for trusted campus networks. Its default configuration trusts client-supplied identity, transmits data in cleartext, and exposes the full filesystem through predictable file handles. Every default is wrong for a modern threat model.

Hardening NFS means layering defenses across four surfaces: **authentication** (who can claim which identity), **authorization** (what each export permits), **network** (who can reach the service), and **protocol** (which NFS versions and features are enabled). No single control is sufficient on its own.

## Priority order

The checklist below is ordered by impact. Completing the Critical tier eliminates the majority of the attack surface documented in the [findings catalog](../../findings/index.md).

| Priority | Actions | Findings mitigated |
|----------|---------|-------------------|
| :material-alert-circle:{ .critical } **Critical** | Kerberos on all exports, no `no_root_squash`, separate filesystems per export, `all_squash` for public shares | [F-1.1](../../findings/identity/F-1.1-uid-gid-spoofing.md), [F-1.2](../../findings/identity/F-1.2-root-squash-bypass.md), [F-2.1](../../findings/access-control/F-2.1-export-escape.md), [F-4.1](../../findings/privesc/F-4.1-no-root-squash.md) |
| :material-alert:{ .high } **High** | Host/network restrictions, read-only where possible, fixed service ports, disable NFSv2/v3 | [F-1.6](../../findings/identity/F-1.6-nfsv2-downgrade.md), [F-3.3](../../findings/network/F-3.3-ip-spoofing-host-trust.md), [F-5.1](../../findings/info-disclosure/F-5.1-export-list-enumeration.md), [F-7.2](../../findings/config/F-7.2-privileged-port-bypass.md) |
| :material-alert-outline:{ .medium } **Medium** | `subtree_check`, portmapper restrictions, MOUNT DUMP monitoring, NFS over TLS | [F-2.6](../../findings/access-control/F-2.6-bind-mount-escape.md), [F-3.1](../../findings/network/F-3.1-plaintext-wire-protocol.md), [F-5.4](../../findings/info-disclosure/F-5.4-rpc-service-enumeration.md) |

## Sub-pages

- **[Hardening checklist](checklist.md)** -- prioritized, actionable steps with finding cross-references
- **[Kerberos authentication](kerberos.md)** -- deploying `sec=krb5p` end-to-end
- **[NFS over TLS](tls.md)** -- RFC 9289 transport encryption
- **[Example configurations](examples.md)** -- three complete `/etc/exports` files from maximum security to minimum acceptable

## Verification

After applying hardening controls, verify them with nfswolf:

```bash
# Full security audit -- identifies every remaining weakness
nfswolf analyze target

# Verify escape is blocked (should fail on separate-filesystem exports)
nfswolf escape target:/export

# Confirm Kerberos enforcement (should report AUTH_TOOWEAK)
nfswolf scan target
```

!!! tip "Test from an attacker's perspective"
    The most reliable way to validate NFS hardening is to attack your own server. Run `nfswolf analyze` from an untrusted network segment -- every finding it reports is a gap in your defenses.
