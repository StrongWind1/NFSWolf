# Denial of service (F-6.x)

Denial-of-service findings targeting NFS server availability through lock manipulation, resource exhaustion, and state destruction.

!!! abstract "Out of Scope"
    All three findings in this category are intentionally **not implemented** in nfswolf. The NLM/NSM lock-DoS module was removed in v0.2.0 along with the NLM and NSM protocol clients. Grace-period blocking and SETCLIENTID state destruction were never implemented. nfswolf is a security assessment tool focused on unauthorized access and data exfiltration. Destroying server availability does not advance that goal and creates collateral damage that makes further testing impossible.

    The findings are documented here for completeness. Detailed write-ups exist for each one, covering the protocol mechanics and kernel behavior that make them possible.

## Summary

| Finding | Title | Severity | RFC Basis | Status | Write-up |
|---------|-------|----------|-----------|--------|----------|
| F-6.1 | NLM Lock Starvation | :material-information:{ .medium } Medium | RFC 1813, NLM v4 | Out of scope | [Detail](F-6.1-nlm-lock-attacks.md) |
| F-6.2 | NFSv4 Grace Period Blocking | :material-information:{ .medium } Medium | RFC 7530 sec 8.6.3 | Out of scope | [Detail](F-6.2-grace-period-dos.md) |
| F-6.3 | SETCLIENTID State Destruction | :material-information:{ .medium } Medium | RFC 7530 sec 16.33 | Out of scope | [Detail](F-6.3-setclientid-state-destruction.md) |

## Findings

### F-6.1: NLM Lock Starvation

!!! info "Out of scope -- NLM client removed in v0.2.0"

The Network Lock Manager (NLM, program 100021) provides advisory file locking for NFSv2 and NFSv3. An attacker can acquire locks on critical files and never release them, starving legitimate clients. NLM locks are advisory on UNIX (applications that do not check locks are unaffected), but mandatory-locking filesystems and applications that depend on `flock()` or `fcntl()` are vulnerable.

The companion Network Status Monitor (NSM, program 100024) tracks client crash/reboot for lock recovery. An attacker who spoofs NSM NOTIFY messages can trick the server into releasing locks held by legitimate clients, or prevent lock recovery after a server reboot.

**Why nfswolf does not implement this**: Lock DoS is destructive and immediately visible. It does not help with data access or privilege escalation. The NLM and NSM clients were removed to reduce the binary's attack surface and avoid accidental lock interference during assessments.

---

### F-6.2: NFSv4 Grace Period Blocking

!!! info "Out of scope -- never implemented"

After an NFSv4 server reboots, it enters a grace period (RFC 7530 sec 8.6.3) during which only lock reclaim operations are accepted; new opens and locks are rejected with `NFS4ERR_GRACE`. An attacker who detects a reboot (F-5.17) can flood the server with SETCLIENTID + OPEN_CONFIRM + LOCK requests during the grace window, extending the period during which legitimate clients cannot acquire new state.

The grace period is typically 90 seconds. During this window, all new file opens fail for all clients. The attacker does not need valid credentials; the SETCLIENTID exchange succeeds with any AUTH_SYS identity.

**Why nfswolf does not implement this**: The attack window is short and the impact is temporary. It does not yield data access or persistent compromise. Triggering it during an assessment disrupts all clients on the server.

---

### F-6.3: SETCLIENTID State Destruction

!!! info "Out of scope -- never implemented"

An attacker who sends SETCLIENTID with a client name matching an existing client's name and credentials that pass the `same_creds()` check causes the server to call `expire_client()`, destroying all of the victim's open state, locks, and delegations.

The `same_creds()` check at `fs/nfsd/nfs4state.c:2689` compares `cr_uid`, `cr_gid`, `cr_group_info`, and `cr_principal`. Under AUTH_SYS, the attacker controls all of these fields (F-1.1). Most NFS clients run as root (uid=0), so passing the credential check is trivial. The kernel comment at line 2696 ("XXX: check that cr_targ_princ fields match?") confirms the developers' own uncertainty about the adequacy of this check.

At lines 4784-4794, confirming the new client with matching name and credentials destroys all of the old client's open state via `expire_client()`. The victim's applications receive `NFS4ERR_EXPIRED` on their next operation and must re-open all files and re-acquire all locks.

**Why nfswolf does not implement this**: State destruction is immediately visible and causes data loss if the victim had pending writes. It is a denial-of-service attack that does not advance the attacker's access. The finding is documented because the `same_creds()` bypass demonstrates the weakness of AUTH_SYS even in NFSv4's stateful model.

## Why these remain documented

These findings are not implemented, but they are part of the NFS threat model. Understanding them matters for defenders:

- **F-6.1** motivates migrating from NFSv3+NLM to NFSv4 (integrated locking) and using `sec=krb5` to prevent credential forgery.
- **F-6.2** motivates monitoring the grace period and having alerting for extended grace windows.
- **F-6.3** motivates using RPCSEC_GSS (krb5) instead of AUTH_SYS, which makes the `same_creds()` check meaningful because the attacker can no longer forge matching credentials.

All three attacks are neutralized by `sec=krb5` because the attacker cannot forge Kerberos credentials to match a legitimate client's principal.
