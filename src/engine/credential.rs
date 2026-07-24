//! Credential escalation ladder shared by every subcommand that performs
//! NFS operations.
//!
//! When the server returns NFS3ERR_ACCES, callers retry through a
//! consistent sequence of (uid, gid) pairs: the file owner first, then
//! root, then well-known service accounts. Centralising the order means
//! the shell, the FUSE adapter, and the offensive subcommands all walk
//! the same ladder, so behaviour is predictable across surfaces.

/// Build the credential escalation ladder for a failed NFS operation.
///
/// `caller` is the (uid, gid) that was rejected.
/// `owner` is the file/directory owner from GETATTR, if available.
///
/// Priority:
///   1. (owner_uid, owner_gid)  -- file owner; works on uid-protected files
///   2. (caller_uid, owner_gid) -- caller claiming the file group; works for
///      group-readable files when root is squashed (e.g. chrony gid=989)
///   3. (0, 0)                  -- root, works when export has no_root_squash
///   4. Common service UIDs (nobody, 1000, www-data, mysql, postgres)
///
/// Used by the shell (ls, cd, cat), the FUSE mount, and the offensive
/// subcommands (escape, brute-handle, uid-spray) so every NFS operation
/// gets the same automatic privilege escalation.
/// The credential ladder: identities to try, in priority order.
///
/// AUTH_SYS lets a client assert any identity, so when an operation is refused
/// the useful next move is to try a different one. This returns the candidates
/// in priority order; the caller attempts each until one is accepted.
///
/// The order is not arbitrary. The file's own owner comes first because it is
/// the identity most likely to be permitted; then the caller's UID paired with
/// the file's group, which catches group-readable files; then root, which a
/// `no_root_squash` export honours; then the service accounts that own most
/// interesting files on a typical host.
///
/// Two related capabilities live elsewhere rather than here. Exhaustive
/// UID/GID brute force is the `uid-spray` subcommand, because it is loud enough
/// to be an explicit operator decision rather than an automatic fallback. The
/// NFSv2 downgrade -- some servers apply `root_squash` on their v3 path but not
/// their v2 one -- is not implemented; see the backlog.
pub(crate) fn credential_ladder(caller: (u32, u32), owner: Option<(u32, u32)>) -> Vec<(u32, u32)> {
    credential_ladder_with(caller, owner, None, &[])
}

/// The credential ladder, shortened by whatever the caller already knows.
///
/// `mode` is the target's permission bits and `observed` is any identity seen
/// owning files on this export. Both come free with calls already made -- the
/// GETATTR that produced the refusal carries the mode, and every READDIRPLUS
/// carries per-entry ownership -- so using them costs nothing and removes
/// guesswork.
///
/// # Why the mode bits can shorten the ladder
///
/// POSIX grants access through exactly one triad: owner if the UID matches,
/// else group if a GID matches, else other. So when `mode & 0o007 == 0`, an
/// identity that is neither the owner nor in the owning group has no path to
/// the file at all, and every service-account rung below is provably wasted
/// RPC. Root still gets its rung, because a `no_root_squash` export bypasses
/// the check entirely.
///
/// This is deterministic, not a guess: it follows from the mode the server
/// itself reported.
pub(crate) fn credential_ladder_with(caller: (u32, u32), owner: Option<(u32, u32)>, mode: Option<u32>, observed: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut list = Vec::with_capacity(16);
    if let Some((file_uid, file_group)) = owner {
        list.push((file_uid, file_group));
        if file_group != caller.1 {
            list.push((caller.0, file_group));
        }
    }
    // Root bypasses the permission check outright where the export allows it,
    // so it is worth trying whatever the mode says.
    list.push((0, 0));

    // With no "other" access, nothing outside the owner and the owning group
    // can reach the file. Stop rather than probe identities that cannot work.
    let other_has_access = mode.is_none_or(|m| m & 0o007 != 0);
    if !other_has_access {
        let mut seen = std::collections::HashSet::new();
        list.retain(|pair| seen.insert(*pair));
        return list;
    }

    // Identities actually seen owning files here beat guesses about which
    // service accounts might exist.
    list.extend_from_slice(observed);

    list.push((65534, 65534));
    list.push((1000, 1000));
    list.push((33, 33)); // www-data
    list.push((27, 27)); // mysql
    list.push((26, 26)); // postgres
    list.push((1001, 1001));
    list.push((1002, 1002));
    // Vec::dedup only removes *adjacent* duplicates, but this ladder is built in
    // priority order and never sorted, so duplicates are usually non-adjacent
    // (e.g. owner (0,0) collides with the later root push, separated by the
    // caller+owner_gid rung). Retain via a seen-set to drop every repeat while
    // keeping the first (highest-priority) occurrence, so no credential is tried
    // twice.
    let mut seen = std::collections::HashSet::new();
    list.retain(|pair| seen.insert(*pair));
    list
}

/// Identities seen owning entries in a directory listing, most common first.
///
/// Every READDIRPLUS reply carries `uid`/`gid` per entry, so after one listing
/// the identities that actually exist on this export are known. Ranking those
/// beats guessing at service accounts: an export owned by uid 5000 will never
/// be reached by trying www-data.
///
/// The caller's own identity is excluded -- it has already been refused.
pub(crate) fn observed_identities(entries: &[crate::proto::nfs3::types::DirEntryPlus], caller: (u32, u32)) -> Vec<(u32, u32)> {
    let mut counts: std::collections::HashMap<(u32, u32), usize> = std::collections::HashMap::new();
    for e in entries {
        if let Some(ref a) = e.attrs {
            let pair = (a.uid, a.gid);
            if pair != caller {
                *counts.entry(pair).or_insert(0) += 1;
            }
        }
    }
    let mut ranked: Vec<((u32, u32), usize)> = counts.into_iter().collect();
    // Frequency first; the pair itself breaks ties so the order is stable
    // across runs rather than dependent on HashMap iteration.
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked.into_iter().map(|(pair, _)| pair).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo, clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::indexing_slicing, reason = "unit test  --  lints are suppressed per project policy")]
    use super::*;

    #[test]
    fn escalation_list_removes_nonadjacent_duplicates() {
        // owner=(0,0) with a non-zero caller_gid puts (0,0) at index 0 and again
        // at the root push (index 2), separated by (caller_uid, 0). Vec::dedup
        // would leave both; the seen-set pass must keep exactly one.
        let list = credential_ladder((1001, 1001), Some((0, 0)));
        let mut seen = std::collections::HashSet::new();
        for pair in &list {
            assert!(seen.insert(*pair), "duplicate credential {pair:?} in escalation ladder");
        }
        assert_eq!(list.iter().filter(|p| **p == (0, 0)).count(), 1, "root (0,0) must appear once");
        assert_eq!(list[0], (0, 0), "owner keeps highest priority");
    }

    #[test]
    fn escalation_list_dedups_owner_matching_service_account() {
        // owner=(1000,1000) collides with the fixed (1000,1000) service push,
        // which sits several entries later -- a non-adjacent duplicate.
        let list = credential_ladder((42, 42), Some((1000, 1000)));
        assert_eq!(list.iter().filter(|p| **p == (1000, 1000)).count(), 1);
        assert_eq!(list[0], (1000, 1000));
    }

    #[test]
    fn escalation_list_has_no_duplicates_without_owner() {
        let list = credential_ladder((33, 33), None);
        let mut seen = std::collections::HashSet::new();
        for pair in &list {
            assert!(seen.insert(*pair), "duplicate credential {pair:?}");
        }
    }
}

#[cfg(test)]
mod evidence_tests {
    use super::*;

    /// The whole point of the mode check: with no "other" bits, an identity
    /// that is neither the owner nor in the owning group cannot reach the file,
    /// so probing service accounts is provably wasted RPC.
    #[test]
    fn no_other_access_prunes_the_guess_rungs() {
        let full = credential_ladder_with((1000, 1000), Some((0, 42)), None, &[]);
        let pruned = credential_ladder_with((1000, 1000), Some((0, 42)), Some(0o640), &[]);
        assert!(pruned.len() < full.len(), "mode 0640 must shorten the ladder");
        assert!(!pruned.contains(&(33, 33)), "www-data cannot read a 0640 file it does not own");
        assert!(!pruned.contains(&(65534, 65534)), "nobody cannot either");
    }

    #[test]
    fn owner_and_group_rungs_survive_pruning() {
        let pruned = credential_ladder_with((1000, 1000), Some((0, 42)), Some(0o640), &[]);
        assert!(pruned.contains(&(0, 42)), "the owner must always be tried");
        assert!(pruned.contains(&(1000, 42)), "caller claiming the file's group must be tried");
    }

    #[test]
    fn root_survives_pruning_because_no_root_squash_bypasses_mode() {
        let pruned = credential_ladder_with((1000, 1000), Some((5000, 5000)), Some(0o600), &[]);
        assert!(pruned.contains(&(0, 0)), "root bypasses the permission check where the export allows it");
    }

    #[test]
    fn world_readable_keeps_the_full_ladder() {
        let full = credential_ladder_with((1000, 1000), Some((0, 42)), None, &[]);
        let with_mode = credential_ladder_with((1000, 1000), Some((0, 42)), Some(0o644), &[]);
        assert_eq!(full.len(), with_mode.len(), "0644 grants other-read, so nothing can be ruled out");
    }

    #[test]
    fn observed_identities_outrank_the_guesses() {
        let ladder = credential_ladder_with((1000, 1000), None, Some(0o644), &[(5000, 5000)]);
        let observed_at = ladder.iter().position(|p| *p == (5000, 5000)).expect("observed pair present");
        let guess_at = ladder.iter().position(|p| *p == (33, 33)).expect("guess present");
        assert!(observed_at < guess_at, "an identity seen owning files beats a guess at www-data");
    }

    #[test]
    fn ladder_never_repeats_a_credential() {
        // The owner colliding with root is the common case worth guarding.
        let ladder = credential_ladder_with((0, 0), Some((0, 0)), None, &[(0, 0), (1000, 1000)]);
        let mut seen = std::collections::HashSet::new();
        for pair in &ladder {
            assert!(seen.insert(*pair), "credential {pair:?} tried twice");
        }
    }
}
