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
pub fn escalation_list(caller: (u32, u32), owner: Option<(u32, u32)>) -> Vec<(u32, u32)> {
    let (caller_uid, caller_gid) = caller;
    let mut list = Vec::with_capacity(14);
    if let Some((owner_uid, owner_gid)) = owner {
        list.push((owner_uid, owner_gid));
        if owner_gid != caller_gid {
            list.push((caller_uid, owner_gid));
        }
    }
    list.push((0, 0));
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

#[cfg(test)]
mod tests {
    #![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo, clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::indexing_slicing, reason = "unit test  --  lints are suppressed per project policy")]
    use super::*;

    #[test]
    fn escalation_list_removes_nonadjacent_duplicates() {
        // owner=(0,0) with a non-zero caller_gid puts (0,0) at index 0 and again
        // at the root push (index 2), separated by (caller_uid, 0). Vec::dedup
        // would leave both; the seen-set pass must keep exactly one.
        let list = escalation_list((1001, 1001), Some((0, 0)));
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
        let list = escalation_list((42, 42), Some((1000, 1000)));
        assert_eq!(list.iter().filter(|p| **p == (1000, 1000)).count(), 1);
        assert_eq!(list[0], (1000, 1000));
    }

    #[test]
    fn escalation_list_has_no_duplicates_without_owner() {
        let list = escalation_list((33, 33), None);
        let mut seen = std::collections::HashSet::new();
        for pair in &list {
            assert!(seen.insert(*pair), "duplicate credential {pair:?}");
        }
    }
}
