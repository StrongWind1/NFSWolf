//! Credential escalation ladder shared by every subcommand that performs
//! NFS operations.
//!
//! When the server returns NFS3ERR_ACCES, callers retry through a
//! consistent sequence of identities: the file owner first, then the
//! caller with the file's group, then root, then identities seen owning
//! files on the export, then well-known service accounts. Centralising the
//! order means the shell, the FUSE adapter, and the offensive subcommands
//! all walk the same ladder, so behaviour is predictable across surfaces.
//!
//! # UIDs and GIDs are searched separately
//!
//! POSIX grants access through the owner triad when the UID matches and
//! through the group triad when the primary GID *or any supplementary GID*
//! matches. AUTH_SYS lets the client claim up to 16 supplementary groups
//! (RFC 5531 sec. 14), so every rung after the operator's own identity
//! claims the file's group, the operator's `--gid`/`--aux-gids`, and the
//! groups seen owning files, alongside whatever UID the rung tries. Group
//! access then no longer depends on pairing the right UID with the right
//! GID.
//!
//! This also matters under `root_squash`: knfsd remaps a claimed uid 0 to
//! the anonymous UID and gid 0 to the anonymous GID, but keeps every other
//! group, primary or supplementary (`nfsd_setuser()`, fs/nfsd/auth.c). A
//! caller claiming uid 0 still reaches files through its non-zero groups.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use crate::proto::auth::{AuthSys, Credential};

/// Most supplementary groups an AUTH_SYS credential carries (`gids<16>`,
/// RFC 5531 sec. 14); knfsd enforces the same limit.
pub(crate) const MAX_GROUPS: usize = 16;

/// How many observed identities get a ladder rung of their own. Each rung
/// costs one RPC per refused operation, so only the most common owners are
/// tried; their groups ride along on every rung anyway.
pub(crate) const OBSERVED_RUNGS: usize = 8;

/// Distinct identities [`ObservedIdentities`] keeps; later ones are dropped
/// so a huge tree cannot grow the table without bound.
const OBSERVED_CAP: usize = 4096;

/// One AUTH_SYS identity: the UID and primary GID to claim, plus the
/// supplementary groups to claim membership of.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Identity {
    pub uid: u32,
    pub gid: u32,
    /// Supplementary groups, primary GID first, at most [`MAX_GROUPS`].
    pub groups: Vec<u32>,
}

impl Identity {
    /// Build an identity, normalising the group list: primary GID first, no
    /// repeats, at most [`MAX_GROUPS`] entries.
    #[must_use]
    pub(crate) fn new(uid: u32, gid: u32, groups: &[u32]) -> Self {
        let mut list = Vec::with_capacity(groups.len().saturating_add(1).min(MAX_GROUPS));
        for g in std::iter::once(gid).chain(groups.iter().copied()) {
            if list.len() == MAX_GROUPS {
                break;
            }
            if !list.contains(&g) {
                list.push(g);
            }
        }
        Self { uid, gid, groups: list }
    }

    /// The AUTH_SYS credential for this identity.
    #[must_use]
    pub(crate) fn credential(&self, machinename: &str) -> Credential {
        Credential::Sys(AuthSys::with_groups(self.uid, self.gid, &self.groups, machinename))
    }

    /// The same supplementary groups under a different UID and primary GID.
    ///
    /// Used when the operator switches identity in the shell: `--aux-gids`
    /// stays in force, the old primary GID does not.
    #[must_use]
    pub(crate) fn switched(&self, uid: u32, gid: u32) -> Self {
        let aux: Vec<u32> = self.groups.iter().copied().filter(|g| *g != self.gid).collect();
        Self::new(uid, gid, &aux)
    }
}

/// Identities seen owning files on an export, counted.
///
/// Every READDIRPLUS and LOOKUP reply carries the owner and group of what it
/// names, so recording them costs nothing. The ladder tries the most common
/// owners as rungs and claims the most common groups on every rung.
#[derive(Debug, Default)]
pub(crate) struct ObservedIdentities {
    counts: Mutex<HashMap<(u32, u32), u64>>,
}

impl ObservedIdentities {
    /// Count each `(uid, gid)` once more.
    pub(crate) fn record(&self, ids: impl IntoIterator<Item = (u32, u32)>) {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        for id in ids {
            if let Some(n) = counts.get_mut(&id) {
                *n = n.saturating_add(1);
            } else if counts.len() < OBSERVED_CAP {
                let _ = counts.insert(id, 1);
            }
        }
    }

    /// The `n` most common owners, most frequent first, as ladder rungs.
    ///
    /// UID 0 is left out: root already has its own rung, and under
    /// `root_squash` a claimed uid 0 is the anonymous UID, whose only access
    /// is through groups -- which every rung claims anyway.
    #[must_use]
    pub(crate) fn top_pairs(&self, n: usize) -> Vec<(u32, u32)> {
        let counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let mut pairs: Vec<((u32, u32), u64)> = counts.iter().filter(|((uid, _), _)| *uid != 0).map(|(id, c)| (*id, *c)).collect();
        // Most frequent first; ties broken by identity so the order is stable.
        pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        pairs.into_iter().take(n).map(|(id, _)| id).collect()
    }

    /// The `n` most common owning groups, most frequent first.
    #[must_use]
    pub(crate) fn top_gids(&self, n: usize) -> Vec<u32> {
        let counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let mut per_gid: HashMap<u32, u64> = HashMap::new();
        for ((_, gid), c) in counts.iter() {
            let e = per_gid.entry(*gid).or_insert(0);
            *e = e.saturating_add(*c);
        }
        drop(counts);
        let mut gids: Vec<(u32, u64)> = per_gid.into_iter().collect();
        gids.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        gids.into_iter().take(n).map(|(g, _)| g).collect()
    }
}

/// Supplementary groups to claim with a ladder rung whose primary GID is
/// `rung_gid`: the file's own group first, then the operator's groups, then
/// the groups seen owning files, capped at [`MAX_GROUPS`] in that order.
#[must_use]
pub(crate) fn rung_groups(rung_gid: u32, file_gid: Option<u32>, operator_groups: &[u32], observed_gids: &[u32]) -> Vec<u32> {
    let rest: Vec<u32> = file_gid.into_iter().chain(operator_groups.iter().copied()).chain(observed_gids.iter().copied()).collect();
    Identity::new(0, rung_gid, &rest).groups
}

/// The ladder as full identities, for a refused operation by `caller`.
///
/// `owner` and `mode` come from the target's attributes. Each rung of
/// [`credential_ladder_with`] becomes an identity that also claims the file's
/// group, the caller's groups and the most common observed groups (see the
/// module docs). The caller's own identity is left out: it was already
/// refused.
#[must_use]
pub(crate) fn identity_ladder(caller: &Identity, owner: Option<(u32, u32)>, mode: Option<u32>, observed: &ObservedIdentities) -> Vec<Identity> {
    let observed_gids = observed.top_gids(MAX_GROUPS);
    let file_gid = owner.map(|o| o.1);
    let mut ladder: Vec<Identity> = Vec::new();
    for (uid, gid) in credential_ladder_with((caller.uid, caller.gid), owner, mode, &observed.top_pairs(OBSERVED_RUNGS)) {
        let id = Identity::new(uid, gid, &rung_groups(gid, file_gid, &caller.groups, &observed_gids));
        if id != *caller && !ladder.contains(&id) {
            ladder.push(id);
        }
    }
    // The caller's own UID and GID with the extended group list, ahead of
    // everything else when the caller already owns the file's group: the
    // pair rungs above cannot express "same identity, more groups".
    let widened = Identity::new(caller.uid, caller.gid, &rung_groups(caller.gid, file_gid, &caller.groups, &observed_gids));
    if widened != *caller && !ladder.contains(&widened) {
        ladder.insert(0, widened);
    }
    ladder
}

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
#[cfg(test)]
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
        // Unconditional: nfsd_permission() grants owner access regardless of mode bits
        // (NFSD_MAY_OWNER_OVERRIDE, C702 sec. 12.3.3).
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
    tracing::debug!(caller = ?(caller.0, caller.1), owner = ?owner, rungs = list.len(), "credential ladder built");
    list
}

#[cfg(test)]
mod tests {
    #![expect(clippy::pedantic, reason = "unit test  --  lints are suppressed per project policy")]
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

#[cfg(test)]
mod identity_tests {
    use super::*;

    #[test]
    fn identity_puts_primary_first_dedups_and_caps() {
        let many: Vec<u32> = (100..140).collect();
        let id = Identity::new(1000, 50, &[50, 7, 7, 8]);
        assert_eq!(id.groups, vec![50, 7, 8]);
        let capped = Identity::new(1000, 50, &many);
        assert_eq!(capped.groups.len(), MAX_GROUPS);
        assert_eq!(capped.groups[0], 50, "primary GID stays first when the list is capped");
    }

    #[test]
    fn switching_identity_keeps_aux_groups_and_drops_the_old_primary() {
        let id = Identity::new(0, 0, &[522, 42]);
        let switched = id.switched(1000, 1000);
        assert_eq!(switched.groups, vec![1000, 522, 42]);
    }

    #[test]
    fn rung_groups_claim_the_file_group_then_the_operator_then_observed() {
        let groups = rung_groups(1000, Some(30), &[522], &[42, 30]);
        assert_eq!(groups, vec![1000, 30, 522, 42]);
    }

    /// The reported case: uid 0 under root_squash with group 522. knfsd keeps
    /// every non-zero group, so every rung must still claim 522, whatever UID
    /// it tries -- including the file owner's.
    #[test]
    fn every_rung_keeps_the_operators_groups() {
        let caller = Identity::new(0, 0, &[522]);
        let ladder = identity_ladder(&caller, Some((1001, 1001)), Some(0o640), &ObservedIdentities::default());
        assert!(!ladder.is_empty());
        for id in &ladder {
            assert!(id.groups.contains(&522), "rung {id:?} dropped --aux-gids 522");
            assert!(id.groups.contains(&1001), "rung {id:?} does not claim the file's group");
        }
    }

    #[test]
    fn caller_with_the_files_group_is_tried_first() {
        // Group-readable file whose group the caller lacks: the cheapest
        // escalation is the caller's own UID claiming that group.
        let caller = Identity::new(1000, 1000, &[]);
        let ladder = identity_ladder(&caller, Some((0, 30)), Some(0o640), &ObservedIdentities::default());
        assert_eq!(ladder[0].uid, 1000);
        assert!(ladder[0].groups.contains(&30));
    }

    #[test]
    fn the_callers_own_identity_is_not_a_rung() {
        let caller = Identity::new(1000, 1000, &[]);
        let ladder = identity_ladder(&caller, None, None, &ObservedIdentities::default());
        assert!(!ladder.contains(&caller), "the refused identity must not be retried");
    }

    #[test]
    fn observed_owners_become_rungs_and_their_groups_ride_along() {
        let observed = ObservedIdentities::default();
        observed.record([(5000, 700), (5000, 700), (5001, 701), (0, 42)]);
        assert_eq!(observed.top_pairs(8), vec![(5000, 700), (5001, 701)], "most frequent first, uid 0 left out");
        assert_eq!(observed.top_gids(1), vec![700]);
        let ladder = identity_ladder(&Identity::new(1000, 1000, &[]), None, Some(0o644), &observed);
        assert!(ladder.iter().any(|id| id.uid == 5000), "an observed owner gets a rung");
        assert!(ladder.iter().all(|id| id.groups.contains(&700) && id.groups.contains(&42)), "observed groups ride on every rung");
    }

    #[test]
    fn observed_table_is_bounded() {
        let observed = ObservedIdentities::default();
        observed.record((0..10_000u32).map(|i| (i + 1, i)));
        assert!(observed.top_pairs(usize::MAX).len() <= OBSERVED_CAP);
    }
}

/// The ladder against a model of Linux knfsd's permission check, for the
/// cases that matter: group-only files and directories under `root_squash`.
#[cfg(test)]
mod knfsd_model_tests {
    use super::*;

    const ANON: u32 = 65534;
    const READ: u32 = 4;
    const SEARCH: u32 = 1;

    /// Server-side behaviour that changes the outcome.
    #[derive(Clone, Copy)]
    struct Server {
        /// `root_squash`: uid 0 and gid 0 (primary and supplementary) become
        /// the anonymous identity; every other id is kept (`nfsd_setuser()`).
        root_squash: bool,
        /// `rpc.mountd --manage-gids`: the client's supplementary groups are
        /// replaced by the server's own lookup; only the primary GID counts.
        manage_gids: bool,
        /// knfsd lets the owner read regardless of mode
        /// (`NFSD_MAY_OWNER_OVERRIDE`); other servers do not.
        owner_override: bool,
    }

    const KNFSD: Server = Server { root_squash: true, manage_gids: false, owner_override: true };

    /// Whether `id` may perform `want` (READ or SEARCH bits) on an object
    /// owned by `owner` with permission bits `mode`: the squash, then the
    /// single POSIX triad that applies (owner, else group, else other).
    fn permitted(id: &Identity, s: Server, owner: (u32, u32), mode: u32, want: u32) -> bool {
        let squash = |v: u32| if s.root_squash && v == 0 { ANON } else { v };
        let uid = squash(id.uid);
        let groups: Vec<u32> = id.groups.iter().map(|&g| squash(g)).collect();
        if uid == 0 {
            return true; // CAP_DAC_OVERRIDE
        }
        if uid == owner.0 {
            return (s.owner_override && want == READ) || (mode >> 6) & want == want;
        }
        let in_group = if s.manage_gids { groups.first() == Some(&owner.1) } else { groups.contains(&owner.1) };
        let bits = if in_group { mode >> 3 } else { mode };
        bits & want == want
    }

    /// Position of the first identity that gets in: 0 for the caller as
    /// given, n for the nth ladder rung, `None` if nothing works.
    fn first_working(caller: &Identity, s: Server, owner: (u32, u32), mode: u32, want: u32) -> Option<usize> {
        if permitted(caller, s, owner, mode, want) {
            return Some(0);
        }
        let ladder = identity_ladder(caller, Some(owner), Some(mode), &ObservedIdentities::default());
        ladder.iter().position(|id| permitted(id, s, owner, mode, want)).map(|i| i + 1)
    }

    /// The reported case: uid 1000 gid 1000 reading a root:522 file that only
    /// its group may read, under root_squash.
    #[test]
    fn group_only_file_owned_by_root_is_read_on_the_first_rung() {
        let caller = Identity::new(1000, 1000, &[]);
        assert_eq!(first_working(&caller, KNFSD, (0, 522), 0o040, READ), Some(1));
        assert_eq!(first_working(&caller, KNFSD, (0, 522), 0o640, READ), Some(1));
    }

    /// The same for a directory on the way to the file: LOOKUP needs search
    /// permission, and a root:522 0050 directory grants it only to group 522.
    #[test]
    fn group_only_directory_is_searched_on_the_first_rung() {
        let caller = Identity::new(1000, 1000, &[]);
        assert_eq!(first_working(&caller, KNFSD, (0, 522), 0o050, SEARCH), Some(1));
        assert_eq!(first_working(&caller, KNFSD, (0, 522), 0o750, SEARCH), Some(1));
    }

    /// A server that ignores supplementary groups still honours the primary
    /// GID, which a later rung sets to the file's group.
    #[test]
    fn manage_gids_server_is_reached_through_the_primary_gid() {
        let caller = Identity::new(1000, 1000, &[]);
        let server = Server { manage_gids: true, ..KNFSD };
        let found = first_working(&caller, server, (0, 522), 0o040, READ);
        assert!(found.is_some_and(|n| n <= 3), "found at {found:?}");
    }

    /// Owning a group-only file locks the owner out on a server without
    /// knfsd's owner override. Root squashed to nobody, claiming the group,
    /// is no longer the owner and reads through the group triad.
    #[test]
    fn owner_locked_out_of_a_group_only_file_gets_in_through_the_group() {
        let caller = Identity::new(1000, 522, &[]);
        let server = Server { owner_override: false, ..KNFSD };
        assert!(!permitted(&caller, server, (1000, 522), 0o040, READ));
        assert!(first_working(&caller, server, (1000, 522), 0o040, READ).is_some());
    }

    /// A file no group or other may read, owned by root, stays unreadable
    /// under root_squash -- the ladder must not claim otherwise.
    #[test]
    fn root_only_file_under_root_squash_is_out_of_reach() {
        let caller = Identity::new(1000, 1000, &[522]);
        assert_eq!(first_working(&caller, Server { owner_override: false, ..KNFSD }, (0, 0), 0o600, READ), None);
    }
}
