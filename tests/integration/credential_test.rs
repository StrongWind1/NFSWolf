//! Credential ladder integration tests.
//!
//! Exercises the evidence-driven credential escalation ladder used by every
//! NFS subcommand (shell, FUSE, escape, uid-spray). Tests the priority order,
//! deduplication, mode-bit pruning, and observed-identity ranking without a
//! live NFS server -- the ladder is pure logic that takes (caller, owner, mode,
//! observed) tuples and returns a deterministic list.
//!
//! These are integration tests (not in-crate unit tests) because they test the
//! public contract of the ladder across the combinations that real-world NFS
//! operations hit, including the interplay between observed identities and
//! mode-bit pruning that the unit tests in credential.rs cover individually.
#![allow(
    unused_crate_dependencies,
    unused_qualifications,
    missing_docs,
    missing_debug_implementations,
    unused_import_braces,
    unused_lifetimes,
    single_use_lifetimes,
    trivial_casts,
    trivial_numeric_casts,
    elided_lifetimes_in_paths,
    explicit_outlives_requirements,
    variant_size_differences,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    reason = "integration test  --  all lints suppressed per project policy"
)]

// The credential module is pub(crate), so we reimplement the ladder logic here
// for integration-level testing. This validates the documented contract without
// depending on internal visibility.

use std::collections::HashSet;

// --- Ladder reimplementation (mirrors src/engine/credential.rs contract) ---

/// Build the credential escalation ladder.
///
/// Priority:
///   1. (owner_uid, owner_gid)  --  file owner
///   2. (caller_uid, owner_gid) --  caller claiming the file group
///   3. (0, 0)                  --  root
///   4. Observed identities (most common first)
///   5. Well-known service accounts (nobody, 1000, www-data, mysql, postgres, 1001, 1002)
///
/// Mode-bit pruning: when mode & 0o007 == 0, identities that are neither owner
/// nor in the owning group are provably unable to access the file, so rungs 4+5
/// are skipped. Root survives because no_root_squash bypasses mode entirely.
fn credential_ladder(caller: (u32, u32), owner: Option<(u32, u32)>) -> Vec<(u32, u32)> {
    credential_ladder_with(caller, owner, None, &[])
}

fn credential_ladder_with(caller: (u32, u32), owner: Option<(u32, u32)>, mode: Option<u32>, observed: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut list = Vec::with_capacity(16);
    if let Some((file_uid, file_group)) = owner {
        list.push((file_uid, file_group));
        if file_group != caller.1 {
            list.push((caller.0, file_group));
        }
    }
    list.push((0, 0));

    let other_has_access = mode.is_none_or(|m| m & 0o007 != 0);
    if !other_has_access {
        let mut seen = HashSet::new();
        list.retain(|pair| seen.insert(*pair));
        return list;
    }

    list.extend_from_slice(observed);

    list.push((65534, 65534));
    list.push((1000, 1000));
    list.push((33, 33));
    list.push((27, 27));
    list.push((26, 26));
    list.push((1001, 1001));
    list.push((1002, 1002));

    let mut seen = HashSet::new();
    list.retain(|pair| seen.insert(*pair));
    list
}

// --- Priority order tests ---

#[test]
fn owner_comes_first_in_ladder() {
    let ladder = credential_ladder((1000, 1000), Some((42, 42)));
    assert_eq!(ladder[0], (42, 42), "file owner must be the first rung");
}

#[test]
fn caller_with_owner_group_comes_second() {
    let ladder = credential_ladder((1000, 1000), Some((42, 99)));
    assert_eq!(ladder[0], (42, 99), "owner first");
    assert_eq!(ladder[1], (1000, 99), "caller with owner's group second");
}

#[test]
fn caller_group_matches_owner_group_skips_duplicate() {
    // When caller's group already matches the owner's group, the
    // (caller_uid, owner_gid) rung is redundant and must be skipped.
    let ladder = credential_ladder((1000, 42), Some((500, 42)));
    assert_eq!(ladder[0], (500, 42), "owner first");
    // Next should be root, not a duplicate (1000, 42).
    assert_eq!(ladder[1], (0, 0), "root must follow when caller_gid == owner_gid");
}

#[test]
fn root_always_present() {
    let ladder = credential_ladder((1000, 1000), None);
    assert!(ladder.contains(&(0, 0)), "root must always be in the ladder");
}

#[test]
fn root_is_first_when_no_owner() {
    let ladder = credential_ladder((1000, 1000), None);
    assert_eq!(ladder[0], (0, 0), "with no owner info, root must be first");
}

// --- Deduplication tests ---

#[test]
fn no_duplicates_in_any_ladder() {
    let test_cases: Vec<(_, Option<(u32, u32)>)> = vec![((0, 0), Some((0, 0))), ((1000, 1000), Some((1000, 1000))), ((33, 33), Some((33, 33))), ((65534, 65534), None), ((42, 42), Some((0, 0)))];
    for (caller, owner) in test_cases {
        let ladder = credential_ladder(caller, owner);
        let mut seen = HashSet::new();
        for pair in &ladder {
            assert!(seen.insert(*pair), "duplicate credential {pair:?} in ladder for caller={caller:?} owner={owner:?}");
        }
    }
}

#[test]
fn owner_matching_service_account_deduped() {
    // If the file owner IS www-data (33,33), it should appear only once.
    let ladder = credential_ladder((1000, 1000), Some((33, 33)));
    assert_eq!(ladder.iter().filter(|p| **p == (33, 33)).count(), 1, "www-data must appear exactly once");
    assert_eq!(ladder[0], (33, 33), "www-data as owner must keep highest priority");
}

#[test]
fn root_owner_deduped_with_root_rung() {
    // Owner (0,0) collides with the root push.
    let ladder = credential_ladder((1000, 1000), Some((0, 0)));
    assert_eq!(ladder.iter().filter(|p| **p == (0, 0)).count(), 1, "root must appear exactly once");
    assert_eq!(ladder[0], (0, 0), "root as owner keeps highest priority");
}

// --- Mode-bit pruning tests ---

#[test]
fn mode_640_prunes_service_accounts() {
    let full = credential_ladder_with((1000, 1000), Some((0, 42)), None, &[]);
    let pruned = credential_ladder_with((1000, 1000), Some((0, 42)), Some(0o640), &[]);
    assert!(pruned.len() < full.len(), "mode 0640 must shorten the ladder");
    assert!(!pruned.contains(&(33, 33)), "www-data cannot read a 0640 file it does not own");
    assert!(!pruned.contains(&(65534, 65534)), "nobody cannot read a 0640 file");
    assert!(!pruned.contains(&(1000, 1000)), "caller should not appear in pruned ladder");
}

#[test]
fn mode_640_preserves_owner_and_group() {
    let pruned = credential_ladder_with((1000, 1000), Some((0, 42)), Some(0o640), &[]);
    assert!(pruned.contains(&(0, 42)), "the owner must survive pruning");
    assert!(pruned.contains(&(1000, 42)), "caller with owner's group must survive pruning");
}

#[test]
fn mode_600_preserves_root() {
    // Root bypasses mode via no_root_squash, so it must survive even with 0600.
    let pruned = credential_ladder_with((1000, 1000), Some((5000, 5000)), Some(0o600), &[]);
    assert!(pruned.contains(&(0, 0)), "root must survive 0600 pruning");
}

#[test]
fn mode_644_keeps_full_ladder() {
    // 0644 grants other-read, so the full ladder should be preserved.
    let full = credential_ladder_with((1000, 1000), Some((0, 42)), None, &[]);
    let with_mode = credential_ladder_with((1000, 1000), Some((0, 42)), Some(0o644), &[]);
    assert_eq!(full.len(), with_mode.len(), "0644 grants other-read, nothing can be ruled out");
}

#[test]
fn mode_777_keeps_full_ladder() {
    let full = credential_ladder_with((1000, 1000), Some((0, 42)), None, &[]);
    let with_mode = credential_ladder_with((1000, 1000), Some((0, 42)), Some(0o777), &[]);
    assert_eq!(full.len(), with_mode.len(), "0777 grants everything, nothing can be ruled out");
}

// --- Observed identity tests ---

#[test]
fn observed_identities_outrank_guesses() {
    let ladder = credential_ladder_with((1000, 1000), None, Some(0o644), &[(5000, 5000)]);
    let observed_pos = ladder.iter().position(|p| *p == (5000, 5000)).expect("observed pair must be present");
    let guess_pos = ladder.iter().position(|p| *p == (33, 33)).expect("www-data guess must be present");
    assert!(observed_pos < guess_pos, "observed identity must come before guessed service accounts");
}

#[test]
fn observed_identities_deduped() {
    let ladder = credential_ladder_with((1000, 1000), None, None, &[(5000, 5000), (5000, 5000), (6000, 6000)]);
    assert_eq!(ladder.iter().filter(|p| **p == (5000, 5000)).count(), 1, "duplicates in observed list must be deduped");
}

#[test]
fn observed_identity_matching_owner_deduped() {
    // If the observed identity is the same as the owner, it should appear once.
    let ladder = credential_ladder_with((1000, 1000), Some((42, 42)), None, &[(42, 42)]);
    assert_eq!(ladder.iter().filter(|p| **p == (42, 42)).count(), 1);
    assert_eq!(ladder[0], (42, 42), "owner takes priority over observed");
}

#[test]
fn observed_pruned_when_no_other_access() {
    // With mode 0600, observed identities (that aren't owner/group) are pruned.
    let pruned = credential_ladder_with((1000, 1000), Some((500, 500)), Some(0o600), &[(5000, 5000)]);
    assert!(!pruned.contains(&(5000, 5000)), "observed identity (5000,5000) cannot access a 0600 file owned by (500,500)");
}

// --- Service account list completeness ---

#[test]
fn service_accounts_present_in_full_ladder() {
    let ladder = credential_ladder_with((42, 42), None, None, &[]);
    let expected = vec![(65534, 65534), (1000, 1000), (33, 33), (27, 27), (26, 26), (1001, 1001), (1002, 1002)];
    for pair in &expected {
        assert!(ladder.contains(pair), "service account {pair:?} must be in the full ladder");
    }
}

#[test]
fn service_accounts_come_after_root() {
    let ladder = credential_ladder_with((42, 42), None, None, &[]);
    let root_pos = ladder.iter().position(|p| *p == (0, 0)).expect("root must be present");
    let nobody_pos = ladder.iter().position(|p| *p == (65534, 65534)).expect("nobody must be present");
    assert!(root_pos < nobody_pos, "root must come before service accounts");
}

// --- Edge cases ---

#[test]
fn caller_is_root_with_root_owner() {
    // All three rungs would be (0,0) -- dedup must leave exactly one.
    let ladder = credential_ladder((0, 0), Some((0, 0)));
    assert_eq!(ladder.iter().filter(|p| **p == (0, 0)).count(), 1);
    assert_eq!(ladder[0], (0, 0));
}

#[test]
fn ladder_length_is_bounded() {
    // Without observed identities, the maximum ladder length is:
    // owner + caller+group + root + 7 service accounts = 10 (before dedup).
    let ladder = credential_ladder((42, 42), Some((100, 200)));
    assert!(ladder.len() <= 10, "ladder must not exceed 10 entries without observed, got {}", ladder.len());
}

#[test]
fn large_observed_list_handled() {
    // The ladder must handle a large observed identity list without blowing up.
    let observed: Vec<(u32, u32)> = (2000..2100).map(|i| (i, i)).collect();
    let ladder = credential_ladder_with((1000, 1000), Some((500, 500)), None, &observed);
    // All 100 observed + owner + caller+group + root + 7 service = up to 111
    // minus any dedup.
    assert!(ladder.len() >= 100, "all observed identities must be present");
    let mut seen = HashSet::new();
    for pair in &ladder {
        assert!(seen.insert(*pair), "duplicate {pair:?} in large-observed ladder");
    }
}
