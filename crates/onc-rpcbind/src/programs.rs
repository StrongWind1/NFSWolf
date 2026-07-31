//! Well-known RPC program number table.
//!
//! Maps program numbers from the IANA "ONC RPC program number" registry
//! (and common vendor extensions) to human-readable names. Only programs
//! that commonly appear alongside NFS or are security-relevant in NFS
//! engagements are included -- this is not the full IANA registry.
//!
//! Sources: RFC 1057 appendix A, RFC 1813, RFC 7530, IANA RPC program
//! number assignments, and observed Linux/Solaris/NetApp deployments.

/// Sorted table of (program_number, name) pairs.
///
/// Sorted by program number so `known_programs()` returns a deterministic
/// order and `program_name()` can binary-search.
static PROGRAMS: &[(u32, &str)] = &[
    // RFC 1057 appendix A -- portmapper itself.
    (100_000, "portmapper"),
    // RFC 1057 S9.
    (100_003, "nfs"),
    // Sun NIS / ypserv.
    (100_004, "ypserv"),
    // RFC 1813, RFC 1094 appendix A -- MOUNT protocol.
    (100_005, "mountd"),
    // Sun NIS / ypbind.
    (100_007, "ypbind"),
    // Sun walld (wall daemon).
    (100_008, "walld"),
    // Sun rquotad -- remote disk quotas (common on NFS servers).
    (100_011, "rquotad"),
    // Sun sprayd -- diagnostic spray.
    (100_012, "sprayd"),
    // RFC 1057 S9 -- NLM (network lock manager).
    (100_021, "nlockmgr"),
    // RFC 1813 S10 -- NSM (network status monitor / statd).
    (100_024, "status"),
    // Solaris / Linux nfs_acl sideband.
    (100_227, "nfs_acl"),
    // Sun pcnfsd -- PC-NFS authentication daemon.
    (150_001, "pcnfsd"),
];

/// Look up the human-readable name for an RPC program number.
///
/// Returns `None` for programs not in the well-known table.
#[must_use]
pub fn program_name(prog: u32) -> Option<&'static str> {
    // Binary search: the table is sorted by program number.
    // .get() is safe here -- binary_search returns an index within bounds
    // when it finds a match, but clippy cannot prove that statically.
    PROGRAMS.binary_search_by_key(&prog, |&(num, _)| num).ok().and_then(|idx| PROGRAMS.get(idx)).map(|&(_, name)| name)
}

/// The full table of well-known RPC program numbers and names.
///
/// Returned in ascending program-number order.
#[must_use]
pub fn known_programs() -> &'static [(u32, &'static str)] {
    PROGRAMS
}

#[cfg(test)]
mod tests {
    use super::{known_programs, program_name};

    #[test]
    fn known_programs_returns_all_entries() {
        let table = known_programs();
        assert!(!table.is_empty(), "table must not be empty");
        // Verify the table is sorted by program number -- binary search depends on it.
        for pair in table.windows(2) {
            assert!(pair.len() > 1);
            assert!(pair[0].0 < pair[1].0, "table must be sorted: {} should come before {}", pair[0].0, pair[1].0);
        }
    }

    #[test]
    fn core_nfs_programs_resolve() {
        // RFC 1057 appendix A: portmapper.
        assert_eq!(program_name(100_000), Some("portmapper"));
        // RFC 1057 S9: NFS.
        assert_eq!(program_name(100_003), Some("nfs"));
        // RFC 1813, RFC 1094 appendix A: MOUNT.
        assert_eq!(program_name(100_005), Some("mountd"));
        // NLM (network lock manager).
        assert_eq!(program_name(100_021), Some("nlockmgr"));
        // NSM (network status monitor / statd).
        assert_eq!(program_name(100_024), Some("status"));
    }

    #[test]
    fn nis_programs_resolve() {
        assert_eq!(program_name(100_004), Some("ypserv"));
        assert_eq!(program_name(100_007), Some("ypbind"));
    }

    #[test]
    fn auxiliary_programs_resolve() {
        assert_eq!(program_name(100_011), Some("rquotad"));
        assert_eq!(program_name(100_227), Some("nfs_acl"));
        assert_eq!(program_name(150_001), Some("pcnfsd"));
    }

    #[test]
    fn unknown_programs_return_none() {
        assert_eq!(program_name(0), None);
        assert_eq!(program_name(1), None);
        assert_eq!(program_name(99_999), None);
        assert_eq!(program_name(100_001), None);
        assert_eq!(program_name(999_999), None);
        assert_eq!(program_name(u32::MAX), None);
    }
}
