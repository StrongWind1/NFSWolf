//! Per-file open and lock state tracking.
//!
//! After a successful OPEN, the server returns a stateid that the client must
//! present on subsequent READ, WRITE, SETATTR, and CLOSE calls for that file.
//! This module holds the bookkeeping for those stateids and for byte-range
//! locks acquired via LOCK.

use crate::wire::{LockOwner4, LockType4, OpenDelegation4, Stateid4};

/// State for an opened file (OPEN result + subsequent mutations).
#[derive(Debug, Clone)]
pub struct OpenState {
    /// Open stateid from the OPEN response (or updated by OPEN_DOWNGRADE/CLOSE).
    pub stateid: Stateid4,
    /// File handle obtained from GETFH after OPEN.
    pub fh: Vec<u8>,
    /// Share access mode this file was opened with (RFC 7530 S16.16.4).
    pub share_access: u32,
    /// Share deny mode (RFC 7530 S16.16.4).
    pub share_deny: u32,
    /// Delegation granted by the server, if any.
    pub delegation: OpenDelegation4,
    /// Whether OPEN_CONFIRM has been sent for this open-owner (RFC 7530 S16.18).
    pub confirmed: bool,
}

impl OpenState {
    /// The open stateid for use in READ/WRITE/SETATTR/CLOSE.
    #[must_use]
    pub fn stateid(&self) -> Stateid4 {
        self.stateid
    }

    /// The file handle.
    #[must_use]
    pub fn fh(&self) -> &[u8] {
        &self.fh
    }
}

/// State for a byte-range lock (RFC 7530 S16.10).
#[derive(Debug, Clone)]
pub struct LockState {
    /// Lock stateid from the LOCK response.
    pub lock_stateid: Stateid4,
    /// Lock owner.
    pub lock_owner: LockOwner4,
    /// Active lock ranges.
    pub ranges: Vec<LockRange>,
}

/// A single byte-range lock.
#[derive(Debug, Clone, Copy)]
pub struct LockRange {
    /// Starting offset.
    pub offset: u64,
    /// Length (u64::MAX means entire file, RFC 7530 S16.10.4).
    pub length: u64,
    /// Lock type.
    pub locktype: LockType4,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::NFS4_OTHER_SIZE;

    #[test]
    fn open_state_accessors() {
        let state = OpenState { stateid: Stateid4 { seqid: 1, other: [0xAA; NFS4_OTHER_SIZE] }, fh: vec![0x01, 0x02, 0x03], share_access: 1, share_deny: 0, delegation: OpenDelegation4::None, confirmed: false };

        assert_eq!(state.stateid().seqid, 1);
        assert_eq!(state.stateid().other, [0xAA; NFS4_OTHER_SIZE]);
        assert_eq!(state.fh(), &[0x01, 0x02, 0x03]);
        assert_eq!(state.share_access, 1);
        assert_eq!(state.share_deny, 0);
        assert!(!state.confirmed);
    }

    #[test]
    fn lock_state_empty_ranges() {
        let state = LockState { lock_stateid: Stateid4::ANONYMOUS, lock_owner: LockOwner4 { clientid: 42, owner: vec![0x01] }, ranges: vec![] };

        assert_eq!(state.lock_stateid, Stateid4::ANONYMOUS);
        assert_eq!(state.lock_owner.clientid, 42);
        assert!(state.ranges.is_empty());
    }

    #[test]
    fn lock_range_whole_file() {
        let range = LockRange { offset: 0, length: u64::MAX, locktype: LockType4::WriteLt };

        assert_eq!(range.offset, 0);
        assert_eq!(range.length, u64::MAX);
    }
}
