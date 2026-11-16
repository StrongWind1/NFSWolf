//! NFSv4.0 session state -- client identity, lease tracking, open-owner sequencing.
//!
//! NFSv4.0 has no sessions in the v4.1 sense. "Session" here means the
//! (clientid, verifier) pair negotiated via SETCLIENTID + SETCLIENTID_CONFIRM
//! plus the bookkeeping needed to keep the lease alive and sequence open-owner
//! operations correctly.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crate::wire::{CompoundRes, OpenOwner4};

/// NFSv4.0 client session state.
///
/// Holds the clientid negotiated via SETCLIENTID + SETCLIENTID_CONFIRM,
/// the confirm verifier, and the lease duration reported by the server.
///
/// The open-owner seqid counter is atomic, but that does not make concurrent
/// open-owner operations safe: the server processes them strictly in seqid
/// order (RFC 7530 sec. 9.1.7), so a caller must issue them one at a time and
/// record each outcome before sending the next.
#[derive(Debug)]
pub struct Nfs4Session {
    /// Server-assigned client ID.
    clientid: u64,
    /// Confirm verifier from SETCLIENTID response.
    confirm_verifier: [u8; 8],
    /// Whether SETCLIENTID_CONFIRM has been sent.
    confirmed: bool,
    /// Server's lease duration (from GETATTR lease_time or default 90s).
    lease_time: Duration,
    /// Per-session open-owner. NFSv4.0 requires one seqid counter per open-owner.
    open_owner: OpenOwner4,
    /// Monotonic seqid for open-owner operations (OPEN, CLOSE, OPEN_CONFIRM, OPEN_DOWNGRADE).
    /// Starts at 1; 0 is reserved.
    seqid: AtomicU32,
}

impl Nfs4Session {
    /// Create a new session from SETCLIENTID results.
    ///
    /// The `owner_name` becomes the opaque owner identifier in the `OpenOwner4`
    /// sent with every OPEN. Typically a per-process or hostname-based value.
    #[must_use]
    pub fn new(clientid: u64, confirm_verifier: [u8; 8], owner_name: &[u8]) -> Self {
        Self { clientid, confirm_verifier, confirmed: false, lease_time: Duration::from_secs(90), open_owner: OpenOwner4 { clientid, owner: owner_name.to_vec() }, seqid: AtomicU32::new(1) }
    }

    /// Mark the session as confirmed (after SETCLIENTID_CONFIRM succeeds).
    pub fn mark_confirmed(&mut self) {
        self.confirmed = true;
    }

    /// Whether SETCLIENTID_CONFIRM has succeeded.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// The server-assigned client ID.
    pub fn clientid(&self) -> u64 {
        self.clientid
    }

    /// The confirm verifier from SETCLIENTID.
    pub fn confirm_verifier(&self) -> [u8; 8] {
        self.confirm_verifier
    }

    /// The lease duration.
    pub fn lease_time(&self) -> Duration {
        self.lease_time
    }

    /// Set the lease time (typically from GETATTR lease_time attribute).
    pub fn set_lease_time(&mut self, d: Duration) {
        self.lease_time = d;
    }

    /// The open owner for this session.
    pub fn open_owner(&self) -> &OpenOwner4 {
        &self.open_owner
    }

    /// Get the next seqid and advance the counter.
    ///
    /// Advances unconditionally, which is wrong whenever the server did not:
    /// when the operation never ran, when the call failed, or when it returned
    /// one of the errors RFC 7530 sec. 9.1.7 exempts. The client is then one
    /// ahead and every later open-owner operation fails with
    /// `NFS4ERR_BAD_SEQID`.
    #[deprecated(note = "advances even when the server does not; send current_seqid() and call record_outcome() with the reply")]
    pub fn next_seqid(&self) -> u32 {
        self.seqid.fetch_add(1, Ordering::Relaxed)
    }

    /// The seqid to send on the next open-owner operation (OPEN, OPEN_CONFIRM,
    /// OPEN_DOWNGRADE, CLOSE, or a LOCK that creates a lock-owner).
    ///
    /// Reading it does not advance it. Once the reply is in, pass it to
    /// [`record_outcome`](Self::record_outcome).
    pub fn current_seqid(&self) -> u32 {
        self.seqid.load(Ordering::Relaxed)
    }

    /// Advance the open-owner sequence if the operation at `op_index` of `res`
    /// consumed the seqid it was sent with (see
    /// [`CompoundRes::seqid_consumed`]).
    ///
    /// When the COMPOUND itself fails to return, call nothing: the server
    /// most likely never saw the request, and if it did, re-sending the same
    /// seqid gets its cached reply rather than an error.
    pub fn record_outcome(&self, res: &CompoundRes, op_index: usize) {
        if res.seqid_consumed(op_index) {
            _ = self.seqid.fetch_add(1, Ordering::Relaxed);
        }
    }

    // --- Crash recovery helpers ---

    /// Reset the session state for re-establishment after NFS4ERR_STALE_CLIENTID.
    ///
    /// Clears the confirmed flag and resets the seqid counter. The consumer
    /// should call `Nfs4Client::establish()` again to get a new clientid.
    pub fn reset(&mut self) {
        self.confirmed = false;
        self.seqid.store(1, Ordering::Relaxed);
    }

    /// Whether the lease is likely expired based on elapsed time.
    ///
    /// Conservative: returns true if more than `lease_time` has passed since
    /// the last renewal. Consumers should renew well before this.
    pub fn needs_renewal(&self, elapsed_since_last_op: Duration) -> bool {
        elapsed_since_last_op >= self.lease_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{ResOp, ResOpData};

    /// A COMPOUND reply of PUTFH then one seqid-bearing op with `status`.
    fn reply(op_status: Option<u32>) -> CompoundRes {
        let mut results = vec![ResOp { op_code: 22, status: 0, data: ResOpData::None }];
        if let Some(status) = op_status {
            results.push(ResOp { op_code: 18, status, data: ResOpData::None });
        }
        CompoundRes { status: op_status.unwrap_or(70), tag: String::new(), results }
    }

    #[test]
    fn record_outcome_advances_only_when_the_server_did() {
        let sess = Nfs4Session::new(1, [0; 8], b"test");
        sess.record_outcome(&reply(Some(0)), 1);
        assert_eq!(sess.current_seqid(), 2, "OK advances");
        sess.record_outcome(&reply(Some(13)), 1);
        assert_eq!(sess.current_seqid(), 3, "an ordinary error advances");
        sess.record_outcome(&reply(Some(10026)), 1);
        assert_eq!(sess.current_seqid(), 3, "NFS4ERR_BAD_SEQID does not");
        sess.record_outcome(&reply(None), 1);
        assert_eq!(sess.current_seqid(), 3, "an op that never ran does not");
    }

    #[test]
    fn new_session_has_correct_initial_state() {
        let verifier = [0xAA; 8];
        let sess = Nfs4Session::new(0xDEAD_BEEF, verifier, b"nfswolf");

        assert_eq!(sess.clientid(), 0xDEAD_BEEF);
        assert_eq!(sess.confirm_verifier(), verifier);
        assert!(!sess.is_confirmed());
        assert_eq!(sess.lease_time(), Duration::from_secs(90));
        assert_eq!(sess.open_owner().clientid, 0xDEAD_BEEF);
        assert_eq!(sess.open_owner().owner, b"nfswolf");
        assert_eq!(sess.current_seqid(), 1);
    }

    #[test]
    #[expect(deprecated, reason = "the deprecated counter is still covered")]
    fn next_seqid_increments() {
        let sess = Nfs4Session::new(1, [0; 8], b"test");

        assert_eq!(sess.next_seqid(), 1);
        assert_eq!(sess.next_seqid(), 2);
        assert_eq!(sess.next_seqid(), 3);
        assert_eq!(sess.current_seqid(), 4);
    }

    #[test]
    fn mark_confirmed_sets_flag() {
        let mut sess = Nfs4Session::new(1, [0; 8], b"test");
        assert!(!sess.is_confirmed());

        sess.mark_confirmed();
        assert!(sess.is_confirmed());
    }

    #[test]
    fn set_lease_time_updates_duration() {
        let mut sess = Nfs4Session::new(1, [0; 8], b"test");
        assert_eq!(sess.lease_time(), Duration::from_secs(90));

        sess.set_lease_time(Duration::from_secs(45));
        assert_eq!(sess.lease_time(), Duration::from_secs(45));
    }

    #[test]
    fn reset_clears_confirmed_and_resets_seqid() {
        let mut sess = Nfs4Session::new(42, [0xBB; 8], b"test");
        sess.mark_confirmed();
        // Advance the seqid a few times.
        sess.record_outcome(&reply(Some(0)), 1);
        sess.record_outcome(&reply(Some(0)), 1);
        assert!(sess.is_confirmed());
        assert_eq!(sess.current_seqid(), 3);

        sess.reset();
        assert!(!sess.is_confirmed());
        assert_eq!(sess.current_seqid(), 1);
        // clientid and verifier are preserved -- the consumer re-uses the same
        // session object and calls establish() to get a new clientid.
        assert_eq!(sess.clientid(), 42);
        assert_eq!(sess.confirm_verifier(), [0xBB; 8]);
    }

    #[test]
    fn needs_renewal_at_lease_boundary() {
        let sess = Nfs4Session::new(1, [0; 8], b"test");
        // Default lease is 90s.
        assert!(!sess.needs_renewal(Duration::from_secs(89)));
        assert!(sess.needs_renewal(Duration::from_secs(90)));
        assert!(sess.needs_renewal(Duration::from_mins(2)));
    }

    #[test]
    fn needs_renewal_with_custom_lease() {
        let mut sess = Nfs4Session::new(1, [0; 8], b"test");
        sess.set_lease_time(Duration::from_secs(30));

        assert!(!sess.needs_renewal(Duration::from_secs(29)));
        assert!(sess.needs_renewal(Duration::from_secs(30)));
        assert!(sess.needs_renewal(Duration::from_secs(31)));
    }
}
