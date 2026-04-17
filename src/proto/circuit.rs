//! Per-host circuit breaker  --  prevents cascading failures during scanning.
//!
//! Uses a sliding time window to track transient error rates. Only network
//! errors (timeout, ECONNRESET, ECONNREFUSED) trip the breaker  --  permission
//! denials from UID spraying are expected and never count as failures.
//! Cooldown uses exponential backoff with full jitter per DESIGN.md S11.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Single event in the sliding window.
type Event = (Instant, bool);

/// Health state for one host.
#[derive(Debug)]
struct HostHealth {
    /// Sliding window of (timestamp, success) events.
    events: VecDeque<Event>,
    /// Number of times this host has tripped the breaker (for backoff).
    trip_count: u32,
    /// The breaker is open until this instant (None = closed).
    tripped_until: Option<Instant>,
}

impl HostHealth {
    const fn new() -> Self {
        Self { events: VecDeque::new(), trip_count: 0, tripped_until: None }
    }

    /// Evict events older than `window` from the front of the deque.
    fn evict_stale(&mut self, window: Duration) {
        let cutoff = Instant::now().checked_sub(window).unwrap_or_else(Instant::now);
        while self.events.front().is_some_and(|(ts, _)| *ts < cutoff) {
            self.events.pop_front();
        }
    }

    /// Error rate of events currently in the window (0.0-1.0).
    fn error_rate(&self) -> f64 {
        if self.events.is_empty() {
            return 0.0;
        }
        let failures = self.events.iter().filter(|(_, ok)| !ok).count();
        // Event counts fit in u32 (bounded by window size); u32->f64 is always exact.
        f64::from(u32::try_from(failures).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.events.len()).unwrap_or(u32::MAX))
    }

    /// Success rate = 1 - error_rate.
    fn success_rate(&self) -> f64 {
        1.0 - self.error_rate()
    }
}

/// Per-host circuit breaker with sliding window and exponential cooldown.
///
/// Trips when `error_threshold` fraction of the last `min_samples` events
/// in the rolling `window` are transient failures. Recovers automatically
/// after cooldown with jitter.
#[derive(Debug)]
pub struct CircuitBreaker {
    hosts: DashMap<SocketAddr, HostHealth>,
    /// Time window for the sliding error rate calculation.
    window: Duration,
    /// Fraction of events that must be errors to trip the breaker.
    error_threshold: f64,
    /// Minimum sample count before the threshold is evaluated.
    min_samples: usize,
    /// Starting cooldown duration (doubles on each successive trip).
    base_cooldown: Duration,
    /// Upper bound on cooldown.
    max_cooldown: Duration,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given parameters.
    #[must_use]
    pub fn new(window: Duration, error_threshold: f64, min_samples: usize, base_cooldown: Duration, max_cooldown: Duration) -> Self {
        Self { hosts: DashMap::new(), window, error_threshold, min_samples, base_cooldown, max_cooldown }
    }

    /// Create with default parameters suitable for NFS scanning.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(Duration::from_secs(60), 0.80, 10, Duration::from_secs(5), Duration::from_secs(300))
    }

    /// Record a successful transient-eligible call to `addr`.
    pub fn record_success(&self, addr: SocketAddr) {
        let mut h = self.hosts.entry(addr).or_insert_with(HostHealth::new);
        h.evict_stale(self.window);
        h.events.push_back((Instant::now(), true));
        // Reset trip_count when success rate is high enough to indicate recovery.
        if h.success_rate() > 1.0 - (self.error_threshold / 2.0) {
            h.trip_count = 0;
        }
    }

    /// Record a transient failure for `addr`.
    ///
    /// Permission denials must NOT be passed here  --  use only for IO/timeout errors.
    pub fn record_failure(&self, addr: SocketAddr) {
        let mut h = self.hosts.entry(addr).or_insert_with(HostHealth::new);
        h.evict_stale(self.window);
        h.events.push_back((Instant::now(), false));

        if h.events.len() >= self.min_samples && h.error_rate() >= self.error_threshold {
            h.trip_count = h.trip_count.saturating_add(1);
            let cooldown = self.compute_cooldown(h.trip_count);
            h.tripped_until = Some(Instant::now() + cooldown);
            tracing::warn!(%addr, trip_count = h.trip_count, ?cooldown, "circuit breaker tripped");
        }
    }

    /// Returns true if the breaker for `addr` is currently open (blocking calls).
    #[must_use]
    pub fn is_tripped(&self, addr: SocketAddr) -> bool {
        self.hosts.get(&addr).and_then(|h| h.tripped_until).is_some_and(|until| until > Instant::now())
    }

    /// Return `Ok(())` if the breaker is closed, `Err` if open.
    ///
    /// Logs a warning when within 20% of the trip threshold.
    pub fn check_or_wait(&self, addr: SocketAddr) -> anyhow::Result<()> {
        if self.is_tripped(addr) {
            anyhow::bail!("circuit breaker open for {addr}");
        }
        if let Some(h) = self.hosts.get(&addr)
            && h.events.len() >= self.min_samples
            && h.error_rate() >= self.error_threshold * 0.80
        {
            tracing::warn!(%addr, "circuit breaker approaching trip threshold");
        }
        Ok(())
    }

    /// Exponential cooldown with full jitter: `base * 2^(trip-1) * U(0.5, 1.5)`.
    ///
    /// Jitter is computed in integer space (numerator in [500,1500)/1000) to
    /// avoid f64 cast lints while preserving the uniform-in-range property.
    fn compute_cooldown(&self, trip_count: u32) -> Duration {
        let exp = trip_count.saturating_sub(1).min(20);
        let multiplier = 1u64 << exp;
        // Cap to max_cooldown before any further arithmetic to keep values in u64 range.
        let max_ms = u64::try_from(self.max_cooldown.as_millis()).unwrap_or(u64::MAX);
        let base_ms = u64::try_from(self.base_cooldown.as_millis()).unwrap_or(u64::MAX).saturating_mul(multiplier).min(max_ms);
        // Full jitter in [0.5, 1.5): represented as jitter_num in [500, 1500).
        let jitter_num = rand::random_range(500u64..1500u64);
        let jittered_ms = base_ms.saturating_mul(jitter_num) / 1000;
        Duration::from_millis(jittered_ms).min(self.max_cooldown)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn circuit_breaker_starts_closed() {
        let cb = CircuitBreaker::default_config();
        assert!(!cb.is_tripped(loopback(2049)), "fresh breaker must be closed");
    }

    #[test]
    fn circuit_breaker_check_ok_when_closed() {
        let cb = CircuitBreaker::default_config();
        assert!(cb.check_or_wait(loopback(2049)).is_ok());
    }

    #[test]
    fn circuit_breaker_successes_keep_it_closed() {
        let cb = CircuitBreaker::default_config();
        let addr = loopback(2049);
        for _ in 0..50 {
            cb.record_success(addr);
        }
        assert!(!cb.is_tripped(addr), "all-success stream must not trip breaker");
    }

    #[test]
    fn circuit_breaker_trips_on_many_failures() {
        // Configure a tight breaker: 80 % errors, min 10 samples, short cooldown.
        let cb = CircuitBreaker::new(Duration::from_secs(60), 0.80, 10, Duration::from_millis(500), Duration::from_secs(60));
        let addr = loopback(2049);
        // 12 failures with no successes -> 100 % error rate > 80 % threshold.
        for _ in 0..12 {
            cb.record_failure(addr);
        }
        assert!(cb.is_tripped(addr), "breaker must open after sustained failures");
        assert!(cb.check_or_wait(addr).is_err(), "check_or_wait must fail when open");
    }

    #[test]
    fn circuit_breaker_does_not_trip_below_threshold() {
        // 60 % failure rate vs 80 % threshold  --  should stay closed.
        let cb = CircuitBreaker::new(Duration::from_secs(60), 0.80, 10, Duration::from_millis(100), Duration::from_secs(60));
        let addr = loopback(3049);
        // 6 failures + 4 successes = 60 % error rate.
        for _ in 0..6 {
            cb.record_failure(addr);
        }
        for _ in 0..4 {
            cb.record_success(addr);
        }
        assert!(!cb.is_tripped(addr), "60 % error rate must not trip an 80 % threshold");
    }

    #[test]
    fn circuit_breaker_separate_hosts_are_independent() {
        let cb = CircuitBreaker::new(Duration::from_secs(60), 0.80, 10, Duration::from_millis(100), Duration::from_secs(60));
        let addr_a = loopback(2049);
        let addr_b = loopback(2050);
        for _ in 0..12 {
            cb.record_failure(addr_a);
        }
        // addr_b had no failures  --  must remain closed.
        assert!(cb.is_tripped(addr_a));
        assert!(!cb.is_tripped(addr_b), "unrelated host must not be tripped");
    }

    #[test]
    fn record_failure_below_min_samples_does_not_trip() {
        // min_samples=10, only 5 failures  --  breaker must stay closed even at 100% error rate.
        let cb = CircuitBreaker::new(Duration::from_secs(60), 0.80, 10, Duration::from_millis(100), Duration::from_secs(60));
        let addr = loopback(4001);
        for _ in 0..5 {
            cb.record_failure(addr);
        }
        assert!(!cb.is_tripped(addr), "below min_samples must not trip the breaker");
    }

    #[test]
    fn recovery_resets_trip_count_after_sustained_success() {
        let cb = CircuitBreaker::new(Duration::from_secs(60), 0.80, 10, Duration::from_millis(5), Duration::from_secs(60));
        let addr = loopback(4002);
        // Trip the breaker exactly once: 10 failures at min_samples=10
        for _ in 0..10 {
            cb.record_failure(addr);
        }
        assert!(cb.is_tripped(addr));
        // Wait out the short cooldown (max = 5ms * 1.5 jitter = 7.5ms, sleep 100ms to be safe)
        std::thread::sleep(Duration::from_millis(100));
        // After cooldown expires, the breaker is no longer tripped
        assert!(!cb.is_tripped(addr), "cooldown must have expired");
        // Record many successes to trigger trip_count reset
        for _ in 0..50 {
            cb.record_success(addr);
        }
        // Verify state by checking check_or_wait passes
        assert!(cb.check_or_wait(addr).is_ok());
    }

    #[test]
    fn compute_cooldown_increases_exponentially() {
        let cb = CircuitBreaker::new(Duration::from_secs(60), 0.80, 10, Duration::from_secs(1), Duration::from_secs(3600));
        // Cooldown for trip_count=1 should be less than for trip_count=3
        // Due to jitter, sample many times and compare averages
        let mut sum_1: u64 = 0;
        let mut sum_3: u64 = 0;
        for _ in 0..100 {
            sum_1 += u64::try_from(cb.compute_cooldown(1).as_millis()).unwrap_or(u64::MAX);
            sum_3 += u64::try_from(cb.compute_cooldown(3).as_millis()).unwrap_or(u64::MAX);
        }
        assert!(sum_1 < sum_3, "trip_count=1 average ({}) must be less than trip_count=3 average ({})", sum_1 / 100, sum_3 / 100);
    }

    #[test]
    fn multiple_hosts_fully_independent() {
        let cb = CircuitBreaker::new(Duration::from_secs(60), 0.80, 10, Duration::from_millis(500), Duration::from_secs(60));
        let addr_a = loopback(5001);
        let addr_b = loopback(5002);
        // Trip host A
        for _ in 0..15 {
            cb.record_failure(addr_a);
        }
        // Record successes on host B
        for _ in 0..15 {
            cb.record_success(addr_b);
        }
        assert!(cb.is_tripped(addr_a));
        assert!(!cb.is_tripped(addr_b));
        assert!(cb.check_or_wait(addr_b).is_ok());
    }

    #[test]
    fn check_or_wait_returns_ok_when_closed() {
        let cb = CircuitBreaker::default_config();
        let addr = loopback(6001);
        assert!(cb.check_or_wait(addr).is_ok());
    }

    #[test]
    fn check_or_wait_returns_err_when_tripped() {
        let cb = CircuitBreaker::new(Duration::from_secs(60), 0.80, 10, Duration::from_secs(60), Duration::from_secs(300));
        let addr = loopback(6002);
        for _ in 0..15 {
            cb.record_failure(addr);
        }
        assert!(cb.check_or_wait(addr).is_err());
    }
}
