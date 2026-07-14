//! Stealth and timing controls.
//!
//! Configurable delays, jitter, and connection management
//! to avoid detection by network monitoring systems.

// Struct fields are timing parameters; individual docs would repeat the name.
// Toolkit API  --  not all items are used in currently-implemented phases.
use std::time::Duration;

/// Stealth configuration for timing-sensitive operations.
#[derive(Debug, Clone)]
pub(crate) struct StealthConfig {
    /// Fixed delay between operations
    pub delay: Duration,
    /// Maximum random jitter added to delay
    pub jitter: Duration,
}

impl StealthConfig {
    pub(crate) const fn none() -> Self {
        Self { delay: Duration::ZERO, jitter: Duration::ZERO }
    }

    pub(crate) const fn new(delay_ms: u64, jitter_ms: u64) -> Self {
        Self { delay: Duration::from_millis(delay_ms), jitter: Duration::from_millis(jitter_ms) }
    }

    /// Get the next delay duration (base + random jitter).
    pub(crate) fn next_delay(&self) -> Duration {
        if self.delay.is_zero() && self.jitter.is_zero() {
            return Duration::ZERO;
        }

        // Resolve the jitter ceiling in whole milliseconds first. A sub-millisecond
        // jitter (e.g. 500us) is non-zero as a Duration but truncates to 0ms here,
        // which would make `random_range(0..0)` panic on an empty range -- so treat
        // any zero ceiling as "no jitter". The inclusive range lets the configured
        // maximum actually be sampled.
        let jitter_ms = u64::try_from(self.jitter.as_millis()).unwrap_or(u64::MAX);
        let jitter = if jitter_ms == 0 { Duration::ZERO } else { Duration::from_millis(rand::random_range(0..=jitter_ms)) };

        self.delay + jitter
    }

    /// Sleep for the configured delay + jitter.
    pub(crate) async fn wait(&self) {
        let d = self.next_delay();
        if !d.is_zero() {
            tokio::time::sleep(d).await;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
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
        reason = "unit test  --  lints are suppressed per project policy"
    )]
    use super::*;

    #[test]
    fn stealth_config_none_has_zero_delay() {
        let sc = StealthConfig::none();
        assert!(sc.delay.is_zero());
        assert!(sc.jitter.is_zero());
        assert!(sc.next_delay().is_zero());
    }

    #[test]
    fn stealth_config_new_stores_values() {
        let sc = StealthConfig::new(100, 50);
        assert_eq!(sc.delay, Duration::from_millis(100));
        assert_eq!(sc.jitter, Duration::from_millis(50));
    }

    #[tokio::test]
    async fn wait_completes_without_panic() {
        let sc = StealthConfig::none();
        sc.wait().await;
        // If we get here, wait() completed successfully.
    }

    #[test]
    fn stealth_config_zero_jitter_returns_base_delay() {
        let sc = StealthConfig::new(50, 0);
        let delay = sc.next_delay();
        assert_eq!(delay, Duration::from_millis(50), "zero jitter must return exact base delay");
    }

    #[test]
    fn sub_millisecond_jitter_does_not_panic() {
        // jitter < 1ms truncates to 0ms; next_delay must not feed an empty range
        // (0..0) to random_range. The jitter field is public toolkit API and is
        // directly constructible with a sub-ms Duration.
        let sc = StealthConfig { delay: Duration::from_millis(10), jitter: Duration::from_micros(500) };
        let d = sc.next_delay();
        // Sub-ms jitter contributes nothing, so the result is exactly the base delay.
        assert_eq!(d, Duration::from_millis(10));
    }

    #[test]
    fn sub_millisecond_jitter_with_zero_delay_returns_zero() {
        // The exact panic-triggering path before the fix: delay=0 keeps the early
        // zero-check from firing (jitter is non-zero), then jitter_ms truncates to 0.
        let sc = StealthConfig { delay: Duration::ZERO, jitter: Duration::from_micros(900) };
        assert!(sc.next_delay().is_zero());
    }
}
