//! Stealth and timing controls.
//!
//! Configurable delays, jitter, and connection management
//! to avoid detection by network monitoring systems.

// Struct fields are timing parameters; individual docs would repeat the name.
// Toolkit API  --  not all items are used in currently-implemented phases.
use std::time::Duration;

/// Stealth configuration for timing-sensitive operations.
#[derive(Debug, Clone)]
pub struct StealthConfig {
    /// Fixed delay between operations
    pub delay: Duration,
    /// Maximum random jitter added to delay
    pub jitter: Duration,
}

impl StealthConfig {
    pub const fn none() -> Self {
        Self { delay: Duration::ZERO, jitter: Duration::ZERO }
    }

    pub const fn new(delay_ms: u64, jitter_ms: u64) -> Self {
        Self { delay: Duration::from_millis(delay_ms), jitter: Duration::from_millis(jitter_ms) }
    }

    /// Get the next delay duration (base + random jitter).
    pub fn next_delay(&self) -> Duration {
        if self.delay.is_zero() && self.jitter.is_zero() {
            return Duration::ZERO;
        }

        let jitter = if self.jitter.is_zero() {
            Duration::ZERO
        } else {
            let jitter_ms = u64::try_from(self.jitter.as_millis()).unwrap_or(u64::MAX);
            let ms = rand::random_range(0..jitter_ms);
            Duration::from_millis(ms)
        };

        self.delay + jitter
    }

    /// Sleep for the configured delay + jitter.
    pub async fn wait(&self) {
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
}
