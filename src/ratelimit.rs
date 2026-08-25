//! Token-bucket byte rate limiting.
//!
//! One bucket per throttle point: the engine keeps **global** upload /
//! download buckets, and every [`TorrentSession`](crate::session::TorrentSession)
//! keeps its own per-task buckets. A rate of `0` means *unlimited*. Buckets
//! refill from wall time (`now_ms`), so they stay correct across any tick
//! cadence and never lose burst capacity during long stalls.
//!
//! Enforcement happens at the two natural choke points of the engine:
//! the upload path drains each peer's outgoing buffer through the buckets
//! in [`Engine::pump_connection`](crate::engine::Engine), and the download
//! path caps how many request blocks `fill_pipeline` may issue per tick.

use core::cmp;

/// Byte-rate token bucket.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Burst capacity in bytes.
    capacity: u64,
    /// Currently available tokens (bytes).
    tokens: u64,
    /// Refill rate in bytes/second (0 = unlimited).
    rate_bps: u64,
    /// Last refill timestamp (ms).
    last: u64,
}

impl TokenBucket {
    /// Create a bucket. `rate_bps == 0` means unlimited.
    pub fn new(rate_bps: u64, now: u64) -> Self {
        let capacity = burst_capacity(rate_bps);
        TokenBucket {
            capacity,
            tokens: capacity,
            rate_bps,
            last: now,
        }
    }

    /// Change the rate (0 = unlimited), preserving the current burst state.
    pub fn set_rate(&mut self, rate_bps: u64, now: u64) {
        self.refill(now);
        self.capacity = burst_capacity(rate_bps);
        self.tokens = cmp::min(self.tokens, self.capacity);
        self.rate_bps = rate_bps;
    }

    /// The configured rate (bytes/second; 0 = unlimited).
    pub fn rate_bps(&self) -> u64 {
        self.rate_bps
    }

    /// Whether this bucket is unlimited.
    pub fn is_unlimited(&self) -> bool {
        self.rate_bps == 0
    }

    /// Refill and report how many bytes may be spent right now.
    pub fn available(&mut self, now: u64) -> u64 {
        if self.rate_bps == 0 {
            return u64::MAX;
        }
        self.refill(now);
        self.tokens
    }

    /// Spend up to `want` bytes; returns what was actually taken.
    pub fn consume(&mut self, want: u64, now: u64) -> u64 {
        if self.rate_bps == 0 {
            return want;
        }
        self.refill(now);
        let take = cmp::min(want, self.tokens);
        self.tokens -= take;
        take
    }

    /// Refill tokens from elapsed time, clamped to the burst capacity.
    fn refill(&mut self, now: u64) {
        if self.rate_bps == 0 || now <= self.last {
            return;
        }
        let dt = now - self.last;
        let add = dt.saturating_mul(self.rate_bps) / 1000;
        self.tokens = cmp::min(self.capacity, self.tokens.saturating_add(add));
        self.last = now;
    }
}

/// Burst capacity: one second of traffic, clamped to [64 KiB, 8 MiB].
/// Unlimited buckets report `u64::MAX` so every call is a no-op.
fn burst_capacity(rate_bps: u64) -> u64 {
    if rate_bps == 0 {
        return u64::MAX;
    }
    rate_bps.clamp(64 * 1024, 8 * 1024 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_always_serves() {
        let mut b = TokenBucket::new(0, 0);
        assert!(b.is_unlimited());
        assert_eq!(b.available(1_000), u64::MAX);
        assert_eq!(b.consume(u64::MAX, 2_000), u64::MAX);
    }

    #[test]
    fn limited_consumes_and_refills() {
        let mut b = TokenBucket::new(1000, 0); // 1 KiB/s
        assert!(!b.is_unlimited());
        // full burst at creation
        let burst = b.available(0);
        assert!(burst >= 64 * 1024);
        // spend the whole burst
        let taken = b.consume(burst, 0);
        assert_eq!(taken, burst);
        assert_eq!(b.available(0), 0);
        // after 1 s we get 1 KiB back
        assert!(b.available(1000) >= 1000);
        let c = b.consume(100_000, 1000);
        assert_eq!(c, 1000);
        assert_eq!(b.available(1000), 0);
    }

    #[test]
    fn set_rate_rebounds_burst() {
        let mut b = TokenBucket::new(10 * 1024 * 1024, 0);
        let big = b.available(0);
        assert_eq!(big, 8 * 1024 * 1024); // clamped burst
        b.set_rate(0, 0);
        assert!(b.is_unlimited());
        assert_eq!(b.available(0), u64::MAX);
    }
}
