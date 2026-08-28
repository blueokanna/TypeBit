//! Token-bucket byte rate limiting. One bucket per throttle point: the
//! engine keeps global upload/download buckets, each
//! [`TorrentSession`](crate::session::TorrentSession) keeps per-task
//! buckets. `0` = unlimited. Refill from wall time (`now_ms`) so buckets
//! stay correct at any tick cadence.
//!
//! Enforced at the two choke points: upload drains peer buffers through
//! the buckets ([`Engine::pump_connection`](crate::engine::Engine));
//! download caps requests per tick (`fill_pipeline`).
//!
//! ## Upload pacing (tolerance-tight bursts)
//!
//! A plain "one second of traffic" burst lets a fresh bucket dump the whole
//! allowance in the first tick — the classic burst-then-stall that makes a
//! 100 KiB/s limit *look* like a 1 MiB/s spike followed by silence. Upload
//! buckets therefore use the **hard ceiling spec**: the burst capacity is
//! derived from the allowed overshoot tolerance, so **any one-second
//! measurement window stays within `limit × (1 + tol)`**.
//!
//! Tolerance (half-percent units, floored at 1%):
//!
//! | limit | tolerance |
//! |-------|-----------|
//! | 100 KiB/s | 10% |
//! | 200 KiB/s | 9%  (each +50 KiB −0.5%) |
//! | 1 MiB/s   | 1%  (floor) |
//!
//! `burst = rate × tol / 200` bytes (clamped to [4 KiB, 1 MiB]) guarantees
//! the ceiling: over any 1 s window the bucket can hand out at most
//! `rate` (refill) + `burst` (residual) bytes.

use core::cmp;

/// Burst sizing policy for a bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BurstPolicy {
    /// Classic burst: one second of traffic clamped to [64 KiB, 8 MiB].
    /// Used for downloads, where short bursts legitimately fill the pipe.
    Standard,
    /// Tolerance-tight burst (upload): see the module docs.
    UploadTight,
}

/// Byte-rate token bucket.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Burst capacity in bytes.
    capacity: u64,
    /// Currently available tokens (bytes).
    tokens: u64,
    /// Refill rate in bytes/second (0 = unlimited).
    rate_bps: u64,
    /// Burst sizing policy (fixed at construction).
    policy: BurstPolicy,
    /// Last refill timestamp (ms).
    last: u64,
}

impl TokenBucket {
    /// Create a bucket with the standard burst. `rate_bps == 0` is unlimited.
    pub fn new(rate_bps: u64, now: u64) -> Self {
        Self::with_policy(rate_bps, BurstPolicy::Standard, now)
    }

    /// Create an upload bucket with the tolerance-tight burst (see module
    /// docs). `rate_bps == 0` is unlimited.
    pub fn new_upload(rate_bps: u64, now: u64) -> Self {
        Self::with_policy(rate_bps, BurstPolicy::UploadTight, now)
    }

    fn with_policy(rate_bps: u64, policy: BurstPolicy, now: u64) -> Self {
        let capacity = burst_capacity(rate_bps, policy);
        TokenBucket {
            capacity,
            tokens: capacity,
            rate_bps,
            policy,
            last: now,
        }
    }

    /// Change the rate (0 = unlimited), preserving the current burst state
    /// and the bucket's sizing policy.
    pub fn set_rate(&mut self, rate_bps: u64, now: u64) {
        self.refill(now);
        self.capacity = burst_capacity(rate_bps, self.policy);
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

    /// Burst capacity in bytes (`u64::MAX` when unlimited).
    pub fn capacity(&self) -> u64 {
        self.capacity
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

/// Upload tolerance in **half-percent units** for a given rate.
///
/// 100 KiB/s → 20 (10%), each additional 50 KiB/s lowers it by 1 (0.5%),
/// floored at 2 (1%) — the hard ceiling spec. Below 100 KiB/s the 10%
/// ceiling is kept (a sub-10 KiB/s burst floor would stall tiny limits).
pub fn upload_tolerance_half_pct(rate_bps: u64) -> u64 {
    let kb = rate_bps / 1024;
    const BASE: u64 = 20; // 10%
    const FLOOR: u64 = 2; // 1%
    if kb < 100 {
        return BASE;
    }
    BASE.saturating_sub((kb - 100) / 50).max(FLOOR)
}

/// Burst capacity for a rate + policy. Unlimited buckets report `u64::MAX`
/// so every call is a no-op.
fn burst_capacity(rate_bps: u64, policy: BurstPolicy) -> u64 {
    if rate_bps == 0 {
        return u64::MAX;
    }
    match policy {
        BurstPolicy::Standard => rate_bps.clamp(64 * 1024, 8 * 1024 * 1024),
        BurstPolicy::UploadTight => {
            let tol = upload_tolerance_half_pct(rate_bps);
            // burst = rate × tol/200 → any 1 s window ≤ rate×(1+tol/200).
            let burst = rate_bps.saturating_mul(tol) / 200;
            burst.clamp(4 * 1024, 1024 * 1024)
        }
    }
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

    #[test]
    fn upload_tolerance_matches_the_spec() {
        // 100 KiB/s → 10%, 200 KiB/s → 9%, 1 MiB/s → 1% (the spec table).
        assert_eq!(upload_tolerance_half_pct(100 * 1024), 20); // 10%
        assert_eq!(upload_tolerance_half_pct(200 * 1024), 18); // 9%
        assert_eq!(upload_tolerance_half_pct(300 * 1024), 16); // 8%
        assert_eq!(upload_tolerance_half_pct(1024 * 1024), 2); // 1% floor
        assert_eq!(upload_tolerance_half_pct(4096 * 1024), 2); // still 1%
    }

    #[test]
    fn upload_burst_keeps_any_one_second_window_within_tolerance() {
        for (rate, tol) in [
            (100 * 1024, 20u64), // 100 KiB/s, 10%
            (200 * 1024, 18),    // 200 KiB/s, 9%
            (1024 * 1024, 2),    // 1 MiB/s, 1%
            (50 * 1024, 20),     // below 100 → 10%
        ] {
            let b = TokenBucket::new_upload(rate, 0);
            let cap = b.capacity();
            // Worst 1 s window: refill (rate) + residual burst (cap).
            let max_window = rate.saturating_add(cap);
            let ceiling = rate.saturating_add(rate.saturating_mul(tol) / 200);
            assert!(
                max_window <= ceiling,
                "rate {rate} tol {tol}: max window {max_window} exceeds ceiling {ceiling}"
            );
        }
    }

    #[test]
    fn upload_bucket_is_tighter_than_standard() {
        // A 100 KiB/s upload bucket must NOT hold a full second of traffic.
        let u = TokenBucket::new_upload(100 * 1024, 0);
        let s = TokenBucket::new(100 * 1024, 0);
        assert!(u.capacity() < s.capacity());
        assert!(u.capacity() <= 10 * 1024); // ≈ tolerance burst
    }

    #[test]
    fn set_rate_preserves_upload_policy() {
        let mut b = TokenBucket::new_upload(100 * 1024, 0);
        b.set_rate(200 * 1024, 0);
        // 200 KiB/s → 9% → burst = 200*1024*18/200 = 18432.
        assert_eq!(b.capacity(), 18_432);
        // Growing to 1 MiB/s shrinks the relative burst (1% floor).
        b.set_rate(1024 * 1024, 0);
        assert_eq!(b.capacity(), 1024 * 1024 * 2 / 200);
    }

    #[test]
    fn draining_the_bucket_makes_refill_the_rate_authority() {
        // The engine drains the global download bucket into a shared
        // per-tick budget (`consume(u64::MAX)`). The bucket must then refill
        // at exactly `rate × dt` instead of silently regenerating to full
        // capacity — otherwise the "limit" is a no-op.
        let mut b = TokenBucket::new(100 * 1024, 0);
        let budget = b.consume(u64::MAX, 0);
        assert_eq!(budget, 100 * 1024);
        assert_eq!(b.available(0), 0, "bucket drained to zero");
        // After 100 ms exactly 10 KiB are back (rate × dt).
        let refilled = b.available(100);
        assert!(
            (10_000..=10_300).contains(&refilled),
            "refill after 100 ms must be ≈ rate×0.1, got {refilled}"
        );
        // A second drain hands out only what actually refilled — a limit of
        // 100 KiB/s therefore allows ~100 KiB/s, not 1 MiB/s per tick.
        assert_eq!(b.consume(u64::MAX, 100), refilled);
    }
}
