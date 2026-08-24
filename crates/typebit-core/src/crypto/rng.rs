//! ChaCha20-based deterministic CSPRNG.
//!
//! Seeds come from the platform host (`Host::fill_random`); once seeded, the
//! generator is pure `no_std`. Used for peer ids, DHT node ids and nonces.

use super::chacha20::ChaCha20;

/// A small CSPRNG. Cloneable (each clone continues its own stream).
#[derive(Clone)]
pub struct Rng {
    inner: ChaCha20,
}

impl Rng {
    /// Seed from 32 bytes.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let nonce = [0u8; 12];
        Rng {
            inner: ChaCha20::new(seed, nonce),
        }
    }

    /// Fill `out` with random bytes.
    pub fn fill(&mut self, out: &mut [u8]) {
        self.inner.keystream(out);
    }

    /// A random u64.
    pub fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        u64::from_le_bytes(b)
    }

    /// A random u32.
    pub fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        u32::from_le_bytes(b)
    }

    /// Random in `0..n` (uniform, no modulo bias).
    pub fn next_below(&mut self, n: u64) -> u64 {
        debug_assert!(n > 0);
        let limit = u64::MAX - (u64::MAX % n);
        loop {
            let v = self.next_u64();
            if v < limit {
                return v % n;
            }
        }
    }

    /// Random bool.
    pub fn next_bool(&mut self) -> bool {
        self.next_u32() & 1 == 1
    }

    /// 20-byte peer id / node id (DHT uses 20-byte node ids).
    pub fn bytes20(&mut self) -> [u8; 20] {
        let mut b = [0u8; 20];
        self.fill(&mut b);
        b
    }

    /// Random 4-byte transaction id for KRPC.
    pub fn tid(&mut self) -> [u8; 4] {
        self.next_u32().to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_from_seed() {
        let a = Rng::from_seed([7u8; 32]);
        let mut b = a.clone();
        let mut x = [0u8; 32];
        b.fill(&mut x);
        let mut c = a.clone();
        let mut y = [0u8; 32];
        c.fill(&mut y);
        assert_eq!(x, y);
        assert_ne!(&x[..4], &[0u8; 4]);
    }

    #[test]
    fn no_modulo_bias_range() {
        let mut r = Rng::from_seed([1u8; 32]);
        for _ in 0..1000 {
            let v = r.next_below(7);
            assert!(v < 7);
        }
    }
}
