//! Compact bitset for piece availability and block accounting.
//!
//! Backed by `u64` words; `to_bytes`/`from_bytes` use the network bitfield
//! order (most-significant bit first) required by the peer wire protocol.

use crate::error::{Error, Result};
use alloc::vec::Vec;

/// A growable bitset with an O(1) population count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bitfield {
    words: Vec<u64>,
    len: u32,
    count: u32,
}

impl Bitfield {
    /// New zeroed bitset with `len` bits.
    pub fn new(len: u32) -> Self {
        let words = vec![0u64; (len as usize).div_ceil(64)];
        Bitfield {
            words,
            len,
            count: 0,
        }
    }

    /// Number of bits.
    pub fn len(&self) -> u32 {
        self.len
    }

    /// True if there are no bits.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Number of set bits.
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Test bit `i`.
    pub fn get(&self, i: u32) -> bool {
        if i >= self.len {
            return false;
        }
        let (w, b) = (i as usize / 64, i % 64);
        self.words[w] & (1u64 << b) != 0
    }

    /// Set bit `i`.
    pub fn set(&mut self, i: u32) {
        if i >= self.len {
            return;
        }
        let (w, b) = (i as usize / 64, i % 64);
        let mask = 1u64 << b;
        if self.words[w] & mask == 0 {
            self.words[w] |= mask;
            self.count += 1;
        }
    }

    /// Clear bit `i`.
    pub fn clear(&mut self, i: u32) {
        if i >= self.len {
            return;
        }
        let (w, b) = (i as usize / 64, i % 64);
        let mask = 1u64 << b;
        if self.words[w] & mask != 0 {
            self.words[w] &= !mask;
            self.count -= 1;
        }
    }

    /// Set all bits.
    pub fn set_all(&mut self) {
        self.words.iter_mut().for_each(|w| *w = u64::MAX);
        // mask trailing bits beyond len
        if !self.len.is_multiple_of(64) {
            let last = self.words.len() - 1;
            self.words[last] &= (1u64 << (self.len % 64)) - 1;
        }
        self.count = self.len;
    }

    /// Clear all bits.
    pub fn clear_all(&mut self) {
        self.words.iter_mut().for_each(|w| *w = 0);
        self.count = 0;
    }

    /// Any bit set?
    pub fn any(&self) -> bool {
        self.count > 0
    }

    /// All bits set?
    pub fn all_set(&self) -> bool {
        self.count == self.len
    }

    /// First set bit.
    pub fn first_set(&self) -> Option<u32> {
        self.next_set_from(0)
    }

    /// Last set bit.
    pub fn last_set(&self) -> Option<u32> {
        for i in (0..self.words.len()).rev() {
            if self.words[i] != 0 {
                let bit = 63 - self.words[i].leading_zeros();
                return Some((i * 64 + bit as usize) as u32);
            }
        }
        None
    }

    /// Next set bit at or after `from`.
    pub fn next_set_from(&self, from: u32) -> Option<u32> {
        if from >= self.len {
            return None;
        }
        let mut w = from as usize / 64;
        let b = from % 64;
        if self.words[w] >> b != 0 {
            let tz = (self.words[w] >> b).trailing_zeros();
            return Some(from + tz);
        }
        w += 1;
        while w < self.words.len() {
            if self.words[w] != 0 {
                return Some((w * 64 + self.words[w].trailing_zeros() as usize) as u32);
            }
            w += 1;
        }
        None
    }

    /// Next clear bit at or after `from`.
    ///
    /// Word-level: a clear bit is found by inverting the word and taking
    /// `trailing_zeros` (a constant-time bit-scan) instead of a per-bit
    /// loop.
    pub fn next_clear_from(&self, from: u32) -> Option<u32> {
        if from >= self.len {
            return None;
        }
        let mut w = from as usize / 64;
        let b = from % 64;
        // ignore bits below `b` in the first word: invert, THEN mask the
        // low bits out (clear bits = `!word & mask`; `!(word & mask)`
        // would resurrect the masked-off low bits via De Morgan).
        let inv = !self.words[w] & !((1u64 << b) - 1);
        if inv != 0 {
            let tz = inv.trailing_zeros();
            let idx = (w * 64 + tz as usize) as u32;
            return if idx < self.len { Some(idx) } else { None };
        }
        w += 1;
        while w < self.words.len() {
            let inv = !self.words[w];
            if inv != 0 {
                let tz = inv.trailing_zeros();
                let idx = (w * 64 + tz as usize) as u32;
                return if idx < self.len { Some(idx) } else { None };
            }
            w += 1;
        }
        None
    }

    /// Network-format bitfield bytes (MSB first, padded with zeros).
    ///
    /// Word-level: the peer-wire order is MSB-first *within each byte*, and
    /// piece `p` lives at word bit `p % 64`. A network byte is therefore
    /// the bit-reverse of the little-endian-positioned byte of the word;
    /// bytes straddling a word boundary pull the low bits of the next word.
    /// O(bytes) with shift+bit-reverse, no per-bit div/mod.
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = (self.len as usize).div_ceil(8);
        let mut out = vec![0u8; n];
        for i in 0..n {
            let bit = i * 8;
            let w = bit / 64;
            let s = bit % 64;
            let mut byte = (self.words[w] >> s) as u8;
            if s > 56 && w + 1 < self.words.len() {
                byte |= (self.words[w + 1] << (64 - s)) as u8;
            }
            out[i] = byte.reverse_bits();
        }
        out
    }

    /// Load from network-format bytes (MSB first). Bits beyond `count` in the
    /// final byte must be zero (rejected otherwise).
    pub fn from_bytes(&mut self, bytes: &[u8], count: u32) -> Result<()> {
        let expected = (count as usize).div_ceil(8);
        if bytes.len() != expected {
            return Err(Error::Protocol);
        }
        // validate padding bits
        if !count.is_multiple_of(8) {
            let pad = 8 - (count % 8);
            let last = bytes[bytes.len() - 1];
            if last & ((1u8 << pad) - 1) != 0 {
                return Err(Error::Protocol);
            }
        }
        self.len = count;
        self.words = vec![0u64; (count as usize).div_ceil(64)];
        // Word-level load: reverse each network byte's bits, then place it
        // at word bit offset `s`, with the high bits straddling into the
        // next word when the byte crosses a word boundary.
        for (i, &byte) in bytes.iter().enumerate() {
            let bit = i * 8;
            let w = bit / 64;
            let s = bit % 64;
            let rb = byte.reverse_bits();
            self.words[w] |= (rb as u64) << s;
            if s > 56 && w + 1 < self.words.len() {
                self.words[w + 1] |= (rb as u64) >> (64 - s);
            }
        }
        // Mask any bits beyond `count` in the last word (defensive; padding
        // bytes were validated above).
        if !count.is_multiple_of(64) {
            let last = self.words.len() - 1;
            let bits = count % 64;
            let mask = if bits == 0 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            };
            self.words[last] &= mask;
        }
        self.count = self.words.iter().map(|w| w.count_ones()).sum();
        Ok(())
    }

    /// `self |= other` (both must have the same length).
    pub fn or_into(&mut self, other: &Bitfield) {
        debug_assert_eq!(self.len, other.len);
        let old = self.count;
        for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
            *a |= *b;
        }
        self.recount();
        let _ = old;
    }

    /// `self &= !other` (clear bits that are set in `other`).
    pub fn and_not(&mut self, other: &Bitfield) {
        debug_assert_eq!(self.len, other.len);
        for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
            *a &= !*b;
        }
        self.recount();
    }

    /// Number of set bits within `[from, to)`.
    ///
    /// Word-level: mask the boundary words and sum `count_ones` over the
    /// range — O(range/64) instead of O(range).
    pub fn count_range(&self, from: u32, to: u32) -> u32 {
        if from >= to || from >= self.len {
            return 0;
        }
        let to = to.min(self.len);
        let w0 = from as usize / 64;
        let w1 = (to - 1) as usize / 64;
        if w0 == w1 {
            let nbits = to - from;
            let base = if nbits == 64 {
                u64::MAX
            } else {
                (1u64 << nbits) - 1
            };
            return (self.words[w0] & (base << (from % 64))).count_ones();
        }
        let mut n = 0u32;
        // first word: bits `from % 64 .. 64`
        let first_mask = !((1u64 << (from % 64)) - 1);
        n += (self.words[w0] & first_mask).count_ones();
        // middle words are fully in range
        for w in (w0 + 1)..w1 {
            n += self.words[w].count_ones();
        }
        // last word: bits `0 .. (to-1) % 64 + 1`
        let last_bits = (to - 1) % 64 + 1;
        let last_mask = if last_bits == 64 {
            u64::MAX
        } else {
            (1u64 << last_bits) - 1
        };
        n += (self.words[w1] & last_mask).count_ones();
        n
    }

    fn recount(&mut self) {
        self.count = self.words.iter().map(|w| w.count_ones()).sum();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let mut b = Bitfield::new(100);
        assert_eq!(b.count(), 0);
        b.set(3);
        b.set(99);
        b.set(3);
        assert_eq!(b.count(), 2);
        assert!(b.get(3));
        assert!(b.get(99));
        assert!(!b.get(4));
        assert_eq!(b.first_set(), Some(3));
        assert_eq!(b.last_set(), Some(99));
        b.clear(3);
        assert_eq!(b.count(), 1);
        assert_eq!(b.first_set(), Some(99));
    }

    #[test]
    fn next_set() {
        let mut b = Bitfield::new(200);
        b.set(0);
        b.set(70);
        b.set(128);
        assert_eq!(b.next_set_from(0), Some(0));
        assert_eq!(b.next_set_from(1), Some(70));
        assert_eq!(b.next_set_from(71), Some(128));
        assert_eq!(b.next_set_from(129), None);
        assert_eq!(b.next_clear_from(0), Some(1));
        b.set_all();
        assert_eq!(b.count(), 200);
        assert_eq!(b.next_clear_from(0), None);
    }

    #[test]
    fn network_bytes() {
        let mut b = Bitfield::new(10);
        b.set(0);
        b.set(7);
        b.set(8);
        let bytes = b.to_bytes();
        // bits 0,7,8 → MSB first: byte0 = 0b10000001, byte1 = 0b10000000
        assert_eq!(bytes, vec![0b1000_0001, 0b1000_0000]);
        let mut c = Bitfield::new(0);
        c.from_bytes(&bytes, 10).unwrap();
        assert_eq!(c, b);
        // padding violation: last byte with a low bit set
        let bad = vec![0b1000_0001, 0b1000_0001];
        assert!(Bitfield::new(0).from_bytes(&bad, 10).is_err());
    }

    #[test]
    fn byte_roundtrip_across_word_boundaries() {
        // lengths that are not multiples of 8/64 exercise the partial-word
        // and partial-byte paths of the word-level codec.
        for len in [1u32, 7, 8, 9, 63, 64, 65, 127, 128, 129, 200, 1000] {
            for step in 0..len {
                let mut b = Bitfield::new(len);
                b.set(step);
                let bytes = b.to_bytes();
                assert_eq!(bytes.len(), (len as usize).div_ceil(8));
                let mut c = Bitfield::new(0);
                c.from_bytes(&bytes, len).unwrap();
                assert_eq!(c, b, "roundtrip failed for len={len}");
            }
        }
    }

    #[test]
    fn count_range_matches_bruteforce() {
        let mut b = Bitfield::new(150);
        for i in (0..150).step_by(3) {
            b.set(i);
        }
        for from in [0u32, 1, 63, 64, 65, 100] {
            for to in [from, 63, 64, 65, 100, 128, 150] {
                if to < from {
                    continue;
                }
                let fast = b.count_range(from, to);
                let mut slow = 0u32;
                for i in from..to.min(150) {
                    if b.get(i) {
                        slow += 1;
                    }
                }
                assert_eq!(fast, slow, "count_range [{from},{to})");
            }
        }
    }

    #[test]
    fn or_and_not() {
        let mut a = Bitfield::new(64);
        a.set(0);
        a.set(1);
        let mut b = Bitfield::new(64);
        b.set(1);
        b.set(2);
        a.or_into(&b);
        assert_eq!(a.count(), 3);
        a.and_not(&b);
        assert_eq!(a.count(), 1);
        assert!(a.get(0));
    }
}
