//! MD4 message digest (RFC 1320), `no_std` + alloc.
//!
//! Implemented because the eD2k/eMule network identifies files by the MD4
//! of their content (`ed2k://|file|<name>|<size>|<md4>|/`). MD4 is broken
//! for collision resistance; it is used here purely for eMule-link
//! compatibility and **never** for integrity-critical receipts (those use
//! Ed25519/SHA-256). Streams larger than 2^61 bytes are not supported
//! (the length field is 64-bit, consistent with the RFC).

use alloc::vec::Vec;

/// The MD4 context.
#[derive(Clone)]
pub struct Md4 {
    state: [u32; 4],
    buf: [u8; 64],
    buf_len: usize,
    total: u64,
}

const INIT: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

// Per-round shifts (RFC 1320 §3.4).
const R1: [u32; 4] = [3, 7, 11, 19];
const R2: [u32; 4] = [3, 5, 9, 13];
const R3: [u32; 4] = [3, 9, 11, 15];

// Message-word order per round (RFC 1320 §3.4).
const K1: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const K2: [usize; 16] = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
const K3: [usize; 16] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];

impl Default for Md4 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md4 {
    /// New context.
    pub fn new() -> Self {
        Md4 {
            state: INIT,
            buf: [0u8; 64],
            buf_len: 0,
            total: 0,
        }
    }

    /// Feed bytes.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = core::cmp::min(64 - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Finalize, returning the 16-byte digest.
    pub fn finalize(mut self) -> [u8; 16] {
        let bit_len = self.total.wrapping_mul(8);
        let mut tail = Vec::with_capacity(128);
        tail.extend_from_slice(&self.buf[..self.buf_len]);
        tail.push(0x80);
        while tail.len() % 64 != 56 {
            tail.push(0);
        }
        tail.extend_from_slice(&bit_len.to_le_bytes());
        for chunk in tail.chunks_exact(64) {
            let mut block = [0u8; 64];
            block.copy_from_slice(chunk);
            self.compress(&block);
        }
        let mut out = [0u8; 16];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// One-shot digest.
    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut m = Md4::new();
        m.update(data);
        m.finalize()
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        let [mut a, mut b, mut c, mut d] = self.state;

        for i in 0..16 {
            let s = R1[i % 4];
            let xk = x[K1[i]];
            match i % 4 {
                0 => {
                    let f = (b & c) | (!b & d);
                    a = a.wrapping_add(f).wrapping_add(xk).rotate_left(s);
                }
                1 => {
                    let f = (a & b) | (!a & c);
                    d = d.wrapping_add(f).wrapping_add(xk).rotate_left(s);
                }
                2 => {
                    let f = (d & a) | (!d & b);
                    c = c.wrapping_add(f).wrapping_add(xk).rotate_left(s);
                }
                _ => {
                    let f = (c & d) | (!c & a);
                    b = b.wrapping_add(f).wrapping_add(xk).rotate_left(s);
                }
            }
        }

        for i in 0..16 {
            let s = R2[i % 4];
            let xk = x[K2[i]].wrapping_add(0x5a82_7999);
            match i % 4 {
                0 => {
                    let g = (b & c) | (b & d) | (c & d);
                    a = a.wrapping_add(g).wrapping_add(xk).rotate_left(s);
                }
                1 => {
                    let g = (a & b) | (a & c) | (b & c);
                    d = d.wrapping_add(g).wrapping_add(xk).rotate_left(s);
                }
                2 => {
                    let g = (d & a) | (d & b) | (a & b);
                    c = c.wrapping_add(g).wrapping_add(xk).rotate_left(s);
                }
                _ => {
                    let g = (c & d) | (c & a) | (d & a);
                    b = b.wrapping_add(g).wrapping_add(xk).rotate_left(s);
                }
            }
        }
        for i in 0..16 {
            let s = R3[i % 4];
            let xk = x[K3[i]].wrapping_add(0x6ed9_eba1);
            match i % 4 {
                0 => {
                    let h = b ^ c ^ d;
                    a = a.wrapping_add(h).wrapping_add(xk).rotate_left(s);
                }
                1 => {
                    let h = a ^ b ^ c;
                    d = d.wrapping_add(h).wrapping_add(xk).rotate_left(s);
                }
                2 => {
                    let h = d ^ a ^ b;
                    c = c.wrapping_add(h).wrapping_add(xk).rotate_left(s);
                }
                _ => {
                    let h = c ^ d ^ a;
                    b = b.wrapping_add(h).wrapping_add(xk).rotate_left(s);
                }
            }
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: [u8; 16]) -> alloc::string::String {
        let mut s = alloc::string::String::with_capacity(32);
        for b in d {
            s.push_str(&alloc::format!("{:02x}", b));
        }
        s
    }

    #[test]
    fn rfc1320_vectors() {
        // RFC 1320 §5 test suite.
        let cases: &[(&str, &str)] = &[
            ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
            ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
            ("message digest", "d9130a8164549fe818874806e1c7014b"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "d79e1c308aa5bbcdeea8ed63df412da9",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "043f8582f241db351ce627e153e7f0e4",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536",
            ),
        ];
        for (msg, expect) in cases {
            assert_eq!(hex(Md4::digest(msg.as_bytes())), *expect, "msg={msg:?}");
        }
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let whole = Md4::digest(&data);
        let mut m = Md4::new();
        for chunk in data.chunks(7) {
            m.update(chunk);
        }
        assert_eq!(m.finalize(), whole);
    }
}
