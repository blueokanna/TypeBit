//! ChaCha20 stream cipher (RFC 8439, IETF 12-byte nonce variant).
//!
//! Used as the deterministic PRNG core for peer ids, DHT node ids, tokens,
//! and transaction ids. Pure `no_std`, zero `unsafe`, constant-time-free
//! (not used for secrets).

const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8; 64]) {
    let mut s = [0u32; 16];
    s[..4].copy_from_slice(&CONSTANTS);
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    s[12] = counter;
    for i in 0..3 {
        s[13 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }
    let mut x = s;
    for _ in 0..10 {
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);
        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7, 8, 13);
        quarter_round(&mut x, 3, 4, 9, 14);
    }
    for i in 0..16 {
        x[i] = x[i].wrapping_add(s[i]);
    }
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&x[i].to_le_bytes());
    }
}

/// A ChaCha20 keystream generator (encrypt = XOR with keystream).
#[derive(Clone)]
pub struct ChaCha20 {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
    block: [u8; 64],
    pos: usize,
}

impl ChaCha20 {
    /// Create with a 32-byte key and 12-byte nonce.
    pub fn new(key: [u8; 32], nonce: [u8; 12]) -> Self {
        ChaCha20::with_counter(key, nonce, 0)
    }

    /// Create with an explicit initial block counter (RFC 8439 uses 1).
    pub fn with_counter(key: [u8; 32], nonce: [u8; 12], counter: u32) -> Self {
        let mut c = ChaCha20 {
            key,
            nonce,
            counter,
            block: [0u8; 64],
            pos: 64,
        };
        c.refill();
        c
    }

    fn refill(&mut self) {
        block(&self.key, self.counter, &self.nonce, &mut self.block);
        self.counter = self.counter.wrapping_add(1);
        self.pos = 0;
    }

    /// XOR `data` with the keystream in place (encrypt/decrypt).
    pub fn apply(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            if self.pos == 64 {
                self.refill();
            }
            *b ^= self.block[self.pos];
            self.pos += 1;
        }
    }

    /// Generate `n` keystream bytes (no input).
    pub fn keystream(&mut self, out: &mut [u8]) {
        let mut zeros = [0u8; 128];
        let mut off = 0usize;
        while off < out.len() {
            let take = core::cmp::min(zeros.len(), out.len() - off);
            zeros[..take].fill(0);
            self.apply(&mut zeros[..take]);
            out[off..off + take].copy_from_slice(&zeros[..take]);
            off += take;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8439_block_function() {
        // RFC 8439 §2.3.2: key 00..1f, nonce (00:00:00:09:00:00:00:4a:00:00:00:00),
        // block counter 1 → the serialized block.
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut out = [0u8; 64];
        block(&key, 1, &nonce, &mut out);
        let expected = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn rfc8439_poly1305_keygen() {
        // RFC 8439 §2.6.2 (A.4): key 80..9f, nonce (00:00:00:00:00:01:02:03:04:05:06:07),
        // block counter 0 → the 32-byte one-time Poly1305 key (authoritative prefix).
        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let mut c = ChaCha20::with_counter(key, nonce, 0);
        let mut out = [0u8; 32];
        c.keystream(&mut out);
        let expected = [
            0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc, 0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2,
            0x94, 0x71, 0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5, 0x08, 0xdb, 0xb8, 0xe2,
            0xfd, 0xd1, 0xa6, 0x46,
        ];
        assert_eq!(&out[..], &expected[..]);
        // and roundtrip through apply()
        let mut c2 = ChaCha20::with_counter(key, nonce, 0);
        let mut buf = vec![0u8; 32];
        c2.apply(&mut buf);
        assert_eq!(buf[..], expected[..]);
    }
}
