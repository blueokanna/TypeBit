//! SHA-1 (FIPS 180-1) — required by BitTorrent v1 piece hashing.
//!
//! Pure `no_std`, zero `unsafe`. Tested against the FIPS 180-1 vectors.

/// Incremental SHA-1 hasher.
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    len: u64,
    block: [u8; 64],
    n: usize,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// New hasher with the standard initial state.
    pub fn new() -> Self {
        Sha1 {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            len: 0,
            block: [0u8; 64],
            n: 0,
        }
    }

    /// Absorb `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        let mut off = 0usize;
        if self.n > 0 && self.n + data.len() >= 64 {
            let take = 64 - self.n;
            self.block[self.n..].copy_from_slice(&data[..take]);
            compress(&mut self.state, &self.block);
            self.n = 0;
            off = take;
        }
        while off + 64 <= data.len() {
            let mut b = [0u8; 64];
            b.copy_from_slice(&data[off..off + 64]);
            compress(&mut self.state, &b);
            off += 64;
        }
        let rem = data.len() - off;
        if rem > 0 {
            self.block[self.n..self.n + rem].copy_from_slice(&data[off..]);
            self.n += rem;
        }
    }

    /// Finalize, returning the 20-byte digest.
    pub fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.len.wrapping_mul(8);
        self.update(&[0x80]);
        while self.n != 56 {
            self.update(&[0]);
        }
        self.block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        compress(&mut self.state, &self.block);
        let mut out = [0u8; 20];
        for (i, s) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&s.to_be_bytes());
        }
        out
    }

    /// One-shot SHA-1.
    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut h = Sha1::new();
        h.update(data);
        h.finalize()
    }
}

#[allow(clippy::too_many_arguments)]
fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let (mut a, mut b, mut c, mut d, mut e) = (state[0], state[1], state[2], state[3], state[4]);
    for i in 0..80 {
        let (f, k) = match i / 20 {
            0 => ((b & c) | ((!b) & d), 0x5A827999u32),
            1 => (b ^ c ^ d, 0x6ED9EBA1),
            2 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
            _ => (b ^ c ^ d, 0xCA62C1D6),
        };
        let tmp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = tmp;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    fn hex(d: [u8; 20]) -> String {
        let mut s = String::new();
        for b in d {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    #[test]
    fn fips_vectors() {
        // FIPS 180-1 examples
        assert_eq!(
            hex(Sha1::digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(Sha1::digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            hex(Sha1::digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        // incremental == one-shot
        let mut h = Sha1::new();
        for chunk in b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".chunks(7) {
            h.update(chunk);
        }
        assert_eq!(
            hex(h.finalize()),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }
}
