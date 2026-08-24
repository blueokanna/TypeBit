//! Base32 codec (RFC 4648), `no_std` + alloc.
//!
//! IPFS CIDv1 uses lowercase base32 without padding (multibase prefix `b`).
//! This module implements decode + encode for the RFC 4648 alphabet
//! `abcdefghijklmnopqrstuvwxyz234567`.

use alloc::string::String;
use alloc::vec::Vec;

/// RFC 4648 base32 alphabet (lowercase).
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Decode base32 (padding optional; `=` tolerated at the end, case
/// insensitive per RFC 4648). Returns `None` on invalid characters.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let mut body = Vec::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b == b'=' {
            continue;
        }
        let v = match b {
            b'a'..=b'z' => b - b'a',
            b'A'..=b'Z' => b - b'A',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return None,
        };
        body.push(v);
    }
    if body.is_empty() {
        return Some(Vec::new());
    }
    // 8 input chars → 5 output bytes
    let mut out = Vec::with_capacity(body.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in &body {
        acc = (acc << 5) | c as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1u32 << bits).wrapping_sub(1);
        }
    }
    // leftover bits must be zero (canonical)
    if acc != 0 {
        return None;
    }
    Some(out)
}

/// Encode bytes into lowercase base32 without padding.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
        acc &= (1u32 << bits).wrapping_sub(1);
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn rfc4648_vectors() {
        // RFC 4648 §10 test vectors (lowercase, no padding).
        let cases: &[(&str, &str)] = &[
            ("", ""),
            ("f", "my"),
            ("fo", "mzxq"),
            ("foo", "mzxw6"),
            ("foob", "mzxw6yq"),
            ("fooba", "mzxw6ytb"),
            ("foobar", "mzxw6ytboi"),
        ];
        for (plain, enc) in cases {
            assert_eq!(encode(plain.as_bytes()), enc.to_string(), "enc {plain:?}");
            assert_eq!(decode(enc).unwrap(), plain.as_bytes(), "dec {enc:?}");
        }
    }

    #[test]
    fn roundtrip() {
        for len in 0..=64 {
            let data: Vec<u8> = (0..len).map(|i| (i * 29 + 3) as u8).collect();
            let enc = encode(&data);
            assert_eq!(decode(&enc).unwrap(), data, "len={len}");
            assert_eq!(
                decode(&enc.to_uppercase()).unwrap(),
                data,
                "upper len={len}"
            );
        }
    }

    #[test]
    fn rejects_invalid() {
        assert!(decode("mzxw6ytb1").is_none()); // digit 1 not in alphabet
        assert!(decode("!!!").is_none());
        assert!(decode("mzxw6ytb==").is_some());
    }
}
