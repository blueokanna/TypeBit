//! In-tree cryptography (the engine may only link the four ecosystem
//! crates). Implemented from scratch, `no_std`, `unsafe`-free, pinned
//! against standard test vectors:
//!
//! - [`sha1`] — FIPS 180-1 (BitTorrent v1)
//! - [`sha256`] — FIPS 180-4 (BitTorrent v2 / BEP-52, receipts)
//! - [`sha512`] — FIPS 180-4 (Ed25519)
//! - [`ed25519`] — RFC 8032 signatures (provable receipts)
//! - [`chacha20`] / [`rng`] — ChaCha20 CSPRNG (peer ids, DHT ids, nonces)
//! - [`hmac_sha256`] — HMAC-SHA256 (DHT announce tokens, keyed receipts)

pub mod base32;
pub mod base58;
pub mod base64;
pub mod chacha20;
pub mod ed25519;
pub mod md4;
pub mod rng;
pub mod sha1;
pub mod sha256;
pub mod sha512;

pub use base32::{decode as base32_decode, encode as base32_encode};
pub use base58::{decode as base58_decode, encode as base58_encode};
pub use base64::{decode as base64_decode, encode as base64_encode, Variant};
pub use md4::Md4;
pub use rng::Rng;
pub use sha1::Sha1;
pub use sha256::Sha256;
pub use sha512::Sha512;

/// HMAC-SHA256 (RFC 2104). Used for DHT announce tokens and keyed
/// receipt commitments.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let d = Sha256::digest(key);
        k[..32].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::digest2(&ipad, data);
    Sha256::digest2(&opad, &inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn rfc4231_hmac_case1() {
        // RFC 4231 Test Case 1
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let out = hmac_sha256(&key, data);
        let expect = unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(&out[..], &expect[..]);
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
