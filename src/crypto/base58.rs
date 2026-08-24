//! Base58 (Bitcoin/IPFS alphabet) codec, `no_std` + alloc.
//!
//! Used to decode IPFS CIDv0 (`Qm…`) and eMule/Kad node identifiers.
//! The alphabet is the Bitcoin base58 alphabet:
//! `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`
//! (no `0`, `O`, `I`, `l`).

use alloc::string::String;
use alloc::vec::Vec;

/// Base58 alphabet (base58btc).
pub const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode a base58 string into bytes (big-endian, leading `1`s become
/// leading zero bytes). Returns `None` on invalid characters.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut zeros = 0usize;
    while zeros < bytes.len() && bytes[zeros] == b'1' {
        zeros += 1;
    }
    let body = &bytes[zeros..];
    if body.is_empty() {
        return Some(vec![0u8; zeros]);
    }
    // `num` is base-256 little-endian; fold each digit: num = num*58 + d.
    let mut num: Vec<u32> = vec![0];
    for &c in body {
        let val = ALPHABET.iter().position(|&a| a == c)? as u32;
        let mut carry = val;
        for b in num.iter_mut() {
            let cur = *b * 58 + carry;
            *b = cur & 0xff;
            carry = cur >> 8;
        }
        while carry > 0 {
            num.push(carry & 0xff);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(num.iter().rev().map(|&x| x as u8));
    Some(out)
}

/// Encode bytes into base58 (big-endian; leading zero bytes become `1`s).
pub fn encode(data: &[u8]) -> String {
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    // big-endian base-256 operand, leading zeros already trimmed
    let mut num = Vec::from(&data[zeros..]);
    if num.is_empty() {
        return "1".repeat(zeros);
    }
    // divide by 58 repeatedly; remainders are base58 digits (little-endian)
    let mut digits: Vec<char> = Vec::with_capacity(num.len() * 2);
    while !num.is_empty() {
        let mut rem: u32 = 0;
        for b in num.iter_mut() {
            let cur = (rem << 8) | *b as u32;
            *b = (cur / 58) as u8;
            rem = cur % 58;
        }
        digits.push(ALPHABET[rem as usize] as char);
        // drop leading zeros (the operand shrank)
        let first = num.iter().position(|&b| b != 0).unwrap_or(num.len());
        num.drain(..first);
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &c in digits.iter().rev() {
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidv0_prefix() {
        let mut mh = vec![0x12u8, 0x20];
        mh.extend_from_slice(&[7u8; 32]);
        let cid = encode(&mh);
        // Python authority: QmNp5n7FFav5ZDaHAj6HzuhJ8LDbL1N6NRzAgT6piWS2Kx
        assert_eq!(cid, "QmNp5n7FFav5ZDaHAj6HzuhJ8LDbL1N6NRzAgT6piWS2Kx");
        assert_eq!(decode(&cid).unwrap(), mh);
    }

    #[test]
    fn empty() {
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(encode(b""), "");
        assert_eq!(decode("1").unwrap(), vec![0u8]);
        assert_eq!(encode(&[0u8]), "1");
        // base58(5) = '6' (alphabet index 5); two leading zero bytes → "11".
        assert_eq!(encode(&[0u8, 0, 5]), "116");
    }

    #[test]
    fn roundtrip() {
        for len in [0usize, 1, 2, 7, 19, 20, 32, 34, 45] {
            let data: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            let enc = encode(&data);
            assert_eq!(decode(&enc).unwrap(), data, "len={len}");
        }
    }

    #[test]
    fn known_vector() {
        // base58("hello") from public references.
        let enc = encode(b"hello");
        assert_eq!(enc, "Cn8eVZg");
        assert_eq!(decode("Cn8eVZg").unwrap(), b"hello");
    }

    #[test]
    fn rejects_invalid() {
        assert!(decode("0OIl").is_none());
        assert!(decode("abc!").is_none());
    }
}
