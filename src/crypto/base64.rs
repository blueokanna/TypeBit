//! RFC 4648 Base64 codec (`no_std`, alloc-only).
//!
//! Standard alphabet with `=` padding, plus a URL-safe variant that swaps
//! `+`/`/` for `-`/`_`. Used by the unified download-link layer to unwrap
//! Thunder (`thunder://`), QQ-Xuanfeng (`qqdl://`) and FlashGet
//! (`flashget://`) URLs, which are all Base64-wrapped.

use alloc::string::String;
use alloc::vec::Vec;

/// Standard RFC 4648 alphabet.
const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// URL-safe alphabet (RFC 4648 §5).
const URLSAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Which alphabet to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// Standard `+/` alphabet.
    Standard,
    /// URL-safe `-_` alphabet.
    UrlSafe,
}

/// Encode `data` into Base64 (with padding).
pub fn encode(data: &[u8], v: Variant) -> String {
    let alpha = match v {
        Variant::Standard => STD,
        Variant::UrlSafe => URLSAFE,
    };
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0usize;
    while i + 3 <= data.len() {
        let b = [data[i], data[i + 1], data[i + 2]];
        out.push(alpha[(b[0] >> 2) as usize] as char);
        out.push(alpha[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
        out.push(alpha[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize] as char);
        out.push(alpha[(b[2] & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let b = data[i];
        out.push(alpha[(b >> 2) as usize] as char);
        out.push(alpha[((b & 0x03) << 4) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let b = [data[i], data[i + 1]];
        out.push(alpha[(b[0] >> 2) as usize] as char);
        out.push(alpha[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
        out.push(alpha[((b[1] & 0x0f) << 2) as usize] as char);
        out.push('=');
    }
    out
}

/// Decode Base64 (padding optional, `=` tolerated mid-string).
/// Returns `None` on invalid characters or length.
pub fn decode(s: &str, v: Variant) -> Option<Vec<u8>> {
    let (alpha, inv) = match v {
        Variant::Standard => (STD, inv_std()),
        Variant::UrlSafe => (URLSAFE, inv_urlsafe()),
    };
    let _ = alpha;
    // strip padding
    let body: Vec<u8> = s
        .bytes()
        .filter(|&b| b != b'=')
        .map(|b| inv[b as usize])
        .collect();
    if body.len() % 4 == 1 {
        return None; // a lone trailing sextet is impossible
    }
    let mut out = Vec::with_capacity(body.len() / 4 * 3);
    let mut i = 0usize;
    while i + 4 <= body.len() {
        let [a, b, c, d] = [body[i], body[i + 1], body[i + 2], body[i + 3]];
        if a > 63 || b > 63 || c > 63 || d > 63 {
            return None;
        }
        out.push((a << 2) | (b >> 4));
        out.push((b << 4) | (c >> 2));
        out.push((c << 6) | d);
        i += 4;
    }
    let rem = body.len() % 4;
    if rem == 2 {
        let [a, b] = [body[i], body[i + 1]];
        if a > 63 || b > 63 {
            return None;
        }
        out.push((a << 2) | (b >> 4));
    } else if rem == 3 {
        let [a, b, c] = [body[i], body[i + 1], body[i + 2]];
        if a > 63 || b > 63 || c > 63 {
            return None;
        }
        out.push((a << 2) | (b >> 4));
        out.push((b << 4) | (c >> 2));
    }
    Some(out)
}

fn inv_std() -> [u8; 256] {
    let mut inv = [0xFFu8; 256];
    for (i, &c) in STD.iter().enumerate() {
        inv[c as usize] = i as u8;
    }
    inv
}

fn inv_urlsafe() -> [u8; 256] {
    let mut inv = [0xFFu8; 256];
    for (i, &c) in URLSAFE.iter().enumerate() {
        inv[c as usize] = i as u8;
    }
    inv
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn rfc4648_vectors() {
        let cases: &[(&str, &str)] = &[
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, enc) in cases {
            let got = encode(plain.as_bytes(), Variant::Standard);
            assert_eq!(got, enc.to_string(), "encode {plain:?}");
            let back = decode(enc, Variant::Standard).unwrap();
            assert_eq!(back, plain.as_bytes(), "decode {enc:?}");
        }
    }

    #[test]
    fn roundtrip_binary() {
        for len in 0..=100 {
            let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            for v in [Variant::Standard, Variant::UrlSafe] {
                let enc = encode(&data, v);
                let back = decode(&enc, v).unwrap();
                assert_eq!(back, data, "len={len} var={v:?}");
            }
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode("!!!!", Variant::Standard).is_none());
        assert!(decode("Zg", Variant::Standard).is_some()); // no padding ok
        assert!(decode("a", Variant::Standard).is_none());
        // url-safe '-' rejected in standard mode; accepted in url-safe mode
        assert!(decode("-w==", Variant::Standard).is_none());
        assert!(decode("-w==", Variant::UrlSafe).is_some());
    }
}
