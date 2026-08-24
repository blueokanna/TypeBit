//! Magnet URI parsing (BEP-9 / BEP-53).
//!
//! Supports `urn:btih` (v1), `urn:btmh` (v2 multihash), `urn:sha1`,
//! `dn`, repeated `tr`, `x.pe`, `ws` and `as` fields, with percent-decoding.

use crate::error::{Error, Result};
use crate::metainfo::InfoHash;
use crate::platform::NetAddr;
use alloc::string::String;
use alloc::vec::Vec;

/// A parsed magnet link.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Magnet {
    /// Info hash (either v1 or v2).
    pub info_hash: Option<InfoHash>,
    /// Display name.
    pub name: Option<String>,
    /// Tracker announce URLs.
    pub trackers: Vec<String>,
    /// Exact peer endpoints (`x.pe`).
    pub peers: Vec<NetAddr>,
    /// Web seeds (`ws`).
    pub web_seeds: Vec<String>,
    /// Exact source (`as`).
    pub sources: Vec<String>,
}

impl Magnet {
    /// Parse a magnet URI string.
    pub fn parse(uri: &str) -> Result<Magnet> {
        let rest = uri.strip_prefix("magnet:?").ok_or(Error::Magnet)?;
        let mut m = Magnet::default();
        for part in rest.split('&') {
            if part.is_empty() {
                continue;
            }
            let (k, v) = match part.split_once('=') {
                Some(p) => p,
                None => (part, ""),
            };
            match k {
                "xt" => {
                    let v = String::from_utf8_lossy(&percent_decode(v)).into_owned();
                    if let Some(h) = v.strip_prefix("urn:btih:") {
                        if h.len() == 32 {
                            // base32 sha1 (rare)
                            if let Some(hh) = base32_decode_sha1(h) {
                                m.info_hash = Some(InfoHash::v1(hh));
                            }
                        } else {
                            if let Ok(h) = InfoHash::from_hex(h) {
                                m.info_hash = Some(h);
                            }
                        }
                    } else if let Some(h) = v.strip_prefix("urn:btmh:") {
                        if let Ok(h) = InfoHash::from_multihash(h) {
                            m.info_hash = Some(h);
                        }
                    } else if let Some(h) = v.strip_prefix("urn:sha1:") {
                        if let Some(hh) = base32_decode_sha1(h) {
                            m.info_hash = Some(InfoHash::v1(hh));
                        }
                    }
                }
                "dn" => m.name = Some(String::from_utf8_lossy(&percent_decode(v)).into_owned()),
                "tr" => m
                    .trackers
                    .push(String::from_utf8_lossy(&percent_decode(v)).into_owned()),
                "x.pe" | "x.pe1" => {
                    let v = String::from_utf8_lossy(&percent_decode(v)).into_owned();
                    if let Some(a) = parse_endpoint(&v) {
                        m.peers.push(a);
                    }
                }
                "ws" => m
                    .web_seeds
                    .push(String::from_utf8_lossy(&percent_decode(v)).into_owned()),
                "as" => m
                    .sources
                    .push(String::from_utf8_lossy(&percent_decode(v)).into_owned()),
                _ => {}
            }
        }
        if m.info_hash.is_none() {
            return Err(Error::Magnet);
        }
        Ok(m)
    }

    /// Render back to a magnet URI (re-encoding the info hash).
    pub fn to_uri(&self) -> String {
        let mut s = String::from("magnet:?");
        if let Some(h) = &self.info_hash {
            s.push_str("xt=urn:");
            if h.is_v1() {
                s.push_str("btih:");
                s.push_str(&h.to_hex());
            } else {
                s.push_str("btmh:1220");
                s.push_str(&h.to_hex());
            }
        }
        if let Some(n) = &self.name {
            s.push_str("&dn=");
            s.push_str(&percent_encode(n.as_bytes()));
        }
        for t in &self.trackers {
            s.push_str("&tr=");
            s.push_str(&percent_encode(t.as_bytes()));
        }
        s
    }
}

/// RFC 3986 percent decoding (bytes preserved).
pub fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = hexv(b[i + 1]);
            let lo = hexv(b[i + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn hexv(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Percent-encode a byte string (unreserved chars kept).
pub fn percent_encode(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &c in b {
        let ok = c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~');
        if ok {
            out.push(c as char);
        } else {
            out.push('%');
            out.push(HEX[(c >> 4) as usize] as char);
            out.push(HEX[(c & 0xf) as usize] as char);
        }
    }
    out
}

fn parse_endpoint(s: &str) -> Option<NetAddr> {
    // forms: ipv4:port, [ipv6]:port, host:port (host resolved by caller)
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(idx) = rest.find(']') {
            let ip = &rest[..idx];
            let port: u16 = rest[idx + 1..].trim_start_matches(':').parse().ok()?;
            let mut bytes = [0u8; 16];
            if parse_ipv6(ip, &mut bytes) {
                return Some(NetAddr::V6(bytes, port));
            }
        }
    }
    let (ip, port) = s.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let mut parts = ip.split('.');
    let a: u8 = parts.next()?.parse().ok()?;
    let b: u8 = parts.next()?.parse().ok()?;
    let c: u8 = parts.next()?.parse().ok()?;
    let d: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(NetAddr::V4([a, b, c, d], port))
}

fn parse_ipv6(s: &str, out: &mut [u8; 16]) -> bool {
    // minimal IPv6 parser (full groups, no compression) — enough for magnet x.pe
    let groups: Vec<&str> = s.split(':').collect();
    if groups.len() != 8 {
        return false;
    }
    for (i, g) in groups.iter().enumerate() {
        let v = match u16::from_str_radix(g, 16) {
            Ok(v) => v,
            Err(_) => return false,
        };
        out[i * 2] = (v >> 8) as u8;
        out[i * 2 + 1] = v as u8;
    }
    true
}

/// Base32 decode into a 20-byte SHA-1 hash (RFC 4648, no padding).
fn base32_decode_sha1(s: &str) -> Option<[u8; 20]> {
    const ALPH: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = [0u8; 20];
    let mut idx = 0usize;
    for &c in s.as_bytes() {
        let v = ALPH.iter().position(|&a| a == c)? as u32;
        bits = (bits << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            if idx < 20 {
                out[idx] = (bits >> nbits) as u8;
                idx += 1;
            }
        }
    }
    if idx != 20 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v1_magnet() {
        let m = Magnet::parse(
            "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=test+file&tr=udp%3A%2F%2Ftracker.example%3A6969%2Fannounce",
        )
        .unwrap();
        assert_eq!(
            m.info_hash.unwrap().to_hex(),
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(m.name.as_deref(), Some("test+file"));
        assert_eq!(m.trackers.len(), 1);
    }

    #[test]
    fn parse_v2_magnet() {
        let h = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let m = Magnet::parse(&format!("magnet:?xt=urn:btmh:1220{}", h)).unwrap();
        assert!(m.info_hash.unwrap().is_v2());
    }

    #[test]
    fn roundtrip_uri() {
        let m = Magnet::parse("magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=a%20b&tr=http%3A%2F%2Fx%2Fa")
            .unwrap();
        let u = m.to_uri();
        let m2 = Magnet::parse(&u).unwrap();
        assert_eq!(m.info_hash, m2.info_hash);
        assert_eq!(m.name, m2.name);
        assert_eq!(m.trackers, m2.trackers);
    }

    #[test]
    fn percent_decode_works() {
        assert_eq!(percent_decode("a%20b"), b"a b");
        assert_eq!(percent_decode("plain"), b"plain");
    }
}
