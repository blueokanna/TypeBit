//! Bencode codec (BEP-3) with strict resource limits.
//!
//! Used for `.torrent` metainfo, tracker announce/scrape responses and DHT
//! KRPC messages. Byte strings preserve raw bytes (torrents carry binary
//! hash data). The parser also exposes a raw-range walker so the exact
//! bencoded `info` dictionary can be captured for infohash computation
//! without re-encoding.

use crate::error::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;

/// Maximum nesting depth.
pub const MAX_DEPTH: usize = 64;
/// Maximum byte-string length.
pub const MAX_STR_LEN: usize = 16 * 1024 * 1024;
/// Maximum number of dict keys / list items.
pub const MAX_ITEMS: usize = 1_000_000;

/// A decoded bencode value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BVal {
    /// Integer.
    Int(i64),
    /// Byte string (may contain arbitrary bytes).
    Bytes(Vec<u8>),
    /// List.
    List(Vec<BVal>),
    /// Dictionary (keys are raw byte strings, kept in byte order).
    Dict(BTreeMap<Vec<u8>, BVal>),
}

impl BVal {
    /// Parse `input` completely (trailing bytes rejected).
    pub fn parse(input: &[u8]) -> Result<BVal> {
        let mut p = Parser::new(input);
        let v = p.value(0)?;
        if p.pos != input.len() {
            return Err(Error::Bencode);
        }
        Ok(v)
    }

    /// Look up a key in a dict; `None` if not a dict or missing.
    pub fn get(&self, key: &[u8]) -> Option<&BVal> {
        match self {
            BVal::Dict(m) => m.get(key),
            _ => None,
        }
    }

    /// Interpret as integer.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            BVal::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Interpret as bytes.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            BVal::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Interpret as string (lossy for non-UTF-8; bencode keys are usually ASCII).
    pub fn as_str(&self) -> Option<&str> {
        self.as_bytes().and_then(|b| core::str::from_utf8(b).ok())
    }

    /// Interpret as list.
    pub fn as_list(&self) -> Option<&[BVal]> {
        match self {
            BVal::List(l) => Some(l),
            _ => None,
        }
    }

    /// Interpret as dict.
    pub fn as_dict(&self) -> Option<&BTreeMap<Vec<u8>, BVal>> {
        match self {
            BVal::Dict(d) => Some(d),
            _ => None,
        }
    }

    /// Encode back to bencode bytes.
    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_value(self, out, 0);
    }

    /// Convenience: `b"key"`-style literal keys.
    pub fn dict_get_int(&self, key: &[u8]) -> Option<i64> {
        self.get(key).and_then(|v| v.as_int())
    }
}

fn encode_value(v: &BVal, out: &mut Vec<u8>, depth: usize) {
    debug_assert!(depth <= MAX_DEPTH);
    match v {
        BVal::Int(i) => {
            out.push(b'i');
            out.extend_from_slice(i.to_string().as_bytes());
            out.push(b'e');
        }
        BVal::Bytes(b) => {
            out.extend_from_slice(b.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(b);
        }
        BVal::List(l) => {
            out.push(b'l');
            for item in l {
                encode_value(item, out, depth + 1);
            }
            out.push(b'e');
        }
        BVal::Dict(m) => {
            out.push(b'd');
            for (k, val) in m {
                out.extend_from_slice(k.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(k);
                encode_value(val, out, depth + 1);
            }
            out.push(b'e');
        }
    }
}

/// Convenience constructor for byte strings.
pub fn bytes(b: impl Into<Vec<u8>>) -> BVal {
    BVal::Bytes(b.into())
}

/// Convenience constructor for integers.
pub fn int(i: i64) -> BVal {
    BVal::Int(i)
}

/// Convenience constructor for lists.
pub fn list(items: Vec<BVal>) -> BVal {
    BVal::List(items)
}

/// Convenience constructor for dicts.
pub fn dict(entries: Vec<(&[u8], BVal)>) -> BVal {
    let mut m = BTreeMap::new();
    for (k, v) in entries {
        m.insert(k.to_vec(), v);
    }
    BVal::Dict(m)
}

/// Result of a raw walk: the start/end offsets of a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawRange {
    /// Start offset (inclusive).
    pub start: usize,
    /// End offset (exclusive).
    pub end: usize,
    /// Whether the value is a container (list/dict).
    pub is_container: bool,
}

/// A position-aware parser over `input`.
pub struct Parser<'a> {
    input: &'a [u8],
    /// Current offset.
    pub pos: usize,
}

impl<'a> Parser<'a> {
    /// Create a parser at offset 0.
    pub fn new(input: &'a [u8]) -> Self {
        Parser { input, pos: 0 }
    }

    /// Parse the value at the current position (advancing `pos`).
    pub fn value(&mut self, depth: usize) -> Result<BVal> {
        if depth > MAX_DEPTH {
            return Err(Error::Depth);
        }
        let b = *self.input.get(self.pos).ok_or(Error::Bencode)?;
        match b {
            b'i' => self.int(),
            b'l' => self.list(depth),
            b'd' => self.dict(depth),
            b'0'..=b'9' => self.string(),
            _ => Err(Error::Bencode),
        }
    }

    /// Parse a value and return its raw byte range without building a tree.
    pub fn raw_range(&mut self, depth: usize) -> Result<RawRange> {
        let start = self.pos;
        let b = *self.input.get(self.pos).ok_or(Error::Bencode)?;
        let is_container = matches!(b, b'l' | b'd');
        self.skip_value(depth)?;
        Ok(RawRange {
            start,
            end: self.pos,
            is_container,
        })
    }

    /// Skip a value, advancing `pos` past it.
    pub fn skip_value(&mut self, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Error::Depth);
        }
        let b = *self.input.get(self.pos).ok_or(Error::Bencode)?;
        match b {
            b'i' => {
                self.pos += 1;
                let mut saw_digit = false;
                loop {
                    let c = *self.input.get(self.pos).ok_or(Error::Bencode)?;
                    self.pos += 1;
                    if c == b'e' {
                        break;
                    }
                    if c == b'-' {
                        continue;
                    }
                    if c.is_ascii_digit() {
                        saw_digit = true;
                    } else {
                        return Err(Error::Bencode);
                    }
                }
                if !saw_digit {
                    return Err(Error::Bencode);
                }
            }
            b'l' => {
                self.pos += 1;
                loop {
                    if *self.input.get(self.pos).ok_or(Error::Bencode)? == b'e' {
                        self.pos += 1;
                        break;
                    }
                    self.skip_value(depth + 1)?;
                }
            }
            b'd' => {
                self.pos += 1;
                let mut items = 0usize;
                loop {
                    if *self.input.get(self.pos).ok_or(Error::Bencode)? == b'e' {
                        self.pos += 1;
                        break;
                    }
                    // dict key must be a string
                    let b = *self.input.get(self.pos).ok_or(Error::Bencode)?;
                    if !b.is_ascii_digit() {
                        return Err(Error::Bencode);
                    }
                    self.skip_string()?;
                    self.skip_value(depth + 1)?;
                    items += 1;
                    if items > MAX_ITEMS {
                        return Err(Error::Full);
                    }
                }
            }
            b'0'..=b'9' => self.skip_string()?,
            _ => return Err(Error::Bencode),
        }
        Ok(())
    }

    /// Current position.
    pub fn position(&self) -> usize {
        self.pos
    }

    fn int(&mut self) -> Result<BVal> {
        self.pos += 1; // 'i'
        let start = self.pos;
        loop {
            let c = *self.input.get(self.pos).ok_or(Error::Bencode)?;
            if c == b'e' {
                let s = core::str::from_utf8(&self.input[start..self.pos])
                    .map_err(|_| Error::Bencode)?;
                self.pos += 1;
                let i = parse_bencoded_int(s)?;
                return Ok(BVal::Int(i));
            }
            self.pos += 1;
            if self.pos - start > 24 {
                return Err(Error::Bencode);
            }
        }
    }

    fn skip_string(&mut self) -> Result<()> {
        let len = self.string_len()?;
        self.pos = self.pos.checked_add(len).ok_or(Error::Bencode)?;
        if self.pos > self.input.len() {
            return Err(Error::Bencode);
        }
        Ok(())
    }

    /// Parse `N:` length prefix, leaving `pos` at the payload start.
    pub fn string(&mut self) -> Result<BVal> {
        let len = self.string_len()?;
        if len > MAX_STR_LEN {
            return Err(Error::TooLarge);
        }
        let end = self.pos.checked_add(len).ok_or(Error::Bencode)?;
        if end > self.input.len() {
            return Err(Error::Bencode);
        }
        let out = self.input[self.pos..end].to_vec();
        self.pos = end;
        Ok(BVal::Bytes(out))
    }

    /// Parse `N:` length prefix, leaving `pos` at the payload start.
    fn string_len(&mut self) -> Result<usize> {
        let start = self.pos;
        let mut len: usize = 0;
        loop {
            let c = *self.input.get(self.pos).ok_or(Error::Bencode)?;
            match c {
                b'0'..=b'9' => {
                    len = len
                        .checked_mul(10)
                        .and_then(|l| l.checked_add((c - b'0') as usize))
                        .ok_or(Error::Bencode)?;
                    if len > MAX_STR_LEN {
                        return Err(Error::TooLarge);
                    }
                }
                b':' => {
                    if self.pos == start {
                        return Err(Error::Bencode);
                    }
                    self.pos += 1;
                    return Ok(len);
                }
                _ => return Err(Error::Bencode),
            }
            self.pos += 1;
            if self.pos - start > 10 {
                return Err(Error::Bencode);
            }
        }
    }

    fn list(&mut self, depth: usize) -> Result<BVal> {
        self.pos += 1;
        let mut out = Vec::new();
        loop {
            if *self.input.get(self.pos).ok_or(Error::Bencode)? == b'e' {
                self.pos += 1;
                return Ok(BVal::List(out));
            }
            if out.len() >= MAX_ITEMS {
                return Err(Error::Full);
            }
            out.push(self.value(depth + 1)?);
        }
    }

    fn dict(&mut self, depth: usize) -> Result<BVal> {
        self.pos += 1;
        let mut out = BTreeMap::new();
        loop {
            if *self.input.get(self.pos).ok_or(Error::Bencode)? == b'e' {
                self.pos += 1;
                return Ok(BVal::Dict(out));
            }
            if out.len() >= MAX_ITEMS {
                return Err(Error::Full);
            }
            let key = match self.string()? {
                BVal::Bytes(k) => k,
                _ => return Err(Error::Bencode),
            };
            let val = self.value(depth + 1)?;
            out.insert(key, val);
        }
    }
}

fn parse_bencoded_int(s: &str) -> Result<i64> {
    if s.is_empty() {
        return Err(Error::Bencode);
    }
    // reject leading zeros / "-0"
    let body = s.strip_prefix('-').unwrap_or(s);
    if body.len() > 1 && body.starts_with('0') {
        return Err(Error::Bencode);
    }
    if body == "0" && s.starts_with('-') {
        return Err(Error::Bencode);
    }
    s.parse::<i64>().map_err(|_| Error::Bencode)
}

/// Encode helper for building small dicts without allocation churn.
pub fn encode_to_vec(v: &BVal) -> Vec<u8> {
    let mut out = Vec::new();
    v.encode(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        let v = dict(vec![
            (b"announce", bytes("http://tracker.example/announce")),
            (b"pieces", bytes(vec![7u8; 40])),
            (b"length", int(1234)),
            (
                b"nested",
                dict(vec![(b"x", list(vec![int(1), int(2), int(-3)]))]),
            ),
            (b"empty", list(vec![])),
            (b"emptyd", dict(vec![])),
        ]);
        let enc = encode_to_vec(&v);
        let dec = BVal::parse(&enc).unwrap();
        assert_eq!(dec, v);
    }

    #[test]
    fn raw_range_of_info() {
        // simulate a torrent: d8:announce...4:info d...ee
        let v = dict(vec![
            (b"announce", bytes("http://x/a")),
            (
                b"info",
                dict(vec![
                    (b"name", bytes("file.bin")),
                    (b"piece length", int(16384)),
                    (b"pieces", bytes(vec![0xAB; 20])),
                    (b"length", int(16384)),
                ]),
            ),
        ]);
        let enc = encode_to_vec(&v);
        let mut p = Parser::new(&enc);
        // skip 'd'
        assert_eq!(enc[0], b'd');
        p.pos = 1;
        // key "announce"
        p.skip_string().unwrap();
        p.skip_value(0).unwrap();
        // key "info"
        p.skip_string().unwrap();
        let r = p.raw_range(0).unwrap();
        let info_raw = &enc[r.start..r.end];
        // re-parse info_raw and compare to expected info dict
        let info = BVal::parse(info_raw).unwrap();
        assert_eq!(info, v.get(&b"info"[..]).unwrap().clone());
        // infohash-style: SHA-1 of raw info bytes
        let _ = crate::crypto::Sha1::digest(info_raw);
    }

    #[test]
    fn rejects_trailing() {
        let mut enc = encode_to_vec(&int(5));
        enc.push(b'x');
        assert!(BVal::parse(&enc).is_err());
    }

    #[test]
    fn rejects_bad_int() {
        assert!(BVal::parse(b"i05e").is_err());
        assert!(BVal::parse(b"i-e").is_err());
        assert!(BVal::parse(b"i-0e").is_err());
        assert_eq!(BVal::parse(b"i-5e").unwrap(), BVal::Int(-5));
        assert_eq!(BVal::parse(b"i0e").unwrap(), BVal::Int(0));
    }

    #[test]
    fn depth_limit() {
        let mut s = Vec::new();
        for _ in 0..70 {
            s.push(b'l');
        }
        s.push(b'e');
        for _ in 0..70 {
            s.push(b'e');
        }
        assert!(BVal::parse(&s).is_err());
    }
}
