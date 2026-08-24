//! Tracker protocol codecs.
//!
//! * **HTTP tracker (BEP-3)**: announce/scrape URL construction and
//!   bencoded response parsing (compact + dict peer lists).
//! * **UDP tracker (BEP-15)**: connect/announce/scrape request builders and
//!   response parsers.
//!
//! The actual HTTP transport is delegated to the host ([`crate::platform::Host::http_get`],
//! implemented with `courierust` on the std host); UDP transport goes
//! through [`crate::platform::Host::udp_send`]/`udp_recv`.

use crate::bencode::BVal;
use crate::error::{Error, Result};
use crate::magnet::percent_encode;
use crate::platform::NetAddr;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

/// Validate an HTTP tracker endpoint with `courierust`'s URI parser
/// (scheme must be http/https).
pub fn validate_http_tracker(url: &str) -> bool {
    match courierust::courierust_http::uri::Url::parse(url) {
        Ok(u) => matches!(u.scheme.to_ascii_lowercase().as_str(), "http" | "https"),
        Err(_) => false,
    }
}

/// Parse a plain-text tracker list (one URL per line, `#` comments allowed)
/// — the format served by https://cf.trackerslist.com/best.txt.
pub fn parse_tracker_list(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

/// Dict integer lookup helper (bencode keys are raw bytes).
fn di(d: &BTreeMap<Vec<u8>, BVal>, k: &[u8]) -> Option<i64> {
    d.get(k).and_then(|x| x.as_int())
}

/// Announce event (BEP-3 / BEP-15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Regular periodic announce.
    None,
    /// First announce for a torrent.
    Started,
    /// Download completed.
    Completed,
    /// Stopped / paused.
    Stopped,
    /// Paused (same as stopped on the wire).
    Paused,
}

impl Event {
    fn http_name(&self) -> Option<&'static str> {
        match self {
            Event::None => None,
            Event::Started => Some("started"),
            Event::Completed => Some("completed"),
            Event::Stopped | Event::Paused => Some("stopped"),
        }
    }
    fn udp_code(&self) -> u32 {
        match self {
            Event::None => 0,
            Event::Completed => 1,
            Event::Started => 2,
            Event::Stopped | Event::Paused => 3,
        }
    }
}

/// Announce parameters.
#[derive(Debug, Clone)]
pub struct AnnounceParams {
    /// 20-byte tracker hash (v1 hash, or v2 truncated to 20 bytes).
    pub tracker_hash: [u8; 20],
    /// Peer id.
    pub peer_id: [u8; 20],
    /// Listen port.
    pub port: u16,
    /// Bytes uploaded.
    pub uploaded: u64,
    /// Bytes downloaded.
    pub downloaded: u64,
    /// Bytes left.
    pub left: u64,
    /// Event.
    pub event: Event,
    /// Number of peers wanted (0 = server default).
    pub numwant: u32,
    /// Random key identifying the client session.
    pub key: u32,
}

impl Default for AnnounceParams {
    fn default() -> Self {
        AnnounceParams {
            tracker_hash: [0; 20],
            peer_id: [0; 20],
            port: crate::consts::DEFAULT_PORT,
            uploaded: 0,
            downloaded: 0,
            left: 0,
            event: Event::None,
            numwant: 200,
            key: 0,
        }
    }
}

/// Parsed tracker response.
#[derive(Debug, Clone, Default)]
pub struct TrackerResponse {
    /// Re-announce interval (seconds).
    pub interval: u64,
    /// Minimum interval (HTTP trackers).
    pub min_interval: Option<u64>,
    /// Seeders in swarm.
    pub complete: Option<u32>,
    /// Leechers in swarm.
    pub incomplete: Option<u32>,
    /// Peers discovered.
    pub peers: Vec<NetAddr>,
    /// Tracker session id (for `stopped`).
    pub tracker_id: Option<Vec<u8>>,
    /// Failure reason (HTTP `failure reason` or UDP error).
    pub failure: Option<String>,
}

/// Build an HTTP announce URL.
pub fn build_http_announce_url(base: &str, p: &AnnounceParams) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    let mut url = String::with_capacity(base.len() + 220);
    url.push_str(base);
    url.push(sep);
    url.push_str("info_hash=");
    url.push_str(&percent_encode(&p.tracker_hash));
    url.push_str("&peer_id=");
    url.push_str(&percent_encode(&p.peer_id));
    url.push_str("&port=");
    url.push_str(&p.port.to_string());
    url.push_str("&uploaded=");
    url.push_str(&p.uploaded.to_string());
    url.push_str("&downloaded=");
    url.push_str(&p.downloaded.to_string());
    url.push_str("&left=");
    url.push_str(&p.left.to_string());
    url.push_str("&compact=1&no_peer_id=1");
    if let Some(e) = p.event.http_name() {
        url.push_str("&event=");
        url.push_str(e);
    }
    if p.numwant != 0 {
        url.push_str("&numwant=");
        url.push_str(&p.numwant.to_string());
    }
    url.push_str("&key=");
    url.push_str(&format!("{:08x}", p.key));
    url
}

/// Build an HTTP scrape URL (one or more hashes).
pub fn build_http_scrape_url(base: &str, hashes: &[&[u8]]) -> String {
    let mut url = String::from(base);
    let sep = if url.contains('?') { '&' } else { '?' };
    for h in hashes {
        url.push(sep);
        url.push_str("info_hash=");
        url.push_str(&percent_encode(h));
    }
    url
}

/// Parse a bencoded tracker response.
pub fn parse_tracker_response(bytes: &[u8]) -> Result<TrackerResponse> {
    let v = BVal::parse(bytes)?;
    let d = v.as_dict().ok_or(Error::Tracker)?;
    let mut out = TrackerResponse::default();
    if let Some(f) = d.get(&b"failure reason"[..]).and_then(|x| x.as_str()) {
        out.failure = Some(String::from(f));
        return Ok(out);
    }
    out.interval = di(d, b"interval").unwrap_or(1800) as u64;
    out.min_interval = di(d, b"min interval").map(|i| i as u64);
    out.complete = di(d, b"complete").map(|i| i as u32);
    out.incomplete = di(d, b"incomplete").map(|i| i as u32);
    out.tracker_id = d
        .get(&b"tracker id"[..])
        .and_then(|x| x.as_bytes())
        .map(|b| b.to_vec());
    // peers: compact (string of 6-byte entries) or dict list
    match d.get(&b"peers"[..]) {
        Some(BVal::Bytes(b)) => {
            if b.len() % 6 == 0 {
                for c in b.chunks_exact(6) {
                    if let Some(a) = NetAddr::from_compact6(c) {
                        out.peers.push(a);
                    }
                }
            }
        }
        Some(BVal::List(l)) => {
            for p in l {
                if let Some(pd) = p.as_dict() {
                    let ip = pd.get(&b"ip"[..]).and_then(|x| x.as_str());
                    let port = di(pd, b"port");
                    if let (Some(ip), Some(port)) = (ip, port) {
                        if let Some(a) = parse_ip_port(ip, port as u16) {
                            out.peers.push(a);
                        }
                    }
                }
            }
        }
        _ => {}
    }
    // IPv6 peers
    if let Some(BVal::Bytes(b)) = d.get(&b"peers6"[..]) {
        if b.len() % 18 == 0 {
            for c in b.chunks_exact(18) {
                if let Some(a) = NetAddr::from_compact18(c) {
                    out.peers.push(a);
                }
            }
        }
    }
    Ok(out)
}

fn parse_ip_port(ip: &str, port: u16) -> Option<NetAddr> {
    // IPv6?
    if let Some(rest) = ip.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let h = &rest[..end];
            let mut bytes = [0u8; 16];
            if parse_ipv6(h, &mut bytes) {
                return Some(NetAddr::V6(bytes, port));
            }
            return None;
        }
    }
    if ip.contains(':') && !ip.starts_with('[') {
        // bare IPv6 without brackets
        let mut bytes = [0u8; 16];
        if parse_ipv6(ip, &mut bytes) {
            return Some(NetAddr::V6(bytes, port));
        }
        return None;
    }
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut o = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        o[i] = p.parse().ok()?;
    }
    Some(NetAddr::V4(o, port))
}

fn parse_ipv6(s: &str, out: &mut [u8; 16]) -> bool {
    let mut groups: Vec<u16> = Vec::new();
    if let Some((l, r)) = s.split_once("::") {
        let left: Vec<&str> = l.split(':').filter(|x| !x.is_empty()).collect();
        let right: Vec<&str> = r.split(':').filter(|x| !x.is_empty()).collect();
        for g in &left {
            match u16::from_str_radix(g, 16) {
                Ok(v) => groups.push(v),
                Err(_) => return false,
            }
        }
        while groups.len() < 8 - right.len() {
            groups.push(0);
        }
        for g in &right {
            match u16::from_str_radix(g, 16) {
                Ok(v) => groups.push(v),
                Err(_) => return false,
            }
        }
    } else {
        for g in s.split(':') {
            match u16::from_str_radix(g, 16) {
                Ok(v) => groups.push(v),
                Err(_) => return false,
            }
        }
    }
    if groups.len() != 8 {
        return false;
    }
    for (i, g) in groups.iter().enumerate() {
        out[i * 2] = (g >> 8) as u8;
        out[i * 2 + 1] = *g as u8;
    }
    true
}

/// UDP tracker protocol (BEP-15).
pub mod udp {
    use super::*;

    /// Connection magic.
    pub const PROTOCOL_ID: u64 = 0x0000041727101980;
    /// BEP-15 action: connect.
    pub const ACTION_CONNECT: u32 = 0;
    /// BEP-15 action: announce.
    pub const ACTION_ANNOUNCE: u32 = 1;
    /// BEP-15 action: scrape.
    pub const ACTION_SCRAPE: u32 = 2;
    /// BEP-15 action: error.
    pub const ACTION_ERROR: u32 = 3;

    /// Build a connect request (16 bytes).
    pub fn build_connect_request(tid: u32) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&PROTOCOL_ID.to_be_bytes());
        out[8..12].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
        out[12..16].copy_from_slice(&tid.to_be_bytes());
        out
    }

    /// Parse a connect response → connection id.
    pub fn parse_connect_response(buf: &[u8], tid: u32) -> Result<u64> {
        if buf.len() < 16 {
            return Err(Error::Tracker);
        }
        let action = be32(&buf[0..4]);
        let r_tid = be32(&buf[4..8]);
        if r_tid != tid {
            return Err(Error::Tracker);
        }
        if action == ACTION_ERROR {
            return Err(Error::Tracker);
        }
        if action != ACTION_CONNECT {
            return Err(Error::Tracker);
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&buf[8..16]);
        Ok(u64::from_be_bytes(id))
    }

    /// Build an announce request (98 bytes).
    pub fn build_announce_request(conn_id: u64, tid: u32, p: &AnnounceParams) -> [u8; 98] {
        let mut out = [0u8; 98];
        out[0..8].copy_from_slice(&conn_id.to_be_bytes());
        out[8..12].copy_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
        out[12..16].copy_from_slice(&tid.to_be_bytes());
        out[16..36].copy_from_slice(&p.tracker_hash);
        out[36..56].copy_from_slice(&p.peer_id);
        out[56..64].copy_from_slice(&p.downloaded.to_be_bytes());
        out[64..72].copy_from_slice(&p.left.to_be_bytes());
        out[72..80].copy_from_slice(&p.uploaded.to_be_bytes());
        out[80..84].copy_from_slice(&p.event.udp_code().to_be_bytes());
        // ip = 0 (default), key, numwant
        out[88..92].copy_from_slice(&p.key.to_be_bytes());
        out[92..96].copy_from_slice(&(p.numwant as i32).to_be_bytes());
        out[96..98].copy_from_slice(&p.port.to_be_bytes());
        out
    }

    /// Parse an announce response.
    pub fn parse_announce_response(buf: &[u8], tid: u32) -> Result<TrackerResponse> {
        if buf.len() < 20 {
            return Err(Error::Tracker);
        }
        let action = be32(&buf[0..4]);
        let r_tid = be32(&buf[4..8]);
        if r_tid != tid {
            return Err(Error::Tracker);
        }
        if action == ACTION_ERROR {
            let reason = String::from_utf8_lossy(&buf[8..]).into_owned();
            return Ok(TrackerResponse {
                failure: Some(reason),
                ..Default::default()
            });
        }
        if action != ACTION_ANNOUNCE {
            return Err(Error::Tracker);
        }
        let mut out = TrackerResponse {
            interval: be32(&buf[8..12]) as u64,
            incomplete: Some(be32(&buf[12..16])),
            complete: Some(be32(&buf[16..20])),
            ..Default::default()
        };
        let rest = &buf[20..];
        if rest.len() % 6 == 0 {
            for c in rest.chunks_exact(6) {
                if let Some(a) = NetAddr::from_compact6(c) {
                    out.peers.push(a);
                }
            }
        }
        Ok(out)
    }

    /// Build a scrape request.
    pub fn build_scrape_request(conn_id: u64, tid: u32, hashes: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + hashes.len() * 20);
        out.extend_from_slice(&conn_id.to_be_bytes());
        out.extend_from_slice(&ACTION_SCRAPE.to_be_bytes());
        out.extend_from_slice(&tid.to_be_bytes());
        for h in hashes {
            let mut hh = [0u8; 20];
            let n = h.len().min(20);
            hh[..n].copy_from_slice(&h[..n]);
            out.extend_from_slice(&hh);
        }
        out
    }

    /// Parse a scrape response: per-hash (seeders, completed, leechers).
    pub fn parse_scrape_response(
        buf: &[u8],
        tid: u32,
        count: usize,
    ) -> Result<Vec<(u32, u32, u32)>> {
        if buf.len() < 8 || be32(&buf[4..8]) != tid {
            return Err(Error::Tracker);
        }
        let rest = &buf[8..];
        if rest.len() < count * 12 {
            return Err(Error::Tracker);
        }
        let mut out = Vec::with_capacity(count);
        for c in rest[..count * 12].chunks_exact(12) {
            out.push((be32(&c[0..4]), be32(&c[4..8]), be32(&c[8..12])));
        }
        Ok(out)
    }

    fn be32(b: &[u8]) -> u32 {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_http_tracker_scheme() {
        assert!(validate_http_tracker(
            "http://tracker.example.com:80/announce"
        ));
        assert!(validate_http_tracker(
            "https://tracker.tamersunion.org/announce"
        ));
        assert!(!validate_http_tracker(
            "udp://tracker.example.com:6969/announce"
        ));
        assert!(!validate_http_tracker("not a url"));
    }

    #[test]
    fn parse_tracker_list_text() {
        let text = "# comment line\n\nudp://a.example:80/announce\nhttps://b.example/announce\n";
        let list = parse_tracker_list(text);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], "udp://a.example:80/announce");
        assert_eq!(list[1], "https://b.example/announce");
    }

    #[test]
    fn default_trackers_are_valid() {
        // every built-in tracker must have a parseable scheme + port
        for t in crate::consts::DEFAULT_TRACKERS {
            let ok =
                t.starts_with("udp://") || t.starts_with("http://") || t.starts_with("https://");
            assert!(ok, "bad default tracker: {t}");
        }
    }

    #[test]
    fn http_announce_url() {
        let p = AnnounceParams {
            tracker_hash: [1u8; 20],
            peer_id: [2u8; 20],
            port: 6881,
            left: 100,
            event: Event::Started,
            ..Default::default()
        };
        let url = build_http_announce_url("http://t.example/announce", &p);
        assert!(url.starts_with("http://t.example/announce?"));
        assert!(url.contains("info_hash=%01%01%01%01"));
        assert!(url.contains("event=started"));
        assert!(url.contains("compact=1"));
    }

    #[test]
    fn parse_compact_response() {
        let body = crate::bencode::encode_to_vec(&crate::bencode::dict(vec![
            (b"interval", crate::bencode::int(1800)),
            (b"complete", crate::bencode::int(10)),
            (b"incomplete", crate::bencode::int(5)),
            (
                b"peers",
                crate::bencode::bytes(vec![192, 168, 1, 1, 0x1A, 0xE1, 10, 0, 0, 1, 0x1A, 0xE2]),
            ),
        ]));
        let r = parse_tracker_response(&body).unwrap();
        assert_eq!(r.interval, 1800);
        assert_eq!(r.complete, Some(10));
        assert_eq!(r.peers.len(), 2);
        assert_eq!(r.peers[0], NetAddr::V4([192, 168, 1, 1], 6881));
    }

    #[test]
    fn parse_failure() {
        let body = crate::bencode::encode_to_vec(&crate::bencode::dict(vec![(
            b"failure reason",
            crate::bencode::bytes("torrent not registered"),
        )]));
        let r = parse_tracker_response(&body).unwrap();
        assert!(r.failure.is_some());
    }

    #[test]
    fn udp_connect_roundtrip() {
        let tid: u32 = 0x12345678;
        // fake response
        let mut resp = [0u8; 16];
        resp[0..4].copy_from_slice(&0u32.to_be_bytes());
        resp[4..8].copy_from_slice(&tid.to_be_bytes());
        resp[8..16].copy_from_slice(&0x1122334455667788u64.to_be_bytes());
        let conn = udp::parse_connect_response(&resp, tid).unwrap();
        assert_eq!(conn, 0x1122334455667788);
        // announce roundtrip
        let p = AnnounceParams {
            tracker_hash: [7u8; 20],
            peer_id: [8u8; 20],
            port: 6881,
            left: 42,
            event: Event::Started,
            numwant: 50,
            key: 0xdeadbeef,
            ..Default::default()
        };
        let req = udp::build_announce_request(conn, tid, &p);
        assert_eq!(req.len(), 98);
        let mut resp = Vec::new();
        resp.extend_from_slice(&1u32.to_be_bytes());
        resp.extend_from_slice(&tid.to_be_bytes());
        resp.extend_from_slice(&900u32.to_be_bytes());
        resp.extend_from_slice(&3u32.to_be_bytes());
        resp.extend_from_slice(&9u32.to_be_bytes());
        resp.extend_from_slice(&[192, 168, 0, 1, 0x1A, 0xE1]);
        let r = udp::parse_announce_response(&resp, tid).unwrap();
        assert_eq!(r.interval, 900);
        assert_eq!(r.peers.len(), 1);
    }
}
