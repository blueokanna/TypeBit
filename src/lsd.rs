//! Local Service Discovery (LSD, BEP-14).
//!
//! Announces our presence in active swarms to neighbours on the same LAN
//! over UDP multicast, and answers their announces. This is the standard
//! way LAN-local peers (same office / home network / campus) find each
//! other without any internet tracker or DHT.
//!
//! Protocol (from the BEP):
//! ```text
//! BT-SEARCH * HTTP/1.1\r\n
//! Host: <multicast group>\r\n
//! Port: <bt listen port>\r\n
//! Infohash: <40-hex infohash>\r\n
//! cookie: <opaque hex, optional>\r\n
//! \r\n
//! ```
//! A client that has the announced torrent replies with the same shape
//! (its own `Port`, the same infohash) sent **unicast** to the source
//! address of the announce. The peer address is `source IP : Port header`.
//!
//! Usage rules we follow: at most one announce per minute, round-robin the
//! active torrents so each is re-announced every ~5 minutes.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

/// IPv4 LSD multicast group (org-local scope).
pub const LSD_GROUP_V4: crate::platform::NetAddr =
    crate::platform::NetAddr::V4([239, 192, 152, 143], 6771);
/// IPv6 LSD multicast group (site-local scope).
pub const LSD_GROUP_V6: crate::platform::NetAddr = crate::platform::NetAddr::V6(
    [
        0xff, 0x15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xef, 0xc0, 0x98, 0x8f,
    ],
    6771,
);
/// LSD announce interval (ms) — one announce per minute max.
pub const LSD_INTERVAL_MS: u64 = 60_000;

/// One parsed LSD announce.
#[derive(Debug, Clone)]
pub struct LsdAnnounce {
    /// The announcing peer's BitTorrent listen port (from the `Port` header).
    pub port: u16,
    /// Opaque sender cookie (from the `cookie` header), if present. Used to
    /// filter our own multicast echoes.
    pub cookie: Option<[u8; 8]>,
    /// Announced infohashes (one or more `Infohash` headers).
    pub infohashes: Vec<[u8; 20]>,
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decode a hex string into bytes. `None` on odd length or invalid chars.
fn hex_decode(s: &[u8]) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.chunks_exact(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

/// Encode bytes as lowercase hex (no alloc::format dependency needed).
fn hex_encode(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0xf) as usize] as char);
    }
    s
}

/// Build a BT-SEARCH announce / response packet for one infohash.
/// A response carries the same shape, sent unicast to the requester.
pub fn build_announce(infohash: &[u8; 20], port: u16, cookie: Option<&[u8; 8]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"BT-SEARCH * HTTP/1.1\r\n");
    // Host header: the multicast group (matching what we send to / joined).
    out.extend_from_slice(b"Host: 239.192.152.143\r\n");
    out.extend_from_slice(b"Port: ");
    out.extend_from_slice(port.to_string().as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(b"Infohash: ");
    out.extend_from_slice(hex_encode(infohash).as_bytes());
    out.extend_from_slice(b"\r\n");
    if let Some(c) = cookie {
        out.extend_from_slice(b"cookie: ");
        out.extend_from_slice(hex_encode(c).as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Parse a received BT-SEARCH datagram. Returns `None` for anything that
/// is not a well-formed LSD announce.
pub fn parse(data: &[u8]) -> Option<LsdAnnounce> {
    if !data.starts_with(b"BT-SEARCH") {
        return None;
    }
    // Split on CRLF (tolerate bare LF too).
    let mut port: Option<u16> = None;
    let mut cookie: Option<[u8; 8]> = None;
    let mut infohashes: Vec<[u8; 20]> = Vec::new();
    let mut first = true;
    for line in data.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if first {
            first = false;
            continue; // "BT-SEARCH * HTTP/1.1"
        }
        if line.is_empty() {
            continue;
        }
        // Header: "Name: value"
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = &line[..colon];
        let value = line[colon + 1..]
            .iter()
            .copied()
            .skip_while(|&b| b == b' ' || b == b'\t')
            .collect::<Vec<u8>>();
        match name {
            b"Port" => {
                if port.is_none() {
                    let s = core::str::from_utf8(&value).ok()?;
                    port = s.trim().parse::<u16>().ok();
                }
            }
            b"cookie" => {
                if cookie.is_none() {
                    if let Some(dec) = hex_decode(&value) {
                        if dec.len() == 8 {
                            let mut c = [0u8; 8];
                            c.copy_from_slice(&dec);
                            cookie = Some(c);
                        }
                    }
                }
            }
            b"Infohash" => {
                if let Some(dec) = hex_decode(&value) {
                    if dec.len() == 20 {
                        let mut ih = [0u8; 20];
                        ih.copy_from_slice(&dec);
                        infohashes.push(ih);
                    }
                }
            }
            _ => {}
        }
    }
    if port.is_none() || infohashes.is_empty() {
        return None;
    }
    Some(LsdAnnounce {
        port: port?,
        cookie,
        infohashes,
    })
}

/// Round-robin announce scheduler state (one announce per
/// [`LSD_INTERVAL_MS`], each active torrent re-announced every
/// `active_count` intervals, matching BEP-14's "~5 minutes per torrent").
#[derive(Debug)]
pub struct LsdScheduler {
    /// Opaque cookie used to recognise our own multicast echoes.
    pub cookie: [u8; 8],
    /// Last announce time (ms).
    pub last_announce_at: u64,
    /// Round-robin cursor over the active infohash list.
    pub cursor: usize,
}

impl LsdScheduler {
    /// Create a scheduler with a fresh opaque cookie; the first announce
    /// is allowed immediately.
    pub fn new(cookie: [u8; 8], now: u64) -> Self {
        LsdScheduler {
            cookie,
            last_announce_at: now.saturating_sub(LSD_INTERVAL_MS),
            cursor: 0,
        }
    }

    /// Pick the next infohash to announce, if enough time has passed.
    /// Returns `None` when we must stay quiet (rate limit).
    pub fn next_announce<'a>(&mut self, active: &'a [[u8; 20]], now: u64) -> Option<&'a [u8; 20]> {
        if active.is_empty() {
            return None;
        }
        if now.saturating_sub(self.last_announce_at) < LSD_INTERVAL_MS {
            return None;
        }
        let ih = &active[self.cursor % active.len()];
        self.cursor += 1;
        self.last_announce_at = now;
        Some(ih)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn announce_roundtrip() {
        let ih = [7u8; 20];
        let cookie = [0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4];
        let msg = build_announce(&ih, 6881, Some(&cookie));
        assert!(msg.starts_with(b"BT-SEARCH * HTTP/1.1\r\n"));
        assert!(msg.windows(10).any(|w| w == b"Port: 6881"));
        assert!(msg.windows(12).any(|w| w == b"Infohash: 07"));

        let parsed = parse(&msg).expect("parse");
        assert_eq!(parsed.port, 6881);
        assert_eq!(parsed.cookie, Some(cookie));
        assert_eq!(parsed.infohashes, vec![[7u8; 20]]);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(parse(b"BT-SEARCH * HTTP/1.1\r\n\r\n").is_none());
        assert!(parse(b"").is_none());
    }

    #[test]
    fn multiple_infohashes_are_parsed() {
        let ih1 = [1u8; 20];
        let ih2 = [2u8; 20];
        let mut msg = build_announce(&ih1, 6881, None);
        // append a second Infohash header before the final blank line
        let tail = msg.split_off(msg.len() - 2);
        msg.extend_from_slice(b"Infohash: ");
        msg.extend_from_slice(hex_encode(&ih2).as_bytes());
        msg.extend_from_slice(b"\r\n");
        msg.extend_from_slice(&tail);
        let parsed = parse(&msg).expect("parse");
        assert_eq!(parsed.infohashes, vec![ih1, ih2]);
    }

    #[test]
    fn scheduler_rate_limits() {
        let cookie = [0u8; 8];
        let mut s = LsdScheduler::new(cookie, 1_000_000);
        let active = [[1u8; 20], [2u8; 20]];
        // First call announces (interval elapsed via the constructor).
        assert!(s.next_announce(&active, 1_000_000).is_some());
        // Immediately again → rate limited.
        assert!(s.next_announce(&active, 1_000_001).is_none());
        // After one minute → next torrent (round-robin).
        let ih = s.next_announce(&active, 1_060_001);
        assert_eq!(ih, Some(&[2u8; 20]));
    }
}
