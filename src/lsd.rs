//! Local Service Discovery (LSD, BEP-14): announce our presence in active
//! swarms to LAN neighbours over UDP multicast, and answer their announces
//! — no internet tracker or DHT needed.
//!
//! Protocol:
//! ```text
//! BT-SEARCH * HTTP/1.1\r\n
//! Host: <multicast group>\r\n
//! Port: <bt listen port>\r\n
//! Infohash: <40-hex infohash>\r\n
//! cookie: <opaque hex, optional>\r\n
//! \r\n
//! ```
//! A client that has the torrent replies **unicast** to the announce source.
//! We announce at most once per minute, round-robining torrents (~5 min each).

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
/// Fixed LSD (BEP-14) UDP port. LSD announces are sent to
/// `<group>:6771`, so a client MUST have a socket bound to this port to
/// receive LAN announces — binding to the BT listen port (like DHT) misses
/// them.
pub const LSD_PORT: u16 = 6771;
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
/// Default LSD announce interval (ms) — one announce per minute max
/// (BEP-14's hard floor for the whole client). Torrents are round-robined
/// one per interval, so each active torrent is re-announced every
/// `active_count` intervals (~5 minutes with 5 active torrents, matching
/// BEP-14's "≈5 minutes per torrent").
pub const LSD_INTERVAL_MS: u64 = 60_000;
/// Absolute lower bound for the LSD announce interval (ms): a config cannot
/// push the LAN broadcast faster than this — the multicast group is shared
/// and bursts would be network noise (mechanism 4's hard timer).
pub const LSD_INTERVAL_MIN_MS: u64 = 30_000;
/// Minimum gap (ms) between two unicast **replies** to the same neighbour
/// (mechanism 4, anti-amplification): a hostile LAN peer can otherwise use
/// our multicast group as a reflector by blasting `BT-SEARCH` datagrams at
/// us with a victim's spoofed source address.
pub const LSD_REPLY_GAP_MS: u64 = 10_000;
/// Maximum number of infohashes announced in one immediate burst when the
/// active set changes (a torrent started / just completed). Bounded so a
/// client with dozens of torrents does not flood the LAN multicast group on
/// every state flip; steady state stays at one hash per interval.
pub const LSD_ANNOUNCE_BURST_MAX: usize = 20;

/// **LAN-aware adaptive pacing.** A neighbour heard within this window (ms)
/// proves the LAN is live — the effective announce interval drops to
/// [`LSD_ACTIVE_INTERVAL_MS`] so a freshly-added torrent reaches the
/// listening neighbour within seconds (mutual discovery latency is the
/// whole point of LSD). When no neighbour has been heard for this long, the
/// LAN is treated as quiet and the standard interval applies — we do not
/// spam a dead network.
pub const LSD_NEIGHBOR_WINDOW_MS: u64 = 90_000;
/// Effective announce interval (ms) while a LAN neighbour is live. Bounded
/// by the same hard floor reasoning as [`LSD_INTERVAL_MIN_MS`] — never a
/// storm, just noticeably faster mutual discovery.
pub const LSD_ACTIVE_INTERVAL_MS: u64 = 20_000;

/// Upper bound on infohashes accepted from a single announce datagram.
pub const MAX_INFOHASHES_PER_ANNOUNCE: usize = 32;

/// The `Host:` header value for the LSD multicast group (no port — the
/// listen port is a separate `Port` header).
fn host_header(group: crate::platform::NetAddr) -> String {
    match group {
        crate::platform::NetAddr::V4(ip, _) => {
            let mut s = String::with_capacity(15);
            for (i, o) in ip.iter().enumerate() {
                if i > 0 {
                    s.push('.');
                }
                s.push_str(&o.to_string());
            }
            s
        }
        crate::platform::NetAddr::V6(ip, _) => {
            let mut s = String::with_capacity(39);
            s.push('[');
            for (i, g) in ip.chunks(2).enumerate() {
                if i > 0 {
                    s.push(':');
                }
                let v = u16::from_be_bytes([g[0], g[1]]);
                // RFC 5952: each group is lowercase hex with no leading zeros.
                s.push_str(&alloc::format!("{:x}", v));
            }
            s.push(']');
            s
        }
    }
}

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
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    // Length is guaranteed even above, so `as_chunks` never truncates.
    for pair in s.as_chunks::<2>().0 {
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
/// `group` is the multicast group the announce targets — the `Host` header
/// must match its address family (v4 group → dotted quad, v6 → bracketed
/// group).
pub fn build_announce(
    infohash: &[u8; 20],
    port: u16,
    cookie: Option<&[u8; 8]>,
    group: crate::platform::NetAddr,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"BT-SEARCH * HTTP/1.1\r\n");
    out.extend_from_slice(b"Host: ");
    out.extend_from_slice(host_header(group).as_bytes());
    out.extend_from_slice(b"\r\n");
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
                if infohashes.len() >= MAX_INFOHASHES_PER_ANNOUNCE {
                    continue; // ignore excess infohashes (flood bound)
                }
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

/// Round-robin announce scheduler state (one announce per configured
/// interval, each active torrent re-announced every `active_count`
/// intervals, matching BEP-14's "~5 minutes per torrent"). The interval is
/// configurable but clamped to a hard floor ([`LSD_INTERVAL_MIN_MS`]) so a
/// config can never turn the LAN broadcast into a storm.
///
/// The scheduler supports **LAN-aware adaptive pacing**: when a live
/// neighbour has been heard recently, the effective interval drops to
/// [`LSD_ACTIVE_INTERVAL_MS`] so a freshly-added torrent reaches the
/// listening neighbour within seconds; when the LAN is quiet, the standard
/// interval applies and we do not spam a dead network.
#[derive(Debug)]
pub struct LsdScheduler {
    /// Opaque cookie used to recognise our own multicast echoes.
    pub cookie: [u8; 8],
    /// Announce interval (ms), clamped to [`LSD_INTERVAL_MIN_MS`].
    pub interval_ms: u64,
    /// Last announce time (ms).
    pub last_announce_at: u64,
    /// Round-robin cursor over the active infohash list.
    pub cursor: usize,
}

impl LsdScheduler {
    /// Create a scheduler with a fresh opaque cookie; the first announce
    /// is allowed immediately. `interval_ms` is clamped to the hard floor.
    pub fn new(cookie: [u8; 8], now: u64, interval_ms: u64) -> Self {
        LsdScheduler {
            cookie,
            interval_ms: interval_ms.max(LSD_INTERVAL_MIN_MS),
            last_announce_at: now.saturating_sub(interval_ms),
            cursor: 0,
        }
    }

    /// Whether an announce is due at the scheduler's base interval.
    pub fn due(&self, now: u64) -> bool {
        self.due_with(now, self.interval_ms)
    }

    /// Whether an announce is due at a specific effective interval.
    pub fn due_with(&self, now: u64, interval_ms: u64) -> bool {
        now.saturating_sub(self.last_announce_at) >= interval_ms
    }

    /// Pick the next infohash to announce at the base interval.
    pub fn next_announce<'a>(&mut self, active: &'a [[u8; 20]], now: u64) -> Option<&'a [u8; 20]> {
        self.next_announce_with(active, now, self.interval_ms)
    }

    /// Pick the next infohash to announce at a specific effective interval.
    /// Returns `None` when we must stay quiet (rate limit).
    pub fn next_announce_with<'a>(
        &mut self,
        active: &'a [[u8; 20]],
        now: u64,
        interval_ms: u64,
    ) -> Option<&'a [u8; 20]> {
        if active.is_empty() {
            return None;
        }
        if now.saturating_sub(self.last_announce_at) < interval_ms {
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
        let msg = build_announce(&ih, 6881, Some(&cookie), LSD_GROUP_V4);
        assert!(msg.starts_with(b"BT-SEARCH * HTTP/1.1\r\n"));
        assert!(msg.windows(10).any(|w| w == b"Port: 6881"));
        assert!(msg.windows(12).any(|w| w == b"Infohash: 07"));

        let parsed = parse(&msg).expect("parse");
        assert_eq!(parsed.port, 6881);
        assert_eq!(parsed.cookie, Some(cookie));
        assert_eq!(parsed.infohashes, vec![[7u8; 20]]);
    }

    #[test]
    fn host_header_matches_group_family() {
        let ih = [1u8; 20];
        let raw4 = build_announce(&ih, 6881, None, LSD_GROUP_V4);
        let v4 = String::from_utf8_lossy(&raw4);
        assert!(
            v4.contains("Host: 239.192.152.143"),
            "v4 announce must carry the v4 group Host, got {v4:?}"
        );
        let raw6 = build_announce(&ih, 6881, None, LSD_GROUP_V6);
        let v6 = String::from_utf8_lossy(&raw6);
        assert!(
            v6.contains("Host: [ff15:0:0:0:0:0:efc0:988f]"),
            "v6 announce must carry the v6 group Host, got {v6:?}"
        );
    }

    #[test]
    fn infohash_cap_bounds_parsing() {
        // A single datagram must not force us to parse an unbounded number
        // of infohashes (LAN flood / amplification bound).
        let mut msg = Vec::new();
        msg.extend_from_slice(b"BT-SEARCH * HTTP/1.1\r\nPort: 6881\r\n");
        let n = MAX_INFOHASHES_PER_ANNOUNCE + 64;
        for i in 0..n {
            let ih = [i as u8; 20];
            msg.extend_from_slice(b"Infohash: ");
            msg.extend_from_slice(hex_encode(&ih).as_bytes());
            msg.extend_from_slice(b"\r\n");
        }
        msg.extend_from_slice(b"\r\n");
        let parsed = parse(&msg).expect("parse");
        assert_eq!(
            parsed.infohashes.len(),
            MAX_INFOHASHES_PER_ANNOUNCE,
            "excess infohashes must be dropped"
        );
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
        let mut msg = build_announce(&ih1, 6881, None, LSD_GROUP_V4);
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
        let mut s = LsdScheduler::new(cookie, 1_000_000, 60_000);
        let active = [[1u8; 20], [2u8; 20]];
        // First call announces (interval elapsed via the constructor).
        assert!(s.next_announce(&active, 1_000_000).is_some());
        // Immediately again → rate limited.
        assert!(s.next_announce(&active, 1_000_001).is_none());
        // After one minute → next torrent (round-robin).
        let ih = s.next_announce(&active, 1_060_001);
        assert_eq!(ih, Some(&[2u8; 20]));
    }

    #[test]
    fn scheduler_interval_is_floored() {
        let cookie = [0u8; 8];
        // A config of 5 s must be clamped to the 30 s hard floor.
        let mut s = LsdScheduler::new(cookie, 1_000_000, 5_000);
        assert_eq!(s.interval_ms, LSD_INTERVAL_MIN_MS);
        // Still rate-limited after 20 s (< 30 s floor).
        assert!(s.next_announce(&active_two(), 1_020_000).is_none());
        // Due after the floor.
        assert!(s.next_announce(&active_two(), 1_031_000).is_some());
    }

    #[test]
    fn adaptive_interval_allows_faster_announce_when_neighbour_active() {
        let cookie = [0u8; 8];
        let mut s = LsdScheduler::new(cookie, 1_000_000, LSD_INTERVAL_MS);
        let active = active_two();

        // Base interval (60 s) not yet elapsed 30 s after the last announce
        // (the constructor back-dated it, so the first call fires).
        assert!(s.next_announce(&active, 1_000_000).is_some());

        // 20 s later the base interval has NOT elapsed → quiet at base.
        assert!(!s.due_with(1_020_000, LSD_INTERVAL_MS));
        // …but a live neighbour makes the effective interval 20 s → due.
        assert!(s.due_with(1_020_000, LSD_ACTIVE_INTERVAL_MS));
        let ih = s.next_announce_with(&active, 1_020_000, LSD_ACTIVE_INTERVAL_MS);
        assert_eq!(ih, Some(&[2u8; 20]));

        // After announcing at the active interval, the hard floor still
        // applies: 10 s later is not due even with a live neighbour.
        assert!(!s.due_with(1_030_000, LSD_ACTIVE_INTERVAL_MS));
        // 20 s after the announce → due again.
        assert!(s.due_with(1_040_000, LSD_ACTIVE_INTERVAL_MS));
    }

    fn active_two() -> [[u8; 20]; 2] {
        [[1u8; 20], [2u8; 20]]
    }
}
