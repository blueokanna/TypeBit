//! Anti-leech engine: client fingerprinting, per-peer reputation,
//! reciprocity-aware choke scoring (tit-for-tat), snub handling, corrupt
//! accountability with bans, optimistic unchoke rotation, anti-flap.
//!
//! Behavior-first: client identity is a *soft* signal; hard consequences
//! (bans, disconnects) come only from measured misbehavior. Depends only
//! on [`crate::platform`], so algorithms are unit-testable in isolation.

use crate::platform::{ConnId, NetAddr};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Client fingerprinting
// ---------------------------------------------------------------------------

/// Soft client classification from the peer id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientClass {
    /// A mainstream, generally fair client.
    Standard,
    /// An aggressive / historically asymmetric client (softly deprioritized).
    Leech,
    /// Unidentified.
    Unknown,
}

/// A fingerprinted client identity (peer-id prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientId {
    /// Up to 4 ASCII code bytes (e.g. `qB`, `TR`, `XL`).
    code: [u8; 4],
    /// Number of code bytes in use.
    code_len: u8,
    /// Classification.
    class: ClientClass,
}

impl ClientId {
    fn new(code: &[u8], class: ClientClass) -> Self {
        let mut c = [b'?'; 4];
        let n = code.len().min(4);
        c[..n].copy_from_slice(&code[..n]);
        ClientId {
            code: c,
            code_len: n as u8,
            class,
        }
    }

    /// The client code as a string (e.g. `"qB"`).
    pub fn code_str(&self) -> alloc::string::String {
        alloc::string::String::from_utf8_lossy(&self.code[..self.code_len as usize]).into_owned()
    }

    /// The classification.
    pub fn class(&self) -> ClientClass {
        self.class
    }
}

/// Fingerprint a 20-byte peer id into a [`ClientId`].
///
/// Recognizes the two dominant encodings:
/// * Azureus-style `-XX####-...` (qBittorrent, Transmission, libtorrent,
///   uTorrent, BitComet, Xunlei, …);
/// * Shadow/BitTornado-style `X####...` (mainline, BitTornado, …);
/// * the modern Xunlei family starting with `7` + digits.
pub fn fingerprint(peer_id: &[u8; 20]) -> ClientId {
    if peer_id[0] == b'-' {
        return ClientId::new(&peer_id[1..5], classify(&peer_id[1..5]));
    }
    if peer_id[0].is_ascii_alphabetic() && peer_id[1].is_ascii_alphanumeric() {
        return ClientId::new(&peer_id[0..2], classify(&peer_id[0..2]));
    }
    if peer_id[0] == b'7' && peer_id[1].is_ascii_digit() {
        return ClientId::new(b"7XL", ClientClass::Leech);
    }
    ClientId::new(b"????", ClientClass::Unknown)
}

fn classify(code: &[u8]) -> ClientClass {
    let two = code.get(0..2);
    match two {
        // Aggressive / historically asymmetric clients (soft deprioritization).
        Some([b'X', b'L']) | Some([b'S', b'D']) | Some([b'Q', b'D']) | Some([b'F', b'G'])
        | Some([b'7', b'X']) => ClientClass::Leech,
        // Mainstream, generally fair clients.
        Some([b'q', b'B']) | Some([b'T', b'R']) | Some([b'L', b'T']) | Some([b'A', b'R'])
        | Some([b'R', b'T']) | Some([b'D', b'E']) | Some([b'U', b'T']) | Some([b'B', b'C'])
        | Some([b'T', b'S']) | Some([b'F', b'D']) | Some([b'B', b'E']) | Some([b'A', b'B'])
        | Some([b'A', b'Z']) | Some([b'K', b'T']) | Some([b'l', b't']) | Some([b'M', b'P'])
        | Some([b'X', b'T']) | Some([b'W', b'W']) | Some([b'M', b'4']) | Some([b'M', b'5'])
        | Some([b'M', b'7']) | Some([b'S', b'3']) | Some([b'T', b'3']) | Some([b'A', b'2'])
        | Some([b'O', b'3']) => ClientClass::Standard,
        _ => ClientClass::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Per-peer reputation
// ---------------------------------------------------------------------------

/// Behavior ledger attached to every [`Peer`](crate::swarm::Peer).
#[derive(Debug, Clone, Default)]
pub struct PeerReputation {
    /// Fingerprinted client (set after handshake).
    pub client: Option<ClientId>,
    /// Weighted count of corrupt blocks attributed to this peer.
    pub corrupt_blocks: u32,
    /// Count of protocol violations (malformed frames, bad requests…).
    pub protocol_violations: u32,
}

// ---------------------------------------------------------------------------
// Ban manager
// ---------------------------------------------------------------------------

/// Why a peer was banned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanReason {
    /// Repeatedly supplied corrupt blocks.
    Corrupt,
    /// Repeated protocol violations.
    Protocol,
    /// Reserved for explicit free-rider bans.
    FreeRide,
}

#[derive(Debug, Clone, Copy)]
struct BanEntry {
    until: u64,
    reason: BanReason,
}

/// Time-boxed ban list keyed by address and (when known) peer id.
///
/// Growth is bounded by `max` entries; expired entries are removed by
/// [`BanManager::sweep`] (called from the session tick).
#[derive(Debug)]
pub struct BanManager {
    by_addr: BTreeMap<NetAddr, BanEntry>,
    by_peer: BTreeMap<[u8; 20], BanEntry>,
    max: usize,
}

impl Default for BanManager {
    fn default() -> Self {
        BanManager::new(4096)
    }
}

impl BanManager {
    /// Create an empty manager that refuses to grow past `max` entries.
    pub fn new(max: usize) -> Self {
        BanManager {
            by_addr: BTreeMap::new(),
            by_peer: BTreeMap::new(),
            max: max.max(1),
        }
    }

    /// Ban `addr` (and optionally `peer_id`) for `ttl_ms`. Returns `true`
    /// when a new entry was added (the caller decides whether to disconnect).
    pub fn ban(
        &mut self,
        addr: NetAddr,
        peer_id: Option<&[u8; 20]>,
        ttl_ms: u64,
        reason: BanReason,
        now: u64,
    ) -> bool {
        if ttl_ms == 0 {
            return false;
        }
        let until = now.saturating_add(ttl_ms);
        let mut added = false;
        if self.by_addr.len() < self.max || self.by_addr.contains_key(&addr) {
            self.by_addr.insert(addr, BanEntry { until, reason });
            added = true;
        }
        if let Some(pid) = peer_id {
            if self.by_peer.len() < self.max || self.by_peer.contains_key(pid) {
                self.by_peer.insert(*pid, BanEntry { until, reason });
                added = true;
            }
        }
        added
    }

    /// Whether `addr` is currently banned.
    pub fn is_banned(&self, addr: &NetAddr, now: u64) -> bool {
        self.by_addr
            .get(addr)
            .map(|e| e.until > now)
            .unwrap_or(false)
    }

    /// The reason `addr` is banned, if it is currently banned.
    pub fn reason_of(&self, addr: &NetAddr, now: u64) -> Option<BanReason> {
        self.by_addr
            .get(addr)
            .filter(|e| e.until > now)
            .map(|e| e.reason)
    }

    /// Whether `peer_id` is currently banned.
    pub fn peer_id_banned(&self, peer_id: &[u8; 20], now: u64) -> bool {
        self.by_peer
            .get(peer_id)
            .map(|e| e.until > now)
            .unwrap_or(false)
    }

    /// Number of live ban entries.
    pub fn len(&self) -> usize {
        self.by_addr.len() + self.by_peer.len()
    }

    /// Whether there are no live ban entries.
    pub fn is_empty(&self) -> bool {
        self.by_addr.is_empty() && self.by_peer.is_empty()
    }

    /// Drop expired entries.
    pub fn sweep(&mut self, now: u64) {
        self.by_addr.retain(|_, e| e.until > now);
        self.by_peer.retain(|_, e| e.until > now);
    }

    /// Remove every ban.
    pub fn clear(&mut self) {
        self.by_addr.clear();
        self.by_peer.clear();
    }
}

// ---------------------------------------------------------------------------
// Persistent reputation store
// ---------------------------------------------------------------------------

/// One peer's accumulated behavior ledger, keyed by both address and peer
/// id. Lives across disconnects (and, via [`ReputationStore::encode`], across
/// sessions) so a repeat offender is re-penalized immediately when it
/// returns instead of starting from a clean slate.
///
/// Growth is bounded by `cap` (oldest entries are evicted) and entries age
/// out after `ttl_ms` of inactivity.
#[derive(Debug, Clone)]
pub struct ReputationStore {
    by_addr: BTreeMap<NetAddr, RepEntry>,
    by_peer: BTreeMap<[u8; 20], RepEntry>,
    cap: usize,
    ttl_ms: u64,
}

/// Behavior counters for one identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RepEntry {
    /// Attributed corrupt blocks (lifetime).
    corrupt: u32,
    /// Protocol violations (lifetime).
    violations: u32,
    /// Distinct incidents (for diagnostics / future escalation).
    incidents: u16,
    /// Last observed time (ms); entries idle past `ttl` are swept.
    last_seen: u64,
}

impl ReputationStore {
    /// Create a store bounded at `cap` entries; entries idle past `ttl_ms`
    /// are removed by [`ReputationStore::sweep`].
    pub fn new(cap: usize, ttl_ms: u64) -> Self {
        ReputationStore {
            by_addr: BTreeMap::new(),
            by_peer: BTreeMap::new(),
            cap: cap.max(1),
            ttl_ms,
        }
    }

    /// Record a successful handshake (refreshes `last_seen`).
    pub fn note_handshake(&mut self, addr: NetAddr, peer_id: &[u8; 20], now: u64) {
        self.touch(addr, now);
        self.touch_peer(peer_id, now);
    }

    /// Add `delta` corrupt blocks for this identity; returns the new total
    /// for the peer id (0 when the peer id is unknown — shouldn't happen).
    pub fn note_corrupt(
        &mut self,
        addr: NetAddr,
        peer_id: Option<&[u8; 20]>,
        delta: u32,
        now: u64,
    ) -> u32 {
        if delta == 0 {
            return 0;
        }
        let mut total = 0u32;
        {
            let e = self.entry_mut(addr);
            e.corrupt = e.corrupt.saturating_add(delta);
            e.incidents = e.incidents.saturating_add(1);
            e.last_seen = now;
        }
        if let Some(pid) = peer_id {
            let e = self.peer_entry_mut(pid);
            e.corrupt = e.corrupt.saturating_add(delta);
            e.incidents = e.incidents.saturating_add(1);
            e.last_seen = now;
            total = e.corrupt;
        }
        total
    }

    /// Record a protocol violation for this identity.
    pub fn note_violation(&mut self, addr: NetAddr, peer_id: Option<&[u8; 20]>, now: u64) {
        let e = self.entry_mut(addr);
        e.violations = e.violations.saturating_add(1);
        e.incidents = e.incidents.saturating_add(1);
        e.last_seen = now;
        if let Some(pid) = peer_id {
            let e = self.peer_entry_mut(pid);
            e.violations = e.violations.saturating_add(1);
            e.incidents = e.incidents.saturating_add(1);
            e.last_seen = now;
        }
    }

    /// Stored `(corrupt, violations)` for a peer id, if any.
    pub fn stored_for(&self, peer_id: &[u8; 20]) -> Option<(u32, u32)> {
        self.by_peer.get(peer_id).map(|e| (e.corrupt, e.violations))
    }

    /// Stored `(corrupt, violations)` for an address, if any.
    pub fn stored_addr(&self, addr: &NetAddr) -> Option<(u32, u32)> {
        self.by_addr.get(addr).map(|e| (e.corrupt, e.violations))
    }

    /// Number of live entries.
    pub fn len(&self) -> usize {
        self.by_addr.len() + self.by_peer.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.by_addr.is_empty() && self.by_peer.is_empty()
    }

    /// Forget entries idle for longer than the TTL.
    pub fn sweep(&mut self, now: u64) {
        let ttl = self.ttl_ms;
        self.by_addr
            .retain(|_, e| now.saturating_sub(e.last_seen) < ttl);
        self.by_peer
            .retain(|_, e| now.saturating_sub(e.last_seen) < ttl);
    }

    /// Forget everything.
    pub fn clear(&mut self) {
        self.by_addr.clear();
        self.by_peer.clear();
    }

    /// Serialize deterministically (BTreeMap iteration is key-ordered) for
    /// persistence in the session state. Versioned + magic-prefixed so
    /// future formats can migrate and foreign bytes are rejected.
    pub fn encode(&self) -> Vec<u8> {
        const MAGIC: &[u8; 5] = b"TBREP";
        let mut out = Vec::with_capacity(64 + 37 * (self.by_addr.len() + self.by_peer.len()));
        out.extend_from_slice(MAGIC);
        out.push(1); // format version
        out.extend_from_slice(&(self.cap as u32).to_le_bytes());
        out.extend_from_slice(&self.ttl_ms.to_le_bytes());
        out.extend_from_slice(&(self.by_addr.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.by_peer.len() as u32).to_le_bytes());
        for (addr, e) in &self.by_addr {
            push_addr(&mut out, *addr);
            push_entry(&mut out, e);
        }
        for (pid, e) in &self.by_peer {
            out.push(20);
            out.extend_from_slice(pid);
            push_entry(&mut out, e);
        }
        out
    }

    /// Parse bytes produced by [`ReputationStore::encode`]. Returns `None`
    /// on any malformed input (never panics, never trusts lengths blindly).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        const MAGIC: &[u8; 5] = b"TBREP";
        if bytes.len() < 5 + 1 + 4 + 8 + 4 + 4 || &bytes[..5] != MAGIC || bytes[5] != 1 {
            return None;
        }
        let mut off = 6usize;
        let cap = rd_u32(bytes, &mut off)? as usize;
        let ttl = rd_u64(bytes, &mut off)?;
        let na = rd_u32(bytes, &mut off)? as usize;
        let np = rd_u32(bytes, &mut off)? as usize;
        // sanity: reject absurd counts before looping
        if na.saturating_add(np) > cap.saturating_mul(2) + 1024 {
            return None;
        }
        let mut store = ReputationStore::new(cap.max(1), ttl);
        for _ in 0..na {
            let addr = rd_addr(bytes, &mut off)?;
            let e = rd_entry(bytes, &mut off)?;
            if store.by_addr.len() < store.cap {
                store.by_addr.insert(addr, e);
            }
        }
        for _ in 0..np {
            if bytes.get(off) != Some(&20) {
                return None;
            }
            off += 1;
            let pid: [u8; 20] = bytes.get(off..off + 20)?.try_into().ok()?;
            off += 20;
            let e = rd_entry(bytes, &mut off)?;
            if store.by_peer.len() < store.cap {
                store.by_peer.insert(pid, e);
            }
        }
        Some(store)
    }

    /// Insert-or-refresh an address entry, enforcing the cap (oldest first).
    fn entry_mut(&mut self, addr: NetAddr) -> &mut RepEntry {
        if !self.by_addr.contains_key(&addr) && self.by_addr.len() >= self.cap {
            self.evict_oldest_addr();
        }
        self.by_addr.entry(addr).or_insert(RepEntry {
            corrupt: 0,
            violations: 0,
            incidents: 0,
            last_seen: 0,
        })
    }

    /// Insert-or-refresh a peer-id entry, enforcing the cap.
    fn peer_entry_mut(&mut self, pid: &[u8; 20]) -> &mut RepEntry {
        if !self.by_peer.contains_key(pid) && self.by_peer.len() >= self.cap {
            self.evict_oldest_peer();
        }
        self.by_peer.entry(*pid).or_insert(RepEntry {
            corrupt: 0,
            violations: 0,
            incidents: 0,
            last_seen: 0,
        })
    }

    fn touch(&mut self, addr: NetAddr, now: u64) {
        self.entry_mut(addr).last_seen = now;
    }

    fn touch_peer(&mut self, pid: &[u8; 20], now: u64) {
        self.peer_entry_mut(pid).last_seen = now;
    }

    /// Drop the least-recently-seen address entry (bounded linear scan;
    /// insertions past the cap are rare, the map is small in practice).
    fn evict_oldest_addr(&mut self) {
        let oldest = self
            .by_addr
            .iter()
            .min_by_key(|(_, e)| e.last_seen)
            .map(|(a, _)| *a);
        if let Some(a) = oldest {
            self.by_addr.remove(&a);
        }
    }

    fn evict_oldest_peer(&mut self) {
        let oldest = self
            .by_peer
            .iter()
            .min_by_key(|(_, e)| e.last_seen)
            .map(|(p, _)| *p);
        if let Some(p) = oldest {
            self.by_peer.remove(&p);
        }
    }
}

impl Default for ReputationStore {
    fn default() -> Self {
        ReputationStore::new(8192, 7 * 24 * 3600 * 1000)
    }
}

// -- fixed-size binary codec helpers (no allocator surprises, no panics) --

fn push_addr(out: &mut Vec<u8>, a: NetAddr) {
    match a {
        NetAddr::V4(ip, port) => {
            out.push(0);
            out.extend_from_slice(&[0u8; 12]);
            out.extend_from_slice(&ip);
            out.extend_from_slice(&port.to_le_bytes());
        }
        NetAddr::V6(ip, port) => {
            out.push(1);
            out.extend_from_slice(&ip);
            out.extend_from_slice(&port.to_le_bytes());
        }
    }
}

fn rd_addr(bytes: &[u8], off: &mut usize) -> Option<NetAddr> {
    let fam = *bytes.get(*off)?;
    *off += 1;
    match fam {
        0 => {
            let ip: [u8; 4] = bytes.get(*off + 12..*off + 16)?.try_into().ok()?;
            let port = u16::from_le_bytes(bytes.get(*off + 16..*off + 18)?.try_into().ok()?);
            *off += 18;
            Some(NetAddr::V4(ip, port))
        }
        1 => {
            let ip: [u8; 16] = bytes.get(*off..*off + 16)?.try_into().ok()?;
            let port = u16::from_le_bytes(bytes.get(*off + 16..*off + 18)?.try_into().ok()?);
            *off += 18;
            Some(NetAddr::V6(ip, port))
        }
        _ => None,
    }
}

fn push_entry(out: &mut Vec<u8>, e: &RepEntry) {
    out.extend_from_slice(&e.corrupt.to_le_bytes());
    out.extend_from_slice(&e.violations.to_le_bytes());
    out.extend_from_slice(&(e.incidents as u32).to_le_bytes());
    out.extend_from_slice(&e.last_seen.to_le_bytes());
}

fn rd_entry(bytes: &[u8], off: &mut usize) -> Option<RepEntry> {
    let corrupt = rd_u32(bytes, off)?;
    let violations = rd_u32(bytes, off)?;
    let incidents = rd_u32(bytes, off)? as u16;
    let last_seen = rd_u64(bytes, off)?;
    Some(RepEntry {
        corrupt,
        violations,
        incidents,
        last_seen,
    })
}

fn rd_u32(bytes: &[u8], off: &mut usize) -> Option<u32> {
    let b: [u8; 4] = bytes.get(*off..*off + 4)?.try_into().ok()?;
    *off += 4;
    Some(u32::from_le_bytes(b))
}

fn rd_u64(bytes: &[u8], off: &mut usize) -> Option<u64> {
    let b: [u8; 8] = bytes.get(*off..*off + 8)?.try_into().ok()?;
    *off += 8;
    Some(u64::from_le_bytes(b))
}

// ---------------------------------------------------------------------------
// Corrupt-block attribution
// ---------------------------------------------------------------------------

/// Distribute blame for a failed piece across its suppliers.
///
/// A supplier that provided most of the blocks is the prime suspect and is
/// penalized hardest; small contributors are treated as collateral and
/// spared. Returns `(conn, penalty_blocks)` pairs with `penalty > 0`.
pub fn attribute_corruption(
    suppliers: &BTreeMap<ConnId, u32>,
    total_blocks: u32,
) -> Vec<(ConnId, u32)> {
    let total = total_blocks.max(1);
    let mut out: Vec<(ConnId, u32)> = Vec::new();
    for (c, n) in suppliers {
        let frac = n.saturating_mul(100) / total;
        let pen = if frac >= 50 {
            2
        } else if frac >= 20 {
            1
        } else {
            0
        };
        if pen > 0 {
            out.push((*c, pen));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Choke policy & scoring
// ---------------------------------------------------------------------------

/// Anti-leech choke policy. Replaces the old rate-only `ChokeConfig`.
#[derive(Debug, Clone)]
pub struct LeechConfig {
    // -- slot management (BEP-3) --
    /// Upload slots while seeding.
    pub seeding_slots: u32,
    /// Unchoke slots while leeching.
    pub leeching_slots: u32,
    /// Optimistic-unchoke rotation interval (ms).
    pub optimistic_interval_ms: u64,
    /// Snub timeout (ms): we stop prioritizing peers that owe us data.
    pub snub_timeout_ms: u64,
    /// Re-choke interval (ms).
    pub rechoke_interval_ms: u64,

    // -- anti-leech --
    /// Corrupt blocks after which a peer is banned.
    pub corrupt_ban_threshold: u32,
    /// Score penalty per attributed corrupt block.
    pub corrupt_score_penalty: i64,
    /// Score penalty for a snubbed peer.
    pub snub_score_penalty: i64,
    /// Leeching: score per KiB/s a peer uploads to us.
    pub leech_upload_weight: i64,
    /// Seeding: score per KiB a peer has uploaded to us (ratio health).
    pub seed_reciprocity_weight: i64,
    /// Leeching: penalty for peers that take our scarce upload but never
    /// give back (tit-for-tat).
    pub nonrecip_penalty: i64,
    /// Seeding: penalty for peers that download a lot but never upload.
    pub free_ride_penalty: i64,
    /// Seeding: a peer is a free-rider when its
    /// `given / taken` ratio (in permyriad) is below this floor…
    pub min_share_permyriad: u32,
    /// …and it has taken at least this many bytes from us.
    pub free_ride_floor_bytes: u64,
    /// Soft penalty for known aggressive clients (behavior still dominates).
    pub client_leech_penalty: i64,
    /// Anti-leech measure: hard-block known leech clients
    pub block_leech_clients: bool,
    /// Minimum score margin a newcomer needs to displace an incumbent
    /// unchoked peer (anti-flap hysteresis). 0 disables stickiness.
    pub anti_flap_threshold: i64,
    /// Ban TTL (ms) for behavioral bans.
    pub ban_ttl_ms: u64,
    /// Cap on live ban entries.
    pub max_bans: usize,
    /// Protocol violations after which a peer is banned.
    pub protocol_ban_threshold: u32,

    // -- reciprocity grace & score bounding --
    /// A peer must be connected this long before the tit-for-tat / free-rider
    /// penalties can apply. Without a grace period a brand-new peer that is
    /// still warming up its upload pipeline is unfairly scored at `-2M` and
    /// can never earn a slot except through the optimistic rotation.
    pub recip_grace_ms: u64,
    /// Upper bound on the *positive* reciprocity contribution to the choke
    /// score. Lifetime bytes are unbounded (a 1 GB uploader would otherwise
    /// outscore every behavioral penalty forever), so we clamp the reward:
    /// a corrupt/snubbing/free-riding peer must always be pushable to the
    /// bottom of the ranking regardless of how much it uploaded in the past.
    pub max_reciprocity_reward: i64,
    /// A peer that holds an unchoke slot but has *never* requested a block
    /// from us for this long is "idle" (bandwidth squatting) and is
    /// penalized so the slot can serve an active downloader instead.
    pub idle_slot_timeout_ms: u64,
    /// Score penalty for an idle slot holder.
    pub idle_slot_penalty: i64,

    // -- connection hygiene --
    /// Max concurrent peers per /24 (IPv4) or /64 (IPv6) subnet, so a
    /// tracker/DHT flood of one address range cannot dominate the budget.
    pub max_peers_per_subnet: u32,
    /// Cap on live reputation entries (per torrent).
    pub rep_store_cap: usize,
    /// A stored reputation entry older than this is forgotten (ms).
    pub rep_ttl_ms: u64,
    /// Spurious cancels (cancel for a block never requested) before the
    /// peer earns a protocol violation. Absorbs one-off cancel/piece races.
    pub cancel_spam_threshold: u32,
    /// Structurally invalid requests (zero-length, oversized, misaligned,
    /// past the piece end) before a protocol violation is counted.
    pub invalid_request_threshold: u32,
}

impl Default for LeechConfig {
    fn default() -> Self {
        LeechConfig {
            seeding_slots: 8,
            leeching_slots: 8,
            optimistic_interval_ms: 30_000,
            snub_timeout_ms: 60_000,
            rechoke_interval_ms: 10_000,
            corrupt_ban_threshold: 3,
            corrupt_score_penalty: 2_000_000,
            snub_score_penalty: 4_000_000,
            leech_upload_weight: 64,
            seed_reciprocity_weight: 4,
            nonrecip_penalty: 1_000_000,
            free_ride_penalty: 2_000_000,
            min_share_permyriad: 100, // 1% return is enough to stay unlabeled
            free_ride_floor_bytes: 1024 * 1024,
            client_leech_penalty: 200_000,
            block_leech_clients: true,
            anti_flap_threshold: 16_000,
            ban_ttl_ms: 30 * 60 * 1000,
            max_bans: 4096,
            protocol_ban_threshold: 5,
            recip_grace_ms: 45_000,
            max_reciprocity_reward: 1_000_000,
            idle_slot_timeout_ms: 60_000,
            idle_slot_penalty: 1_500_000,
            max_peers_per_subnet: 8,
            rep_store_cap: 8192,
            rep_ttl_ms: 7 * 24 * 3600 * 1000,
            cancel_spam_threshold: 8,
            invalid_request_threshold: 4,
        }
    }
}

/// Everything the choke scheduler needs to know about one peer.
/// `session` builds these from [`Peer`](crate::swarm::Peer); keeping this a
/// plain data struct keeps `leech` decoupled from the connection code.
#[derive(Debug, Clone, Copy)]
pub struct PeerChokeView {
    /// Connection id.
    pub id: ConnId,
    /// Fingerprinted client (may be `None` pre-handshake).
    pub client: Option<ClientId>,
    /// Bytes this peer has uploaded to us (`Peer::down_total`).
    pub given: u64,
    /// Bytes we have uploaded to this peer (`Peer::up_total`).
    pub taken: u64,
    /// Their current upload rate to us (B/s, `Peer::down_rate`).
    pub rate_up: u32,
    /// Our current upload rate to them (B/s, `Peer::up_rate`).
    pub rate_down: u32,
    /// Attributed corrupt blocks.
    pub corrupt: u32,
    /// Snubbed (owed us data but went quiet).
    pub snubbed: bool,
    /// They are interested in our data.
    pub interested: bool,
    /// Connection age in ms (drives the reciprocity grace period).
    pub age_ms: u64,
    /// Milliseconds since they last requested a block from us. Peers that
    /// never requested report their connection age (so `idle_ms` stays
    /// meaningful without a sentinel).
    pub idle_ms: u64,
    /// Blocks we have served them on this connection.
    pub served_requests: u32,
}

fn permyriad(numer: u64, denom: u64) -> u32 {
    if denom == 0 {
        return u32::MAX;
    }
    (numer.saturating_mul(10_000) / denom).min(u32::MAX as u64) as u32
}

/// Anti-leech choke score for one peer. Higher = more deserving of a slot.
///
/// Seeding: reward peers that return data, penalize free-riders, snubs,
/// corrupt senders, idle squatters, aggressive clients. Leeching: reward
/// fast uploaders, penalize non-reciprocators (tit-for-tat).
///
/// Guards: a **grace period** ([`LeechConfig::recip_grace_ms`]) delays
/// reciprocity penalties so newcomers can warm up; the reward is
/// **clamped** ([`LeechConfig::max_reciprocity_reward`]) so lifetime bytes
/// never shield behavioral penalties.
pub fn choke_score(cfg: &LeechConfig, seeding: bool, v: &PeerChokeView) -> i64 {
    if cfg.block_leech_clients
        && v.client
            .map(|c| c.class == ClientClass::Leech)
            .unwrap_or(false)
    {
        return i64::MIN / 4;
    }
    let mut s: i64 = 0;
    let past_grace = v.age_ms >= cfg.recip_grace_ms;

    if seeding {
        let given_kib = (v.given / 1024) as i64;
        let rate_term = (v.rate_up as i64) * cfg.seed_reciprocity_weight / 1024;
        let recip = given_kib
            .saturating_mul(cfg.seed_reciprocity_weight)
            .saturating_add(rate_term)
            .min(cfg.max_reciprocity_reward);
        s += recip;
        if past_grace
            && v.taken >= cfg.free_ride_floor_bytes
            && permyriad(v.given, v.taken) < cfg.min_share_permyriad
        {
            s -= cfg.free_ride_penalty;
        }
    } else {
        let rate_term = (v.rate_up as i64) * cfg.leech_upload_weight / 1024;
        s += rate_term.min(cfg.max_reciprocity_reward);
        if past_grace && v.taken >= cfg.free_ride_floor_bytes && v.given == 0 {
            s -= cfg.nonrecip_penalty;
        }
    }
    if v.interested && past_grace && v.served_requests == 0 && v.idle_ms >= cfg.idle_slot_timeout_ms
    {
        s -= cfg.idle_slot_penalty;
    }
    s -= (v.corrupt as i64) * cfg.corrupt_score_penalty;
    if v.snubbed {
        s -= cfg.snub_score_penalty;
    }
    if let Some(c) = v.client {
        if c.class == ClientClass::Leech {
            s -= cfg.client_leech_penalty;
        }
    }
    s
}

/// Select the peers to unchoke.
///
/// Rules: (1) seeding → only interested peers eligible; leeching → all
/// ready peers. (2) The optimistic peer (BEP-3) reserves one slot for
/// newcomers. (3) Unchoked peers keep their slot (anti-flap). (4) Remaining
/// slots go to best-scoring newcomers, displacing incumbents only when they
/// beat the weakest holder by `anti_flap_threshold`.
pub fn select_unchoke_set<F>(
    views: &[PeerChokeView],
    seeding: bool,
    cfg: &LeechConfig,
    is_cur_unchoked: F,
    optimistic: Option<ConnId>,
) -> Vec<ConnId>
where
    F: Fn(ConnId) -> bool,
{
    let slots = if seeding {
        cfg.seeding_slots
    } else {
        cfg.leeching_slots
    } as usize;
    if slots == 0 || views.is_empty() {
        return Vec::new();
    }

    struct Cand {
        id: ConnId,
        score: i64,
    }
    let mut cands: Vec<Cand> = views
        .iter()
        .filter(|v| v.interested || !seeding)
        .filter(|v| {
            !(cfg.block_leech_clients
                && v.client
                    .map(|c| c.class == ClientClass::Leech)
                    .unwrap_or(false))
        })
        .map(|v| Cand {
            id: v.id,
            score: choke_score(cfg, seeding, v),
        })
        .collect();
    cands.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.id.cmp(&b.id)));

    let mut result: Vec<ConnId> = Vec::with_capacity(slots);

    if let Some(o) = optimistic {
        let eligible = cands.iter().any(|c| c.id == o)
            && views
                .iter()
                .find(|v| v.id == o)
                .map(|v| !v.snubbed && v.corrupt < cfg.corrupt_ban_threshold)
                .unwrap_or(false);
        if eligible && !result.contains(&o) {
            result.push(o);
        }
    }

    for c in cands.iter() {
        if result.len() >= slots {
            break;
        }
        if is_cur_unchoked(c.id) && optimistic != Some(c.id) && !result.contains(&c.id) {
            result.push(c.id);
        }
    }
    for c in cands.iter() {
        if result.contains(&c.id) || is_cur_unchoked(c.id) {
            continue;
        }
        if result.len() < slots {
            result.push(c.id);
            continue;
        }
        let weakest = result
            .iter()
            .filter(|id| optimistic != Some(**id))
            .filter_map(|id| cands.iter().find(|c| c.id == *id))
            .map(|c| c.score)
            .min();
        if let Some(w) = weakest {
            let beats = if cfg.anti_flap_threshold > 0 {
                c.score >= w.saturating_add(cfg.anti_flap_threshold)
            } else {
                c.score > w
            };
            if beats {
                let wid = result
                    .iter()
                    .find(|id| {
                        optimistic != Some(**id)
                            && cands
                                .iter()
                                .find(|x| x.id == **id)
                                .map(|x| x.score)
                                .unwrap_or(i64::MIN)
                                == w
                    })
                    .copied();
                if let Some(wid) = wid {
                    result.retain(|id| *id != wid);
                    result.push(c.id);
                }
            }
        }
    }
    result
}

/// Choose the single ready peer to drop so a better candidate can connect
/// when the session is at capacity. Hard negatives sort by severity:
/// corrupt suppliers (active poisoning) first, then snubs, then the lowest
/// choke score. The optimistic slot and the `keep` set are protected.
pub fn pick_eviction(
    views: &[PeerChokeView],
    seeding: bool,
    cfg: &LeechConfig,
    optimistic: Option<ConnId>,
    keep: &[ConnId],
) -> Option<ConnId> {
    let mut best: Option<(u8, i64, ConnId)> = None;
    for v in views {
        if optimistic == Some(v.id) || keep.contains(&v.id) {
            continue;
        }
        // 2 = corrupt supplier, 1 = snub, 0 = clean.
        let hard = if v.corrupt > 0 {
            2
        } else if v.snubbed {
            1
        } else {
            0
        };
        let score = choke_score(cfg, seeding, v);
        let better = match best {
            Some((bh, bs, _)) => (hard > bh) || (hard == bh && score < bs),
            None => true,
        };
        if better {
            best = Some((hard, score, v.id));
        }
    }
    best.map(|(_, _, id)| id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(id: ConnId, given: u64, taken: u64, rate_up: u32, interested: bool) -> PeerChokeView {
        PeerChokeView {
            id,
            client: None,
            given,
            taken,
            rate_up,
            rate_down: 0,
            corrupt: 0,
            snubbed: false,
            interested,
            age_ms: 120_000,
            idle_ms: 0,
            served_requests: 1,
        }
    }

    #[test]
    fn fingerprints_clients() {
        let qb: [u8; 20] = *b"-qB4390-abcdefghijkl";
        assert_eq!(fingerprint(&qb).code_str(), "qB43");
        assert_eq!(fingerprint(&qb).class(), ClientClass::Standard);
        let xl: [u8; 20] = *b"-XL0012-abcdefghijkl";
        assert_eq!(fingerprint(&xl).class(), ClientClass::Leech);
        let xl7: [u8; 20] = *b"71111-abcdefghijklmn";
        assert_eq!(fingerprint(&xl7).class(), ClientClass::Leech);
        let unknown: [u8; 20] =
            *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13";
        assert_eq!(fingerprint(&unknown).class(), ClientClass::Unknown);
    }

    #[test]
    fn corruption_attribution_is_weighted() {
        let mut m = BTreeMap::new();
        m.insert(1, 8u32);
        m.insert(2, 3u32);
        m.insert(3, 1u32);
        let out = attribute_corruption(&m, 12);
        assert!(out.contains(&(1, 2))); // 66% → prime suspect
        assert!(out.contains(&(2, 1))); // 25% → partial
        assert!(!out.iter().any(|(c, _)| *c == 3)); // 8% → collateral
    }

    #[test]
    fn seeding_prefers_reciprocators() {
        let cfg = LeechConfig::default();
        let free_rider = view(1, 0, 10 * 1024 * 1024, 0, true);
        let citizen = view(2, 5 * 1024 * 1024, 10 * 1024 * 1024, 0, true);
        let fr = choke_score(&cfg, true, &free_rider);
        let ci = choke_score(&cfg, true, &citizen);
        assert!(
            ci > fr,
            "reciprocator should outscore free-rider when seeding"
        );
    }

    #[test]
    fn leeching_rewards_fast_uploaders() {
        let cfg = LeechConfig::default();
        let slow = view(1, 0, 0, 1_000, true);
        let fast = view(2, 0, 0, 500_000, true);
        assert!(choke_score(&cfg, false, &fast) > choke_score(&cfg, false, &slow));
    }

    #[test]
    fn snub_and_corrupt_lose_slots() {
        let cfg = LeechConfig::default();
        let good = view(1, 0, 0, 500_000, true);
        let mut bad = view(2, 0, 0, 500_000, true);
        bad.snubbed = true;
        bad.corrupt = 1;
        assert!(choke_score(&cfg, false, &good) > choke_score(&cfg, false, &bad));
    }

    #[test]
    fn blocked_leech_clients_never_win_any_slot() {
        let cfg = LeechConfig::default();
        let mut leech = view(1, 0, 0, 500_000, true);
        leech.client = Some(ClientId::new(b"XL", ClientClass::Leech));
        let mut citizen = view(2, 0, 0, 500_000, true);
        citizen.client = Some(ClientId::new(b"qB", ClientClass::Standard));

        assert!(
            choke_score(&cfg, false, &leech) < choke_score(&cfg, false, &citizen),
            "blocked leech must be at the absolute bottom"
        );

        let views = [leech];
        let set = select_unchoke_set(&views, false, &cfg, |_| false, Some(1));
        assert!(
            !set.contains(&1),
            "leech client must never be unchoked, even optimistically"
        );

        let soft = LeechConfig {
            block_leech_clients: false,
            ..Default::default()
        };
        let views = [leech, citizen];
        let set = select_unchoke_set(&views, false, &soft, |_| false, None);
        assert!(
            set.contains(&1),
            "with blocking off the leech client is only softly penalized"
        );
    }

    #[test]
    fn anti_flap_keeps_incumbents() {
        let cfg = LeechConfig {
            leeching_slots: 1,
            anti_flap_threshold: 16_000,
            ..Default::default()
        };
        let inc = view(1, 0, 0, 100_000, true);
        let newcomer = view(2, 0, 0, 300_000, true);
        let views = [inc, newcomer];
        let set = select_unchoke_set(&views, false, &cfg, |id| id == 1, None);
        assert_eq!(set, vec![1], "incumbent should stay within the margin");
        let dominant = view(3, 0, 0, 1_000_000, true);
        let views = [inc, newcomer, dominant];
        let set = select_unchoke_set(&views, false, &cfg, |id| id == 1, None);
        assert_eq!(set, vec![3]);
    }

    #[test]
    fn optimistic_gets_slot() {
        let cfg = LeechConfig {
            leeching_slots: 1,
            ..Default::default()
        };
        let a = view(1, 0, 0, 100, true);
        let b = view(2, 0, 0, 200, true);
        let views = [a, b];
        let set = select_unchoke_set(&views, false, &cfg, |_| false, Some(1));
        assert!(set.contains(&1), "optimistic peer should be unchoked");
    }

    #[test]
    fn ban_manager_ttl_and_cap() {
        let mut bm = BanManager::new(4);
        let a = NetAddr::V4([10, 0, 0, 1], 6881);
        let pid = [7u8; 20];
        assert!(bm.ban(a, Some(&pid), 1000, BanReason::Corrupt, 0));
        assert!(bm.is_banned(&a, 500));
        assert!(bm.peer_id_banned(&pid, 500));
        assert!(!bm.is_banned(&a, 1500));
        bm.sweep(1500);
        assert_eq!(bm.len(), 0);
        for i in 0..10u8 {
            bm.ban(
                NetAddr::V4([10, 0, 0, i], 6881),
                None,
                1000,
                BanReason::Protocol,
                0,
            );
        }
        assert!(bm.len() <= 4);
    }

    #[test]
    fn free_rider_needs_grace() {
        let cfg = LeechConfig::default();
        let mut young = view(1, 0, 10 * 1024 * 1024, 0, true);
        young.age_ms = 5_000;
        let old = view(2, 0, 10 * 1024 * 1024, 0, true); // 120 s, past grace
        let young_s = choke_score(&cfg, true, &young);
        let old_s = choke_score(&cfg, true, &old);
        assert!(
            young_s > old_s,
            "a young peer must not be labelled a free-rider before grace"
        );
        // ...but once past grace, the same behavior is penalized hard
        let mut grown = view(3, 0, 10 * 1024 * 1024, 0, true);
        grown.age_ms = cfg.recip_grace_ms + 1;
        let grown_s = choke_score(&cfg, true, &grown);
        assert!(
            grown_s < young_s && grown_s <= old_s,
            "past grace the free-rider penalty must apply"
        );
    }

    #[test]
    fn clamped_reciprocity_lets_behavior_dominate() {
        let cfg = LeechConfig::default();
        // 1 GiB lifetime uploader that is also a corrupt supplier: the
        // corruption penalty must still sink its score.
        let mut whale = view(1, 1024 * 1024 * 1024, 0, 0, true);
        whale.corrupt = 1;
        let honest = view(2, 0, 0, 0, true);
        assert!(
            choke_score(&cfg, true, &honest) > choke_score(&cfg, true, &whale),
            "clamped reciprocity must let corruption dominate"
        );
    }

    #[test]
    fn idle_slot_squatter_loses_score() {
        let cfg = LeechConfig::default();
        let mut idle = view(1, 0, 0, 0, true);
        idle.age_ms = cfg.recip_grace_ms + 1;
        idle.idle_ms = cfg.idle_slot_timeout_ms + 1;
        idle.served_requests = 0;
        let active = view(2, 0, 0, 0, true);
        assert!(
            choke_score(&cfg, true, &active) > choke_score(&cfg, true, &idle),
            "an interested peer that never pulls should be penalized"
        );
    }

    #[test]
    fn zero_margin_still_displaces() {
        let cfg = LeechConfig {
            leeching_slots: 1,
            anti_flap_threshold: 0,
            ..Default::default()
        };
        let inc = view(1, 0, 0, 100_000, true);
        let newcomer = view(2, 0, 0, 300_000, true);
        let views = [inc, newcomer];
        let set = select_unchoke_set(&views, false, &cfg, |id| id == 1, None);
        assert_eq!(
            set,
            vec![2],
            "margin 0 should let a strictly better newcomer displace"
        );
    }

    #[test]
    fn optimistic_excluded_when_corrupt() {
        let cfg = LeechConfig {
            leeching_slots: 1,
            ..Default::default()
        };
        let mut bad = view(1, 0, 0, 100, true);
        bad.corrupt = cfg.corrupt_ban_threshold; // at the ban line
        let other = view(2, 0, 0, 50, true);
        let views = [bad, other];
        let set = select_unchoke_set(&views, false, &cfg, |_| false, Some(1));
        assert!(
            !set.contains(&1),
            "optimistic slot must not shelter a corrupt peer"
        );
        assert!(set.contains(&2));
    }

    #[test]
    fn eviction_prefers_hard_negatives() {
        let cfg = LeechConfig::default();
        let mut corrupt = view(1, 0, 0, 0, true);
        corrupt.corrupt = 1;
        let mut snubbed = view(2, 0, 0, 0, true);
        snubbed.snubbed = true;
        let low = view(3, 0, 0, 100, true);
        let views = [low, snubbed, corrupt];
        let pick = pick_eviction(&views, false, &cfg, None, &[]);
        assert_eq!(pick, Some(1), "corrupt peer should be evicted first");
        // optimistic is protected
        let views = [low, snubbed, corrupt];
        let pick = pick_eviction(&views, false, &cfg, Some(3), &[]);
        assert_ne!(pick, Some(3));
    }

    #[test]
    fn reputation_store_roundtrip_and_ttl() {
        let mut rs = ReputationStore::new(16, 1000);
        let a = NetAddr::V4([10, 0, 0, 7], 6881);
        let pid = [9u8; 20];
        rs.note_corrupt(a, Some(&pid), 3, 100);
        rs.note_violation(a, Some(&pid), 100);
        assert_eq!(rs.stored_for(&pid), Some((3, 1)));
        assert_eq!(rs.stored_addr(&a), Some((3, 1)));
        let bytes = rs.encode();
        let mut back = ReputationStore::decode(&bytes).expect("decode");
        assert_eq!(back.stored_for(&pid), Some((3, 1)));
        assert_eq!(back.stored_addr(&a), Some((3, 1)));
        // TTL sweep drops it
        back.sweep(1000 + 1001);
        assert!(back.is_empty());
        // garbage input is rejected, never panics
        assert!(ReputationStore::decode(&[0u8; 3]).is_none());
        assert!(ReputationStore::decode(&bytes[..bytes.len() - 1]).is_none());
        let mut bad = bytes.clone();
        bad[0] ^= 0xff; // corrupt the magic → structural rejection
        assert!(ReputationStore::decode(&bad).is_none());
        bad = bytes.clone();
        bad[5] = 2; // unknown format version → rejection
        assert!(ReputationStore::decode(&bad).is_none());
    }

    #[test]
    fn reputation_store_cap_bounds_growth() {
        let mut rs = ReputationStore::new(4, u64::MAX);
        for i in 0..20u8 {
            rs.note_corrupt(NetAddr::V4([10, 0, 0, i], 6881), None, 1, 1000 + i as u64);
        }
        assert!(rs.len() <= 4);
    }
}
