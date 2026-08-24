//! Peer connection state and swarm choking logic.
//!
//! A [`Peer`] owns everything about one TCP connection: phase, availability,
//! extension state, rates, and the outgoing byte buffer. The choke/unchoke
//! algorithm is rate-based with an optimistic unchoke slot (BEP-3), snub
//! detection, and seeding-mode upload-rate scheduling.

use crate::bitfield::Bitfield;
use crate::consts::REQUEST_PIPELINE;
use crate::monitoring::DiscoverySource;
use crate::platform::{ConnId, NetAddr};
use crate::wire::{ExtHandshake, Message, MessageStream};
use alloc::vec::Vec;

/// Lifecycle phase of a peer connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerPhase {
    /// Connecting (non-blocking connect in progress).
    Connecting,
    /// Our handshake sent; waiting for theirs.
    Handshake,
    /// Handshake complete; exchanging bitfield/extension messages.
    Ready,
    /// Dead.
    Closed,
}

/// Per-connection peer state.
#[derive(Debug)]
pub struct Peer {
    /// Host connection handle.
    pub id: ConnId,
    /// Remote endpoint.
    pub addr: NetAddr,
    /// Lifecycle phase.
    pub phase: PeerPhase,
    /// Their peer id (after handshake).
    pub peer_id: Option<[u8; 20]>,
    /// Their reserved bits.
    pub reserved: [u8; 8],
    /// We are choking them.
    pub am_choking: bool,
    /// We are interested in them.
    pub am_interested: bool,
    /// They are choking us.
    pub peer_choking: bool,
    /// They are interested in us.
    pub peer_interested: bool,
    /// Their piece availability (empty if have_all/have_none).
    pub have: Bitfield,
    /// `have_all` received (fast extension).
    pub have_all: bool,
    /// `have_none` received.
    pub have_none: bool,
    /// Their extended-handshake data.
    pub ext: Option<ExtHandshake>,
    /// `ut_metadata` extended id (if any).
    pub ext_metadata: Option<u8>,
    /// `ut_pex` extended id (if any).
    pub ext_pex: Option<u8>,
    /// They are a seed (have everything).
    pub is_seed: bool,
    /// Supports fast extension.
    pub fast: bool,
    /// Supports DHT.
    pub supports_dht: bool,
    /// Supports v2 (BEP-52).
    pub supports_v2: bool,
    /// Bytes received total.
    pub down_total: u64,
    /// Bytes sent total.
    pub up_total: u64,
    /// Download rate (bytes/s, smoothed).
    pub down_rate: u32,
    /// Upload rate (bytes/s, smoothed).
    pub up_rate: u32,
    /// Timestamp of last inbound activity.
    pub last_active: u64,
    /// Timestamp of last data received (for snub detection).
    pub last_data_in: u64,
    /// Timestamp of connection start.
    pub connected_at: u64,
    /// Snubbed (no data for a while despite requests).
    pub snubbed: bool,
    /// This peer holds an optimistic-unchoke slot.
    pub optimistic: bool,
    /// Outstanding request count on this connection.
    pub requests_in_flight: u32,
    /// Outgoing byte buffer (engine drains via host).
    pub out: Vec<u8>,
    /// Incoming message stream.
    pub msgs: MessageStream,
    /// Handshake prefix buffer.
    pub handshake_buf: Vec<u8>,
    /// How this peer was found.
    pub source: DiscoverySource,
    /// Last PEX message sent.
    pub pex_sent_at: u64,
    /// Rate-sampling window accumulators.
    pub window_down: u64,
    /// Bytes uploaded in the current window.
    pub window_up: u64,
    /// When the current rate window started.
    pub window_started: u64,
}

impl Peer {
    /// Create a new peer (outbound or inbound).
    pub fn new(id: ConnId, addr: NetAddr, piece_count: u32, source: DiscoverySource) -> Self {
        Peer {
            id,
            addr,
            phase: PeerPhase::Connecting,
            peer_id: None,
            reserved: [0u8; 8],
            am_choking: true,
            am_interested: false,
            peer_choking: true,
            peer_interested: false,
            have: Bitfield::new(piece_count),
            have_all: false,
            have_none: false,
            ext: None,
            ext_metadata: None,
            ext_pex: None,
            is_seed: false,
            fast: false,
            supports_dht: false,
            supports_v2: false,
            down_total: 0,
            up_total: 0,
            down_rate: 0,
            up_rate: 0,
            last_active: 0,
            last_data_in: 0,
            connected_at: 0,
            snubbed: false,
            optimistic: false,
            requests_in_flight: 0,
            out: Vec::with_capacity(16 * 1024),
            msgs: MessageStream::new(),
            handshake_buf: Vec::new(),
            source,
            pex_sent_at: 0,
            window_down: 0,
            window_up: 0,
            window_started: 0,
        }
    }

    /// Whether we know the peer has piece `p`.
    pub fn has_piece(&self, p: u32) -> bool {
        self.have_all || self.have.get(p)
    }

    /// Whether we should be interested (they have something we lack).
    pub fn should_be_interested(&self, our_have: &Bitfield) -> bool {
        if self.peer_choking || self.have_none {
            return false;
        }
        if self.have_all {
            return !our_have.all_set();
        }
        // any piece they have that we don't
        let n = self.have.len().min(our_have.len());
        let mut i = self.have.first_set();
        while let Some(p) = i {
            if p >= n {
                break;
            }
            if !our_have.get(p) {
                return true;
            }
            i = self.have.next_set_from(p + 1);
        }
        false
    }

    /// Max request pipeline depth for this peer.
    pub fn max_pipeline(&self) -> u32 {
        REQUEST_PIPELINE
    }

    /// Queue a message for sending.
    pub fn send(&mut self, m: &Message) {
        self.out.extend_from_slice(&m.encode());
    }

    /// Whether the out buffer is empty.
    pub fn flushed(&self) -> bool {
        self.out.is_empty()
    }

    /// Reset the rate window (called on a fixed cadence).
    pub fn roll_window(&mut self, now: u64) {
        let span_ms = now.saturating_sub(self.window_started).max(1);
        self.down_rate = ((self.window_down as u64) * 1000 / span_ms) as u32;
        self.up_rate = ((self.window_up as u64) * 1000 / span_ms) as u32;
        self.window_down = 0;
        self.window_up = 0;
        self.window_started = now;
    }

    /// Record downloaded bytes.
    pub fn on_data_in(&mut self, n: usize, now: u64) {
        self.down_total += n as u64;
        self.window_down += n as u64;
        self.last_active = now;
        self.last_data_in = now;
        self.snubbed = false;
    }

    /// Record uploaded bytes.
    pub fn on_data_out(&mut self, n: usize, now: u64) {
        self.up_total += n as u64;
        self.window_up += n as u64;
        self.last_active = now;
    }
}

/// Parameters for the choke/unchoke scheduler.
#[derive(Debug, Clone, Copy)]
pub struct ChokeConfig {
    /// Upload slots when seeding.
    pub seeding_slots: u32,
    /// Unchoke slots when leeching.
    pub leeching_slots: u32,
    /// Optimistic unchoke rotation interval (ms).
    pub optimistic_interval_ms: u64,
    /// Snub timeout (ms).
    pub snub_timeout_ms: u64,
    /// Re-choke interval (ms).
    pub interval_ms: u64,
}

impl Default for ChokeConfig {
    fn default() -> Self {
        ChokeConfig {
            seeding_slots: 8,
            leeching_slots: 8,
            optimistic_interval_ms: 30_000,
            snub_timeout_ms: 60_000,
            interval_ms: 10_000,
        }
    }
}

/// A candidate for an unchoke slot with its score.
struct Candidate {
    id: ConnId,
    rate: u32,
    optimistic: bool,
    snubbed: bool,
}

/// Compute which peers should be unchoked.
/// `seeding` selects the algorithm (upload-rate vs download-rate).
/// Returns the list of conn ids to unchoke.
pub fn compute_unchoke_set<F>(
    peers: &[&Peer],
    seeding: bool,
    cfg: &ChokeConfig,
    is_optimistic: F,
) -> Vec<ConnId>
where
    F: Fn(ConnId) -> bool,
{
    let slots = if seeding {
        cfg.seeding_slots
    } else {
        cfg.leeching_slots
    } as usize;
    let mut candidates: Vec<Candidate> = peers
        .iter()
        .filter(|p| p.phase == PeerPhase::Ready)
        .filter(|p| p.peer_interested || !seeding)
        .map(|p| Candidate {
            id: p.id,
            rate: if seeding { p.up_rate } else { p.down_rate },
            optimistic: is_optimistic(p.id),
            snubbed: p.snubbed,
        })
        .collect();
    // sort: non-snubbed first, then by rate descending
    candidates.sort_by(|a, b| b.rate.cmp(&a.rate).then_with(|| a.snubbed.cmp(&b.snubbed)));
    let mut unchoked: Vec<ConnId> = Vec::with_capacity(slots);
    for c in &candidates {
        if unchoked.len() >= slots {
            break;
        }
        if c.snubbed {
            continue;
        }
        unchoked.push(c.id);
    }
    // ensure the optimistic peer stays if slots remain and it's a peer
    if unchoked.len() < slots {
        for c in &candidates {
            if c.optimistic && !unchoked.contains(&c.id) {
                unchoked.push(c.id);
                break;
            }
        }
    }
    unchoked
}

/// Update snub flags: mark peers snubbed when they owe us data but are
/// quiet for too long.
pub fn update_snubs<'a>(
    peers: impl IntoIterator<Item = &'a mut Peer>,
    now: u64,
    cfg: &ChokeConfig,
) {
    for p in peers {
        if p.phase == PeerPhase::Ready && !p.peer_choking && p.requests_in_flight > 0 {
            if now.saturating_sub(p.last_data_in) > cfg.snub_timeout_ms {
                p.snubbed = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: ConnId, down: u32, interested: bool) -> Peer {
        let mut p = Peer::new(
            id,
            NetAddr::V4([127, 0, 0, 1], 6881),
            64,
            DiscoverySource::Tracker,
        );
        p.phase = PeerPhase::Ready;
        p.down_rate = down;
        p.peer_interested = interested;
        p
    }

    #[test]
    fn unchoke_picks_fastest() {
        let peers: Vec<Peer> = vec![
            peer(1, 100, true),
            peer(2, 9000, true),
            peer(3, 5000, false),
        ];
        let refs: Vec<&Peer> = peers.iter().collect();
        let mut cfg = ChokeConfig::default();
        cfg.leeching_slots = 2;
        let set = compute_unchoke_set(&refs, false, &cfg, |_| false);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&2));
        assert!(set.contains(&3) || set.contains(&1));
    }

    #[test]
    fn snub_detection() {
        let cfg = ChokeConfig::default();
        let mut p = peer(1, 100, true);
        p.phase = PeerPhase::Ready;
        p.peer_choking = false;
        p.requests_in_flight = 2;
        p.last_data_in = 0;
        update_snubs(core::slice::from_mut(&mut p), cfg.snub_timeout_ms + 1, &cfg);
        assert!(p.snubbed);
    }

    #[test]
    fn interested_detection() {
        let mut p = peer(1, 0, false);
        p.peer_choking = false;
        p.have.set(5);
        let mut ours = Bitfield::new(64);
        ours.set(5);
        assert!(!p.should_be_interested(&ours));
        ours.clear(5);
        assert!(p.should_be_interested(&ours));
    }
}
