//! Peer connection state and wire-level bookkeeping.
//!
//! A [`Peer`] owns everything about one TCP connection: phase, availability,
//! extension state, rates, reputation (anti-leech ledger), and the outgoing
//! byte buffer. The choke/unchoke **algorithm** itself lives in
//! [`crate::leech`] (reciprocity scoring, snubs, bans); this module only
//! supplies the per-connection state it operates on.

use crate::bitfield::Bitfield;
use crate::consts::REQUEST_PIPELINE;
use crate::leech::PeerReputation;
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
    /// Last time they requested a block from us (ms; 0 = never). Drives
    /// the idle-slot (bandwidth squatting) detection.
    pub last_request_at: u64,
    /// Blocks we have served them on this connection.
    pub served_requests: u32,
    /// Cancels for blocks we never had outstanding to them (abuse signal).
    pub spurious_cancels: u32,
    /// Structurally invalid requests (abuse signal).
    pub invalid_requests: u32,
    /// Outgoing byte buffer (engine drains via host).
    pub out: Vec<u8>,
    /// Incoming message stream.
    pub msgs: MessageStream,
    /// Handshake prefix buffer.
    pub handshake_buf: Vec<u8>,
    /// How this peer was found.
    pub source: DiscoverySource,
    /// Anti-leech reputation ledger (client, corrupt blocks, violations).
    pub rep: PeerReputation,
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
            last_request_at: 0,
            served_requests: 0,
            spurious_cancels: 0,
            invalid_requests: 0,
            out: Vec::with_capacity(16 * 1024),
            msgs: MessageStream::new(),
            handshake_buf: Vec::new(),
            source,
            rep: PeerReputation::default(),
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
    ///
    /// Interest is deliberately **independent of choke state**: it answers
    /// "do they have at least one piece we want?", while whether we may
    /// *request* from them is governed by `peer_choking`. Gating interest on
    /// `peer_choking` deadlocks fresh downloads — a seed that only unchokes
    /// peers who already declared `Interested` would never unchoke us,
    /// because we would never declare interest while choked. We therefore
    /// send `Interested` as soon as their availability shows a wanted piece,
    /// choked or not.
    pub fn should_be_interested(&self, our_have: &Bitfield) -> bool {
        if self.have_none {
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
        self.down_rate = ((self.window_down * 1000) / span_ms) as u32;
        self.up_rate = ((self.window_up * 1000) / span_ms) as u32;
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

    /// Refresh the snub flag: we are snubbed when we expect data from them
    /// (they unchoked us and we have outstanding requests) but they stay
    /// quiet for `timeout_ms`. The flag clears as soon as the situation
    /// improves (data arrives or expectations end).
    pub fn refresh_snub(&mut self, now: u64, timeout_ms: u64) {
        self.snubbed = self.phase == PeerPhase::Ready
            && !self.peer_choking
            && self.requests_in_flight > 0
            && now.saturating_sub(self.last_data_in) > timeout_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: ConnId) -> Peer {
        let mut p = Peer::new(
            id,
            NetAddr::V4([127, 0, 0, 1], 6881),
            64,
            DiscoverySource::Tracker,
        );
        p.phase = PeerPhase::Ready;
        p
    }

    #[test]
    fn snub_detection_and_clear() {
        let mut p = peer(1);
        p.peer_choking = false;
        p.requests_in_flight = 2;
        p.last_data_in = 0;
        p.refresh_snub(1000, 500);
        assert!(p.snubbed);
        // data arrives → cleared
        p.on_data_in(16, 1001);
        assert!(!p.snubbed);
        // no outstanding requests → never snubbed
        p.requests_in_flight = 0;
        p.last_data_in = 0;
        p.refresh_snub(2000, 500);
        assert!(!p.snubbed);
    }

    #[test]
    fn interested_detection() {
        let mut p = peer(1);
        p.peer_choking = false;
        p.have.set(5);
        let mut ours = Bitfield::new(64);
        ours.set(5);
        assert!(!p.should_be_interested(&ours));
        ours.clear(5);
        assert!(p.should_be_interested(&ours));
        // choking must NOT suppress interest (interest ≠ unchoke) — a seed
        // that unchokes only interested peers would otherwise deadlock us.
        p.peer_choking = true;
        assert!(p.should_be_interested(&ours));
        // have_none (they have nothing) still suppresses interest
        p.have_none = true;
        assert!(!p.should_be_interested(&ours));
    }
}
