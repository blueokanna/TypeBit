//! BEP-29 uTP — Micro Transport Protocol over UDP, with LEDBAT congestion
//! control (RFC 6817 style): yields bandwidth when the network is busy,
//! fills the pipe when idle. All I/O goes through [`Host::udp_send`], so it
//! runs on every platform. Pure `no_std + alloc`, zero `unsafe`.
//!
//! Wire format (20-byte header):
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |type_ver       | extension     | connection_id                 |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | timestamp_microseconds                                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | timestamp_difference_microseconds                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | wnd_size                                                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | seq_nr                        | ack_nr                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::error::{Error, Result};
use crate::platform::{ConnId, Host, NetAddr};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

/// uTP protocol version (low nibble of `type_ver`).
pub const UTP_VERSION: u8 = 1;
/// Fixed header length.
pub const HDR_LEN: usize = 20;
/// Maximum payload per DATA packet (fits a 1500-byte MTU with IP+UDP).
pub const MAX_PAYLOAD: usize = 1400;
/// Upper bound on the advertised receive window (bytes).
pub const RECV_WINDOW: usize = 512 * 1024;
/// LEDBAT target one-way delay (microseconds).
pub const TARGET_DELAY_US: u64 = 100_000;
/// LEDBAT gain divisor (window changes by cwnd/gain per RTT at full offset).
pub const GAIN_DENOM: i64 = 16;
/// Minimum congestion window (two packets).
pub const MIN_WINDOW: u64 = 2 * MAX_PAYLOAD as u64;
/// Maximum congestion window.
pub const MAX_WINDOW: u64 = 1024 * 1024;
/// Initial congestion window (four packets).
pub const INIT_WINDOW: u64 = 4 * MAX_PAYLOAD as u64;
/// Base-delay reset period (µs) — lets the LEDBAT baseline track path changes.
pub const BASE_DELAY_RESET_US: u64 = 10_000_000;
/// Idle timeout (µs) before a connection is torn down.
pub const IDLE_TIMEOUT_US: u64 = 90_000_000;
/// Maximum SYN retransmissions before giving up.
pub const MAX_SYN_RETRIES: u32 = 5;
/// Maximum DATA retransmissions before the connection is reset.
pub const MAX_DATA_RETRIES: u32 = 8;
/// RTO floor (µs) — absorbs scheduler jitter and coarse timers.
pub const RTO_MIN_US: u64 = 150_000;
/// RTO ceiling (µs).
pub const RTO_MAX_US: u64 = 4_000_000;

// Packet types (top nibble of type_ver).
const ST_DATA: u8 = 0;
const ST_FIN: u8 = 1;
const ST_STATE: u8 = 2;
const ST_RESET: u8 = 3;
const ST_SYN: u8 = 4;

// Extensions.
const EXT_NONE: u8 = 0;
const EXT_SACK: u8 = 1;

/// High bit marks a uTP connection handle; TCP handles from hosts never
/// reach this range.
pub const UTP_HANDLE_FLAG: u32 = 0x8000_0000;

/// True when a connection handle belongs to the uTP transport.
pub fn is_utp_handle(id: ConnId) -> bool {
    id & UTP_HANDLE_FLAG != 0
}

/// True when a UDP datagram looks like a uTP packet (version nibble = 1).
pub fn is_utp_datagram(b: &[u8]) -> bool {
    b.len() >= HDR_LEN && b[0] & 0x0F == UTP_VERSION
}

/// True when `a` is at or before `b` in 16-bit sequence space (half-window).
fn seq_le(a: u16, b: u16) -> bool {
    b.wrapping_sub(a) < 0x8000
}

/// The 20-byte uTP header (BEP-29).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Header {
    ptype: u8,
    extension: u8,
    conn_id: u16,
    timestamp: u32,
    timestamp_diff: u32,
    wnd_size: u32,
    seq_nr: u16,
    ack_nr: u16,
}

impl Header {
    fn encode(&self, out: &mut [u8; HDR_LEN]) {
        out[0] = (self.ptype << 4) | UTP_VERSION;
        out[1] = self.extension;
        out[2..4].copy_from_slice(&self.conn_id.to_be_bytes());
        out[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        out[8..12].copy_from_slice(&self.timestamp_diff.to_be_bytes());
        out[12..16].copy_from_slice(&self.wnd_size.to_be_bytes());
        out[16..18].copy_from_slice(&self.seq_nr.to_be_bytes());
        out[18..20].copy_from_slice(&self.ack_nr.to_be_bytes());
    }

    fn decode(b: &[u8]) -> Option<Header> {
        if b.len() < HDR_LEN {
            return None;
        }
        let type_ver = b[0];
        if type_ver & 0x0F != UTP_VERSION {
            return None;
        }
        Some(Header {
            ptype: type_ver >> 4,
            extension: b[1],
            conn_id: u16::from_be_bytes([b[2], b[3]]),
            timestamp: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            timestamp_diff: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            wnd_size: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
            seq_nr: u16::from_be_bytes([b[16], b[17]]),
            ack_nr: u16::from_be_bytes([b[18], b[19]]),
        })
    }
}

/// One sent-but-unacknowledged DATA packet, kept for retransmission.
struct Unacked {
    /// Full packet (header + payload), resent verbatim.
    packet: Vec<u8>,
    /// Payload length (for window accounting).
    payload_len: usize,
    /// Last transmission time (µs).
    sent_at: u64,
    /// Retransmission count.
    attempts: u32,
}

/// Connection lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UtpState {
    /// SYN sent, waiting for the peer's SYN-ACK.
    SynSent,
    /// Established; data may flow.
    Connected,
    /// We sent FIN, waiting for its ACK.
    FinSent,
    /// Terminated.
    Closed,
}

/// Per-connection uTP state.
struct UtpSocket {
    /// Engine-side handle.
    handle: ConnId,
    /// Peer endpoint.
    addr: NetAddr,
    /// Wire connection id we put in outgoing packets.
    send_id: u16,
    /// Wire connection id we expect in incoming packets.
    recv_id: u16,
    state: UtpState,
    /// Sequence number of our SYN (for the handshake transition).
    syn_seq: u16,
    /// Next seq_nr to assign to a DATA/FIN packet.
    next_seq: u16,
    /// Highest contiguous seq received (our ACK value).
    ack_nr: u16,
    /// Reassembled bytes ready for the session.
    recv_buf: VecDeque<u8>,
    /// Out-of-order received payloads by seq (reported via SACK).
    oob: BTreeMap<u16, Vec<u8>>,
    /// Bytes queued by the session, awaiting packetisation.
    send_buf: VecDeque<u8>,
    /// Sent, unacknowledged packets.
    unacked: BTreeMap<u16, Unacked>,
    /// Bytes in flight (sum of unacked payloads).
    in_flight: u64,
    /// Peer's advertised receive window (bytes).
    peer_wnd: u64,
    /// LEDBAT congestion window (bytes).
    cwnd: u64,
    /// Base one-way delay (µs) — running minimum.
    base_delay: u64,
    /// EWMA of the queuing delay (µs).
    our_delay: u64,
    /// Smoothed RTT (µs).
    rtt: u64,
    /// Retransmission timeout (µs).
    rto: u64,
    /// When the base delay is reset.
    base_delay_reset_at: u64,
    /// Next allowed LEDBAT window update.
    next_window_update: u64,
    /// An ACK is owed to the peer.
    ack_pending: bool,
    /// µs of the last packet received (for ACK echo holding time).
    last_recv_at: u64,
    /// Timestamp (µs) echoed in ACKs: the ts of the last DATA we received.
    last_data_ts: u32,
    /// µs of the last send or receive (idle detection).
    last_activity: u64,
    /// µs of the last SYN transmission.
    syn_sent_at: u64,
    /// µs the FIN was (first) sent.
    fin_sent_at: u64,
    /// SYN retransmission count.
    syn_attempts: u32,
    /// Peer sent FIN (their stream ended).
    peer_fin: bool,
    /// We sent FIN (our stream ended) — suppress further data sends.
    fin_sent: bool,
}

impl UtpSocket {
    fn new(handle: ConnId, addr: NetAddr, send_id: u16, recv_id: u16, now: u64) -> Self {
        UtpSocket {
            handle,
            addr,
            send_id,
            recv_id,
            state: UtpState::SynSent,
            syn_seq: 0,
            next_seq: 0,
            ack_nr: 0,
            recv_buf: VecDeque::new(),
            oob: BTreeMap::new(),
            send_buf: VecDeque::new(),
            unacked: BTreeMap::new(),
            in_flight: 0,
            peer_wnd: RECV_WINDOW as u64,
            cwnd: INIT_WINDOW,
            base_delay: u64::MAX,
            our_delay: 0,
            rtt: RTO_MIN_US,
            rto: RTO_MIN_US,
            base_delay_reset_at: now.saturating_add(BASE_DELAY_RESET_US),
            next_window_update: 0,
            ack_pending: false,
            last_recv_at: 0,
            last_data_ts: 0,
            last_activity: now,
            syn_sent_at: 0,
            fin_sent_at: 0,
            syn_attempts: 0,
            peer_fin: false,
            fin_sent: false,
        }
    }

    fn is_connected(&self) -> bool {
        self.state == UtpState::Connected
    }

    fn advertised_window(&self) -> u32 {
        let used = (self.recv_buf.len() as u64)
            .saturating_add((self.oob.len() as u64).saturating_mul(MAX_PAYLOAD as u64));
        (RECV_WINDOW as u64)
            .saturating_sub(used)
            .min(u32::MAX as u64) as u32
    }

    /// Base header for an outgoing packet.
    fn hdr(&self, ptype: u8, seq: u16, ack: u16, now: u64) -> Header {
        Header {
            ptype,
            extension: EXT_NONE,
            conn_id: self.send_id,
            timestamp: now as u32,
            timestamp_diff: 0,
            wnd_size: self.advertised_window(),
            seq_nr: seq,
            ack_nr: ack,
        }
    }

    /// Serialise one outgoing packet (header + optional SACK ext + payload).
    fn build_packet(&self, ptype: u8, seq: u16, ack: u16, payload: &[u8], now: u64) -> Vec<u8> {
        let mut hdr = self.hdr(ptype, seq, ack, now);
        // ACK-ish packets echo the last received DATA timestamp + holding
        // time so the peer can run LEDBAT.
        if ptype == ST_STATE || ptype == ST_FIN {
            hdr.timestamp = self.last_data_ts;
            hdr.timestamp_diff = if self.last_recv_at != 0 {
                now.saturating_sub(self.last_recv_at).min(u32::MAX as u64) as u32
            } else {
                0
            };
        }
        // SACK mask for out-of-order data (only meaningful when ACKing).
        let (ext, mask) = if ptype == ST_STATE || ptype == ST_FIN {
            self.sack_mask()
        } else {
            (EXT_NONE, Vec::new())
        };
        let mut out = Vec::with_capacity(HDR_LEN + 2 + mask.len() + payload.len());
        let mut head = [0u8; HDR_LEN];
        hdr.encode(&mut head);
        out.extend_from_slice(&head);
        if ext != EXT_NONE {
            out.push(ext);
            out.push(mask.len() as u8);
            out.extend_from_slice(&mask);
        }
        out.extend_from_slice(payload);
        out
    }

    /// Build a SACK extension bitmask covering received OOB seqs after our
    /// current ACK value. Bits map to ack_nr+1, ack_nr+2, …
    fn sack_mask(&self) -> (u8, Vec<u8>) {
        if self.oob.is_empty() {
            return (EXT_NONE, Vec::new());
        }
        let mut mask = [0u8; 32]; // 256 packets — far beyond any real window
        let mut any = false;
        for &seq in self.oob.keys() {
            let off = seq.wrapping_sub(self.ack_nr).wrapping_sub(1) as u32;
            if off >= 256 {
                continue;
            }
            mask[(off / 8) as usize] |= 1 << (off % 8);
            any = true;
        }
        if any {
            (EXT_SACK, mask.to_vec())
        } else {
            (EXT_NONE, Vec::new())
        }
    }

    /// Handle one received packet (header already decoded).
    fn on_packet<H: Host>(&mut self, host: &mut H, h: &Header, payload: &[u8], now: u64) {
        self.last_activity = now;
        match h.ptype {
            ST_SYN => {
                // A (re-)SYN on an established connection: re-ack.
                if self.state != UtpState::Closed {
                    self.state = UtpState::Connected;
                    self.ack_pending = true;
                }
            }
            ST_STATE => self.on_ack(h, now),
            ST_DATA => {
                self.last_recv_at = now;
                self.last_data_ts = h.timestamp;
                self.on_ack(h, now);
                self.on_data(h, payload);
            }
            ST_FIN => {
                self.last_recv_at = now;
                self.on_ack(h, now);
                self.peer_fin = true;
                self.ack_pending = true;
            }
            ST_RESET => {
                self.state = UtpState::Closed;
            }
            _ => {}
        }
        // If the handshake completed, flush the pending SYN-ACK.
        if self.state == UtpState::Connected && self.ack_pending && h.ptype == ST_SYN {
            self.send_ack(host, now);
        }
        let _ = host;
    }

    /// Absorb the peer's cumulative ACK + LEDBAT timing feedback.
    fn on_ack(&mut self, h: &Header, now: u64) {
        // LEDBAT/RTT feedback is carried by packets that echo a DATA ts.
        if h.timestamp != 0 {
            let their_ts = h.timestamp as u64;
            let their_delay = h.timestamp_diff as u64;
            if now > their_ts {
                let rtt = now
                    .saturating_sub(their_ts)
                    .saturating_sub(their_delay)
                    .max(1);
                self.rtt = (7 * self.rtt.saturating_add(rtt)) / 8;
                self.rto = (self.rtt * 2).clamp(RTO_MIN_US, RTO_MAX_US);

                let delay = now.saturating_sub(their_ts);
                if delay < self.base_delay {
                    self.base_delay = delay;
                }
                if now >= self.base_delay_reset_at {
                    self.base_delay = delay;
                    self.base_delay_reset_at = now.saturating_add(BASE_DELAY_RESET_US);
                }
                let queued = delay.saturating_sub(self.base_delay);
                self.our_delay = (7 * self.our_delay.saturating_add(queued)) / 8;
            }
        }

        // Handshake: an ACK covering our SYN flips SynSent → Connected.
        if self.state == UtpState::SynSent && seq_le(self.syn_seq, h.ack_nr) {
            self.state = UtpState::Connected;
        }

        // Free unacked packets covered by the cumulative ACK.
        if let Some((&first, _)) = self.unacked.iter().next() {
            if seq_le(first, h.ack_nr) {
                let acked: Vec<u16> = self
                    .unacked
                    .keys()
                    .copied()
                    .filter(|&s| seq_le(s, h.ack_nr))
                    .collect();
                for s in acked {
                    if let Some(u) = self.unacked.remove(&s) {
                        self.in_flight = self.in_flight.saturating_sub(u.payload_len as u64);
                    }
                }
                self.peer_wnd = h.wnd_size as u64;
                self.maybe_update_window(now);
                // FIN acked → fully closed.
                if self.state == UtpState::FinSent && self.unacked.is_empty() {
                    self.state = UtpState::Closed;
                }
            }
        }
    }

    /// LEDBAT window update, once per RTT.
    fn maybe_update_window(&mut self, now: u64) {
        if now < self.next_window_update {
            return;
        }
        self.next_window_update = now.saturating_add(self.rtt.max(RTO_MIN_US));
        let off = TARGET_DELAY_US as i64 - self.our_delay as i64;
        let delta = (self.cwnd as i64)
            .checked_mul(off)
            .map(|v| v / (TARGET_DELAY_US as i64 * GAIN_DENOM))
            .unwrap_or(0);
        self.cwnd = (self.cwnd as i64 + delta).clamp(MIN_WINDOW as i64, MAX_WINDOW as i64) as u64;
    }

    /// Accept a DATA payload and reassemble in order.
    fn on_data(&mut self, h: &Header, payload: &[u8]) {
        if self.state == UtpState::Closed || payload.is_empty() {
            return;
        }
        // Receive-window enforcement: beyond our buffer, drop without ACKing
        // so the sender stalls against our advertised window.
        if (self.recv_buf.len() as u64).saturating_add(self.oob.len() as u64) >= RECV_WINDOW as u64
        {
            return;
        }
        let seq = h.seq_nr;
        if seq_le(seq, self.ack_nr) {
            return; // duplicate
        }
        if seq == self.ack_nr.wrapping_add(1) {
            self.ack_nr = seq;
            self.recv_buf.extend(payload.iter().copied());
            loop {
                let next = self.ack_nr.wrapping_add(1);
                if let Some(p) = self.oob.remove(&next) {
                    self.ack_nr = next;
                    self.recv_buf.extend(p.iter().copied());
                } else {
                    break;
                }
            }
            self.ack_pending = true;
        } else {
            if self.oob.len() < 1024 {
                self.oob.insert(seq, payload.to_vec());
            }
            self.ack_pending = true;
        }
    }

    /// Send an immediate ACK (STATE) if one is owed.
    fn send_ack<H: Host>(&mut self, host: &mut H, now: u64) {
        let pkt = self.build_packet(ST_STATE, self.next_seq, self.ack_nr, &[], now);
        if host.udp_send(&self.addr, &pkt).is_ok() {
            self.ack_pending = false;
            self.last_activity = now;
        }
    }

    /// Packetise queued bytes subject to the congestion + peer window.
    fn transmit<H: Host>(&mut self, host: &mut H, now: u64) {
        if self.state != UtpState::Connected || self.fin_sent {
            return;
        }
        loop {
            let window = self.cwnd.min(self.peer_wnd);
            if self.in_flight + MAX_PAYLOAD as u64 > window {
                break;
            }
            let take = core::cmp::min(self.send_buf.len(), MAX_PAYLOAD);
            if take == 0 {
                break;
            }
            let payload: Vec<u8> = self.send_buf.drain(..take).collect();
            let seq = self.next_seq;
            self.next_seq = self.next_seq.wrapping_add(1);
            let pkt = self.build_packet(ST_DATA, seq, self.ack_nr, &payload, now);
            let plen = payload.len();
            match host.udp_send(&self.addr, &pkt) {
                Ok(()) => {
                    self.unacked.insert(
                        seq,
                        Unacked {
                            packet: pkt,
                            payload_len: plen,
                            sent_at: now,
                            attempts: 0,
                        },
                    );
                    self.in_flight = self.in_flight.saturating_add(plen as u64);
                    self.last_activity = now;
                }
                Err(_) => {
                    // Requeue the payload for a later attempt.
                    for b in payload.into_iter().rev() {
                        self.send_buf.push_front(b);
                    }
                    break;
                }
            }
        }
    }

    /// Retransmissions + delayed ACK (called every tick).
    fn tick_retransmit<H: Host>(&mut self, host: &mut H, now: u64) {
        match self.state {
            UtpState::SynSent => {
                if now.saturating_sub(self.syn_sent_at) >= self.rto {
                    if self.syn_attempts >= MAX_SYN_RETRIES {
                        self.state = UtpState::Closed;
                        return;
                    }
                    self.send_syn(host, now);
                }
            }
            UtpState::Connected | UtpState::FinSent => {
                let expired: Vec<u16> = self
                    .unacked
                    .iter()
                    .filter(|(_, u)| now.saturating_sub(u.sent_at) >= self.rto)
                    .map(|(s, _)| *s)
                    .collect();
                for s in expired {
                    if let Some(u) = self.unacked.get_mut(&s) {
                        u.attempts += 1;
                        u.sent_at = now;
                        if u.attempts >= MAX_DATA_RETRIES {
                            self.state = UtpState::Closed;
                            return;
                        }
                        let pkt = u.packet.clone();
                        let _ = host.udp_send(&self.addr, &pkt);
                    }
                }
            }
            UtpState::Closed => {}
        }
        // Delayed ACK: flush when no data is queued, or after ~25ms.
        if self.ack_pending
            && self.state != UtpState::Closed
            && (self.send_buf.is_empty() || now.saturating_sub(self.last_activity) > 25_000)
        {
            self.send_ack(host, now);
        }
    }

    fn send_syn<H: Host>(&mut self, host: &mut H, now: u64) {
        let mut hdr = self.hdr(ST_SYN, self.syn_seq, 0, now);
        hdr.conn_id = self.send_id;
        let mut head = [0u8; HDR_LEN];
        hdr.encode(&mut head);
        if host.udp_send(&self.addr, &head).is_ok() {
            self.syn_sent_at = now;
            self.syn_attempts += 1;
            self.last_activity = now;
            // The SYN consumes seq 0; the first DATA starts at seq 1.
            if self.next_seq == self.syn_seq {
                self.next_seq = self.syn_seq.wrapping_add(1);
            }
        }
    }

    /// Send FIN once (graceful close of our write side).
    fn send_fin<H: Host>(&mut self, host: &mut H, now: u64) {
        if self.fin_sent {
            return;
        }
        self.fin_sent = true;
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let pkt = self.build_packet(ST_FIN, seq, self.ack_nr, &[], now);
        let _ = host.udp_send(&self.addr, &pkt);
        self.state = UtpState::FinSent;
        self.fin_sent_at = now;
        self.last_activity = now;
    }
}

/// The uTP transport: owns every uTP socket and drives the protocol.
pub struct UtpManager {
    conns: BTreeMap<ConnId, UtpSocket>,
    next_handle: u32,
    /// Outbound connection-ID allocator. BEP-29: the initiator picks an ODD
    next_send_id: u16,
    /// New inbound sockets (SYN accepted), for the engine to attach.
    accepted: VecDeque<(ConnId, NetAddr)>,
    /// Sockets closed by RESET/timeout/FIN-ACK since the last call.
    reaped: VecDeque<ConnId>,
}

impl UtpManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        UtpManager {
            conns: BTreeMap::new(),
            next_handle: 1,
            next_send_id: 1,
            accepted: VecDeque::new(),
            reaped: VecDeque::new(),
        }
    }

    /// Open an outbound connection to `addr`. The SYN is sent on the next
    /// [`Self::tick`].
    pub fn connect(&mut self, addr: NetAddr, now: u64) -> ConnId {
        let handle = self.alloc_handle();
        let send_id = self.next_send_id;
        self.next_send_id = self.next_send_id.wrapping_add(2);
        let recv_id = send_id.wrapping_add(1);
        let mut sock = UtpSocket::new(handle, addr, send_id, recv_id, now);
        sock.ack_nr = sock.syn_seq.wrapping_sub(1);
        self.conns.insert(handle, sock);
        handle
    }

    fn alloc_handle(&mut self) -> ConnId {
        loop {
            let h = UTP_HANDLE_FLAG | self.next_handle;
            self.next_handle = self.next_handle.wrapping_add(1);
            if !self.conns.contains_key(&h) {
                return h;
            }
        }
    }

    /// Whether the connection has completed its handshake.
    pub fn is_connected(&self, id: ConnId) -> bool {
        self.conns
            .get(&id)
            .map(|s| s.is_connected())
            .unwrap_or(false)
    }

    /// Whether the connection is still live.
    pub fn is_live(&self, id: ConnId) -> bool {
        self.conns.contains_key(&id)
    }

    /// Non-blocking read from a connection's reassembled stream.
    ///
    /// - `Ok(n)`: `n` bytes copied.
    /// - `Err(WouldBlock)`: connected, no data yet.
    /// - `Err(NotFound)`: handshake not complete yet.
    /// - `Ok(0)`: EOF (peer FIN drained, or connection closed/reset).
    pub fn recv(&mut self, id: ConnId, buf: &mut [u8]) -> Result<usize> {
        let sock = match self.conns.get_mut(&id) {
            Some(s) => s,
            None => return Ok(0), // closed/reaped → EOF
        };
        match sock.state {
            UtpState::SynSent => Err(Error::NotFound),
            UtpState::Closed => Ok(0),
            UtpState::Connected | UtpState::FinSent => {
                if sock.recv_buf.is_empty() {
                    if sock.peer_fin {
                        Ok(0)
                    } else {
                        Err(Error::WouldBlock)
                    }
                } else {
                    let n = core::cmp::min(buf.len(), sock.recv_buf.len());
                    for (i, b) in sock.recv_buf.drain(..n).enumerate() {
                        buf[i] = b;
                    }
                    Ok(n)
                }
            }
        }
    }

    /// Buffer bytes to send. Transmission happens in [`Self::tick`].
    pub fn send(&mut self, id: ConnId, data: &[u8]) -> Result<usize> {
        let sock = match self.conns.get_mut(&id) {
            Some(s) => s,
            None => return Err(Error::NotFound),
        };
        match sock.state {
            UtpState::SynSent => Err(Error::NotFound),
            UtpState::Closed => Err(Error::NotFound),
            UtpState::Connected | UtpState::FinSent => {
                if sock.fin_sent {
                    return Err(Error::NotFound);
                }
                sock.send_buf.extend(data.iter().copied());
                Ok(data.len())
            }
        }
    }

    /// Gracefully close a connection (FIN on the next tick).
    pub fn close(&mut self, id: ConnId) {
        if let Some(s) = self.conns.get_mut(&id) {
            if s.is_connected() {
                s.state = UtpState::FinSent; // FIN emitted by tick
            } else {
                s.state = UtpState::Closed;
            }
        }
    }

    /// Newly accepted inbound sockets since the last call.
    pub fn take_accepted(&mut self) -> VecDeque<(ConnId, NetAddr)> {
        core::mem::take(&mut self.accepted)
    }

    /// Sockets that closed since the last call (RESET/timeout/FIN-ACK).
    pub fn take_reaped(&mut self) -> VecDeque<ConnId> {
        core::mem::take(&mut self.reaped)
    }

    /// Feed one received UDP datagram. Returns true when it was a uTP packet.
    pub fn handle_datagram<H: Host>(
        &mut self,
        host: &mut H,
        addr: NetAddr,
        payload: &[u8],
        now: u64,
    ) -> bool {
        if payload.len() < HDR_LEN || payload[0] & 0x0F != UTP_VERSION {
            return false;
        }
        let Some(h) = Header::decode(payload) else {
            return false;
        };
        let body = &payload[HDR_LEN..];

        for sock in self.conns.values() {
            if sock.recv_id == h.conn_id {
                let id = sock.handle;
                if let Some(s) = self.conns.get_mut(&id) {
                    s.on_packet(host, &h, body, now);
                }
                return true;
            }
        }

        if h.ptype == ST_SYN {
            let handle = self.alloc_handle();
            let recv_id = h.conn_id;
            let send_id = h.conn_id.wrapping_add(1);
            let mut sock = UtpSocket::new(handle, addr, send_id, recv_id, now);
            sock.state = UtpState::Connected;
            sock.last_data_ts = h.timestamp;
            sock.ack_nr = h.seq_nr; // acknowledge the SYN itself
            sock.ack_pending = true;
            sock.last_recv_at = now;
            sock.send_ack(host, now);
            self.conns.insert(handle, sock);
            self.accepted.push_back((handle, addr));
            return true;
        }
        true
    }

    /// Drive the transport: SYN/retransmit/ACK/data/timeouts. Once per tick.
    pub fn tick<H: Host>(&mut self, host: &mut H, now: u64) {
        let ids: Vec<ConnId> = self.conns.keys().copied().collect();
        for id in ids {
            let Some(sock) = self.conns.get_mut(&id) else {
                continue;
            };
            match sock.state {
                UtpState::SynSent => {
                    if sock.syn_attempts == 0 {
                        sock.send_syn(host, now);
                    }
                }
                UtpState::Connected => {
                    sock.transmit(host, now);
                }
                UtpState::FinSent => {
                    sock.transmit(host, now);
                    if sock.fin_sent_at == 0 {
                        sock.send_fin(host, now);
                    }
                }
                UtpState::Closed => {}
            }
            sock.tick_retransmit(host, now);
            if sock.state != UtpState::Closed
                && now.saturating_sub(sock.last_activity) > IDLE_TIMEOUT_US
            {
                sock.state = UtpState::Closed;
            }
            if sock.state == UtpState::Closed {
                self.conns.remove(&id);
                self.reaped.push_back(id);
            }
        }
    }

    /// Number of live uTP connections.
    pub fn len(&self) -> usize {
        self.conns.len()
    }

    /// True when no uTP connections are live.
    pub fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }
}

impl Default for UtpManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    /// Minimal loopback host: records outgoing datagrams.
    #[derive(Default)]
    struct LoopHost {
        out: Vec<(NetAddr, Vec<u8>)>,
    }

    impl Host for LoopHost {
        fn now_ms(&self) -> u64 {
            0
        }
        fn fill_random(&mut self, _b: &mut [u8]) {}
        fn log(&mut self, _l: crate::platform::LogLevel, _m: &str) {}
        fn http_get(&mut self, _u: &str, _t: u64, _o: &mut alloc::vec::Vec<u8>) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn tcp_connect(&mut self, _a: &NetAddr) -> Result<ConnId> {
            unreachable!()
        }
        fn tcp_connect_done(&mut self, _id: ConnId) -> Result<()> {
            unreachable!()
        }
        fn tcp_send(&mut self, _id: ConnId, _d: &[u8]) -> Result<usize> {
            unreachable!()
        }
        fn tcp_recv(&mut self, _id: ConnId, _b: &mut [u8]) -> Result<usize> {
            unreachable!()
        }
        fn tcp_close(&mut self, _id: ConnId) {}
        fn udp_open(&mut self, _p: u16) -> Result<()> {
            Ok(())
        }
        fn udp_send(&mut self, a: &NetAddr, d: &[u8]) -> Result<()> {
            self.out.push((*a, d.to_vec()));
            Ok(())
        }
        fn udp_recv(&mut self, _b: &mut [u8]) -> Result<(NetAddr, usize)> {
            Err(Error::WouldBlock)
        }
        fn disk_open(&mut self, _p: &str) -> Result<u32> {
            unreachable!()
        }
        fn disk_read(&mut self, _id: u32, _off: u64, _b: &mut [u8]) -> Result<usize> {
            unreachable!()
        }
        fn disk_write(&mut self, _id: u32, _off: u64, _d: &[u8]) -> Result<()> {
            unreachable!()
        }
        fn disk_prealloc(&mut self, _id: u32, _s: u64) -> Result<()> {
            Ok(())
        }
        fn disk_flush(&mut self, _id: u32) -> Result<()> {
            Ok(())
        }
        fn disk_close(&mut self, _id: u32) {}
    }

    /// Deliver every packet recorded on `host.out` into `b`.
    fn deliver(host: &mut LoopHost, b: &mut UtpManager) {
        let pkts = core::mem::take(&mut host.out);
        for (addr, pkt) in pkts {
            b.handle_datagram(host, addr, &pkt, 1_000_000);
        }
    }

    #[test]
    fn header_roundtrip() {
        let h = Header {
            ptype: ST_DATA,
            extension: EXT_NONE,
            conn_id: 0x1234,
            timestamp: 0xdeadbeef,
            timestamp_diff: 0x01020304,
            wnd_size: 0x00ff00ff,
            seq_nr: 0xabcd,
            ack_nr: 0x00fe,
        };
        let mut b = [0u8; HDR_LEN];
        h.encode(&mut b);
        let d = Header::decode(&b).expect("decode");
        assert_eq!(h, d);
        b[0] = 0x10; // version 0 → rejected
        assert!(Header::decode(&b).is_none());
        assert!(Header::decode(&b[..19]).is_none());
    }

    #[test]
    fn connect_handshake_and_stream() {
        let _a_addr = NetAddr::V4([10, 0, 0, 1], 6881);
        let b_addr = NetAddr::V4([10, 0, 0, 2], 6881);
        let mut host = LoopHost::default();
        let mut a = UtpManager::new();
        let mut b = UtpManager::new();

        let a_conn = a.connect(b_addr, 1_000_000);
        assert!(!a.is_connected(a_conn));

        // A's tick sends the SYN; B accepts it and replies SYN-ACK.
        a.tick(&mut host, 1_000_000);
        assert_eq!(host.out.len(), 1);
        deliver(&mut host, &mut b);
        let accepted = b.take_accepted();
        assert_eq!(accepted.len(), 1);
        let (b_conn, _addr) = accepted[0];
        assert!(b.is_connected(b_conn));

        // B's SYN-ACK travels back; A connects.
        deliver(&mut host, &mut a);
        a.tick(&mut host, 1_000_100);
        assert!(
            a.is_connected(a_conn),
            "A should be connected after SYN-ACK"
        );

        // A sends a payload; B reassembles it.
        let msg = b"hello over utp";
        assert_eq!(a.send(a_conn, msg).unwrap(), msg.len());
        a.tick(&mut host, 1_001_000);
        deliver(&mut host, &mut b);
        b.tick(&mut host, 1_002_000);
        let mut got = [0u8; 64];
        let n = b.recv(b_conn, &mut got).expect("recv");
        assert_eq!(&got[..n], msg);
    }

    #[test]
    fn large_stream_delivers_all_bytes() {
        let _a_addr = NetAddr::V4([10, 0, 0, 1], 6881);
        let b_addr = NetAddr::V4([10, 0, 0, 2], 6881);
        let mut host = LoopHost::default();
        let mut a = UtpManager::new();
        let mut b = UtpManager::new();

        let a_conn = a.connect(b_addr, 1_000_000);
        a.tick(&mut host, 1_000_000);
        deliver(&mut host, &mut b);
        let (b_conn, _) = b.take_accepted().pop_front().unwrap();
        deliver(&mut host, &mut a);
        a.tick(&mut host, 1_000_100);
        assert!(a.is_connected(a_conn));

        // Send 200 KB; loop ticks until all bytes arrive on B.
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut sent = 0usize;
        let mut received = 0usize;
        let mut guard = 0usize;
        let mut now = 1_000_000u64;
        while received < payload.len() && guard < 5000 {
            guard += 1;
            now += 5_000;
            if sent < payload.len() {
                let chunk = &payload[sent..];
                let _ = a.send(a_conn, chunk);
                sent = payload.len();
            }
            a.tick(&mut host, now);
            deliver(&mut host, &mut b);
            let mut sink = [0u8; 4096];
            loop {
                match b.recv(b_conn, &mut sink) {
                    Ok(0) => break,
                    Ok(n) => {
                        // verify content
                        for (i, &byte) in sink[..n].iter().enumerate() {
                            assert_eq!(byte, payload[received + i]);
                        }
                        received += n;
                        if received == payload.len() {
                            break;
                        }
                    }
                    Err(Error::WouldBlock) => break,
                    Err(_) => break,
                }
            }
            b.tick(&mut host, now);
            deliver(&mut host, &mut a);
        }
        assert_eq!(received, payload.len(), "all 200 KB must arrive intact");
    }

    #[test]
    fn out_of_order_reassembly() {
        let mut sock = UtpSocket::new(0x8000_0001, NetAddr::V4([1, 2, 3, 4], 6881), 5, 6, 0);
        sock.state = UtpState::Connected;
        let mut host = LoopHost::default();

        let mk = |seq: u16| Header {
            ptype: ST_DATA,
            extension: EXT_NONE,
            conn_id: 5,
            timestamp: 0,
            timestamp_diff: 0,
            wnd_size: 1 << 20,
            seq_nr: seq,
            ack_nr: 0,
        };
        sock.on_data(&mk(2), b"two");
        assert_eq!(sock.recv_buf.len(), 0, "out of order must buffer");
        sock.on_data(&mk(1), b"one");
        assert_eq!(
            &sock.recv_buf.iter().copied().collect::<Vec<_>>()[..],
            b"onetwo"
        );
        sock.on_data(&mk(3), b"three");
        assert_eq!(
            &sock.recv_buf.iter().copied().collect::<Vec<_>>()[..],
            b"onetwothree"
        );
        let _ = &mut host;
    }
}
