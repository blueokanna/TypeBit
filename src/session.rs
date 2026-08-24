//! Per-torrent session: the heart of the engine.
//!
//! A [`TorrentSession`] owns everything for one torrent: peer connections,
//! piece/block bookkeeping, the utility scheduler, tracker/DHT/PEX peer
//! discovery, metadata fetching (magnet links), the receipt book and the
//! swarm monitor. It talks to the outside world through a [`SessionCtx`]
//! that carries the host, the shared disk cache, the DHT and an event sink.

use crate::bitfield::Bitfield;
use crate::consts::BLOCK_LEN;
use crate::dht::Dht;
use crate::disk_cache::DiskCache;
use crate::engine::EngineEvent;
use crate::error::{Error, Result};
use crate::magnet::Magnet;
use crate::metainfo::{InfoHash, Torrent};
use crate::monitoring::{DiscoverySource, FailureCategory, SwarmMonitor};
use crate::picker::{PickOptions, Picker};
use crate::piece::{block_count_for, PieceTracker};
use crate::platform::{ConnId, Host, NetAddr};
use crate::receipt::ReceiptBook;
use crate::scheduler::{ContentGoal, Scheduler, SchedulerConfig};
use crate::swarm::{compute_unchoke_set, update_snubs, ChokeConfig, Peer, PeerPhase};
use crate::tracker::{self, AnnounceParams, Event as TrackerEvent, TrackerResponse};
use crate::wire::{
    reserved as wire_reserved, ExtHandshake, Handshake, Message, MetadataMsg, PexMsg,
};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Per-torrent configuration.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Save directory (host-resolved path).
    pub save_dir: String,
    /// Max concurrent peers.
    pub max_peers: u32,
    /// Outstanding request blocks per peer.
    pub request_pipeline: u32,
    /// Endgame activation threshold (pieces).
    pub endgame_pieces: u32,
    /// Enable content-aware scheduling (head/tail for video).
    pub smart_scheduling: bool,
    /// Choke/unchoke parameters.
    pub choke: ChokeConfig,
    /// Scheduler weights.
    pub scheduler: SchedulerConfig,
    /// Wall-clock seed for receipts.
    pub node_secret: [u8; 32],
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            save_dir: String::from("."),
            max_peers: 80,
            request_pipeline: crate::consts::REQUEST_PIPELINE,
            endgame_pieces: 32,
            smart_scheduling: true,
            choke: ChokeConfig::default(),
            scheduler: SchedulerConfig::default(),
            node_secret: [0u8; 32],
        }
    }
}

/// Torrent lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// Waiting for metadata (magnet link).
    FetchingMetadata,
    /// Downloading.
    Downloading,
    /// All pieces verified; serving.
    Seeding,
    /// Paused by the user.
    Paused,
    /// Stopped (files closed).
    Stopped,
    /// Terminal failure.
    Failed,
}

/// Tracker transport kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackerKind {
    /// HTTP(S).
    Http,
    /// UDP (BEP-15).
    Udp,
}

/// UDP tracker state machine phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpPhase {
    Idle,
    ConnectSent,
    AnnounceSent,
}

/// State for one tracker URL.
#[derive(Debug, Clone)]
pub struct TrackerState {
    /// Announce URL.
    pub url: Vec<u8>,
    /// Transport kind.
    pub kind: TrackerKind,
    /// Announce interval.
    pub interval: u64,
    /// Next announce time (ms).
    pub next_announce: u64,
    /// Last failure reason.
    pub failure: Option<String>,
    /// UDP state.
    pub udp: UdpTrackerState,
}

/// UDP tracker bookkeeping.
#[derive(Debug, Clone)]
pub struct UdpTrackerState {
    phase: UdpPhase,
    conn_id: u64,
    tid: u32,
    addr: Option<NetAddr>,
    sent_at: u64,
}

impl Default for UdpTrackerState {
    fn default() -> Self {
        UdpTrackerState {
            phase: UdpPhase::Idle,
            conn_id: 0,
            tid: 0,
            addr: None,
            sent_at: 0,
        }
    }
}

/// Metadata (magnet) fetch state.
#[derive(Debug, Clone)]
pub struct MetadataFetch {
    /// Total metadata size.
    pub size: u32,
    /// Received metadata pieces (piece index → bytes).
    pub pieces: BTreeMap<u32, Vec<u8>>,
    /// Requested pieces.
    pub requested: Bitfield,
    /// Outstanding requests.
    pub outstanding: u32,
}

/// The per-torrent session.
pub struct TorrentSession {
    /// Parsed torrent (None until metadata arrives for magnets).
    pub torrent: Option<Torrent>,
    /// Infohash (known even for magnets).
    pub info_hash: InfoHash,
    /// 20-byte hash used for tracker/DHT announces.
    pub tracker_hash: [u8; 20],
    /// Status.
    pub status: SessionStatus,
    /// Save dir.
    pub save_dir: String,
    /// Piece tracker.
    pub pieces: PieceTracker,
    /// Scheduler.
    pub scheduler: Scheduler,
    /// Peers by connection id.
    pub peers: BTreeMap<ConnId, Peer>,
    /// Blocks → requesting peers (endgame cancels).
    requested_by: BTreeMap<(u32, u16), Vec<ConnId>>,
    /// Per-piece peer availability counts.
    pub availability: Vec<u32>,
    /// Assembling piece buffers (piece → bytes).
    assembling: BTreeMap<u32, Vec<u8>>,
    /// Open file handles aligned with torrent.files.
    files: Vec<crate::platform::DiskId>,
    /// Trackers.
    pub trackers: Vec<TrackerState>,
    /// Tracker round-robin position.
    tracker_cursor: usize,
    /// Next announce due time (ms).
    pub announce_at: u64,
    /// Started at (ms).
    pub started_at: u64,
    /// Bytes downloaded (payload).
    pub downloaded_bytes: u64,
    /// Bytes uploaded (payload).
    pub uploaded_bytes: u64,
    /// Last choke pass time.
    last_unchoke_at: u64,
    /// Optimistic unchoke peer.
    optimistic: Option<ConnId>,
    /// Endgame active.
    pub endgame: bool,
    /// Peers queued for connection (drained by the engine).
    pub connect_queue: Vec<(NetAddr, DiscoverySource)>,
    /// DHT lookup started.
    dht_started: bool,
    /// Last PEX broadcast.
    last_pex_at: u64,
    /// Peers known for PEX.
    pex_known: Vec<NetAddr>,
    /// Metadata fetch state.
    metadata: Option<MetadataFetch>,
    /// Web seeds (BEP-19), reserved for direct HTTP piece download.
    #[allow(dead_code)]
    web_seeds: Vec<String>,
    /// Web-seed round robin.
    #[allow(dead_code)]
    webseed_cursor: usize,
    /// Monitor.
    pub monitor: SwarmMonitor,
    /// Receipt book.
    pub receipt_book: ReceiptBook,
    /// Config.
    pub cfg: SessionConfig,
}

/// Everything a session needs from the world during a tick.
pub struct SessionCtx<'a, H: Host> {
    /// Host.
    pub host: &'a mut H,
    /// Shared disk cache.
    pub cache: &'a mut DiskCache,
    /// Our peer id.
    pub peer_id: [u8; 20],
    /// Our listen port.
    pub port: u16,
    /// Current time (ms).
    pub now: u64,
    /// DHT (optional).
    pub dht: Option<&'a mut Dht>,
    /// Event sink.
    pub events: &'a mut Vec<EngineEvent>,
}

impl TorrentSession {
    /// Create a session from a parsed torrent.
    pub fn from_torrent(torrent: Torrent, cfg: SessionConfig, now: u64) -> Result<TorrentSession> {
        let info_hash = torrent.info_hash;
        let tracker_hash = tracker_hash_of(&info_hash);
        let piece_count = torrent.piece_count();
        let scheduler = if cfg.smart_scheduling {
            Scheduler::new(&torrent, cfg.scheduler)
        } else {
            Scheduler::with_goal(&torrent, ContentGoal::Generic, cfg.scheduler)
        };
        let mut trackers: Vec<TrackerState> = Vec::new();
        for tier in torrent.announce_list.iter().chain(core::iter::once(
            torrent
                .announce
                .as_ref()
                .map(|a| alloc::vec![a.clone()])
                .as_ref()
                .unwrap_or(&Vec::new()),
        )) {
            for url in tier {
                trackers.push(TrackerState {
                    url: url.clone(),
                    kind: detect_tracker_kind(url),
                    interval: 1800,
                    next_announce: 0,
                    failure: None,
                    udp: UdpTrackerState::default(),
                });
            }
        }
        // de-duplicate
        trackers.sort_by(|a, b| a.url.cmp(&b.url));
        trackers.dedup_by(|a, b| a.url == b.url);

        let monitor = SwarmMonitor::new(
            info_hash.to_hex(),
            torrent.total_size,
            now,
            torrent.total_size.max(1),
        );
        Ok(TorrentSession {
            info_hash,
            tracker_hash,
            status: SessionStatus::Stopped,
            save_dir: cfg.save_dir.clone(),
            pieces: PieceTracker::new(piece_count, torrent.piece_length),
            scheduler,
            peers: BTreeMap::new(),
            requested_by: BTreeMap::new(),
            availability: vec![0; piece_count as usize],
            assembling: BTreeMap::new(),
            files: Vec::new(),
            trackers,
            tracker_cursor: 0,
            announce_at: 0,
            started_at: 0,
            downloaded_bytes: 0,
            uploaded_bytes: 0,
            last_unchoke_at: 0,
            optimistic: None,
            endgame: false,
            connect_queue: Vec::new(),
            dht_started: false,
            last_pex_at: 0,
            pex_known: Vec::new(),
            metadata: None,
            web_seeds: torrent
                .web_seeds
                .iter()
                .map(|w| String::from_utf8_lossy(w).into_owned())
                .collect(),
            webseed_cursor: 0,
            monitor,
            receipt_book: ReceiptBook::new(info_hash.full()),
            torrent: Some(torrent),
            cfg,
        })
    }

    /// Create a session from a magnet link (metadata will be fetched).
    pub fn from_magnet(magnet: &Magnet, cfg: SessionConfig, now: u64) -> Result<TorrentSession> {
        let info_hash = magnet.info_hash.ok_or(Error::Magnet)?;
        let tracker_hash = tracker_hash_of(&info_hash);
        let mut trackers: Vec<TrackerState> = Vec::new();
        for url in &magnet.trackers {
            let url = url.as_bytes().to_vec();
            let kind = detect_tracker_kind(&url);
            trackers.push(TrackerState {
                url,
                kind,
                interval: 1800,
                next_announce: 0,
                failure: None,
                udp: UdpTrackerState::default(),
            });
        }
        let pieces = PieceTracker::new(0, 0);
        let scheduler = Scheduler::with_goal(
            &Torrent::empty_placeholder(),
            ContentGoal::Generic,
            cfg.scheduler,
        );
        let monitor = SwarmMonitor::new(info_hash.to_hex(), 0, now, 1);
        Ok(TorrentSession {
            torrent: None,
            info_hash,
            tracker_hash,
            status: SessionStatus::FetchingMetadata,
            save_dir: cfg.save_dir.clone(),
            pieces,
            scheduler,
            peers: BTreeMap::new(),
            requested_by: BTreeMap::new(),
            availability: Vec::new(),
            assembling: BTreeMap::new(),
            files: Vec::new(),
            trackers,
            tracker_cursor: 0,
            announce_at: 0,
            started_at: 0,
            downloaded_bytes: 0,
            uploaded_bytes: 0,
            last_unchoke_at: 0,
            optimistic: None,
            endgame: false,
            connect_queue: Vec::new(),
            dht_started: false,
            last_pex_at: 0,
            pex_known: Vec::new(),
            metadata: Some(MetadataFetch {
                size: 0,
                pieces: BTreeMap::new(),
                requested: Bitfield::new(0),
                outstanding: 0,
            }),
            web_seeds: Vec::new(),
            webseed_cursor: 0,
            monitor,
            receipt_book: ReceiptBook::new(info_hash.full()),
            cfg,
        })
    }

    /// Start/resume.
    pub fn start<H: Host>(&mut self, ctx: &'_ mut SessionCtx<'_, H>) -> Result<()> {
        if self.status == SessionStatus::Downloading || self.status == SessionStatus::Seeding {
            return Ok(());
        }
        self.status = if self.torrent.is_none() {
            SessionStatus::FetchingMetadata
        } else {
            SessionStatus::Downloading
        };
        self.started_at = ctx.now;
        self.announce_at = ctx.now;
        self.open_files(ctx)?;
        self.announce_to_tracker(ctx, TrackerEvent::Started);
        if let Some(dht) = ctx.dht.as_mut() {
            dht.get_peers(self.tracker_hash, ctx.port, ctx.now);
            self.dht_started = true;
        }
        Ok(())
    }

    /// Pause.
    pub fn pause<H: Host>(&mut self, ctx: &'_ mut SessionCtx<'_, H>) {
        if self.status == SessionStatus::Paused {
            return;
        }
        self.status = SessionStatus::Paused;
        self.announce_to_tracker(ctx, TrackerEvent::Stopped);
        for peer in self.peers.values_mut() {
            peer.send(&Message::NotInterested);
        }
    }

    /// Resume from pause.
    pub fn resume<H: Host>(&mut self, ctx: &'_ mut SessionCtx<'_, H>) {
        if self.status != SessionStatus::Paused {
            return;
        }
        self.status = SessionStatus::Downloading;
        self.announce_at = ctx.now;
        self.announce_to_tracker(ctx, TrackerEvent::Started);
    }

    /// Stop (close connections and files).
    pub fn stop<H: Host>(&mut self, ctx: &'_ mut SessionCtx<'_, H>) {
        if self.status == SessionStatus::Stopped {
            return;
        }
        self.announce_to_tracker(ctx, TrackerEvent::Stopped);
        let conns: Vec<ConnId> = self.peers.keys().copied().collect();
        for c in conns {
            ctx.host.tcp_close(c);
        }
        self.peers.clear();
        for f in self.files.drain(..) {
            let _ = ctx.host.disk_flush(f);
            ctx.host.disk_close(f);
        }
        self.status = SessionStatus::Stopped;
    }

    /// Open all files and preallocate.
    fn open_files<H: Host>(&mut self, ctx: &'_ mut SessionCtx<'_, H>) -> Result<()> {
        if self.files.is_empty() {
            if let Some(t) = &self.torrent {
                for f in &t.files {
                    let path = self.file_path(f);
                    let id = ctx.host.disk_open(&path)?;
                    let _ = ctx.host.disk_prealloc(id, f.length);
                    self.files.push(id);
                }
            }
        }
        Ok(())
    }

    /// Build the absolute host path for a file entry.
    pub fn file_path(&self, f: &crate::metainfo::FileEntry) -> String {
        let mut p = String::from(&self.save_dir);
        p.push('/');
        p.push_str(&f.display_path());
        p
    }

    /// Progress ratio (0.0..=1.0).
    pub fn progress(&self) -> f64 {
        if self.pieces.piece_count() == 0 {
            return if self.status == SessionStatus::Seeding {
                1.0
            } else {
                0.0
            };
        }
        self.pieces.have_count() as f64 / self.pieces.piece_count() as f64
    }

    // ---------- tick ----------

    /// Advance time-based logic. Called by the engine every loop.
    pub fn tick<H: Host>(&mut self, ctx: &'_ mut SessionCtx<'_, H>) {
        match self.status {
            SessionStatus::Stopped | SessionStatus::Paused | SessionStatus::Failed => return,
            _ => {}
        }
        // re-announce
        if ctx.now >= self.announce_at {
            self.announce_to_tracker(ctx, TrackerEvent::None);
        }
        // endgame detection
        if !self.endgame && self.pieces.piece_count() > 0 {
            self.endgame = Picker::should_endgame(&self.pieces, self.cfg.endgame_pieces);
        }
        // choke/unchoke pass
        if ctx.now.saturating_sub(self.last_unchoke_at) >= self.cfg.choke.interval_ms {
            self.choke_pass(ctx);
            self.last_unchoke_at = ctx.now;
        }
        // DHT lookup / peer pull
        if self.dht_started {
            if let Some(dht) = ctx.dht.as_mut() {
                let peers = dht.discovered_peers(&self.tracker_hash);
                for p in peers {
                    self.enqueue_peer(p, DiscoverySource::Dht, ctx.now);
                }
            }
        }
        // PEX broadcast
        if ctx.now.saturating_sub(self.last_pex_at) >= 60_000 {
            self.broadcast_pex();
            self.last_pex_at = ctx.now;
        }
        // metadata fetch kick
        if self.torrent.is_none() {
            self.kick_metadata(ctx);
        }
        // request pipeline for unchoked peers
        if self.torrent.is_some() && self.status == SessionStatus::Downloading {
            let conns: Vec<ConnId> = self.peers.keys().copied().collect();
            for c in conns {
                let choked = {
                    let p = match self.peers.get(&c) {
                        Some(p) => p,
                        None => continue,
                    };
                    p.peer_choking || p.phase != PeerPhase::Ready
                };
                if !choked {
                    self.fill_pipeline(c, ctx);
                }
            }
        }
        // flush cache when under pressure or on a slow cadence
        if ctx.cache.used() > ctx.cache.budget() / 2 {
            let _ = ctx.cache.flush(ctx.host);
        }
        // update monitor rates
        self.update_monitor_rates(ctx.now);
    }

    fn update_monitor_rates(&mut self, now: u64) {
        let downloaded = self.downloaded_bytes;
        self.monitor.set_downloaded(downloaded, now);
        let snapshot: Vec<(ConnId, NetAddr, u32, u32)> = self
            .peers
            .iter()
            .map(|(c, p)| (*c, p.addr, p.down_rate, p.up_rate))
            .collect();
        for (_, addr, d, u) in snapshot {
            self.monitor.record_rates(addr, d, u, now);
        }
    }

    fn choke_pass<H: Host>(&mut self, ctx: &'_ mut SessionCtx<'_, H>) {
        update_snubs(self.peers.values_mut(), ctx.now, &self.cfg.choke);
        // rotate optimistic unchoke
        let rotate = match self.optimistic {
            Some(c) => self
                .peers
                .get(&c)
                .map(|p| {
                    ctx.now.saturating_sub(p.connected_at) > self.cfg.choke.optimistic_interval_ms
                })
                .unwrap_or(true),
            None => true,
        };
        if rotate {
            let ids: Vec<ConnId> = self.peers.keys().copied().collect();
            if !ids.is_empty() {
                let idx = (ctx.now as usize) % ids.len();
                self.optimistic = Some(ids[idx]);
            } else {
                self.optimistic = None;
            }
        }
        let seeding = self.status == SessionStatus::Seeding;
        let refs: Vec<&Peer> = self.peers.values().collect();
        let unchoke = compute_unchoke_set(&refs, seeding, &self.cfg.choke, |id| {
            self.optimistic == Some(id)
        });
        let cur: Vec<ConnId> = self.peers.keys().copied().collect();
        for c in cur {
            let (was_choking, is_choking) = {
                let p = self.peers.get_mut(&c).unwrap();
                let is_choking = !unchoke.contains(&c);
                let was = p.am_choking;
                p.am_choking = is_choking;
                (was, is_choking)
            };
            if was_choking != is_choking {
                let m = if is_choking {
                    Message::Choke
                } else {
                    Message::Unchoke
                };
                if let Some(p) = self.peers.get_mut(&c) {
                    p.send(&m);
                }
            }
        }
        // send interested / not interested
        let conns: Vec<ConnId> = self.peers.keys().copied().collect();
        for c in conns {
            let (want, choked) = {
                let p = match self.peers.get(&c) {
                    Some(p) => p,
                    None => continue,
                };
                (
                    p.should_be_interested(self.pieces.have_bitfield()),
                    p.peer_choking,
                )
            };
            let send = {
                let p = self.peers.get_mut(&c).unwrap();
                let send = want != p.am_interested && p.phase == PeerPhase::Ready;
                p.am_interested = want;
                if send {
                    if want {
                        p.send(&Message::Interested);
                    } else {
                        p.send(&Message::NotInterested);
                    }
                }
                let _ = choked;
                send
            };
            let _ = send;
        }
        // roll rate windows
        for p in self.peers.values_mut() {
            p.roll_window(ctx.now);
        }
    }

    // ---------- peer lifecycle ----------

    /// Register a connection for this session and send our handshake.
    pub fn attach_peer<H: Host>(
        &mut self,
        conn: ConnId,
        addr: NetAddr,
        outbound: bool,
        source: DiscoverySource,
        ctx: &'_ mut SessionCtx<'_, H>,
    ) {
        let pc = self.pieces.piece_count();
        let mut peer = Peer::new(conn, addr, pc, source);
        peer.connected_at = ctx.now;
        peer.window_started = ctx.now;
        peer.phase = PeerPhase::Handshake;
        let mut reserved = [0u8; 8];
        reserved[wire_reserved::EXTENSION.0] |= wire_reserved::EXTENSION.1;
        reserved[wire_reserved::DHT.0] |= wire_reserved::DHT.1;
        reserved[wire_reserved::FAST.0] |= wire_reserved::FAST.1;
        reserved[wire_reserved::METADATA.0] |= wire_reserved::METADATA.1;
        if self.info_hash.is_v2() {
            reserved[wire_reserved::V2.0] |= wire_reserved::V2.1;
        }
        let hs = Handshake {
            reserved,
            info_hash: self.tracker_hash,
            peer_id: ctx.peer_id,
        };
        peer.send_raw(&hs.encode());
        self.monitor.record_connect(addr, source, ctx.now, false);
        self.peers.insert(conn, peer);
        let _ = outbound;
    }

    /// Connection established (outbound connect completed).
    pub fn on_connect_done<H: Host>(&mut self, conn: ConnId, ctx: &'_ mut SessionCtx<'_, H>) {
        if let Some(p) = self.peers.get_mut(&conn) {
            p.phase = PeerPhase::Handshake;
            p.connected_at = ctx.now;
        }
    }

    /// Their handshake arrived.
    pub fn on_handshake<H: Host>(
        &mut self,
        conn: ConnId,
        their: Handshake,
        ctx: &'_ mut SessionCtx<'_, H>,
    ) -> Result<()> {
        let peer = self.peers.get_mut(&conn).ok_or(Error::NotFound)?;
        if their.info_hash != self.tracker_hash {
            return Err(Error::Handshake);
        }
        peer.peer_id = Some(their.peer_id);
        peer.reserved = their.reserved;
        peer.fast = their.has_fast();
        peer.supports_dht = their.has_dht();
        peer.supports_v2 = their.has_v2();
        peer.is_seed = false;
        peer.phase = PeerPhase::Ready;
        // send bitfield (or have_all/have_none)
        if peer.fast {
            if self.pieces.have_count() == self.pieces.piece_count() {
                peer.send(&Message::HaveAll);
            } else if self.pieces.have_count() == 0 {
                peer.send(&Message::HaveNone);
            } else {
                peer.send(&Message::Bitfield(self.pieces.have_bitfield().to_bytes()));
            }
        } else {
            peer.send(&Message::Bitfield(self.pieces.have_bitfield().to_bytes()));
        }
        // extended handshake
        if their.has_extension() {
            let mut ext = ExtHandshake::default();
            ext.m.insert(String::from("ut_metadata"), 3);
            ext.m.insert(String::from("ut_pex"), 5);
            ext.v = Some(String::from("TypeBit"));
            ext.reqq = Some(self.cfg.request_pipeline);
            if let Some(t) = &self.torrent {
                ext.metadata_size = Some(t.info_raw.len() as u32);
            }
            ext.p = Some(ctx.port as u32);
            peer.send(&Message::Extended {
                id: 0,
                payload: ext.encode(),
            });
        }
        // if this is a metadata fetch, request metadata
        if self.torrent.is_none() && peer.ext_metadata.is_none() && their.has_metadata() {
            // request will be triggered once we learn their ut_metadata id
        }
        // interest
        if self.torrent.is_some() {
            let want = peer.should_be_interested(self.pieces.have_bitfield());
            if want {
                peer.am_interested = true;
                peer.send(&Message::Interested);
            }
        }
        // record peer id in monitor (no-op), log via event
        self.monitor.record_rates(peer.addr, 0, 0, ctx.now);
        ctx.events.push(EngineEvent::PeerConnected {
            info_hash: self.info_hash,
            addr: peer.addr,
            peer_id: their.peer_id,
        });
        // send a bit of our known peers via PEX when they support it
        self.broadcast_pex_to(conn);
        Ok(())
    }

    /// Feed inbound bytes and process messages.
    pub fn on_data<H: Host>(&mut self, conn: ConnId, data: &[u8], ctx: &'_ mut SessionCtx<'_, H>) {
        let peer = match self.peers.get_mut(&conn) {
            Some(p) => p,
            None => return,
        };
        peer.on_data_in(data.len(), ctx.now);
        // handshake stage
        if peer.phase == PeerPhase::Handshake {
            peer.handshake_buf.extend_from_slice(data);
            if peer.handshake_buf.len() >= crate::wire::HANDSHAKE_LEN {
                let hs = match Handshake::parse(&peer.handshake_buf[..crate::wire::HANDSHAKE_LEN]) {
                    Ok(h) => h,
                    Err(_) => {
                        self.drop_peer(conn, FailureCategory::Timeout, ctx);
                        return;
                    }
                };
                let leftover = peer.handshake_buf[crate::wire::HANDSHAKE_LEN..].to_vec();
                peer.handshake_buf.clear();
                peer.msgs.feed(&leftover);
                if self.on_handshake(conn, hs, ctx).is_err() {
                    self.drop_peer(conn, FailureCategory::Timeout, ctx);
                    return;
                }
            } else {
                return;
            }
        }
        // post-handshake: feed remaining into message stream
        let peer = match self.peers.get_mut(&conn) {
            Some(p) => p,
            None => return,
        };
        // messages already fed above for the handshake leftover; if phase
        // was already Ready, feed data directly
        if peer.phase == PeerPhase::Ready && peer.handshake_buf.is_empty() {
            peer.msgs.feed(data);
        }
        // drain messages
        loop {
            let msg = {
                let peer = match self.peers.get_mut(&conn) {
                    Some(p) => p,
                    None => return,
                };
                match peer.msgs.poll() {
                    Ok(Some(m)) => m,
                    Ok(None) => break,
                    Err(_) => {
                        self.drop_peer(conn, FailureCategory::Timeout, ctx);
                        return;
                    }
                }
            };
            if self.dispatch(conn, msg, ctx).is_err() {
                self.drop_peer(conn, FailureCategory::Timeout, ctx);
                return;
            }
        }
    }

    /// Peer disconnected: release its state.
    pub fn on_disconnect<H: Host>(&mut self, conn: ConnId, ctx: &'_ mut SessionCtx<'_, H>) {
        let addr = self.peers.get(&conn).map(|p| p.addr);
        if let Some(addr) = addr {
            self.monitor
                .record_disconnect(addr, FailureCategory::Timeout);
            self.monitor.record_rates(addr, 0, 0, ctx.now);
        }
        if let Some(_p) = self.peers.remove(&conn) {
            // release requested blocks (borrow-safe two-phase)
            let mut to_clear: Vec<(u32, u16)> = Vec::new();
            for ((piece, block), reqs) in self.requested_by.iter_mut() {
                if let Some(pos) = reqs.iter().position(|c| *c == conn) {
                    reqs.remove(pos);
                    if reqs.is_empty() {
                        to_clear.push((*piece, *block));
                    }
                }
            }
            self.requested_by.retain(|_, v| !v.is_empty());
            for (piece, block) in to_clear {
                let bc = self.block_count(piece);
                self.pieces.clear_block_requested(piece, block, bc);
            }
        }
        self.recompute_availability();
    }

    /// Drop a peer with a failure category.
    pub fn drop_peer<H: Host>(
        &mut self,
        conn: ConnId,
        cat: FailureCategory,
        ctx: &'_ mut SessionCtx<'_, H>,
    ) {
        let addr = self.peers.get(&conn).map(|p| p.addr);
        if let Some(addr) = addr {
            self.monitor.record_disconnect(addr, cat);
        }
        if let Some(_p) = self.peers.remove(&conn) {
            let mut to_clear: Vec<(u32, u16)> = Vec::new();
            for ((piece, block), reqs) in self.requested_by.iter_mut() {
                if let Some(pos) = reqs.iter().position(|c| *c == conn) {
                    reqs.remove(pos);
                    if reqs.is_empty() {
                        to_clear.push((*piece, *block));
                    }
                }
            }
            self.requested_by.retain(|_, v| !v.is_empty());
            for (piece, block) in to_clear {
                let bc = self.block_count(piece);
                self.pieces.clear_block_requested(piece, block, bc);
            }
        }
        ctx.host.tcp_close(conn);
        self.recompute_availability();
    }

    fn block_count(&self, piece: u32) -> u16 {
        if let Some(t) = &self.torrent {
            if let Ok(pi) = t.piece_info(piece) {
                return block_count_for(pi.len);
            }
        }
        1
    }

    // ---------- message dispatch ----------

    fn dispatch<H: Host>(
        &mut self,
        conn: ConnId,
        msg: Message,
        ctx: &'_ mut SessionCtx<'_, H>,
    ) -> Result<()> {
        match msg {
            Message::Choke => {
                if let Some(p) = self.peers.get_mut(&conn) {
                    p.peer_choking = true;
                }
            }
            Message::Unchoke => {
                if let Some(p) = self.peers.get_mut(&conn) {
                    p.peer_choking = false;
                }
            }
            Message::Interested => {
                if let Some(p) = self.peers.get_mut(&conn) {
                    p.peer_interested = true;
                }
            }
            Message::NotInterested => {
                if let Some(p) = self.peers.get_mut(&conn) {
                    p.peer_interested = false;
                }
            }
            Message::Have(piece) => {
                if let Some(peer) = self.peers.get_mut(&conn) {
                    if piece < peer.have.len() {
                        peer.have.set(piece);
                    }
                }
                self.monitor.record_piece_cover(self.peer_addr(conn), piece);
                self.recompute_availability();
            }
            Message::Bitfield(b) => {
                let n = self.pieces.piece_count();
                if let Some(peer) = self.peers.get_mut(&conn) {
                    if peer.have_all {
                        return Err(Error::Protocol);
                    }
                    if peer.have.from_bytes(&b, n).is_ok() {
                        if peer.have.count() == n {
                            peer.is_seed = true;
                        }
                    } else {
                        return Err(Error::Protocol);
                    }
                }
                self.recompute_availability();
            }
            Message::HaveAll => {
                if let Some(peer) = self.peers.get_mut(&conn) {
                    if peer.have_all || peer.have_none {
                        return Err(Error::Protocol);
                    }
                    peer.have_all = true;
                    peer.is_seed = true;
                }
                self.recompute_availability();
            }
            Message::HaveNone => {
                if let Some(peer) = self.peers.get_mut(&conn) {
                    if peer.have_all || peer.have_none {
                        return Err(Error::Protocol);
                    }
                    peer.have_none = true;
                }
            }
            Message::Request {
                index,
                begin,
                length,
            } => {
                self.on_request(conn, index, begin, length, ctx)?;
            }
            Message::Piece { index, begin, data } => {
                self.on_piece(conn, index, begin, data, ctx)?;
            }
            Message::Cancel { index, begin, .. } => {
                self.cancel_peer_request(conn, index, begin);
            }
            Message::Port(p) => {
                // peer advertises its DHT port
                let addr = self.peers.get(&conn).map(|peer| {
                    let mut a = peer.addr;
                    a = with_port(a, p);
                    a
                });
                if let Some(a) = addr {
                    if let Some(dht) = ctx.dht.as_mut() {
                        // we could add to DHT routing via ping; keep simple: record
                        let _ = dht;
                    }
                    self.monitor.record_rates(a, 0, 0, ctx.now);
                }
            }
            Message::Extended { id, payload } => {
                self.on_extended(conn, id, payload, ctx)?;
            }
            Message::Suggest(piece) | Message::AllowedFast(piece) => {
                if let Some(peer) = self.peers.get_mut(&conn) {
                    if piece < peer.have.len() {
                        peer.have.set(piece);
                    }
                }
            }
            Message::Reject { .. } => {
                // peer rejected a request; pipeline will refill
            }
            Message::KeepAlive => {}
        }
        Ok(())
    }

    fn peer_addr(&self, conn: ConnId) -> NetAddr {
        self.peers
            .get(&conn)
            .map(|p| p.addr)
            .unwrap_or(NetAddr::V4([0; 4], 0))
    }

    // ---------- extended messages ----------

    fn on_extended<H: Host>(
        &mut self,
        conn: ConnId,
        id: u8,
        payload: Vec<u8>,
        ctx: &'_ mut SessionCtx<'_, H>,
    ) -> Result<()> {
        if id == 0 {
            // extended handshake
            let ext = ExtHandshake::parse(&payload)?;
            if let Some(peer) = self.peers.get_mut(&conn) {
                peer.ext = Some(ext.clone());
                peer.ext_metadata = ext.m.get("ut_metadata").copied();
                peer.ext_pex = ext.m.get("ut_pex").copied();
                if let Some(ms) = ext.metadata_size {
                    peer.msgs
                        .set_max_frame((ms as usize).max(peer.msgs.max_frame()));
                }
            }
            // if we need metadata, start requesting
            if self.torrent.is_none() {
                if let Some(peer) = self.peers.get(&conn) {
                    if let Some(meta_id) = peer.ext_metadata {
                        let msg = Message::Extended {
                            id: meta_id,
                            payload: MetadataMsg::Request { piece: 0 }.encode(),
                        };
                        if let Some(p) = self.peers.get_mut(&conn) {
                            p.send(&msg);
                        }
                        if let Some(m) = self.metadata.as_mut() {
                            m.outstanding += 1;
                        }
                    }
                }
            }
            return Ok(());
        }
        // ut_metadata (id 3 as we advertise)
        if id == 3 {
            let m = MetadataMsg::parse(&payload)?;
            return self.on_metadata_msg(conn, m, ctx);
        }
        // ut_pex (id 5)
        if id == 5 {
            let pex = PexMsg::parse(&payload)?;
            self.on_pex(conn, pex, ctx);
            return Ok(());
        }
        Ok(())
    }

    fn on_metadata_msg<H: Host>(
        &mut self,
        conn: ConnId,
        msg: MetadataMsg,
        ctx: &'_ mut SessionCtx<'_, H>,
    ) -> Result<()> {
        match msg {
            MetadataMsg::Request { piece } => {
                // we are the source: serve our info dict
                if let Some(t) = &self.torrent {
                    let meta = &t.info_raw;
                    let piece_len = 16 * 1024usize;
                    let start = piece as usize * piece_len;
                    if start >= meta.len() {
                        return Ok(());
                    }
                    let end = (start + piece_len).min(meta.len());
                    let data = meta[start..end].to_vec();
                    let msg = MetadataMsg::Data {
                        piece,
                        total_size: meta.len() as u32,
                        data,
                    };
                    let peer = self.peers.get_mut(&conn).ok_or(Error::NotFound)?;
                    if let Some(meta_id) = peer.ext_metadata {
                        peer.send(&Message::Extended {
                            id: meta_id,
                            payload: msg.encode(),
                        });
                    }
                }
            }
            MetadataMsg::Data {
                piece,
                total_size,
                data,
            } => {
                let meta = match self.metadata.as_mut() {
                    Some(m) => m,
                    None => return Ok(()),
                };
                if meta.size == 0 {
                    meta.size = total_size;
                    meta.requested = Bitfield::new(total_size.div_ceil(16 * 1024));
                }
                if piece as usize >= meta.requested.len() as usize {
                    return Ok(());
                }
                use alloc::collections::btree_map::Entry;
                if let Entry::Vacant(e) = meta.pieces.entry(piece) {
                    e.insert(data);
                    meta.outstanding = meta.outstanding.saturating_sub(1);
                    meta.requested.set(piece);
                }
                // try to finalize
                self.try_finalize_metadata(ctx);
            }
            MetadataMsg::Reject { piece } => {
                if let Some(m) = self.metadata.as_mut() {
                    if m.requested.get(piece) {
                        m.outstanding = m.outstanding.saturating_sub(1);
                        m.requested.clear(piece);
                    }
                }
            }
        }
        Ok(())
    }

    fn try_finalize_metadata<H: Host>(&mut self, ctx: &'_ mut SessionCtx<'_, H>) {
        let complete = {
            let m = match self.metadata.as_ref() {
                Some(m) => m,
                None => return,
            };
            if m.size == 0 {
                false
            } else {
                let np = m.size.div_ceil(16 * 1024);
                m.pieces.len() as u32 >= np && (0..np).all(|i| m.pieces.contains_key(&i))
            }
        };
        if !complete {
            return;
        }
        // assemble info dict
        let mut raw = Vec::new();
        let np = {
            let m = self.metadata.as_ref().unwrap();
            m.size.div_ceil(16 * 1024)
        };
        for i in 0..np {
            if let Some(d) = self.metadata.as_ref().unwrap().pieces.get(&i) {
                raw.extend_from_slice(d);
            }
        }
        // verify infohash matches
        let hash_ok = if self.info_hash.is_v1() {
            crate::crypto::Sha1::digest(&raw) == self.info_hash.full()[..20]
        } else {
            crate::crypto::Sha256::digest(&raw) == self.info_hash.full()
        };
        if !hash_ok {
            self.metadata = None;
            self.status = SessionStatus::Failed;
            ctx.events.push(EngineEvent::MetadataFailed {
                info_hash: self.info_hash,
            });
            return;
        }
        match Torrent::from_info(&raw) {
            Ok(t) => {
                self.install_torrent(t, ctx);
            }
            Err(_) => {
                self.metadata = None;
                self.status = SessionStatus::Failed;
            }
        }
    }

    fn install_torrent<H: Host>(&mut self, t: Torrent, ctx: &'_ mut SessionCtx<'_, H>) {
        let piece_count = t.piece_count();
        self.pieces = PieceTracker::new(piece_count, t.piece_length);
        self.availability = vec![0; piece_count as usize];
        self.scheduler = Scheduler::new(&t, self.cfg.scheduler);
        self.torrent = Some(t.clone());
        self.metadata = None;
        self.status = SessionStatus::Downloading;
        self.monitor = SwarmMonitor::new(
            self.info_hash.to_hex(),
            t.total_size,
            ctx.now,
            t.total_size.max(1),
        );
        self.announce_at = ctx.now;
        if self.open_files(ctx).is_err() {
            self.status = SessionStatus::Failed;
        }
        ctx.events.push(EngineEvent::MetadataComplete {
            info_hash: self.info_hash,
        });
    }

    fn kick_metadata<H: Host>(&mut self, ctx: &'_ mut SessionCtx<'_, H>) {
        // ensure we are requesting metadata from peers that support it
        let conns: Vec<ConnId> = self.peers.keys().copied().collect();
        for c in conns {
            let can_request = {
                let p = match self.peers.get(&c) {
                    Some(p) => p,
                    None => continue,
                };
                p.ext_metadata.is_some() && p.phase == PeerPhase::Ready
            };
            if !can_request {
                continue;
            }
            let peer = self.peers.get_mut(&c).unwrap();
            let meta_id = peer.ext_metadata.unwrap();
            let (start_piece, outstanding) = {
                let m = self.metadata.as_mut().unwrap();
                let np = if m.size == 0 {
                    0
                } else {
                    m.size.div_ceil(16 * 1024)
                };
                let next = m
                    .requested
                    .next_clear_from(0)
                    .filter(|p| np == 0 || *p < np);
                (next, m.outstanding)
            };
            if outstanding < 8 {
                if let Some(piece) = start_piece {
                    if let Some(m) = self.metadata.as_mut() {
                        m.requested.set(piece);
                        m.outstanding += 1;
                    }
                    peer.send(&Message::Extended {
                        id: meta_id,
                        payload: MetadataMsg::Request { piece }.encode(),
                    });
                }
            }
        }
        // keep the peer discovery flowing for metadata-only sessions
        if ctx.now.saturating_sub(self.announce_at) >= 15_000 {
            self.announce_at = ctx.now;
            self.announce_to_tracker(ctx, TrackerEvent::Started);
        }
    }

    // ---------- tracker ----------

    /// Kick the next tracker announce (HTTP synchronous, UDP asynchronous).
    pub fn announce_to_tracker<H: Host>(
        &mut self,
        ctx: &'_ mut SessionCtx<'_, H>,
        event: TrackerEvent,
    ) {
        if self.trackers.is_empty() {
            self.announce_at = ctx.now + 15 * 60 * 1000;
            return;
        }
        let left = match &self.torrent {
            Some(t) => t.total_size.saturating_sub(self.downloaded_bytes),
            None => 0,
        };
        let params = AnnounceParams {
            tracker_hash: self.tracker_hash,
            peer_id: ctx.peer_id,
            port: ctx.port,
            uploaded: self.uploaded_bytes,
            downloaded: self.downloaded_bytes,
            left,
            event,
            numwant: 200,
            key: 0x54594254, // "TYBT"
        };
        // try trackers in round-robin
        let mut attempt = 0;
        while attempt < self.trackers.len() {
            let idx = self.tracker_cursor % self.trackers.len();
            let kind = self.trackers[idx].kind;
            match kind {
                TrackerKind::Http => {
                    let url = tracker::build_http_announce_url(
                        &String::from_utf8_lossy(&self.trackers[idx].url),
                        &params,
                    );
                    let mut body = Vec::new();
                    match ctx.host.http_get(&url, 15_000, &mut body) {
                        Ok(()) => match tracker::parse_tracker_response(&body) {
                            Ok(resp) => {
                                if let Some(f) = resp.failure {
                                    self.trackers[idx].failure = Some(f);
                                } else {
                                    let interval = resp.interval.max(30);
                                    let peer_count = resp.peers.len();
                                    self.trackers[idx].interval = interval;
                                    self.trackers[idx].next_announce = ctx.now + interval * 1000;
                                    self.trackers[idx].failure = None;
                                    self.on_tracker_peers(resp, ctx);
                                    self.tracker_cursor = (idx + 1) % self.trackers.len();
                                    self.announce_at = ctx.now + interval * 1000;
                                    self.monitor.record_discovery(DiscoverySource::Tracker);
                                    ctx.events.push(EngineEvent::TrackerAnnounced {
                                        info_hash: self.info_hash,
                                        peers: peer_count,
                                    });
                                    return;
                                }
                            }
                            Err(_) => {
                                self.trackers[idx].failure = Some(String::from("bad response"));
                            }
                        },
                        Err(_) => {
                            self.trackers[idx].failure = Some(String::from("http error"));
                        }
                    }
                }
                TrackerKind::Udp => {
                    let st = &mut self.trackers[idx];
                    if st.udp.phase == UdpPhase::Idle {
                        let addr = parse_udp_tracker_addr(&st.url);
                        if let Some(a) = addr {
                            st.udp.addr = Some(a);
                            st.udp.tid = rand_u32(ctx.now);
                            st.udp.sent_at = ctx.now;
                            let req = tracker::udp::build_connect_request(st.udp.tid);
                            let _ = ctx.host.udp_send(&a, &req);
                            st.udp.phase = UdpPhase::ConnectSent;
                        }
                    }
                    self.tracker_cursor = (idx + 1) % self.trackers.len();
                    self.announce_at = ctx.now + 15_000;
                    return;
                }
            }
            attempt += 1;
            self.tracker_cursor = (self.tracker_cursor + 1) % self.trackers.len();
        }
        // all failed: back off
        self.announce_at = ctx.now + 30 * 1000;
    }

    fn on_tracker_peers<H: Host>(&mut self, resp: TrackerResponse, ctx: &'_ mut SessionCtx<'_, H>) {
        if let Some(c) = resp.complete {
            self.monitor.record_connect(
                NetAddr::V4([0, 0, 0, 0], 0),
                DiscoverySource::Tracker,
                ctx.now,
                true,
            );
            // note: seeders are aggregate counts, not a peer; skip peer entry
            let _ = c;
        }
        for p in resp.peers {
            self.enqueue_peer(p, DiscoverySource::Tracker, ctx.now);
        }
    }

    /// Handle a UDP tracker datagram routed to this session.
    pub fn on_udp_tracker_datagram<H: Host>(
        &mut self,
        addr: NetAddr,
        data: &[u8],
        ctx: &'_ mut SessionCtx<'_, H>,
    ) {
        let mut handled = false;
        for st in self.trackers.iter_mut() {
            if st.kind != TrackerKind::Udp {
                continue;
            }
            if st.udp.phase == UdpPhase::Idle {
                continue;
            }
            if data.len() >= 8 {
                let r_tid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                if r_tid != st.udp.tid {
                    continue;
                }
                let action = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                if st.udp.phase == UdpPhase::ConnectSent && action == tracker::udp::ACTION_CONNECT {
                    match tracker::udp::parse_connect_response(data, st.udp.tid) {
                        Ok(conn_id) => {
                            st.udp.conn_id = conn_id;
                            st.udp.phase = UdpPhase::AnnounceSent;
                            st.udp.tid = rand_u32(ctx.now);
                            st.udp.sent_at = ctx.now;
                            let left = self
                                .torrent
                                .as_ref()
                                .map(|t| t.total_size.saturating_sub(self.downloaded_bytes))
                                .unwrap_or(0);
                            let p = AnnounceParams {
                                tracker_hash: self.tracker_hash,
                                peer_id: ctx.peer_id,
                                port: ctx.port,
                                uploaded: self.uploaded_bytes,
                                downloaded: self.downloaded_bytes,
                                left,
                                event: TrackerEvent::None,
                                numwant: 200,
                                key: 0x54594254,
                            };
                            let req = tracker::udp::build_announce_request(conn_id, st.udp.tid, &p);
                            if let Some(a) = st.udp.addr {
                                let _ = ctx.host.udp_send(&a, &req);
                            }
                            self.announce_at = ctx.now + 15_000;
                            handled = true;
                            break;
                        }
                        Err(_) => {
                            st.udp.phase = UdpPhase::Idle;
                            handled = true;
                            break;
                        }
                    }
                } else if st.udp.phase == UdpPhase::AnnounceSent
                    && action == tracker::udp::ACTION_ANNOUNCE
                {
                    match tracker::udp::parse_announce_response(data, st.udp.tid) {
                        Ok(resp) => {
                            let interval = resp.interval.max(30);
                            st.interval = interval;
                            st.next_announce = ctx.now + interval * 1000;
                            st.udp.phase = UdpPhase::Idle;
                            self.announce_at = ctx.now + interval * 1000;
                            self.on_tracker_peers(resp, ctx);
                            handled = true;
                            break;
                        }
                        Err(_) => {
                            st.udp.phase = UdpPhase::Idle;
                            handled = true;
                            break;
                        }
                    }
                }
            }
        }
        let _ = addr;
        let _ = handled;
    }

    // ---------- peer queue / discovery ----------

    fn enqueue_peer(&mut self, addr: NetAddr, source: DiscoverySource, now: u64) {
        if self.peers.len() as u32 >= self.cfg.max_peers {
            return;
        }
        // dedupe by addr among connected + queued
        if self.peers.values().any(|p| p.addr == addr) {
            return;
        }
        if self.connect_queue.iter().any(|(a, _)| *a == addr) {
            return;
        }
        // ignore loopback unless explicit
        self.connect_queue.push((addr, source));
        self.monitor.record_discovery(source);
        let _ = now;
    }

    /// Drain connect queue (engine calls).
    pub fn take_connect_queue(&mut self) -> alloc::vec::Vec<(NetAddr, DiscoverySource)> {
        core::mem::take(&mut self.connect_queue)
    }

    // ---------- PEX ----------

    fn broadcast_pex(&mut self) {
        let conns: Vec<ConnId> = self.peers.keys().copied().collect();
        for c in conns {
            self.broadcast_pex_to(c);
        }
    }

    fn broadcast_pex_to(&mut self, conn: ConnId) {
        let meta_id = match self.peers.get(&conn).and_then(|p| p.ext_pex) {
            Some(id) => id,
            None => return,
        };
        let now = self.peers.get(&conn).map(|p| p.last_active).unwrap_or(0);
        // gather up to 50 known peers (excluding the recipient)
        let others: Vec<NetAddr> = self
            .peers
            .iter()
            .filter(|(c, p)| **c != conn && p.phase == PeerPhase::Ready)
            .map(|(_, p)| p.addr)
            .chain(self.pex_known.iter().copied())
            .collect::<alloc::collections::BTreeSet<_>>()
            .into_iter()
            .take(50)
            .collect();
        let mut msg = PexMsg::default();
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for a in &others {
            if let Some(b) = a.to_compact6() {
                v4.extend_from_slice(&b);
            } else if let Some(b) = a.to_compact18() {
                v6.extend_from_slice(&b);
            }
        }
        msg.added = v4;
        msg.added6 = v6;
        let payload = msg.encode();
        if let Some(p) = self.peers.get_mut(&conn) {
            p.send(&Message::Extended {
                id: meta_id,
                payload,
            });
        }
        let _ = now;
    }

    fn on_pex<H: Host>(&mut self, conn: ConnId, msg: PexMsg, ctx: &'_ mut SessionCtx<'_, H>) {
        let mut added = Vec::new();
        for c in msg.added.chunks_exact(6) {
            if let Some(a) = NetAddr::from_compact6(c) {
                added.push(a);
            }
        }
        for c in msg.added6.chunks_exact(18) {
            if let Some(a) = NetAddr::from_compact18(c) {
                added.push(a);
            }
        }
        for a in added {
            // do not echo back to the sender's own address
            if self.peers.get(&conn).map(|p| p.addr) == Some(a) {
                continue;
            }
            if !self.pex_known.contains(&a) {
                self.pex_known.push(a);
            }
            self.enqueue_peer(a, DiscoverySource::Pex, ctx.now);
        }
        // dropped: remove from pex_known
        for c in msg.dropped.chunks_exact(6) {
            if let Some(a) = NetAddr::from_compact6(c) {
                if let Some(pos) = self.pex_known.iter().position(|x| *x == a) {
                    self.pex_known.remove(pos);
                }
            }
        }
    }

    // ---------- request pipeline ----------

    fn fill_pipeline<H: Host>(&mut self, conn: ConnId, _ctx: &'_ mut SessionCtx<'_, H>) {
        let mut guard = 0u32;
        while guard < 512 {
            guard += 1;
            let (pipe, _chunked, want) = {
                let peer = match self.peers.get(&conn) {
                    Some(p) => p,
                    None => return,
                };
                let pipe = peer.requests_in_flight;
                let chunked = pipe >= peer.max_pipeline();
                let want = peer.am_interested && !peer.peer_choking && !chunked;
                (pipe, chunked, want)
            };
            if !want {
                break;
            }
            let opts = PickOptions {
                endgame: self.endgame,
            };
            let piece = {
                let peer = self.peers.get(&conn).unwrap();
                Picker::pick_piece(
                    &self.pieces,
                    self.scheduler.utilities(),
                    &self.availability,
                    &peer.have,
                    opts,
                )
            };
            let piece = match piece {
                Some(p) => p,
                None => break,
            };
            let (block, begin, len, total_blocks) = {
                let pi = match self.torrent.as_ref().and_then(|t| t.piece_info(piece).ok()) {
                    Some(pi) => pi,
                    None => break,
                };
                let total_blocks = block_count_for(pi.len);
                let b = match Picker::pick_block(&self.pieces, piece, total_blocks, true) {
                    Some(b) => b,
                    None => {
                        // this piece is fully requested by others; try next
                        // by marking in-flight (already), continue loop
                        continue;
                    }
                };
                let begin = (b as u32) * BLOCK_LEN;
                let len = core::cmp::min(BLOCK_LEN, pi.len - begin);
                (b, begin, len, total_blocks)
            };
            // mark globally requested
            self.pieces.mark_block_requested(piece, block, total_blocks);
            self.requested_by
                .entry((piece, block))
                .or_default()
                .push(conn);
            if let Some(p) = self.peers.get_mut(&conn) {
                p.requests_in_flight += 1;
                p.send(&Message::Request {
                    index: piece,
                    begin,
                    length: len,
                });
            }
            let _ = pipe;
        }
    }

    /// A block (piece message) arrived.
    fn on_piece<H: Host>(
        &mut self,
        conn: ConnId,
        index: u32,
        begin: u32,
        data: Vec<u8>,
        ctx: &'_ mut SessionCtx<'_, H>,
    ) -> Result<()> {
        let t = match &self.torrent {
            Some(t) => t.clone(),
            None => return Err(Error::Protocol),
        };
        let pi = t.piece_info(index)?;
        let total_blocks = block_count_for(pi.len);
        let block = begin / BLOCK_LEN;
        if (block as u16) >= total_blocks || begin % BLOCK_LEN != 0 {
            return Err(Error::Protocol);
        }
        if data.len() as u32 != core::cmp::min(BLOCK_LEN, pi.len - begin) {
            return Err(Error::Protocol);
        }
        // endgame: cancel duplicate requests to other peers
        if let Some(reqs) = self.requested_by.get(&(index, block as u16)) {
            for &c in reqs {
                if c != conn {
                    if let Some(p) = self.peers.get_mut(&c) {
                        p.send(&Message::Cancel {
                            index,
                            begin,
                            length: data.len() as u32,
                        });
                        p.requests_in_flight = p.requests_in_flight.saturating_sub(1);
                    }
                }
            }
        }
        self.requested_by.remove(&(index, block as u16));
        self.pieces
            .clear_block_requested(index, block as u16, total_blocks);
        // decrement the sender's in-flight count
        if let Some(p) = self.peers.get_mut(&conn) {
            p.requests_in_flight = p.requests_in_flight.saturating_sub(1);
        }
        let newly = self
            .pieces
            .mark_block_received(index, block as u16, total_blocks);
        if !newly {
            return Ok(());
        }
        // assemble
        let entry = self
            .assembling
            .entry(index)
            .or_insert_with(|| vec![0u8; pi.len as usize]);
        if begin as usize + data.len() <= entry.len() {
            entry[begin as usize..begin as usize + data.len()].copy_from_slice(&data);
        }
        self.downloaded_bytes += data.len() as u64;
        self.monitor.record_piece_cover(self.peer_addr(conn), index);
        if self.pieces.piece_data_complete(index, total_blocks) {
            // verify
            let buf = match self.assembling.remove(&index) {
                Some(b) => b,
                None => return Ok(()),
            };
            match t.verify_piece(index, &buf) {
                Ok(()) => {
                    // write to disk cache (piece may span files)
                    let abs = t.piece_abs_offset(index)?;
                    self.write_abs(ctx, abs, &buf)?;
                    self.pieces.mark_piece_have(index);
                    // broadcast have
                    let conns: Vec<ConnId> = self.peers.keys().copied().collect();
                    for c in conns {
                        if let Some(p) = self.peers.get_mut(&c) {
                            if p.phase == PeerPhase::Ready {
                                p.send(&Message::Have(index));
                            }
                        }
                    }
                    // receipt book + monitor
                    self.receipt_book.record_range(abs, abs + buf.len() as u64);
                    let sample = crate::crypto::Sha256::digest(&buf[..buf.len().min(4096)]);
                    self.receipt_book.record_sample(abs, sample);
                    ctx.events.push(EngineEvent::PieceVerified {
                        info_hash: self.info_hash,
                        piece: index,
                    });
                    if self.pieces.have_count() == self.pieces.piece_count() {
                        self.status = SessionStatus::Seeding;
                        self.announce_at = ctx.now;
                        self.announce_to_tracker(ctx, TrackerEvent::Completed);
                        ctx.events.push(EngineEvent::TorrentComplete {
                            info_hash: self.info_hash,
                        });
                    }
                }
                Err(_) => {
                    // hash failure: reset piece, penalize sender
                    self.pieces.reset_piece(index);
                    self.monitor.record_hash_failure(index);
                    self.scheduler.mark_suspicious(index);
                    ctx.events.push(EngineEvent::HashFailure {
                        info_hash: self.info_hash,
                        piece: index,
                    });
                }
            }
        }
        Ok(())
    }

    /// Serving: a peer requests a block from us.
    fn on_request<H: Host>(
        &mut self,
        conn: ConnId,
        index: u32,
        begin: u32,
        length: u32,
        ctx: &'_ mut SessionCtx<'_, H>,
    ) -> Result<()> {
        let (have, am_choking) = {
            let peer = match self.peers.get(&conn) {
                Some(p) => p,
                None => return Ok(()),
            };
            (self.pieces.is_have(index), peer.am_choking)
        };
        if !have || am_choking {
            // we don't have it or we're choking them → reject if fast
            if let Some(p) = self.peers.get_mut(&conn) {
                if p.fast {
                    p.send(&Message::Reject {
                        index,
                        begin,
                        length,
                    });
                }
            }
            return Ok(());
        }
        let t = match &self.torrent {
            Some(t) => t.clone(),
            None => return Ok(()),
        };
        let pi = t.piece_info(index)?;
        if begin + length > pi.len {
            return Err(Error::Protocol);
        }
        // read the block from disk cache (absolute offset)
        let abs = t.piece_abs_offset(index)? + begin as u64;
        let mut buf = vec![0u8; length as usize];
        let n = self.read_abs(ctx, abs, &mut buf)?;
        if n as u32 != length {
            return Ok(()); // can't serve fully
        }
        self.uploaded_bytes += n as u64;
        if let Some(p) = self.peers.get_mut(&conn) {
            p.on_data_out(n, ctx.now);
            p.send(&Message::Piece {
                index,
                begin,
                data: buf,
            });
        }
        Ok(())
    }

    fn cancel_peer_request(&mut self, conn: ConnId, index: u32, begin: u32) {
        let block = (begin / BLOCK_LEN) as u16;
        if let Some(reqs) = self.requested_by.get_mut(&(index, block)) {
            if let Some(pos) = reqs.iter().position(|c| *c == conn) {
                reqs.remove(pos);
            }
            if reqs.is_empty() {
                self.requested_by.remove(&(index, block));
                self.pieces
                    .clear_block_requested(index, block, self.block_count(index));
            }
        }
        if let Some(p) = self.peers.get_mut(&conn) {
            p.requests_in_flight = p.requests_in_flight.saturating_sub(1);
        }
    }

    // ---------- disk helpers ----------

    /// Read `len` payload bytes at absolute offset (walking files).
    fn read_abs<H: Host>(
        &mut self,
        ctx: &'_ mut SessionCtx<'_, H>,
        abs: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        let t = match &self.torrent {
            Some(t) => t.clone(),
            None => return Err(Error::NotFound),
        };
        let mut got = 0usize;
        let mut pos = abs;
        while got < buf.len() {
            let (file_idx, file_off) = t.locate_offset(pos)?;
            let f = &t.files[file_idx as usize];
            let take = core::cmp::min((buf.len() - got) as u64, f.length - file_off);
            if take == 0 {
                break;
            }
            let disk = *self.files.get(file_idx as usize).ok_or(Error::NotFound)?;
            let n = ctx
                .cache
                .read(ctx.host, disk, file_off, &mut buf[got..got + take as usize])?;
            got += n;
            pos += n as u64;
            if n == 0 {
                break;
            }
        }
        Ok(got)
    }

    /// Write payload bytes at absolute offset (walking files) via the cache.
    fn write_abs<H: Host>(
        &mut self,
        ctx: &'_ mut SessionCtx<'_, H>,
        abs: u64,
        data: &[u8],
    ) -> Result<()> {
        let t = match &self.torrent {
            Some(t) => t.clone(),
            None => return Err(Error::NotFound),
        };
        let mut pos = abs;
        let mut off = 0usize;
        while off < data.len() {
            let (file_idx, file_off) = t.locate_offset(pos)?;
            let f = &t.files[file_idx as usize];
            let take = core::cmp::min((data.len() - off) as u64, f.length - file_off);
            if take == 0 {
                break;
            }
            let disk = *self.files.get(file_idx as usize).ok_or(Error::NotFound)?;
            ctx.cache
                .write(ctx.host, disk, file_off, &data[off..off + take as usize])?;
            off += take as usize;
            pos += take;
        }
        // flush the piece right away so verified data hits disk promptly
        if let Some(disk) = self.files.first().copied() {
            let _ = ctx.cache.flush_disk(ctx.host, disk);
        }
        Ok(())
    }

    // ---------- availability ----------

    /// Recompute per-piece peer counts from connected peers.
    pub fn recompute_availability(&mut self) {
        let n = self.pieces.piece_count() as usize;
        if n == 0 {
            return;
        }
        self.availability = vec![0u32; n];
        for p in self.peers.values() {
            if p.have_all {
                for a in self.availability.iter_mut() {
                    *a += 1;
                }
                continue;
            }
            let mut i = p.have.first_set();
            while let Some(b) = i {
                if (b as usize) < n {
                    self.availability[b as usize] += 1;
                }
                i = p.have.next_set_from(b + 1);
            }
        }
        self.scheduler.update_availability(&self.availability);
    }
}

// ---------- free helpers ----------

/// 20-byte tracker/DHT hash from an infohash (v2 truncated).
pub fn tracker_hash_of(ih: &InfoHash) -> [u8; 20] {
    let mut h = [0u8; 20];
    let b = ih.as_bytes();
    let n = b.len().min(20);
    h[..n].copy_from_slice(&b[..n]);
    h
}

fn detect_tracker_kind(url: &[u8]) -> TrackerKind {
    if url.starts_with(b"udp://") {
        TrackerKind::Udp
    } else {
        TrackerKind::Http
    }
}

fn parse_udp_tracker_addr(url: &[u8]) -> Option<NetAddr> {
    // udp://host:port/announce
    let s = core::str::from_utf8(url).ok()?;
    let rest = s.strip_prefix("udp://")?;
    let hostport = rest.split('/').next()?;
    let (host, port) = hostport.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    // resolve IPv4 literal (host resolves DNS later in std host)
    let mut parts = host.split('.');
    let a: u8 = parts.next()?.parse().ok()?;
    let b: u8 = parts.next()?.parse().ok()?;
    let c: u8 = parts.next()?.parse().ok()?;
    let d: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(NetAddr::V4([a, b, c, d], port))
}

fn with_port(a: NetAddr, port: u16) -> NetAddr {
    match a {
        NetAddr::V4(ip, _) => NetAddr::V4(ip, port),
        NetAddr::V6(ip, _) => NetAddr::V6(ip, port),
    }
}

/// Cheap deterministic random u32 from the clock (for tids only).
fn rand_u32(seed: u64) -> u32 {
    // splitmix64
    let mut z = seed.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    (z ^ (z >> 31)) as u32
}

// Small helper extension for Peer out buffer.
trait SendRaw {
    fn send_raw(&mut self, data: &[u8]);
}

impl SendRaw for Peer {
    fn send_raw(&mut self, data: &[u8]) {
        self.out.extend_from_slice(data);
    }
}

// (re-export) compact peer helpers used by PEX.
/// Encode IPv4 peers as compact 6-byte entries (BEP-23).
pub fn pex_compact4(list: &[NetAddr]) -> Vec<u8> {
    crate::wire::compact_peers4(list)
}

// (re-export) compact peer helpers used by PEX.
/// Encode IPv6 peers as compact 18-byte entries (BEP-23).
pub fn pex_compact6(list: &[NetAddr]) -> Vec<u8> {
    crate::wire::compact_peers6(list)
}
