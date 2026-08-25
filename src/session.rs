//! Per-torrent session: owns peer connections, piece/block bookkeeping, the
//! utility scheduler, tracker/DHT/PEX discovery, metadata fetching (magnet
//! links), receipts and the swarm monitor; talks outward via [`SessionCtx`].

use crate::bitfield::Bitfield;
use crate::consts::BLOCK_LEN;
use crate::dht::Dht;
use crate::disk_cache::DiskCache;
use crate::engine::EngineEvent;
use crate::error::{Error, Result};
use crate::leech::{self, BanManager, BanReason, LeechConfig, PeerChokeView, ReputationStore};
use crate::magnet::Magnet;
use crate::metainfo::{InfoHash, Torrent};
use crate::monitoring::{DiscoverySource, FailureCategory, SwarmMonitor};
use crate::picker::{PickOptions, Picker};
use crate::piece::{block_count_for, PieceTracker};
use crate::platform::{ConnId, Host, NetAddr};
use crate::ratelimit::TokenBucket;
use crate::receipt::ReceiptBook;
use crate::scheduler::{ContentGoal, Scheduler, SchedulerConfig};
use crate::socks::{self as socks_mod, ProxyConfig};
use crate::swarm::{Peer, PeerPhase};
use crate::tracker::{self, AnnounceParams, Event as TrackerEvent, TrackerResponse};
use crate::verify::{HashKind, VerifyJob};
use crate::wire::{
    reserved as wire_reserved, ExtHandshake, Handshake, Message, MetadataMsg, PexMsg,
};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// How often a session re-issues its DHT `get_peers` lookup while running.
/// `get_peers` is idempotent (it never duplicates an active lookup), so a
/// lookup pruned early — e.g. started before the bootstrap populated the
/// routing table — is re-created here once the DHT has something to ask.
const DHT_ANNOUNCE_INTERVAL_MS: u64 = 60_000;

/// Per-file download priority (selective download).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilePriority {
    /// Do not download this file (pieces touching only skipped files are
    /// never requested; a torrent is complete once all *selected* pieces
    /// verify).
    Skip,
    /// Default priority.
    Normal,
    /// Download before Normal (piece score multiplier).
    High,
}

impl FilePriority {
    /// Piece score multiplier (Skip → excluded from picking).
    pub fn multiplier(self) -> i64 {
        match self {
            FilePriority::Skip => 0,
            FilePriority::Normal => 1,
            FilePriority::High => 4,
        }
    }

    /// Stable byte for persistence (0=Skip, 1=Normal, 2=High).
    pub fn to_byte(self) -> u8 {
        match self {
            FilePriority::Skip => 0,
            FilePriority::Normal => 1,
            FilePriority::High => 2,
        }
    }
}

/// Decode a persisted priority byte (unknown values degrade to Normal).
fn file_priority_from_u8(b: u8) -> FilePriority {
    match b {
        0 => FilePriority::Skip,
        1 => FilePriority::Normal,
        2 => FilePriority::High,
        _ => FilePriority::Normal,
    }
}

/// Web-seed URL path for a file: percent-encoded path components joined
/// with '/'.
fn web_seed_path(f: &crate::metainfo::FileEntry) -> String {
    let mut s = String::new();
    for (i, c) in f.path.iter().enumerate() {
        if i > 0 {
            s.push('/');
        }
        s.push_str(&crate::magnet::percent_encode(c));
    }
    s
}

/// Web seed (BEP-19) download options.
#[derive(Debug, Clone)]
pub struct WebSeedConfig {
    /// Enable fetching pieces from web seeds.
    pub enabled: bool,
    /// Per-block HTTP timeout (ms). Web seed blocks are fetched one per
    /// engine tick through the blocking host HTTP seam.
    pub timeout_ms: u64,
    /// Consecutive failures before rotating to the next seed / backing off.
    pub max_fails: u32,
    /// Backoff after every seed failed (ms).
    pub backoff_ms: u64,
}

impl Default for WebSeedConfig {
    fn default() -> Self {
        WebSeedConfig {
            enabled: true,
            timeout_ms: 10_000,
            max_fails: 5,
            backoff_ms: 60_000,
        }
    }
}

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
    /// Anti-leech choke policy.
    pub leech: LeechConfig,
    /// Scheduler weights.
    pub scheduler: SchedulerConfig,
    /// Wall-clock seed for receipts.
    pub node_secret: [u8; 32],
    /// Extra tracker URLs merged into every session (e.g. refreshed from
    /// [`crate::consts::TRACKERS_LIST_URL`]).
    pub trackers: Vec<String>,
    /// Fall back to the built-in [`crate::consts::DEFAULT_TRACKERS`] when a
    /// torrent carries no announce URLs.
    pub use_default_trackers: bool,
    /// Per-task upload limit in bytes/second (0 = unlimited).
    pub upload_limit_bps: u64,
    /// Per-task download limit in bytes/second (0 = unlimited).
    pub download_limit_bps: u64,
    /// Per-file priorities (index = file index). Missing entries = Normal.
    pub file_priorities: Vec<FilePriority>,
    /// SOCKS5 proxy (Tor / I2P) for this session. When set, the session is
    /// outbound-only: it never advertises a reachable port, drops UDP
    /// trackers, and routes HTTP tracker announces through the proxy.
    pub proxy: Option<ProxyConfig>,
    /// Web seed (BEP-19) options.
    pub webseed: WebSeedConfig,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            save_dir: String::from("."),
            max_peers: 80,
            request_pipeline: crate::consts::REQUEST_PIPELINE,
            endgame_pieces: 32,
            smart_scheduling: true,
            leech: LeechConfig::default(),
            scheduler: SchedulerConfig::default(),
            node_secret: [0u8; 32],
            trackers: Vec::new(),
            proxy: None,
            webseed: WebSeedConfig::default(),
            use_default_trackers: true,
            upload_limit_bps: 0,
            download_limit_bps: 0,
            file_priorities: Vec::new(),
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
    /// Consecutive failures (>= 3 pauses this tracker until one succeeds).
    pub fails: u32,
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

/// One in-progress web-seed (BEP-19) piece fetch.
///
/// Web seeds are fetched one 16 KiB block per engine tick through the
/// blocking host HTTP seam (`Host::http_get_range`, or the SOCKS5 path in
/// proxy mode), so the engine never stalls for more than one small request
/// and the memory footprint is a single piece.
#[derive(Debug, Clone, Default)]
pub struct WebSeedState {
    /// Piece currently being fetched (None = idle).
    pub piece: Option<u32>,
    /// Next block index to request.
    pub next_block: u16,
    /// Total blocks in the current piece.
    pub total_blocks: u16,
    /// Assembled piece bytes (len == piece length).
    pub data: Vec<u8>,
    /// Index of the web seed currently in use (round robin).
    pub seed_idx: usize,
    /// Consecutive failures on the current seed.
    pub fails: u32,
    /// Backoff deadline (ms) before retrying after all seeds failed.
    pub retry_at: u64,
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
    /// When the optimistic slot was assigned (ms).
    optimistic_at: u64,
    /// Endgame active.
    pub endgame: bool,
    /// Peers queued for connection (drained by the engine).
    pub connect_queue: Vec<(NetAddr, DiscoverySource)>,
    /// DHT lookup started.
    dht_started: bool,
    /// Last time a DHT `get_peers` lookup was issued (ms).
    last_dht_announce: u64,
    /// Last PEX broadcast.
    last_pex_at: u64,
    /// Peers known for PEX.
    pex_known: Vec<NetAddr>,
    /// Metadata fetch state.
    metadata: Option<MetadataFetch>,
    /// Web seeds (BEP-19) for direct HTTP piece download.
    web_seeds: Vec<String>,
    /// Web-seed (BEP-19) fetch state.
    webseed: WebSeedState,
    /// Monitor.
    pub monitor: SwarmMonitor,
    /// Receipt book.
    pub receipt_book: ReceiptBook,
    /// Anti-leech ban list.
    pub bans: BanManager,
    /// Persistent anti-leech reputation (across disconnects and sessions).
    pub reputation: ReputationStore,
    /// Last worst-peer eviction pass (ms).
    last_evict_at: u64,
    /// Per-task upload rate bucket (0 = unlimited).
    pub upload_limit: TokenBucket,
    /// Per-task download rate bucket (0 = unlimited).
    pub download_limit: TokenBucket,
    /// Per-tick upload allowance granted by the engine (global slice).
    pub tick_up_allowance: u64,
    /// Per-tick remaining download allowance granted by the engine.
    pub tick_down_remaining: u64,
    /// Per-piece priority multiplier (0 = skipped).
    piece_priorities: Vec<i64>,
    /// Number of pieces selected for download (skipped pieces excluded).
    selected_piece_count: u32,
    /// Piece index → supplier connection ids (corrupt-block attribution).
    piece_suppliers: BTreeMap<u32, Vec<ConnId>>,
    /// Assembled pieces handed to the verifier (piece → bytes), drained by
    /// the engine each tick.
    pending_verify: BTreeMap<u32, Vec<u8>>,
    /// Pieces currently being verified (piece → total blocks); keeps the
    /// picker away until the result lands.
    verifying: BTreeMap<u32, u32>,
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
    /// Cap on remembered PEX endpoints (flood bound).
    const MAX_PEX_KNOWN: usize = 2048;
    /// Cap on the per-peer outgoing byte buffer (memory + upload-fairness
    /// bound under throttling).
    const MAX_PEER_OUT_BUF: usize = 512 * 1024;

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
        let trackers = seed_trackers(
            torrent
                .announce_list
                .iter()
                .flatten()
                .cloned()
                .chain(torrent.announce.iter().cloned()),
            &cfg,
        );

        let monitor = SwarmMonitor::new(
            info_hash.to_hex(),
            torrent.total_size,
            now,
            torrent.total_size.max(1),
        );
        let (piece_priorities, selected_piece_count) =
            compute_piece_priorities(&torrent, &cfg.file_priorities);
        let max_bans = cfg.leech.max_bans;
        let upload_limit = TokenBucket::new(cfg.upload_limit_bps, now);
        let download_limit = TokenBucket::new(cfg.download_limit_bps, now);
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
            optimistic_at: 0,
            endgame: false,
            connect_queue: Vec::new(),
            dht_started: false,
            last_dht_announce: 0,
            last_pex_at: 0,
            pex_known: Vec::new(),
            metadata: None,
            web_seeds: torrent
                .web_seeds
                .iter()
                .map(|w| String::from_utf8_lossy(w).into_owned())
                .collect(),
            webseed: WebSeedState::default(),
            monitor,
            receipt_book: ReceiptBook::new(info_hash.full()),
            bans: BanManager::new(max_bans),
            reputation: ReputationStore::new(cfg.leech.rep_store_cap, cfg.leech.rep_ttl_ms),
            last_evict_at: 0,
            upload_limit,
            download_limit,
            tick_up_allowance: 0,
            tick_down_remaining: 0,
            piece_priorities,
            selected_piece_count,
            piece_suppliers: BTreeMap::new(),
            pending_verify: BTreeMap::new(),
            verifying: BTreeMap::new(),
            torrent: Some(torrent),
            cfg,
        })
    }

    /// Create a session from a magnet link (metadata will be fetched).
    pub fn from_magnet(magnet: &Magnet, cfg: SessionConfig, now: u64) -> Result<TorrentSession> {
        let info_hash = magnet.info_hash.ok_or(Error::Magnet)?;
        let tracker_hash = tracker_hash_of(&info_hash);
        let trackers = seed_trackers(magnet.trackers.iter().map(|s| s.as_bytes().to_vec()), &cfg);
        let pieces = PieceTracker::new(0, 0);
        let scheduler = Scheduler::with_goal(
            &Torrent::empty_placeholder(),
            ContentGoal::Generic,
            cfg.scheduler,
        );
        let monitor = SwarmMonitor::new(info_hash.to_hex(), 0, now, 1);
        let max_bans = cfg.leech.max_bans;
        let upload_limit = TokenBucket::new(cfg.upload_limit_bps, now);
        let download_limit = TokenBucket::new(cfg.download_limit_bps, now);
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
            optimistic_at: 0,
            endgame: false,
            connect_queue: Vec::new(),
            dht_started: false,
            last_dht_announce: 0,
            last_pex_at: 0,
            pex_known: Vec::new(),
            metadata: Some(MetadataFetch {
                size: 0,
                pieces: BTreeMap::new(),
                requested: Bitfield::new(0),
                outstanding: 0,
            }),
            web_seeds: Vec::new(),
            webseed: WebSeedState::default(),
            monitor,
            receipt_book: ReceiptBook::new(info_hash.full()),
            bans: BanManager::new(max_bans),
            reputation: ReputationStore::new(cfg.leech.rep_store_cap, cfg.leech.rep_ttl_ms),
            last_evict_at: 0,
            upload_limit,
            download_limit,
            tick_up_allowance: 0,
            tick_down_remaining: 0,
            piece_priorities: Vec::new(),
            selected_piece_count: 0,
            piece_suppliers: BTreeMap::new(),
            pending_verify: BTreeMap::new(),
            verifying: BTreeMap::new(),
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
        } else if self.selected_piece_count == 0 {
            // Everything is skipped: nothing left to download.
            SessionStatus::Seeding
        } else {
            SessionStatus::Downloading
        };
        self.started_at = ctx.now;
        self.announce_at = ctx.now;
        self.refresh_completion();
        self.open_files(ctx)?;
        self.announce_to_tracker(ctx, TrackerEvent::Started);
        if let Some(dht) = ctx.dht.as_mut() {
            dht.get_peers(self.tracker_hash, ctx.port, ctx.now);
            self.dht_started = true;
            self.last_dht_announce = ctx.now;
        }
        Ok(())
    }

    /// Re-evaluate completion: once every *selected* piece is verified we
    /// are seeding. No-op unless the session is in an active download state.
    fn refresh_completion(&mut self) {
        if self.torrent.is_some()
            && matches!(
                self.status,
                SessionStatus::Downloading | SessionStatus::Seeding
            )
            && self.pieces.have_count() >= self.selected_piece_count
        {
            self.status = SessionStatus::Seeding;
        }
    }

    /// Whether the session is running and consuming rate-limit budgets
    /// (not stopped, paused, or failed).
    pub fn is_active(&self) -> bool {
        matches!(
            self.status,
            SessionStatus::Downloading | SessionStatus::Seeding | SessionStatus::FetchingMetadata
        )
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
        self.refresh_completion();
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

    /// Number of pieces selected for download (skipped files excluded).
    pub fn selected_piece_count(&self) -> u32 {
        self.selected_piece_count
    }

    /// Progress ratio (0.0..=1.0) relative to the *selected* pieces.
    pub fn progress(&self) -> f64 {
        let sel = self.selected_piece_count;
        if sel == 0 {
            return if self.status == SessionStatus::Seeding {
                1.0
            } else {
                0.0
            };
        }
        self.pieces.have_count() as f64 / sel as f64
    }

    // ---------- task management ----------

    /// Set the download priority of one file (selective download). Returns
    /// `Err(Range)` when the file index is out of bounds or the torrent
    /// metadata has not arrived yet.
    pub fn set_file_priority(&mut self, file: u32, prio: FilePriority) -> Result<()> {
        match &self.torrent {
            Some(t) => {
                if file as usize >= t.files.len() {
                    return Err(Error::Range);
                }
            }
            None => return Err(Error::NotFound),
        }
        let idx = file as usize;
        if self.cfg.file_priorities.len() <= idx {
            self.cfg
                .file_priorities
                .resize(idx + 1, FilePriority::Normal);
        }
        self.cfg.file_priorities[idx] = prio;
        self.recompute_priorities();
        Ok(())
    }

    /// The priority of one file (`Normal` when unset).
    pub fn file_priority(&self, file: u32) -> FilePriority {
        self.cfg
            .file_priorities
            .get(file as usize)
            .copied()
            .unwrap_or(FilePriority::Normal)
    }

    /// All file priorities (index-aligned with the torrent's file list).
    pub fn file_priorities(&self) -> &[FilePriority] {
        &self.cfg.file_priorities
    }

    /// Change the per-task upload limit (bytes/second; 0 = unlimited).
    pub fn set_upload_limit(&mut self, bps: u64, now: u64) {
        self.cfg.upload_limit_bps = bps;
        self.upload_limit.set_rate(bps, now);
    }

    /// Change the per-task download limit (bytes/second; 0 = unlimited).
    pub fn set_download_limit(&mut self, bps: u64, now: u64) {
        self.cfg.download_limit_bps = bps;
        self.download_limit.set_rate(bps, now);
    }

    /// Restore persisted state onto a freshly re-created session (smart
    /// resume): verified/partial pieces, per-file priorities, per-task rate
    /// limits, and the anti-leech reputation ledger. Call right after
    /// construction and before `start`.
    #[allow(clippy::too_many_arguments)] // single restore entry point, engine-only call
    pub fn apply_saved_state(
        &mut self,
        have: &[u8],
        partial: &[(u32, Vec<u8>)],
        priorities: &[u8],
        upload_limit_bps: u64,
        download_limit_bps: u64,
        reputation: &[u8],
        now: u64,
    ) -> Result<()> {
        self.pieces.restore(have, partial)?;
        if !priorities.is_empty() {
            let t = match &self.torrent {
                Some(t) => t.clone(),
                None => return Err(Error::NotFound),
            };
            let n = core::cmp::min(priorities.len(), t.files.len());
            self.cfg.file_priorities.clear();
            self.cfg
                .file_priorities
                .extend(priorities[..n].iter().map(|b| file_priority_from_u8(*b)));
            self.recompute_priorities();
        }
        // anti-leech: restore the persistent reputation ledger so repeat
        // offenders start pre-penalized. Malformed blobs are ignored.
        if !reputation.is_empty() {
            if let Some(r) = ReputationStore::decode(reputation) {
                self.reputation = r;
                self.reputation.sweep(now);
            }
        }
        self.set_upload_limit(upload_limit_bps, now);
        self.set_download_limit(download_limit_bps, now);
        self.refresh_completion();
        Ok(())
    }

    /// Manually add a tracker URL (deduped). Returns `true` if added.
    pub fn add_tracker(&mut self, url: &str) -> bool {
        let b = url.as_bytes().to_vec();
        let before = self.trackers.len();
        push_tracker(&mut self.trackers, b);
        self.trackers.len() > before
    }

    /// Manually remove a tracker URL. Returns `true` if removed.
    pub fn remove_tracker(&mut self, url: &str) -> bool {
        let b = url.as_bytes();
        let before = self.trackers.len();
        self.trackers.retain(|t| t.url != b);
        self.trackers.len() < before
    }

    /// Current tracker URLs (in announce order).
    pub fn tracker_urls(&self) -> Vec<String> {
        self.trackers
            .iter()
            .map(|t| String::from_utf8_lossy(&t.url).into_owned())
            .collect()
    }

    /// Recompute the per-piece priority multipliers from the file
    /// priorities, and refresh the selected-piece bookkeeping.
    fn recompute_priorities(&mut self) {
        let t = match &self.torrent {
            Some(t) => t.clone(),
            None => {
                self.piece_priorities.clear();
                self.selected_piece_count = 0;
                return;
            }
        };
        let (prio, selected) = compute_piece_priorities(&t, &self.cfg.file_priorities);
        self.piece_priorities = prio;
        self.selected_piece_count = selected;
        // the selection may have shrunk below what we already have
        self.refresh_completion();
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
        // anti-leech: expire bans, keep the list bounded
        self.bans.sweep(ctx.now);
        // anti-leech: age out stale reputation entries
        self.reputation.sweep(ctx.now);
        // endgame detection (relative to the selected pieces)
        if !self.endgame && self.selected_piece_count > 0 {
            let outstanding = self
                .selected_piece_count
                .saturating_sub(self.pieces.have_count());
            self.endgame = outstanding <= self.cfg.endgame_pieces;
        }
        // choke/unchoke pass
        if ctx.now.saturating_sub(self.last_unchoke_at) >= self.cfg.leech.rechoke_interval_ms {
            self.choke_pass(ctx);
            self.last_unchoke_at = ctx.now;
        }
        // anti-leech: when near capacity with candidates waiting, evict the
        // worst peers so better candidates can connect. This keeps the
        // swarm fresh instead of letting bad peers occupy slots forever.
        if self.peers.len() as u32 >= self.cfg.max_peers.saturating_mul(3) / 4
            && !self.connect_queue.is_empty()
            && ctx.now.saturating_sub(self.last_evict_at) >= self.cfg.leech.rechoke_interval_ms
        {
            self.last_evict_at = ctx.now;
            self.evict_worst(ctx);
        }
        // DHT lookup / peer pull
        if self.dht_started {
            if let Some(dht) = ctx.dht.as_mut() {
                // Re-issue the lookup on a cadence. `get_peers` never
                // duplicates an active lookup, so this is cheap while one is
                // running; but a lookup that was pruned (timeout, or started
                // before the bootstrap populated the table) is re-created
                // here — otherwise a later-successful bootstrap would never
                // be asked for this torrent again and the downloader would
                // stay at 0 peers forever.
                if ctx.now.saturating_sub(self.last_dht_announce) >= DHT_ANNOUNCE_INTERVAL_MS {
                    self.last_dht_announce = ctx.now;
                    dht.get_peers(self.tracker_hash, ctx.port, ctx.now);
                }
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
        // web seeds (BEP-19): supplement peer downloads, one block per tick
        self.drive_webseed(ctx);
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

    // ---------- web seeds (BEP-19) ----------

    /// Fetch pieces from web seeds: one 16 KiB block per tick through the
    /// blocking host HTTP seam, assembled and handed to the existing
    /// verification pipeline. Only pieces fully contained within a single
    /// file are fetchable — a web seed serves each file as a separate
    /// resource, so a piece straddling a file boundary cannot be requested.
    ///
    /// In proxy mode the block is fetched *through* the SOCKS proxy so the
    /// real IP is never exposed to the web seed server.
    fn drive_webseed<H: Host>(&mut self, ctx: &'_ mut SessionCtx<'_, H>) {
        if !self.cfg.webseed.enabled || self.torrent.is_none() || self.web_seeds.is_empty() {
            return;
        }
        if self.status != SessionStatus::Downloading {
            return;
        }
        let now = ctx.now;
        // (a) pick a piece when idle
        if self.webseed.piece.is_none() {
            if now < self.webseed.retry_at {
                return;
            }
            let t = match self.torrent.as_ref() {
                Some(t) => t,
                None => return,
            };
            if let Some((p, len)) = self.pick_webseed_piece(t) {
                self.webseed.piece = Some(p);
                self.webseed.next_block = 0;
                self.webseed.total_blocks = block_count_for(len);
                self.webseed.data = vec![0u8; len as usize];
            } else {
                return; // nothing fetchable right now
            }
        }
        let piece = match self.webseed.piece {
            Some(p) => p,
            None => return,
        };
        // (b) resolve this block's URL and byte window (immutable snapshot)
        let (url, range_start, range_end, blen) = {
            let t = match self.torrent.as_ref() {
                Some(t) => t,
                None => return,
            };
            match self.webseed_block(t, piece, self.webseed.next_block) {
                Some(m) => m,
                None => {
                    self.abort_webseed_piece();
                    return;
                }
            }
        };
        // (c) fetch one block through the (possibly proxied) HTTP seam
        let timeout = self.cfg.webseed.timeout_ms;
        let mut body = Vec::new();
        let got = match &self.cfg.proxy {
            Some(p) => socks_mod::socks_http_get_range(
                ctx.host,
                p,
                &url,
                range_start,
                range_end,
                timeout,
                &mut body,
            ),
            None => ctx
                .host
                .http_get_range(&url, range_start, range_end, timeout, &mut body),
        };
        match got {
            Ok(()) if body.len() as u64 == blen => {
                let off = (self.webseed.next_block as u32 * BLOCK_LEN) as usize;
                self.webseed.data[off..off + body.len()].copy_from_slice(&body);
                self.downloaded_bytes += body.len() as u64;
                self.monitor
                    .record_piece_cover(NetAddr::V4([0, 0, 0, 0], 0), piece);
                self.webseed.fails = 0;
                self.webseed.next_block = self.webseed.next_block.saturating_add(1);
            }
            Ok(()) => {
                // range not honored / truncated: the data is untrustworthy
                self.webseed.fails = self.webseed.fails.saturating_add(1);
            }
            Err(_) => {
                self.webseed.fails = self.webseed.fails.saturating_add(1);
            }
        }
        // (d) failure handling: rotate seeds, then back off
        if self.webseed.fails >= self.cfg.webseed.max_fails {
            self.webseed.seed_idx = (self.webseed.seed_idx + 1) % self.web_seeds.len();
            if self.web_seeds.len() <= 1 {
                self.webseed.retry_at = now.saturating_add(self.cfg.webseed.backoff_ms);
            }
            self.abort_webseed_piece();
            return;
        }
        // (e) piece complete → hand to the verification pipeline
        if self.webseed.next_block >= self.webseed.total_blocks {
            let buf = core::mem::take(&mut self.webseed.data);
            self.pieces.set_in_flight(piece, true);
            self.verifying
                .insert(piece, self.webseed.total_blocks as u32);
            self.pending_verify.insert(piece, buf);
            self.webseed.piece = None;
            self.webseed.next_block = 0;
            self.webseed.total_blocks = 0;
        }
    }

    /// Pick the next piece for a web seed: missing, not in flight, in a
    /// selected file, and fully contained within one file. Rotates the
    /// scan start for fairness.
    fn pick_webseed_piece(&self, t: &Torrent) -> Option<(u32, u32)> {
        let n = t.piece_count();
        if n == 0 {
            return None;
        }
        let start = (self.webseed.seed_idx as u64 % n as u64) as u32;
        for k in 0..n {
            let p = (start + k) % n;
            if self.pieces.is_have(p) || self.pieces.is_in_flight(p) {
                continue;
            }
            if self.piece_priorities.get(p as usize).copied().unwrap_or(1) <= 0 {
                continue; // piece belongs only to skipped files
            }
            let (abs, len) = match (t.piece_abs_offset(p), t.piece_info(p)) {
                (Ok(a), Ok(pi)) => (a, pi.len as u64),
                _ => continue,
            };
            if !self.piece_in_single_file(t, abs, len) {
                continue; // straddles a file boundary → not one resource
            }
            return Some((p, len as u32));
        }
        None
    }

    /// Resolve the next block's web-seed URL and byte window within the
    /// containing file. Returns `(url, range_start, range_end, len)`.
    ///
    /// The Range is **relative to the file resource** (the web seed serves
    /// each file as a separate URL): `pi.offset + begin`. Using the
    /// absolute torrent offset here would request a wrong window for every
    /// file that does not start at byte 0 of the torrent.
    fn webseed_block(
        &self,
        t: &Torrent,
        piece: u32,
        block: u16,
    ) -> Option<(String, u64, u64, u64)> {
        let pi = t.piece_info(piece).ok()?;
        let begin = (block as u32) * BLOCK_LEN;
        if begin >= pi.len {
            return None;
        }
        let blen = core::cmp::min(BLOCK_LEN, pi.len - begin) as u64;
        let range_start = pi.offset + begin as u64;
        let range_end = range_start + blen - 1;
        let base = self
            .web_seeds
            .get(self.webseed.seed_idx % self.web_seeds.len())?
            .clone();
        let url = if t.files.len() == 1 {
            // single-file torrent: the web seed URL points at the file
            base
        } else {
            // multi-file: append the percent-encoded relative path
            let mut u = String::from(base.trim_end_matches('/'));
            u.push('/');
            u.push_str(&web_seed_path(&t.files[pi.file as usize]));
            u
        };
        Some((url, range_start, range_end, blen))
    }

    /// Whether the byte range `[abs, abs+len)` lies fully within one file.
    fn piece_in_single_file(&self, t: &Torrent, abs: u64, len: u64) -> bool {
        let mut off = 0u64;
        for f in &t.files {
            if f.length == 0 {
                continue;
            }
            if abs >= off && abs.saturating_add(len) <= off.saturating_add(f.length) {
                return true;
            }
            off += f.length;
        }
        false
    }

    /// Abandon the current web-seed piece (rotation or unrecoverable error).
    fn abort_webseed_piece(&mut self) {
        self.webseed.piece = None;
        self.webseed.next_block = 0;
        self.webseed.total_blocks = 0;
        self.webseed.data.clear();
    }

    fn choke_pass<H: Host>(&mut self, ctx: &'_ mut SessionCtx<'_, H>) {
        // 1. refresh snub flags
        for p in self.peers.values_mut() {
            p.refresh_snub(ctx.now, self.cfg.leech.snub_timeout_ms);
        }
        // 2. rotate the optimistic slot fairly: newcomers get a chance to
        //    prove reciprocity before we pick permanent favorites.
        let rotate = match self.optimistic {
            Some(c) => self
                .peers
                .get(&c)
                .map(|_| {
                    ctx.now.saturating_sub(self.optimistic_at)
                        >= self.cfg.leech.optimistic_interval_ms
                })
                .unwrap_or(true),
            None => true,
        };
        if rotate {
            self.optimistic = self.pick_optimistic();
            self.optimistic_at = ctx.now;
        }
        // 3. build the choke views for ready peers (merging any stored
        //    reputation so repeat offenders are scored from the start)
        let views: Vec<PeerChokeView> = self
            .peers
            .values()
            .filter(|p| p.phase == PeerPhase::Ready)
            .map(|p| self.peer_choke_view(p, ctx.now))
            .collect();
        let seeding = self.status == SessionStatus::Seeding;
        let unchoke = leech::select_unchoke_set(
            &views,
            seeding,
            &self.cfg.leech,
            |id| self.peers.get(&id).map(|p| !p.am_choking).unwrap_or(false),
            self.optimistic,
        );
        // 4. apply choke / unchoke transitions
        let cur: Vec<ConnId> = self.peers.keys().copied().collect();
        for c in cur {
            let (was, now_choking) = {
                let p = match self.peers.get_mut(&c) {
                    Some(p) => p,
                    None => continue,
                };
                let now_choking = !unchoke.contains(&c);
                let was = p.am_choking;
                p.am_choking = now_choking;
                (was, now_choking)
            };
            if was != now_choking {
                let m = if now_choking {
                    Message::Choke
                } else {
                    Message::Unchoke
                };
                if let Some(p) = self.peers.get_mut(&c) {
                    p.send(&m);
                }
            }
        }
        // 5. interested / not interested
        let conns: Vec<ConnId> = self.peers.keys().copied().collect();
        for c in conns {
            let want = {
                let p = match self.peers.get(&c) {
                    Some(p) => p,
                    None => continue,
                };
                p.should_be_interested(self.pieces.have_bitfield())
            };
            let send = {
                let p = match self.peers.get_mut(&c) {
                    Some(p) => p,
                    None => continue,
                };
                let send = want != p.am_interested && p.phase == PeerPhase::Ready;
                p.am_interested = want;
                if send {
                    if want {
                        p.send(&Message::Interested);
                    } else {
                        p.send(&Message::NotInterested);
                    }
                }
                send
            };
            let _ = send;
        }
        // 6. roll rate windows
        for p in self.peers.values_mut() {
            p.roll_window(ctx.now);
        }
    }

    /// Build the choke/eviction view for one peer, merging any reputation
    /// the peer carries from previous connections (or previous sessions)
    /// into its corrupt ledger so repeat offenders are scored correctly
    /// from the very first choke pass.
    fn peer_choke_view(&self, p: &Peer, now: u64) -> PeerChokeView {
        let stored = p
            .peer_id
            .as_ref()
            .and_then(|pid| self.reputation.stored_for(pid))
            .or_else(|| self.reputation.stored_addr(&p.addr))
            .unwrap_or((0, 0));
        let age_ms = now.saturating_sub(p.connected_at);
        let idle_ms = if p.last_request_at == 0 {
            age_ms
        } else {
            now.saturating_sub(p.last_request_at)
        };
        PeerChokeView {
            id: p.id,
            client: p.rep.client,
            given: p.down_total,
            taken: p.up_total,
            rate_up: p.down_rate,
            rate_down: p.up_rate,
            corrupt: p.rep.corrupt_blocks.saturating_add(stored.0),
            snubbed: p.snubbed,
            interested: p.peer_interested,
            age_ms,
            idle_ms,
            served_requests: p.served_requests,
        }
    }

    /// Evict the single worst ready peer to make room for a queued
    /// candidate. Hard negatives (corrupt suppliers, snubs) go first; the
    /// optimistic slot is protected. Hard-negative evictions are recorded
    /// in the reputation store so the peer cannot simply rejoin and squat.
    fn evict_worst<H: Host>(&mut self, ctx: &'_ mut SessionCtx<'_, H>) {
        let views: Vec<PeerChokeView> = self
            .peers
            .values()
            .filter(|p| p.phase == PeerPhase::Ready)
            .map(|p| self.peer_choke_view(p, ctx.now))
            .collect();
        if views.is_empty() {
            return;
        }
        let seeding = self.status == SessionStatus::Seeding;
        let keep: Vec<ConnId> = Vec::new();
        let Some(id) =
            leech::pick_eviction(&views, seeding, &self.cfg.leech, self.optimistic, &keep)
        else {
            return;
        };
        let (addr, peer_id, hard) = {
            let p = match self.peers.get(&id) {
                Some(p) => p,
                None => return,
            };
            (p.addr, p.peer_id, p.rep.corrupt_blocks > 0 || p.snubbed)
        };
        if hard {
            self.reputation
                .note_violation(addr, peer_id.as_ref(), ctx.now);
        }
        self.drop_peer(id, FailureCategory::Timeout, ctx);
    }

    /// Pick the next optimistic-unchoke candidate: among ready peers that
    /// are currently choked (i.e. not already holding a slot), the one
    /// connected the longest. Falls back to any ready peer.
    fn pick_optimistic(&self) -> Option<ConnId> {
        let ready: Vec<ConnId> = self
            .peers
            .values()
            .filter(|p| p.phase == PeerPhase::Ready)
            .map(|p| p.id)
            .collect();
        if ready.is_empty() {
            return None;
        }
        let choked: Vec<ConnId> = ready
            .iter()
            .copied()
            .filter(|c| self.peers.get(c).map(|p| p.am_choking).unwrap_or(true))
            .collect();
        let pool = if choked.is_empty() { &ready } else { &choked };
        pool.iter().copied().min_by_key(|c| {
            self.peers
                .get(c)
                .map(|p| p.connected_at)
                .unwrap_or(u64::MAX)
        })
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
        // anti-leech: never accept a banned address
        if self.bans.is_banned(&addr, ctx.now) {
            ctx.host.tcp_close(conn);
            return;
        }
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
        if their.info_hash != self.tracker_hash {
            return Err(Error::Handshake);
        }
        // anti-leech: a peer id we banned cannot reconnect under a new conn
        if self.bans.peer_id_banned(&their.peer_id, ctx.now) {
            return Err(Error::Handshake);
        }
        // anti-leech: one peer id must not appear from two endpoints at
        // once — that is identity spoofing / shared-client abuse. Reject
        // the newcomer and record the offense.
        let dup = self.peers.values().any(|q| {
            q.id != conn && q.phase != PeerPhase::Closed && q.peer_id == Some(their.peer_id)
        });
        if dup {
            let addr = self
                .peers
                .get(&conn)
                .map(|p| p.addr)
                .unwrap_or(NetAddr::V4([0, 0, 0, 0], 0));
            self.reputation
                .note_violation(addr, Some(&their.peer_id), ctx.now);
            return Err(Error::Handshake);
        }
        // anti-leech: seed this connection with the identity's *stored*
        // reputation (from earlier connections / sessions). A repeat
        // corrupt offender is re-banned immediately instead of getting a
        // clean slate, and its choke score starts depressed.
        let (addr, stored_corrupt) = {
            let peer = self.peers.get_mut(&conn).ok_or(Error::NotFound)?;
            peer.rep.client = Some(leech::fingerprint(&their.peer_id));
            peer.peer_id = Some(their.peer_id);
            let addr = peer.addr;
            let corrupt = self
                .reputation
                .stored_for(&their.peer_id)
                .map(|(c, v)| {
                    peer.rep.corrupt_blocks = peer.rep.corrupt_blocks.saturating_add(c);
                    peer.rep.protocol_violations = peer.rep.protocol_violations.saturating_add(v);
                    c
                })
                .unwrap_or(0);
            (addr, corrupt)
        };
        if stored_corrupt >= self.cfg.leech.corrupt_ban_threshold {
            self.reputation
                .note_violation(addr, Some(&their.peer_id), ctx.now);
            self.ban_peer(conn, addr, BanReason::Corrupt, ctx);
            return Err(Error::Handshake);
        }
        self.reputation
            .note_handshake(addr, &their.peer_id, ctx.now);
        let peer = self.peers.get_mut(&conn).ok_or(Error::NotFound)?;
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
            // Proxy mode: we accept no inbound connections, so never
            // advertise a reachable listen port to peers.
            ext.p = Some(if self.cfg.proxy.is_some() {
                0
            } else {
                ctx.port as u32
            });
            peer.send(&Message::Extended {
                id: 0,
                payload: ext.encode(),
            });
        }
        // if this is a metadata fetch, request metadata
        if self.torrent.is_none() && peer.ext_metadata.is_none() && their.has_metadata() {
            // request will be triggered once we learn their ut_metadata id
        }
        // Interest is NOT decided here: their availability (bitfield /
        // have_all / have_none) always follows the handshake, so we derive
        // it from `sync_interest` as soon as `dispatch` processes those
        // messages — and again on every `have`. That keeps a seed that
        // unchokes only interested peers from deadlocking us (see
        // `Peer::should_be_interested`).
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
        let mut just_handshook = false;
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
                just_handshook = true;
            } else {
                return;
            }
        }
        // post-handshake: feed remaining into message stream
        let peer = match self.peers.get_mut(&conn) {
            Some(p) => p,
            None => return,
        };
        // If this call consumed the handshake, its bytes (and only the
        // bytes *after* it) were already routed above: the handshake went
        // into `handshake_buf` and the leftover into `msgs`. Re-feeding
        // `data` here would inject the raw handshake bytes into the message
        // stream — its leading 4 bytes (`0x13 'B' 'i' 't'`) parse as a
        // ~323 MB frame, so every peer would be dropped as a "protocol
        // violator" the instant its handshake + first messages (bitfield,
        // unchoke…) arrive in one TCP segment. Only feed `data` when the
        // peer was already Ready before this call.
        if !just_handshook && peer.phase == PeerPhase::Ready && peer.handshake_buf.is_empty() {
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
                        self.note_protocol_violation(conn, ctx);
                        return;
                    }
                }
            };
            if self.dispatch(conn, msg, ctx).is_err() {
                self.note_protocol_violation(conn, ctx);
                return;
            }
        }
    }

    /// Record a protocol violation; ban the peer once it crosses the
    /// configured threshold.
    fn note_protocol_violation<H: Host>(&mut self, conn: ConnId, ctx: &'_ mut SessionCtx<'_, H>) {
        let mut ban = false;
        if let Some(p) = self.peers.get_mut(&conn) {
            p.rep.protocol_violations = p.rep.protocol_violations.saturating_add(1);
            ban = p.rep.protocol_violations >= self.cfg.leech.protocol_ban_threshold;
        }
        if ban {
            let (addr, peer_id) = {
                let p = match self.peers.get(&conn) {
                    Some(p) => p,
                    None => return,
                };
                (p.addr, p.peer_id)
            };
            // remember the offense across disconnects / sessions.
            self.reputation
                .note_violation(addr, peer_id.as_ref(), ctx.now);
            self.ban_peer(conn, addr, BanReason::Protocol, ctx);
        } else {
            self.drop_peer(conn, FailureCategory::Timeout, ctx);
        }
    }

    /// Ban a peer (address + peer id) and disconnect it.
    fn ban_peer<H: Host>(
        &mut self,
        conn: ConnId,
        addr: NetAddr,
        reason: BanReason,
        ctx: &'_ mut SessionCtx<'_, H>,
    ) {
        let peer_id = self.peers.get(&conn).and_then(|p| p.peer_id);
        let ttl = self.cfg.leech.ban_ttl_ms;
        self.bans.ban(addr, peer_id.as_ref(), ttl, reason, ctx.now);
        ctx.events.push(EngineEvent::PeerBanned {
            info_hash: self.info_hash,
            addr,
            reason,
        });
        self.drop_peer(conn, FailureCategory::Timeout, ctx);
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
                self.sync_interest(conn);
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
                self.sync_interest(conn);
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
                self.sync_interest(conn);
            }
            Message::HaveNone => {
                if let Some(peer) = self.peers.get_mut(&conn) {
                    if peer.have_all || peer.have_none {
                        return Err(Error::Protocol);
                    }
                    peer.have_none = true;
                }
                self.sync_interest(conn);
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
                self.cancel_peer_request(conn, index, begin, ctx)?;
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

    /// Recompute whether we are interested in `conn` and emit the
    /// `Interested`/`NotInterested` transition when it changed. Interest
    /// means "they have at least one piece we lack" and is independent of
    /// choke state — see [`Peer::should_be_interested`]. Called whenever
    /// their availability changes (bitfield / have_all / have_none / have).
    fn sync_interest(&mut self, conn: ConnId) {
        let our_have = self.pieces.have_bitfield().clone();
        let want = {
            let p = match self.peers.get(&conn) {
                Some(p) => p,
                None => return,
            };
            if p.phase != PeerPhase::Ready {
                return;
            }
            p.should_be_interested(&our_have)
        };
        let p = match self.peers.get_mut(&conn) {
            Some(p) => p,
            None => return,
        };
        if want == p.am_interested {
            return;
        }
        p.am_interested = want;
        let m = if want {
            Message::Interested
        } else {
            Message::NotInterested
        };
        p.send(&m);
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
            let ext = ExtHandshake::parse(&payload)?;
            if let Some(peer) = self.peers.get_mut(&conn) {
                peer.ext = Some(ext.clone());
                peer.ext_metadata = ext.m.get("ut_metadata").copied();
                peer.ext_pex = ext.m.get("ut_pex").copied();
                if let Some(ms) = ext.metadata_size {
                    let legit_cap = crate::consts::MAX_METADATA_SIZE as usize;
                    let cap = (ms as usize).min(legit_cap).max(peer.msgs.max_frame());
                    peer.msgs.set_max_frame(cap);
                }
            }
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
                if total_size > crate::consts::MAX_METADATA_SIZE {
                    return Err(Error::Protocol);
                }
                let meta = match self.metadata.as_mut() {
                    Some(m) => m,
                    None => return Ok(()),
                };
                if meta.size == 0 {
                    meta.size = total_size;
                    meta.requested = Bitfield::new(total_size.div_ceil(16 * 1024));
                } else if meta.size != total_size {
                    return Err(Error::Protocol);
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
        self.recompute_priorities();
        self.metadata = None;
        if self.selected_piece_count == 0 {
            self.status = SessionStatus::Seeding;
        } else {
            self.status = SessionStatus::Downloading;
        }
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
            port: if self.cfg.proxy.is_some() {
                0
            } else {
                ctx.port
            },
            uploaded: self.uploaded_bytes,
            downloaded: self.downloaded_bytes,
            left,
            event,
            numwant: 200,
            key: 0x54594254, // "TYBT"
        };
        let mut attempt = 0;
        let total = self.trackers.len();
        while attempt < total {
            let idx = self.tracker_cursor % total;
            if self.trackers[idx].fails >= 3 {
                self.tracker_cursor = (self.tracker_cursor + 1) % total;
                attempt += 1;
                continue;
            }
            let kind = self.trackers[idx].kind;
            match kind {
                TrackerKind::Http => {
                    let url = tracker::build_http_announce_url(
                        &String::from_utf8_lossy(&self.trackers[idx].url),
                        &params,
                    );
                    let mut body = Vec::new();
                    let got = match &self.cfg.proxy {
                        Some(p) => socks_mod::socks_http_get(ctx.host, p, &url, 15_000, &mut body),
                        None => ctx.host.http_get(&url, 15_000, &mut body),
                    };
                    match got {
                        Ok(()) => match tracker::parse_tracker_response(&body) {
                            Ok(resp) => {
                                if let Some(f) = resp.failure {
                                    self.trackers[idx].failure = Some(f);
                                    self.trackers[idx].fails =
                                        self.trackers[idx].fails.saturating_add(1);
                                } else {
                                    let interval = resp.interval.max(30);
                                    let peer_count = resp.peers.len();
                                    self.trackers[idx].interval = interval;
                                    self.trackers[idx].next_announce = ctx.now + interval * 1000;
                                    self.trackers[idx].failure = None;
                                    self.trackers[idx].fails = 0;
                                    self.on_tracker_peers(resp, ctx);
                                    self.tracker_cursor = (idx + 1) % total;
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
                                self.trackers[idx].fails =
                                    self.trackers[idx].fails.saturating_add(1);
                            }
                        },
                        Err(_) => {
                            if self.cfg.proxy.is_some() {
                                self.trackers[idx].fails =
                                    self.trackers[idx].fails.saturating_add(1);
                                self.trackers[idx].failure =
                                    Some(String::from("udp disabled in proxy mode"));
                                attempt += 1;
                                self.tracker_cursor = (self.tracker_cursor + 1) % total;
                                continue;
                            }
                            self.trackers[idx].failure = Some(String::from("http error"));
                            self.trackers[idx].fails = self.trackers[idx].fails.saturating_add(1);
                        }
                    }
                }
                TrackerKind::Udp => {
                    let st = &mut self.trackers[idx];
                    // UDP is lossy: if a request has gone unanswered for one
                    // announce interval, restart the handshake instead of
                    // waiting on a packet that will never come (otherwise a
                    // single lost connect request would stall this tracker
                    // forever). Three consecutive timeouts park it like any
                    // other failing tracker.
                    if st.udp.phase != UdpPhase::Idle
                        && ctx.now.saturating_sub(st.udp.sent_at) >= 15_000
                    {
                        st.udp.phase = UdpPhase::Idle;
                        st.fails = st.fails.saturating_add(1);
                    }
                    if st.udp.phase == UdpPhase::Idle {
                        // Resolve once and cache (hostname trackers are the
                        // norm); the timeout reset above reuses `addr`.
                        let addr = match st.udp.addr {
                            Some(a) => Some(a),
                            None => parse_udp_tracker_addr(&st.url, &mut |h, p| {
                                ctx.host.resolve_host(h, p)
                            }),
                        };
                        if let Some(a) = addr {
                            st.udp.addr = Some(a);
                            st.udp.tid = rand_u32(ctx.now);
                            st.udp.sent_at = ctx.now;
                            let req = tracker::udp::build_connect_request(st.udp.tid);
                            if ctx.host.udp_send(&a, &req).is_err() {
                                // A send failure must be visible, not silent:
                                // park this tracker so the announce loop moves
                                // on to the next one instead of wedging here.
                                st.fails = st.fails.saturating_add(1);
                                st.failure = Some(String::from("udp send failed"));
                                st.udp.phase = UdpPhase::Idle;
                            } else {
                                st.udp.phase = UdpPhase::ConnectSent;
                            }
                        }
                    }
                    self.tracker_cursor = (idx + 1) % total;
                    self.announce_at = ctx.now + 15_000;
                    return;
                }
            }
            attempt += 1;
            self.tracker_cursor = (self.tracker_cursor + 1) % total;
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
                                if ctx.host.udp_send(&a, &req).is_err() {
                                    // Send failed: reset the handshake so the
                                    // next announce retries, and record the
                                    // failure instead of silently hanging in
                                    // AnnounceSent.
                                    st.udp.phase = UdpPhase::Idle;
                                    st.fails = st.fails.saturating_add(1);
                                    st.failure = Some(String::from("udp send failed"));
                                }
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
                            st.fails = 0;
                            st.failure = None;
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
        // anti-leech: never connect to a banned address
        if self.bans.is_banned(&addr, now) {
            return;
        }
        if self.subnet_count(&addr) >= self.cfg.leech.max_peers_per_subnet {
            return;
        }
        // absolute cap on queued candidates (flood bound)
        if self.connect_queue.len() >= 4 * self.cfg.max_peers.max(1) as usize {
            return;
        }
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
        self.connect_queue.push((addr, source));
        self.monitor.record_discovery(source);
        let _ = now;
    }

    /// Count of connected + queued peers sharing `addr`'s subnet.
    fn subnet_count(&self, addr: &NetAddr) -> u32 {
        let key = subnet_key(addr);
        let mut n = 0u32;
        for p in self.peers.values() {
            if subnet_key(&p.addr) == key {
                n += 1;
            }
        }
        for (a, _) in &self.connect_queue {
            if subnet_key(a) == key {
                n += 1;
            }
        }
        n
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
        for c in msg.added.as_chunks::<6>().0 {
            if let Some(a) = NetAddr::from_compact6(c) {
                added.push(a);
            }
        }
        for c in msg.added6.as_chunks::<18>().0 {
            if let Some(a) = NetAddr::from_compact18(c) {
                added.push(a);
            }
        }
        for a in added {
            // do not echo back to the sender's own address
            if self.peers.get(&conn).map(|p| p.addr) == Some(a) {
                continue;
            }
            if !self.pex_known.contains(&a) && self.pex_known.len() < Self::MAX_PEX_KNOWN {
                self.pex_known.push(a);
            }
            self.enqueue_peer(a, DiscoverySource::Pex, ctx.now);
        }
        // dropped: remove from pex_known
        for c in msg.dropped.as_chunks::<6>().0 {
            if let Some(a) = NetAddr::from_compact6(c) {
                if let Some(pos) = self.pex_known.iter().position(|x| *x == a) {
                    self.pex_known.remove(pos);
                }
            }
        }
    }

    // ---------- request pipeline ----------

    fn fill_pipeline<H: Host>(&mut self, conn: ConnId, ctx: &'_ mut SessionCtx<'_, H>) {
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
                    peer.have_all,
                    &self.piece_priorities,
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
            // download rate budget: never issue requests past what the
            // per-task bucket and the per-tick global slice permit.
            let avail = self.download_limit.available(ctx.now);
            if avail < len as u64 {
                break;
            }
            if self.tick_down_remaining < len as u64 {
                break;
            }
            self.download_limit.consume(len as u64, ctx.now);
            self.tick_down_remaining -= len as u64;
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
        _ctx: &'_ mut SessionCtx<'_, H>,
    ) -> Result<()> {
        let t = match &self.torrent {
            Some(t) => t.clone(),
            None => return Err(Error::Protocol),
        };
        let pi = t.piece_info(index)?;
        let total_blocks = block_count_for(pi.len);
        let block = begin / BLOCK_LEN;
        if (block as u16) >= total_blocks || !begin.is_multiple_of(BLOCK_LEN) {
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
        // anti-leech: remember who supplied this block (for corrupt-blame)
        self.piece_suppliers.entry(index).or_default().push(conn);
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
            // Hand the assembled piece to the verifier (worker pool or
            // inline, decided by the engine). It stays out of the picker
            // until the result lands: re-mark in-flight and record it.
            if let Some(buf) = self.assembling.remove(&index) {
                self.pieces.set_in_flight(index, true);
                self.verifying.insert(index, total_blocks as u32);
                self.pending_verify.insert(index, buf);
            }
        }
        Ok(())
    }

    /// Drain pieces that finished assembling and await verification
    /// (engine calls once per tick).
    pub fn take_pending_verify(&mut self) -> BTreeMap<u32, Vec<u8>> {
        core::mem::take(&mut self.pending_verify)
    }

    /// Build a verification job for an assembled piece (reads the torrent).
    /// Returns the bytes back when the job cannot be built, so the caller
    /// can fall back to inline verification.
    pub fn build_verify_job(&self, piece: u32, data: Vec<u8>) -> (Option<VerifyJob>, Vec<u8>) {
        let t = match self.torrent.as_ref() {
            Some(t) => t,
            None => return (None, data),
        };
        let pi = match t.piece_info(piece) {
            Ok(pi) => pi,
            Err(_) => return (None, data),
        };
        let expect = match t.piece_hash(piece) {
            Some(h) => h.to_vec(),
            None => return (None, data),
        };
        let job = VerifyJob {
            torrent: self.info_hash,
            piece,
            len: pi.len,
            kind: HashKind::from(t.kind),
            expect,
            data,
        };
        (Some(job), Vec::new())
    }

    /// Verify a piece inline (single-threaded fallback; shares the same
    /// pure checker as the worker pool).
    pub fn verify_inline(&self, piece: u32, data: Vec<u8>) -> (bool, Vec<u8>) {
        let t = match &self.torrent {
            Some(t) => t,
            None => return (false, data),
        };
        let ok = match (t.piece_info(piece), t.piece_hash(piece)) {
            (Ok(pi), Some(expect)) => {
                crate::verify::verify_piece(HashKind::from(t.kind), pi.len, &data, expect)
            }
            _ => false,
        };
        (ok, data)
    }

    /// Apply a verification outcome (from the pool or inline).
    pub fn on_verified<H: Host>(
        &mut self,
        piece: u32,
        ok: bool,
        data: Vec<u8>,
        ctx: &'_ mut SessionCtx<'_, H>,
    ) -> Result<()> {
        let total_blocks = match self.verifying.remove(&piece) {
            Some(tb) => tb,
            None => return Ok(()), // unknown / already settled
        };
        let t = match &self.torrent {
            Some(t) => t.clone(),
            None => return Ok(()),
        };
        if ok {
            self.complete_piece_verified(piece, data, &t, ctx)
        } else {
            self.complete_piece_failed(piece, total_blocks, ctx);
            Ok(())
        }
    }

    /// Success path for a verified piece: write, mark have, announce.
    fn complete_piece_verified<H: Host>(
        &mut self,
        index: u32,
        buf: Vec<u8>,
        t: &Torrent,
        ctx: &'_ mut SessionCtx<'_, H>,
    ) -> Result<()> {
        // write to disk cache (piece may span files)
        let abs = t.piece_abs_offset(index)?;
        self.write_abs(ctx, abs, &buf)?;
        self.pieces.mark_piece_have(index);
        self.piece_suppliers.remove(&index);
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
        if self.pieces.have_count() >= self.selected_piece_count {
            self.status = SessionStatus::Seeding;
            self.announce_at = ctx.now;
            self.announce_to_tracker(ctx, TrackerEvent::Completed);
            ctx.events.push(EngineEvent::TorrentComplete {
                info_hash: self.info_hash,
            });
        }
        Ok(())
    }

    /// Failure path for a piece: reset, attribute blame, penalize/ban.
    fn complete_piece_failed<H: Host>(
        &mut self,
        index: u32,
        total_blocks: u32,
        ctx: &'_ mut SessionCtx<'_, H>,
    ) {
        // hash failure: reset the piece, attribute blame to the peers that
        // supplied its blocks, ban repeat offenders.
        self.pieces.reset_piece(index);
        self.monitor.record_hash_failure(index);
        self.scheduler.mark_suspicious(index);
        self.punish_corrupt_suppliers(index, total_blocks, ctx);
        ctx.events.push(EngineEvent::HashFailure {
            info_hash: self.info_hash,
            piece: index,
        });
    }

    /// Attribute a failed piece to its suppliers, penalize them, and ban
    /// peers that cross the corruption threshold.
    fn punish_corrupt_suppliers<H: Host>(
        &mut self,
        piece: u32,
        total_blocks: u32,
        ctx: &'_ mut SessionCtx<'_, H>,
    ) {
        let sups = match self.piece_suppliers.remove(&piece) {
            Some(s) => s,
            None => return,
        };
        let mut counts: BTreeMap<ConnId, u32> = BTreeMap::new();
        for c in sups {
            *counts.entry(c).or_insert(0) += 1;
        }
        let penalties = leech::attribute_corruption(&counts, total_blocks);
        let threshold = self.cfg.leech.corrupt_ban_threshold;
        let mut to_ban: Vec<(ConnId, NetAddr)> = Vec::new();
        for (c, pen) in penalties {
            if let Some(p) = self.peers.get_mut(&c) {
                p.rep.corrupt_blocks = p.rep.corrupt_blocks.saturating_add(pen);
                let pid = p.peer_id;
                // remember the offense across disconnects / sessions so the
                // peer starts pre-penalized next time it connects.
                self.reputation
                    .note_corrupt(p.addr, pid.as_ref(), pen, ctx.now);
                if p.rep.corrupt_blocks >= threshold {
                    to_ban.push((c, p.addr));
                }
            }
        }
        for (c, addr) in to_ban {
            self.ban_peer(c, addr, BanReason::Corrupt, ctx);
        }
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
        let t = match &self.torrent {
            Some(t) => t.clone(),
            None => return Ok(()),
        };
        // anti-leech: structurally invalid requests are unambiguous protocol
        // violations (zero-length, misaligned, oversized, past the piece end,
        // or a piece that does not exist). A single one can be a buggy peer,
        // so we count them and only treat repeat offenders as violators.
        let structurally_bad = match t.piece_info(index) {
            Ok(pi) => {
                length == 0
                    || length > BLOCK_LEN
                    || !begin.is_multiple_of(BLOCK_LEN)
                    || (begin as u64) + (length as u64) > pi.len as u64
            }
            Err(_) => true,
        };
        if structurally_bad {
            let spam = {
                let p = match self.peers.get_mut(&conn) {
                    Some(p) => p,
                    None => return Ok(()),
                };
                p.invalid_requests += 1;
                p.invalid_requests >= self.cfg.leech.invalid_request_threshold
            };
            if spam {
                return Err(Error::Protocol);
            }
            // politely reject (fast extension) and stay connected
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
        // anti-leech: any *valid* request shows intent — remember when they
        // last asked (drives the idle-slot detection).
        if let Some(p) = self.peers.get_mut(&conn) {
            p.last_request_at = ctx.now;
        }
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
        // anti-leech: bound the per-peer outgoing queue so a fast requester
        // cannot balloon memory or monopolize upload when throttled.
        if let Some(p) = self.peers.get(&conn) {
            if p.out.len() >= Self::MAX_PEER_OUT_BUF {
                if p.fast {
                    if let Some(p) = self.peers.get_mut(&conn) {
                        p.send(&Message::Reject {
                            index,
                            begin,
                            length,
                        });
                    }
                }
                return Ok(());
            }
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
            p.served_requests = p.served_requests.saturating_add(1);
            p.on_data_out(n, ctx.now);
            p.send(&Message::Piece {
                index,
                begin,
                data: buf,
            });
        }
        Ok(())
    }

    fn cancel_peer_request<H: Host>(
        &mut self,
        conn: ConnId,
        index: u32,
        begin: u32,
        _ctx: &'_ mut SessionCtx<'_, H>,
    ) -> Result<()> {
        let block = (begin / BLOCK_LEN) as u16;
        let outstanding = self
            .requested_by
            .get(&(index, block))
            .map(|reqs| reqs.contains(&conn))
            .unwrap_or(false);
        if !outstanding {
            // anti-leech: a cancel for a block we never asked this peer for
            // is spurious (cancel/piece races aside). Count them; repeated
            // spurious cancels earn a protocol violation.
            let spam = {
                let p = match self.peers.get_mut(&conn) {
                    Some(p) => p,
                    None => return Ok(()),
                };
                p.spurious_cancels += 1;
                p.spurious_cancels >= self.cfg.leech.cancel_spam_threshold
            };
            if spam {
                return Err(Error::Protocol);
            }
            return Ok(());
        }
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
        Ok(())
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

/// Map per-file priorities onto per-piece priority multipliers.
///
/// Returns `(piece_priorities, selected_piece_count)`. A piece is *selected*
/// (multiplier > 0) when it overlaps at least one non-skipped file. For v1
/// torrents a piece may straddle file boundaries; downloading it is then
/// still required to satisfy the wanted file, so Skip only ever wins when
/// *every* overlapping file is skipped. The multiplier is the maximum of the
/// overlapping files (High = 4, Normal = 1).
fn compute_piece_priorities(t: &Torrent, file_priorities: &[FilePriority]) -> (Vec<i64>, u32) {
    let n = t.piece_count() as usize;
    if n == 0 {
        return (Vec::new(), 0);
    }
    let pl = t.piece_length as u64;
    let mut need = vec![false; n];
    let mut high = vec![false; n];
    let mut abs = 0u64;
    for (fi, f) in t.files.iter().enumerate() {
        let fp = file_priorities
            .get(fi)
            .copied()
            .unwrap_or(FilePriority::Normal);
        // piece range [first, last) overlapping [abs, abs + len)
        let first = (abs / pl) as usize;
        let last = ((abs + f.length).div_ceil(pl)) as usize;
        for p in first.min(n)..last.min(n) {
            match fp {
                FilePriority::Skip => {}
                FilePriority::Normal => need[p] = true,
                FilePriority::High => high[p] = true,
            }
        }
        abs = abs.saturating_add(f.length);
    }
    let mut prio = Vec::with_capacity(n);
    let mut selected = 0u32;
    for p in 0..n {
        let m = if high[p] {
            4
        } else if need[p] {
            1
        } else {
            0
        };
        if m > 0 {
            selected += 1;
        }
        prio.push(m);
    }
    (prio, selected)
}

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

/// Parse a `udp://host:port/announce` endpoint. IPv4 literals are decoded
/// directly; hostnames (the common case for public UDP trackers — e.g.
/// `udp://tracker.opentrackr.org:1337`) are resolved through the host's
/// `resolve_host`, without which they would silently never announce.
fn parse_udp_tracker_addr<F>(url: &[u8], resolve: &mut F) -> Option<NetAddr>
where
    F: FnMut(&str, u16) -> Option<NetAddr>,
{
    let s = core::str::from_utf8(url).ok()?;
    let rest = s.strip_prefix("udp://")?;
    let hostport = rest.split('/').next()?;
    let (host, port) = hostport.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    // IPv4 literal first (no DNS needed).
    let mut parts = host.split('.');
    let literal = parts.next()?.parse::<u8>().ok().and_then(|a| {
        let b = parts.next()?.parse::<u8>().ok()?;
        let c = parts.next()?.parse::<u8>().ok()?;
        let d = parts.next()?.parse::<u8>().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some([a, b, c, d])
    });
    if let Some(ip) = literal {
        return Some(NetAddr::V4(ip, port));
    }
    // Hostname (or bracketed IPv6 literal) → the host resolves it.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    resolve(host, port)
}

/// Build the per-session tracker list: torrent-declared URLs first, then
/// config extras, deduped; when nothing was declared and
/// `cfg.use_default_trackers` is set, fall back to the built-in public
/// list (qBittorrent/BitComet compatible).
fn seed_trackers<I: IntoIterator<Item = Vec<u8>>>(
    from: I,
    cfg: &SessionConfig,
) -> Vec<TrackerState> {
    // Proxy mode is outbound-only: UDP trackers would announce from the
    // real IP and leak it, so they are dropped at load time.
    let anonymous = cfg.proxy.is_some();
    let mut out: Vec<TrackerState> = Vec::new();
    for url in from {
        push_tracker_if_allowed(&mut out, url, anonymous);
    }
    for url in &cfg.trackers {
        push_tracker_if_allowed(&mut out, url.as_bytes().to_vec(), anonymous);
    }
    if out.is_empty() && cfg.use_default_trackers {
        for url in crate::trackerlist::DEFAULT_TRACKERS {
            push_tracker_if_allowed(&mut out, url.as_bytes().to_vec(), anonymous);
        }
    }
    out
}

fn push_tracker_if_allowed(out: &mut Vec<TrackerState>, url: Vec<u8>, anonymous: bool) {
    if anonymous && detect_tracker_kind(&url) == TrackerKind::Udp {
        return;
    }
    push_tracker(out, url);
}

fn push_tracker(out: &mut Vec<TrackerState>, url: Vec<u8>) {
    if out.iter().any(|t| t.url == url) {
        return;
    }
    let kind = detect_tracker_kind(&url);
    out.push(TrackerState {
        url,
        kind,
        interval: 1800,
        next_announce: 0,
        failure: None,
        fails: 0,
        udp: UdpTrackerState::default(),
    });
}

fn with_port(a: NetAddr, port: u16) -> NetAddr {
    match a {
        NetAddr::V4(ip, _) => NetAddr::V4(ip, port),
        NetAddr::V6(ip, _) => NetAddr::V6(ip, port),
    }
}

/// Canonical subnet key: the /24 prefix for IPv4, the /64 prefix for IPv6.
/// Used to bound how many peers from one address range we admit.
fn subnet_key(addr: &NetAddr) -> [u8; 8] {
    match *addr {
        NetAddr::V4(ip, _) => {
            let mut k = [0u8; 8];
            k[..3].copy_from_slice(&ip[..3]);
            k
        }
        NetAddr::V6(ip, _) => {
            let mut k = [0u8; 8];
            k.copy_from_slice(&ip[..8]);
            k
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metainfo::{FileEntry, Torrent, TorrentKind};
    use crate::platform::DiskId;

    /// A 2-file v1 torrent: piece 0 lives in file 0, pieces 1–2 in file 1.
    fn test_torrent() -> Torrent {
        let pl = 256 * 1024u32;
        Torrent {
            name: String::from("ws"),
            piece_length: pl,
            total_size: pl as u64 * 2 + 100,
            files: vec![
                FileEntry {
                    path: vec![b"dir".to_vec(), b"a.bin".to_vec()],
                    length: pl as u64,
                    root: None,
                },
                FileEntry {
                    path: vec![b"b.bin".to_vec()],
                    length: pl as u64 + 100,
                    root: None,
                },
            ],
            kind: TorrentKind::V1,
            info_hash: InfoHash::v1([1u8; 20]),
            v1_hashes: Some(vec![[0u8; 20]; 3]),
            v2_hashes: None,
            announce: None,
            announce_list: Vec::new(),
            web_seeds: vec![b"http://seed.example/base/".to_vec()],
            private: false,
            piece_layers: Vec::new(),
            info_raw: Vec::new(),
            comment: None,
            created_by: None,
            creation_date: None,
        }
    }

    fn session() -> TorrentSession {
        let cfg = SessionConfig {
            save_dir: String::from("/tmp"),
            ..Default::default()
        };
        TorrentSession::from_torrent(test_torrent(), cfg, 0).expect("session")
    }

    /// A host that records every UDP datagram it sends and resolves one
    /// fake tracker hostname — enough to exercise the UDP tracker path.
    struct UdpTrackerHost {
        sent: Vec<NetAddr>,
    }

    impl crate::platform::Host for UdpTrackerHost {
        fn now_ms(&self) -> u64 {
            1_000_000
        }
        fn fill_random(&mut self, _b: &mut [u8]) {}
        fn log(&mut self, _l: crate::platform::LogLevel, _m: &str) {}
        fn http_get(&mut self, _u: &str, _t: u64, _o: &mut Vec<u8>) -> crate::error::Result<()> {
            Err(crate::error::Error::NotSupported)
        }
        fn resolve_host(&self, host: &str, port: u16) -> Option<NetAddr> {
            if host == "tracker.example.com" {
                Some(NetAddr::V4([192, 0, 2, 10], port))
            } else {
                None
            }
        }
        fn tcp_connect(&mut self, _a: &NetAddr) -> crate::error::Result<ConnId> {
            Err(crate::error::Error::NotSupported)
        }
        fn tcp_connect_done(&mut self, _id: ConnId) -> crate::error::Result<()> {
            Err(crate::error::Error::NotSupported)
        }
        fn tcp_send(&mut self, _id: ConnId, _d: &[u8]) -> crate::error::Result<usize> {
            Err(crate::error::Error::NotSupported)
        }
        fn tcp_recv(&mut self, _id: ConnId, _b: &mut [u8]) -> crate::error::Result<usize> {
            Err(crate::error::Error::WouldBlock)
        }
        fn tcp_close(&mut self, _id: ConnId) {}
        fn udp_open(&mut self, _p: u16) -> crate::error::Result<()> {
            Ok(())
        }
        fn udp_send(&mut self, addr: &NetAddr, _d: &[u8]) -> crate::error::Result<()> {
            self.sent.push(*addr);
            Ok(())
        }
        fn udp_recv(&mut self, _b: &mut [u8]) -> crate::error::Result<(NetAddr, usize)> {
            Err(crate::error::Error::WouldBlock)
        }
        fn disk_open(&mut self, _p: &str) -> crate::error::Result<DiskId> {
            Ok(1)
        }
        fn disk_read(
            &mut self,
            _id: DiskId,
            _o: u64,
            _b: &mut [u8],
        ) -> crate::error::Result<usize> {
            Ok(0)
        }
        fn disk_write(&mut self, _id: DiskId, _o: u64, _d: &[u8]) -> crate::error::Result<()> {
            Ok(())
        }
        fn disk_prealloc(&mut self, _id: DiskId, _s: u64) -> crate::error::Result<()> {
            Ok(())
        }
        fn disk_flush(&mut self, _id: DiskId) -> crate::error::Result<()> {
            Ok(())
        }
        fn disk_close(&mut self, _id: DiskId) {}
    }

    /// A host whose sockets are inert (no data ever arrives) — enough to
    /// construct a `SessionCtx` for pure in-memory session tests.
    struct NoopHost;

    impl crate::platform::Host for NoopHost {
        fn now_ms(&self) -> u64 {
            1_000_000
        }
        fn fill_random(&mut self, _b: &mut [u8]) {}
        fn log(&mut self, _l: crate::platform::LogLevel, _m: &str) {}
        fn http_get(&mut self, _u: &str, _t: u64, _o: &mut Vec<u8>) -> crate::error::Result<()> {
            Err(crate::error::Error::NotSupported)
        }
        fn tcp_connect(&mut self, _a: &NetAddr) -> crate::error::Result<ConnId> {
            Ok(1)
        }
        fn tcp_connect_done(&mut self, _id: ConnId) -> crate::error::Result<()> {
            Ok(())
        }
        fn tcp_send(&mut self, _id: ConnId, d: &[u8]) -> crate::error::Result<usize> {
            Ok(d.len())
        }
        fn tcp_recv(&mut self, _id: ConnId, _b: &mut [u8]) -> crate::error::Result<usize> {
            Err(crate::error::Error::WouldBlock)
        }
        fn tcp_close(&mut self, _id: ConnId) {}
        fn udp_open(&mut self, _p: u16) -> crate::error::Result<()> {
            Err(crate::error::Error::NotSupported)
        }
        fn udp_send(&mut self, _a: &NetAddr, _d: &[u8]) -> crate::error::Result<()> {
            Err(crate::error::Error::NotSupported)
        }
        fn udp_recv(&mut self, _b: &mut [u8]) -> crate::error::Result<(NetAddr, usize)> {
            Err(crate::error::Error::WouldBlock)
        }
        fn disk_open(&mut self, _p: &str) -> crate::error::Result<DiskId> {
            Ok(1)
        }
        fn disk_read(
            &mut self,
            _id: DiskId,
            _o: u64,
            _b: &mut [u8],
        ) -> crate::error::Result<usize> {
            Ok(0)
        }
        fn disk_write(&mut self, _id: DiskId, _o: u64, _d: &[u8]) -> crate::error::Result<()> {
            Ok(())
        }
        fn disk_prealloc(&mut self, _id: DiskId, _s: u64) -> crate::error::Result<()> {
            Ok(())
        }
        fn disk_flush(&mut self, _id: DiskId) -> crate::error::Result<()> {
            Ok(())
        }
        fn disk_close(&mut self, _id: DiskId) {}
    }

    /// Craft the wire bytes of a remote peer that sends its handshake and
    /// its first messages (bitfield + unchoke) inside ONE TCP segment — the
    /// common case, since TCP coalesces a seed's first burst.
    fn remote_handshake_plus_first_messages(info_hash: [u8; 20], have_all: bool) -> Vec<u8> {
        let mut reserved = [0u8; 8];
        reserved[5] = 0x10; // extension (BEP-10)
        reserved[7] = 0x04 | 0x08; // fast + metadata (BEP-6/BEP-9)
        let mut b = Vec::new();
        b.push(19);
        b.extend_from_slice(b"BitTorrent protocol");
        b.extend_from_slice(&reserved);
        b.extend_from_slice(&info_hash);
        b.extend_from_slice(&[9u8; 20]); // peer id
                                         // first messages in the same segment
        b.extend_from_slice(&Message::Unchoke.encode());
        if have_all {
            b.extend_from_slice(&Message::HaveAll.encode());
        } else {
            b.extend_from_slice(&Message::Bitfield(vec![0b111]).encode());
        }
        b
    }

    #[test]
    fn handshake_and_first_messages_in_one_segment_keep_peer() {
        let mut s = session();
        let mut host = NoopHost;
        let mut cache = crate::disk_cache::DiskCache::new(1024 * 1024);
        let mut events = Vec::new();
        let mut ctx = SessionCtx {
            host: &mut host,
            cache: &mut cache,
            peer_id: [7u8; 20],
            port: 6881,
            now: 1_000_000,
            dht: None,
            events: &mut events,
        };
        s.attach_peer(
            1,
            NetAddr::V4([93, 184, 216, 34], 6881),
            true,
            DiscoverySource::Tracker,
            &mut ctx,
        );
        assert!(s.peers.contains_key(&1));
        // one segment: handshake + unchoke + have_all
        let seg = remote_handshake_plus_first_messages([1u8; 20], true);
        s.on_data(1, &seg, &mut ctx);
        // The peer MUST survive the handshake and process the trailing
        // messages — a seed that unchokes us in the same segment as its
        // handshake is the normal case, not a protocol violation.
        let p = s.peers.get(&1).expect("peer was dropped after handshake");
        assert_eq!(p.phase, PeerPhase::Ready);
        assert!(!p.peer_choking, "unchoke was not processed");
        assert!(p.have_all, "have_all was not processed");
        assert!(p.is_seed);
    }

    #[test]
    fn interested_is_sent_to_a_choking_seed_with_missing_pieces() {
        let mut s = session();
        let mut host = NoopHost;
        let mut cache = crate::disk_cache::DiskCache::new(1024 * 1024);
        let mut events = Vec::new();
        let mut ctx = SessionCtx {
            host: &mut host,
            cache: &mut cache,
            peer_id: [7u8; 20],
            port: 6881,
            now: 1_000_000,
            dht: None,
            events: &mut events,
        };
        s.attach_peer(
            1,
            NetAddr::V4([93, 184, 216, 34], 6881),
            true,
            DiscoverySource::Tracker,
            &mut ctx,
        );
        // handshake + have_all only (the seed has NOT unchoked us yet).
        // Note: unchoke and have_all both encode to 5 bytes, so drop the
        // unchoke by its position right after the 68-byte handshake.
        let mut seg = remote_handshake_plus_first_messages([1u8; 20], true);
        seg.drain(crate::wire::HANDSHAKE_LEN..crate::wire::HANDSHAKE_LEN + 5);
        s.on_data(1, &seg, &mut ctx);
        let p = s.peers.get(&1).expect("peer was dropped after handshake");
        // We lack every piece and it has everything → we MUST be interested,
        // even while choked. Otherwise seeds that only unchoke interested
        // peers never let us download (the classic 0% deadlock).
        assert!(p.am_interested, "no Interested sent to a choking seed");
        assert!(p.peer_choking);
        assert!(p
            .out
            .windows(Message::Interested.encode().len())
            .any(|w| w == Message::Interested.encode().as_slice()));
    }

    /// A one-piece, one-block v1 torrent whose sole piece is a known byte
    /// pattern (so its SHA-1 can be computed up front and the piece will
    /// verify when the seed sends it back).
    fn single_block_torrent() -> Torrent {
        use crate::crypto::Sha1;
        let pl = BLOCK_LEN; // 16 KiB → exactly one block
        let data: Vec<u8> = vec![0xAB; pl as usize];
        let hash = Sha1::digest(&data);
        Torrent {
            name: String::from("dl.bin"),
            piece_length: pl,
            total_size: pl as u64,
            files: vec![FileEntry {
                path: vec![b"dl.bin".to_vec()],
                length: pl as u64,
                root: None,
            }],
            kind: TorrentKind::V1,
            info_hash: InfoHash::v1([2u8; 20]),
            v1_hashes: Some(vec![hash]),
            v2_hashes: None,
            announce: None,
            announce_list: Vec::new(),
            web_seeds: Vec::new(),
            private: false,
            piece_layers: Vec::new(),
            info_raw: Vec::new(),
            comment: None,
            created_by: None,
            creation_date: None,
        }
    }

    #[test]
    fn full_download_from_have_all_seed() {
        use crate::crypto::Sha1;
        let t = single_block_torrent();
        let cfg = SessionConfig {
            save_dir: String::from("/tmp"),
            download_limit_bps: 0,
            upload_limit_bps: 0,
            ..Default::default()
        };
        let mut s = TorrentSession::from_torrent(t, cfg, 1_000_000).expect("session");
        let mut host = NoopHost;
        let mut cache = crate::disk_cache::DiskCache::new(1024 * 1024);
        let mut events = Vec::new();
        let mut ctx = SessionCtx {
            host: &mut host,
            cache: &mut cache,
            peer_id: [7u8; 20],
            port: 6881,
            now: 1_000_000,
            dht: None,
            events: &mut events,
        };
        // Start the session: opens the target file(s) and begins announces
        // (the NoopHost's http_get fails, which the session tolerates).
        s.start(&mut ctx).expect("start");
        // The seed connects and sends handshake + unchoke + have_all in one
        // TCP segment (the common fast-extension seed case).
        s.attach_peer(
            1,
            NetAddr::V4([203, 0, 113, 9], 6881),
            true,
            DiscoverySource::Tracker,
            &mut ctx,
        );
        let seg = remote_handshake_plus_first_messages([2u8; 20], true);
        s.on_data(1, &seg, &mut ctx);
        {
            let p = s.peers.get(&1).expect("seed dropped after handshake");
            assert_eq!(p.phase, PeerPhase::Ready);
            assert!(!p.peer_choking, "seed unchoke not processed");
            assert!(p.am_interested, "not interested in a have_all seed");
        }
        // Grant the per-tick budget (the engine does this in `tick`) and
        // pump the request pipeline.
        s.tick_down_remaining = u64::MAX;
        s.tick_up_allowance = u64::MAX;
        s.fill_pipeline(1, &mut ctx);
        {
            let p = s.peers.get(&1).unwrap();
            let want = Message::Request {
                index: 0,
                begin: 0,
                length: BLOCK_LEN,
            }
            .encode();
            assert!(
                p.out.windows(want.len()).any(|w| w == want.as_slice()),
                "no block request sent to the have_all seed"
            );
        }
        // The seed answers with the piece block.
        let data = vec![0xABu8; BLOCK_LEN as usize];
        let piece_msg = Message::Piece {
            index: 0,
            begin: 0,
            data: data.clone(),
        }
        .encode();
        s.on_data(1, &piece_msg, &mut ctx);
        // The piece is assembled and handed to the verifier.
        assert!(
            s.pending_verify.contains_key(&0),
            "assembled piece was not queued for verification"
        );
        let pending = s.take_pending_verify();
        let buf = pending.get(&0).cloned().expect("piece bytes");
        assert_eq!(Sha1::digest(&buf), Sha1::digest(&data));
        let (ok, buf) = s.verify_inline(0, buf);
        assert!(ok, "piece failed verification");
        s.on_verified(0, ok, buf, &mut ctx).expect("verify apply");
        assert!(s.pieces.is_have(0), "piece was not marked have");
        assert!(
            s.status == SessionStatus::Seeding,
            "one-piece torrent should complete"
        );
        assert!(s.progress() > 0.999);
    }

    #[test]
    fn udp_tracker_resolves_hostname_and_retransmits_after_timeout() {
        // A torrent whose only tracker is a *hostname* UDP tracker — the
        // common shape of public UDP trackers. Without resolution it would
        // silently never announce; without the timeout reset a single lost
        // connect request would stall it forever.
        let mut t = test_torrent();
        t.announce_list = vec![vec![b"udp://tracker.example.com:1337/announce".to_vec()]];
        let cfg = SessionConfig {
            save_dir: String::from("/tmp"),
            ..Default::default()
        };
        let mut s = TorrentSession::from_torrent(t, cfg, 1_000_000).expect("session");
        let mut host = UdpTrackerHost { sent: Vec::new() };
        let mut cache = crate::disk_cache::DiskCache::new(1024 * 1024);
        let mut events = Vec::new();
        // First announce: hostname is resolved through the host → the
        // connect request goes to the resolved address.
        {
            let mut ctx = SessionCtx {
                host: &mut host,
                cache: &mut cache,
                peer_id: [7u8; 20],
                port: 6881,
                now: 1_000_000,
                dht: None,
                events: &mut events,
            };
            s.announce_to_tracker(&mut ctx, TrackerEvent::Started);
        }
        assert_eq!(host.sent.len(), 1, "one connect request on first announce");
        assert_eq!(host.sent[0], NetAddr::V4([192, 0, 2, 10], 1337));
        // Tracker never answers. 16 s later we re-announce: the pending
        // request timed out and a fresh connect request is sent (cached
        // address reused — no second DNS lookup).
        {
            let mut ctx = SessionCtx {
                host: &mut host,
                cache: &mut cache,
                peer_id: [7u8; 20],
                port: 6881,
                now: 1_016_000,
                dht: None,
                events: &mut events,
            };
            s.announce_to_tracker(&mut ctx, TrackerEvent::None);
        }
        assert_eq!(host.sent.len(), 2, "connect request re-sent after timeout");
        assert_eq!(host.sent[1], NetAddr::V4([192, 0, 2, 10], 1337));
    }

    #[test]
    fn web_seed_path_percent_encodes() {
        let f = FileEntry {
            path: vec![b"a b".to_vec(), b"c%2Fd.txt".to_vec()],
            length: 1,
            root: None,
        };
        assert_eq!(web_seed_path(&f), "a%20b/c%252Fd.txt");
    }

    #[test]
    fn webseed_picks_first_fetchable_piece() {
        let s = session();
        let t = test_torrent();
        // piece 0 is whole within file 0; priorities all Normal.
        assert_eq!(s.pick_webseed_piece(&t), Some((0, 256 * 1024)));
        // nothing left once everything is have
        let mut s = s;
        for p in 0..3 {
            s.pieces.mark_piece_have(p);
        }
        assert_eq!(s.pick_webseed_piece(&t), None);
    }

    #[test]
    fn webseed_block_resolves_url_and_file_relative_range() {
        let s = session();
        let t = test_torrent();
        // piece 0 → file "dir/a.bin", range relative to the file start (0).
        let (url, start, end, len) = s.webseed_block(&t, 0, 0).unwrap();
        assert_eq!(url, "http://seed.example/base/dir/a.bin");
        assert_eq!(start, 0);
        assert_eq!(end, (BLOCK_LEN - 1) as u64);
        assert_eq!(len, BLOCK_LEN as u64);
        // piece 2 (last partial, 100 B) → file "b.bin", range must be
        // relative to THAT file, i.e. 256 KiB, NOT the absolute torrent
        // offset 512 KiB.
        let (url, start, end, len) = s.webseed_block(&t, 2, 0).unwrap();
        assert_eq!(url, "http://seed.example/base/b.bin");
        assert_eq!(start, 256 * 1024u64);
        assert_eq!(end, 256 * 1024u64 + 99);
        assert_eq!(len, 100);
        // a block past the piece end is refused
        assert!(s.webseed_block(&t, 2, 1).is_none());
    }

    #[test]
    fn webseed_skips_cross_file_pieces() {
        // a piece straddling two files cannot be fetched from one resource
        let mut t = test_torrent();
        t.files[0].length = BLOCK_LEN as u64 + 100; // piece 0 now spans files
        t.total_size = t.files[0].length + t.files[1].length; // keep consistent
        let s = session();
        // piece 0 is rejected (spans files); piece 1 is whole in file 1
        assert_eq!(s.pick_webseed_piece(&t), Some((1, 16584)));
    }
}
