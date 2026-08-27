//! The top-level engine: owns the host, all torrent sessions, the shared
//! disk cache and the DHT, and drives the non-blocking event loop. The host
//! calls [`Engine::tick`] on a fixed cadence and drains [`Engine::take_events`].

use crate::consts::DEFAULT_PORT;
use crate::crypto::Rng;
use crate::dht::{DatagramOutcome, Dht, NodeId};
use crate::disk_cache::DiskCache;
use crate::error::{Error, Result};
use crate::magnet::Magnet;
use crate::metainfo::{InfoHash, Torrent};
use crate::monitoring::DiscoverySource;
use crate::platform::{ConnId, Host, LogLevel, NetAddr};
use crate::portmap::{PortMapConfig, PortMapManager, PortMapPhase};
use crate::ratelimit::TokenBucket;
use crate::session::{FilePriority, SessionConfig, SessionCtx, TorrentSession, TrackerKind};
use crate::socks::{ProxyConfig, Socks5Client, SocksStatus, SocksTarget};
use crate::verify::VerifyPool;
use crate::wire::Handshake;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
pub use engine_events::EngineEvent;

/// Per-tick disk-cache flush budget
const CACHE_FLUSH_BUDGET_BYTES: u64 = 8 * 1024 * 1024;

/// Engine-wide configuration.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Listen port advertised to the swarm / DHT.
    pub listen_port: u16,
    /// Disk cache budget.
    pub cache_bytes: u64,
    /// DHT enabled.
    pub dht_enabled: bool,
    /// Global upload limit in bytes/second across all torrents (0 = unlimited).
    pub global_upload_limit_bps: u64,
    /// Global download limit in bytes/second across all torrents (0 = unlimited).
    pub global_download_limit_bps: u64,
    /// Hard cap on total open peer connections (all torrents).
    pub global_max_connections: usize,
    /// Hard cap on connections from one IP address (anti-flood).
    pub max_connections_per_ip: u32,
    /// Try to open a NAT/firewall port mapping (NAT-PMP, falling back to
    /// UPnP IGD) for the listen port. Needs a host that reports a default
    /// gateway; UPnP additionally needs HTTP POST + a LAN IP.
    pub port_mapping: bool,
    /// Local Service Discovery (BEP-14): announce active swarms on the LAN
    /// and discover same-LAN peers. Off disables both the multicast
    /// announce and the dedicated 6771 receive socket.
    pub lsd_enabled: bool,
    /// LSD announce interval (ms, mechanism 4). One infohash per interval,
    /// round-robin over active torrents. Clamped to a hard floor
    /// ([`crate::lsd::LSD_INTERVAL_MIN_MS`]) so a config can never turn the
    /// LAN broadcast into a storm. 60_000 matches BEP-14's once-per-minute
    /// rule (~5 min per torrent with 5 active torrents).
    pub lsd_interval_ms: u64,
    /// Piece-verification worker threads. `0` = auto-detect under `std`
    /// (one per core minus one, capped at 8) and inline under `no_std`.
    /// The engine event loop never blocks on hashing either way.
    pub verify_workers: usize,
    /// SOCKS5 proxy for anonymous operation (Tor / I2P). When set, the
    /// engine runs **outbound-only**: no inbound connections, no DHT, no
    /// UDP trackers, no port mapping, and the advertised listen port is 0.
    pub proxy: Option<ProxyConfig>,
    /// Deadline (ms) for a TCP connect to complete. A dead proxy or a host
    /// that never reports connect completion must not hold a connection
    /// slot forever.
    pub connect_timeout_ms: u64,
    /// Per-torrent defaults.
    pub session: SessionConfig,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            listen_port: DEFAULT_PORT,
            cache_bytes: crate::consts::DEFAULT_CACHE_BYTES,
            dht_enabled: true,
            global_upload_limit_bps: 0,
            global_download_limit_bps: 0,
            global_max_connections: 512,
            max_connections_per_ip: 8,
            port_mapping: false,
            lsd_enabled: true,
            lsd_interval_ms: crate::lsd::LSD_INTERVAL_MS,
            verify_workers: 0,
            proxy: None,
            connect_timeout_ms: 30_000,
            session: SessionConfig::default(),
        }
    }
}

/// How often the engine retries DHT bootstrap while the routing table is
/// still tiny. Fast retry keeps the DHT searching from app launch and
/// recovers quickly if the table is ever evicted.
const BOOTSTRAP_RETRY_MS: u64 = 5_000;

/// Re-bootstrap while the routing table has fewer than this many nodes.
///
/// A table that only ever reached 1 node (e.g. a single ZERO placeholder
/// whose ping was dropped) would otherwise NEVER re-run
/// [`Engine::bootstrap_dht`] — the guard only fired at exactly `size()==0`.
/// The seeds the async DNS resolver has since produced would sit unused in
/// `dht_seeds` and the DHT would stay dormant forever, which surfaces as
/// "magnet stuck at metadata while qBittorrent succeeds" (DHT is the main
/// peer-discovery source for trackers-less magnets). A small-table
/// threshold re-injects the resolved seeds every retry window until the
/// bootstrap pings snowball the table past the threshold.
const DHT_REBOOTSTRAP_THRESHOLD: usize = 8;

/// Snapshot of engine-wide counters, surfaced to the UI (qBittorrent-style
/// stats dialog). Every field is a real counter — nothing is fabricated.
#[derive(Debug, Clone, Copy, Default)]
pub struct EngineStats {
    /// Disk-cache counters (read hits, read/write ops, …).
    pub cache: crate::disk_cache::CacheStats,
    /// Total bytes buffered in the disk cache (dirty + clean).
    pub cache_bytes: u64,
    /// Disk-cache byte budget.
    pub cache_budget: u64,
    /// Bytes in the clean read-through LRU.
    pub cache_clean: u64,
    /// Clean read-through LRU budget (for the read-overload ratio).
    pub cache_clean_budget: u64,
    /// Dirty blocks awaiting flush (write-back queue depth).
    pub cache_dirty_entries: usize,
    /// Payload bytes received but discarded this session.
    pub discarded_bytes: u64,
    /// Live peer connections across all sessions (non-Closed).
    pub connected_peers: usize,
}

/// The engine. Generic over the host.
pub struct Engine<H: Host> {
    /// Host.
    pub host: H,
    /// Config.
    pub cfg: EngineConfig,
    peer_id: [u8; 20],
    sessions: BTreeMap<InfoHash, TorrentSession>,
    conn_owner: BTreeMap<ConnId, InfoHash>,
    cache: DiskCache,
    dht: Option<Dht>,
    events: Vec<EngineEvent>,
    udp_open: bool,
    /// A UDP open attempt failed; DHT/UDP-trackers have been disabled.
    udp_failed: bool,
    /// Last time a (re-)bootstrap of the DHT was attempted (ms).
    last_bootstrap_at: u64,
    /// Resolved DHT bootstrap seed endpoints (cached — DNS is never repeated
    /// once it succeeds, so a slow resolver cannot stall the engine loop).
    dht_seeds: Vec<NetAddr>,
    /// Hostnames still being resolved asynchronously (for DHT bootstrap).
    dht_seed_pending: Vec<(String, u16)>,
    /// Last time async DHT seed resolution was (re-)kicked (ms).
    dht_resolve_kicked_at: u64,
    /// Whether the "no DHT router resolvable" notice was already emitted.
    dht_no_seed_emitted: bool,
    /// Connections still establishing (outbound).
    connecting: Vec<ConnId>,
    /// Inbound connections whose handshake has not revealed an infohash.
    inbound: BTreeMap<ConnId, InboundPeer>,
    /// Active SOCKS5 handshakes on outbound connections (proxy mode only).
    socks: BTreeMap<ConnId, Socks5Client>,
    /// Intended peer endpoint for each outbound connection in proxy mode.
    socks_target: BTreeMap<ConnId, SocksTarget>,
    /// Absolute deadline (ms) by which each outbound TCP connect must
    /// complete; enforced in `drive_tcp`.
    connect_deadline: BTreeMap<ConnId, u64>,
    last_cache_flush: u64,
    /// Global upload rate bucket.
    global_up: TokenBucket,
    /// Global download rate bucket.
    global_down: TokenBucket,
    /// Port mapping (NAT-PMP / UPnP IGD), when enabled.
    portmap: Option<PortMapManager>,
    /// Last reported port-map phase (for change events).
    last_pm_phase: PortMapPhase,
    /// Local Service Discovery (BEP-14) announce scheduler.
    lsd: crate::lsd::LsdScheduler,
    /// Last unicast LSD reply per source address (mechanism 4,
    /// anti-amplification): we answer a neighbour's `BT-SEARCH` at most once
    /// per [`crate::lsd::LSD_REPLY_GAP_MS`], so a spoofed-source flood
    /// cannot turn us into a multicast reflector.
    lsd_last_reply: BTreeMap<crate::platform::NetAddr, u64>,
    /// Last time a spontaneous `find_node` (bucket refresh) was started.
    last_dht_find_node: u64,
    /// Counter for deriving refresh targets (cheap deterministic random).
    dht_refresh_serial: u64,
    /// Piece-verification worker pool (real threads under `std`; `None`
    /// means inline verification).
    verify_pool: Option<VerifyPool>,
    /// BEP-29 uTP transport — shares the UDP socket with DHT/LSD.
    utp: crate::utp::UtpManager,
}

/// An inbound connection before we know its infohash.
struct InboundPeer {
    addr: NetAddr,
    buf: Vec<u8>,
}

impl<H: Host> Engine<H> {
    /// Cap on unhandshaken inbound connections (flood bound).
    const MAX_INBOUND: usize = 1024;
    /// Cap on buffered bytes per unhandshaken inbound connection.
    const MAX_INBOUND_BUF: usize = 64 * 1024;

    /// Create the engine; seeds entropy from the host.
    ///
    /// When [`EngineConfig::proxy`] is set, the engine immediately applies
    /// anonymity hardening: DHT, port mapping and the UDP socket are
    /// disabled and inbound connections are rejected — the configuration
    /// the caller sees afterwards reflects that.
    pub fn new(host: H, mut cfg: EngineConfig) -> Self {
        // Anonymity hardening (single source of truth = cfg.proxy).
        if cfg.proxy.is_some() {
            cfg.dht_enabled = false;
            cfg.port_mapping = false;
        }
        let mut seed = [0u8; 32];
        let mut h = host;
        let now = h.now_ms();
        h.fill_random(&mut seed);
        let mut rng = Rng::from_seed(seed);
        let peer_id = crate::peer_id::generate(&mut rng);
        let mut lsd_cookie = [0u8; 8];
        rng.fill(&mut lsd_cookie);
        let dht = if cfg.dht_enabled {
            let id = NodeId::random(&mut rng);
            Some(Dht::new(id, cfg.listen_port, &mut rng))
        } else {
            None
        };
        let global_up = TokenBucket::new(cfg.global_upload_limit_bps, now);
        let global_down = TokenBucket::new(cfg.global_download_limit_bps, now);
        let portmap = if cfg.port_mapping {
            let pc = PortMapConfig {
                enabled: true,
                udp_port: cfg.listen_port,
                tcp_port: cfg.listen_port,
                ..Default::default()
            };
            Some(PortMapManager::new(pc))
        } else {
            None
        };
        let verify_pool = {
            #[cfg(feature = "std")]
            {
                let workers = if cfg.verify_workers == 0 {
                    std::thread::available_parallelism()
                        .map(|n| n.get().saturating_sub(1))
                        .unwrap_or(1)
                        .clamp(1, 8)
                } else {
                    cfg.verify_workers
                };
                if workers > 0 {
                    Some(VerifyPool::spawn(workers))
                } else {
                    None
                }
            }
            #[cfg(not(feature = "std"))]
            {
                None
            }
        };
        let lsd_interval = cfg.lsd_interval_ms;
        Engine {
            host: h,
            peer_id,
            sessions: BTreeMap::new(),
            conn_owner: BTreeMap::new(),
            cache: DiskCache::new(cfg.cache_bytes),
            cfg,
            dht,
            events: Vec::new(),
            udp_open: false,
            udp_failed: false,
            last_bootstrap_at: 0,
            dht_seeds: Vec::new(),
            dht_seed_pending: Vec::new(),
            dht_resolve_kicked_at: 0,
            dht_no_seed_emitted: false,
            connecting: Vec::new(),
            inbound: BTreeMap::new(),
            socks: BTreeMap::new(),
            socks_target: BTreeMap::new(),
            connect_deadline: BTreeMap::new(),
            last_cache_flush: 0,
            global_up,
            global_down,
            portmap,
            last_pm_phase: PortMapPhase::Idle,
            lsd: crate::lsd::LsdScheduler::new(lsd_cookie, now, lsd_interval),
            lsd_last_reply: BTreeMap::new(),
            last_dht_find_node: now,
            dht_refresh_serial: 0,
            verify_pool,
            utp: crate::utp::UtpManager::new(),
        }
    }

    /// Our peer id.
    pub fn peer_id(&self) -> &[u8; 20] {
        &self.peer_id
    }

    /// The DHT (for inspection).
    pub fn dht(&self) -> Option<&Dht> {
        self.dht.as_ref()
    }

    /// The externally-confirmed DHT address (BEP-42): `(ip16, udp_port)`; port is 0 until confirmed.
    pub fn dht_external(&self) -> Option<([u8; 16], u16)> {
        let d = self.dht.as_ref()?;
        let ip = d.confirmed_external_ip()?;
        Some((ip, d.confirmed_external_port().unwrap_or(0)))
    }

    /// Number of active torrents.
    pub fn torrent_count(&self) -> usize {
        self.sessions.len()
    }

    /// Add a torrent from `.torrent` bytes.
    pub fn add_torrent(&mut self, data: &[u8], save_dir: &str) -> Result<InfoHash> {
        let torrent = Torrent::from_bytes(data)?;
        self.add_torrent_obj(torrent, save_dir)
    }

    /// Add a torrent from a parsed object.
    pub fn add_torrent_obj(&mut self, torrent: Torrent, save_dir: &str) -> Result<InfoHash> {
        let hash = torrent.info_hash;
        if self.sessions.contains_key(&hash) {
            return Err(Error::InvalidInput);
        }
        let mut cfg = self.cfg.session.clone();
        cfg.save_dir = String::from(save_dir);
        cfg.proxy = self.cfg.proxy.clone();
        cfg.listen_port = self.cfg.listen_port;
        let session = TorrentSession::from_torrent(torrent, cfg, self.host.now_ms())?;
        self.sessions.insert(hash, session);
        Ok(hash)
    }

    /// Add a torrent from a magnet URI (metadata will be fetched).
    pub fn add_magnet(&mut self, uri: &str, save_dir: &str) -> Result<InfoHash> {
        let magnet = Magnet::parse(uri)?;
        let hash = magnet.info_hash.ok_or(Error::Magnet)?;
        if self.sessions.contains_key(&hash) {
            return Err(Error::InvalidInput);
        }
        let mut cfg = self.cfg.session.clone();
        cfg.save_dir = String::from(save_dir);
        cfg.proxy = self.cfg.proxy.clone();
        cfg.listen_port = self.cfg.listen_port;
        let session = TorrentSession::from_magnet(&magnet, cfg, self.host.now_ms())?;
        self.sessions.insert(hash, session);
        Ok(hash)
    }

    /// Start a torrent.
    pub fn start(&mut self, hash: &InfoHash) -> Result<()> {
        let now = self.host.now_ms();
        self.start_udp_if_needed(now);
        let mut ctx = SessionCtx {
            host: &mut self.host,
            cache: &mut self.cache,
            peer_id: self.peer_id,
            port: self.cfg.listen_port,
            now,
            dht: self.dht.as_mut(),
            events: &mut self.events,
        };
        let s = self.sessions.get_mut(hash).ok_or(Error::NotFound)?;
        s.start(&mut ctx)?;
        if !self.cfg.proxy.is_some() && self.udp_open {
            let b = s.info_hash.as_bytes();
            if b.len() == 20 {
                let mut ih20 = [0u8; 20];
                ih20.copy_from_slice(b);
                let msg = crate::lsd::build_announce(
                    &ih20,
                    self.cfg.listen_port,
                    Some(&self.lsd.cookie),
                    crate::lsd::LSD_GROUP_V4,
                );
                let _ = self
                    .host
                    .udp_multicast_send(&crate::lsd::LSD_GROUP_V4, &msg);
            }
        }
        if self
            .dht
            .as_ref()
            .map(|d| d.table().real_size() == 0)
            .unwrap_or(false)
        {
            self.bootstrap_dht(now);
        }
        Ok(())
    }

    /// Collect resolved DHT bootstrap seeds without ever blocking the engine
    /// on DNS. Async-capable hosts resolve on their own thread (results are
    /// drained here every tick); hosts without the async seam fall back to
    /// the blocking resolver, bounded to the bootstrapping path only.
    fn collect_dht_seeds(&mut self, now: u64) {
        let resolved = self.host.take_resolved_hosts();
        for (host, port, addr) in resolved {
            if !self.dht_seeds.contains(&addr) {
                self.dht_seeds.push(addr);
            }
            self.dht_seed_pending
                .retain(|(h, p)| *h != host || *p != port);
        }
        if !self.dht_seeds.is_empty() {
            self.dht_no_seed_emitted = false;
            return;
        }
        if now.saturating_sub(self.dht_resolve_kicked_at) >= BOOTSTRAP_RETRY_MS {
            self.dht_resolve_kicked_at = now;
            let mut any_async = false;
            for (host, port) in crate::consts::DHT_BOOTSTRAP {
                if self
                    .dht_seed_pending
                    .iter()
                    .any(|(h, p)| h == *host && *p == *port)
                {
                    continue;
                }
                if self.host.resolve_host_async(host, *port) {
                    any_async = true;
                    self.dht_seed_pending.push((String::from(*host), *port));
                }
            }
            if !any_async {
                for (host, port) in crate::consts::DHT_BOOTSTRAP {
                    if let Some(a) = self.host.resolve_host(host, *port) {
                        if !self.dht_seeds.contains(&a) {
                            self.dht_seeds.push(a);
                        }
                    }
                }
            }
        }
    }

    /// Ensure the DHT has seeds to query, then ping them. Never blocks the
    /// engine loop: DNS runs on the host's async resolver (or once, cached).
    fn bootstrap_dht(&mut self, now: u64) {
        self.last_bootstrap_at = now;
        self.collect_dht_seeds(now);
        let Some(dht) = self.dht.as_mut() else {
            return;
        };
        if !self.dht_seeds.is_empty() {
            dht.bootstrap(&self.dht_seeds, now);
            self.dht_no_seed_emitted = false;
        } else if !self.dht_no_seed_emitted
            && self.dht_resolve_kicked_at != 0
            && now.saturating_sub(self.dht_resolve_kicked_at) > 10_000
        {
            self.dht_no_seed_emitted = true;
            self.host.log(
                LogLevel::Warn,
                "DHT bootstrap: no router hostname resolvable",
            );
            self.events.push(EngineEvent::Error {
                code: 1,
                detail: "dht_no_seeds",
            });
        }
    }

    /// Pause a torrent.
    pub fn pause(&mut self, hash: &InfoHash) {
        let now = self.host.now_ms();
        let mut ctx = SessionCtx {
            host: &mut self.host,
            cache: &mut self.cache,
            peer_id: self.peer_id,
            port: self.cfg.listen_port,
            now,
            dht: self.dht.as_mut(),
            events: &mut self.events,
        };
        if let Some(s) = self.sessions.get_mut(hash) {
            s.pause(&mut ctx);
        }
    }

    /// Resume a paused torrent.
    pub fn resume(&mut self, hash: &InfoHash) {
        let now = self.host.now_ms();
        let mut ctx = SessionCtx {
            host: &mut self.host,
            cache: &mut self.cache,
            peer_id: self.peer_id,
            port: self.cfg.listen_port,
            now,
            dht: self.dht.as_mut(),
            events: &mut self.events,
        };
        if let Some(s) = self.sessions.get_mut(hash) {
            s.resume(&mut ctx);
        }
    }

    /// Stop and remove a torrent.
    pub fn remove_torrent(&mut self, hash: &InfoHash) -> Result<()> {
        let now = self.host.now_ms();
        let mut ctx = SessionCtx {
            host: &mut self.host,
            cache: &mut self.cache,
            peer_id: self.peer_id,
            port: self.cfg.listen_port,
            now,
            dht: self.dht.as_mut(),
            events: &mut self.events,
        };
        if let Some(mut s) = self.sessions.remove(hash) {
            s.stop(&mut ctx);
        } else {
            return Err(Error::NotFound);
        }
        let conns: Vec<ConnId> = self
            .conn_owner
            .iter()
            .filter(|(_, h)| *h == hash)
            .map(|(c, _)| *c)
            .collect();
        for c in conns {
            self.socks.remove(&c);
            self.socks_target.remove(&c);
            self.connect_deadline.remove(&c);
            self.host.tcp_close(c);
            self.conn_owner.remove(&c);
        }
        Ok(())
    }

    /// Progress of a torrent (0..=1).
    pub fn progress(&self, hash: &InfoHash) -> f64 {
        self.sessions.get(hash).map(|s| s.progress()).unwrap_or(0.0)
    }

    /// Bytes downloaded.
    pub fn downloaded(&self, hash: &InfoHash) -> u64 {
        self.sessions
            .get(hash)
            .map(|s| s.downloaded_bytes)
            .unwrap_or(0)
    }

    /// Bytes uploaded for a torrent.
    pub fn uploaded(&self, hash: &InfoHash) -> u64 {
        self.sessions
            .get(hash)
            .map(|s| s.uploaded_bytes)
            .unwrap_or(0)
    }

    /// Whether a torrent has completed.
    pub fn is_complete(&self, hash: &InfoHash) -> bool {
        self.sessions
            .get(hash)
            .map(|s| s.status == crate::session::SessionStatus::Seeding)
            .unwrap_or(false)
    }

    // ---------- task management ----------

    /// Manually add a tracker URL to a torrent. Returns whether it was added.
    pub fn add_tracker(&mut self, hash: &InfoHash, url: &str) -> Result<bool> {
        let s = self.sessions.get_mut(hash).ok_or(Error::NotFound)?;
        Ok(s.add_tracker(url))
    }

    /// Manually remove a tracker URL from a torrent.
    pub fn remove_tracker(&mut self, hash: &InfoHash, url: &str) -> Result<bool> {
        let s = self.sessions.get_mut(hash).ok_or(Error::NotFound)?;
        Ok(s.remove_tracker(url))
    }

    /// Current tracker URLs of a torrent.
    pub fn trackers(&self, hash: &InfoHash) -> Option<Vec<String>> {
        self.sessions.get(hash).map(|s| s.tracker_urls())
    }

    /// Set the priority of one file in a torrent (selective download).
    pub fn set_file_priority(
        &mut self,
        hash: &InfoHash,
        file: u32,
        prio: FilePriority,
    ) -> Result<()> {
        let s = self.sessions.get_mut(hash).ok_or(Error::NotFound)?;
        s.set_file_priority(file, prio)
    }

    /// Atomically replace the per-file priorities of a torrent and release
    /// any two-phase magnet hold.
    pub fn set_file_priorities(
        &mut self,
        hash: &InfoHash,
        priorities: &[FilePriority],
    ) -> Result<()> {
        let s = self.sessions.get_mut(hash).ok_or(Error::NotFound)?;
        s.set_file_priorities(priorities)
    }

    /// Two-phase magnet support: hold off data downloads until per-file
    /// priorities are committed.
    pub fn set_hold_data(&mut self, hash: &InfoHash, hold: bool) -> Result<()> {
        let s = self.sessions.get_mut(hash).ok_or(Error::NotFound)?;
        s.set_hold_data(hold);
        Ok(())
    }

    /// Whether a torrent session is currently holding off data downloads.
    pub fn holding_data(&self, hash: &InfoHash) -> Option<bool> {
        self.sessions.get(hash).map(|s| s.holding_data())
    }

    /// Priority of one file in a torrent.
    pub fn file_priority(&self, hash: &InfoHash, file: u32) -> Option<FilePriority> {
        self.sessions.get(hash).map(|s| s.file_priority(file))
    }

    /// Per-file priorities of a torrent.
    pub fn file_priorities(&self, hash: &InfoHash) -> Option<Vec<FilePriority>> {
        self.sessions
            .get(hash)
            .map(|s| s.file_priorities().to_vec())
    }

    /// Change the global upload/download limits (bytes/second; 0 = unlimited).
    pub fn set_global_limits(&mut self, down_bps: u64, up_bps: u64) {
        self.cfg.global_download_limit_bps = down_bps;
        self.cfg.global_upload_limit_bps = up_bps;
        let now = self.host.now_ms();
        self.global_down.set_rate(down_bps, now);
        self.global_up.set_rate(up_bps, now);
    }

    /// Change the per-task upload/download limits of one torrent.
    pub fn set_session_limits(
        &mut self,
        hash: &InfoHash,
        down_bps: u64,
        up_bps: u64,
    ) -> Result<()> {
        let now = self.host.now_ms();
        let s = self.sessions.get_mut(hash).ok_or(Error::NotFound)?;
        s.set_upload_limit(up_bps, now);
        s.set_download_limit(down_bps, now);
        Ok(())
    }

    /// Add several `.torrent` blobs at once; each item gets its own result
    /// (a failure in one item never aborts the batch).
    pub fn add_torrents_batch(&mut self, items: &[(&[u8], &str)]) -> Vec<Result<InfoHash>> {
        items
            .iter()
            .map(|(data, dir)| self.add_torrent(data, dir))
            .collect()
    }

    /// Add several magnet links at once; each item gets its own result.
    pub fn add_magnets_batch(&mut self, items: &[(&str, &str)]) -> Vec<Result<InfoHash>> {
        items
            .iter()
            .map(|(uri, dir)| self.add_magnet(uri, dir))
            .collect()
    }

    /// Restore persisted per-torrent state onto an already re-added session
    /// (verified/partial pieces, file priorities, per-task rate limits).
    /// The host re-adds torrents first (`add_torrent`), then calls this for
    /// each entry of a previously saved [`crate::state::SessionState`].
    pub fn restore_torrent(
        &mut self,
        hash: &InfoHash,
        st: &crate::state::TorrentState,
    ) -> Result<()> {
        let now = self.host.now_ms();
        let s = self.sessions.get_mut(hash).ok_or(Error::NotFound)?;
        s.apply_saved_state(
            &st.have,
            &st.partial,
            &st.file_priorities,
            st.upload_limit_bps,
            st.download_limit_bps,
            &st.reputation,
            now,
        )
    }

    /// Install previously-fetched metadata into a magnet session. This is
    /// the persistence path: the bridge stores the raw info dict when the
    /// metadata arrives and re-installs it on restart, so a magnet NEVER has
    /// to re-fetch metadata (qBittorrent parity). Idempotent — a session
    /// that already has metadata is left untouched.
    pub fn install_metadata(&mut self, hash: &InfoHash, info_raw: &[u8]) -> Result<()> {
        if info_raw.is_empty() {
            return Err(Error::InvalidInput);
        }
        let t = crate::metainfo::Torrent::from_info(info_raw)?;
        if t.info_hash != *hash {
            return Err(Error::HashMismatch);
        }
        let now = self.host.now_ms();
        let s = self.sessions.get_mut(hash).ok_or(Error::NotFound)?;
        if s.torrent.is_some() {
            return Ok(()); // already has metadata
        }
        let mut ctx = SessionCtx {
            host: &mut self.host,
            cache: &mut self.cache,
            peer_id: self.peer_id,
            port: self.cfg.listen_port,
            now,
            dht: self.dht.as_mut(),
            events: &mut self.events,
        };
        s.install_torrent(t, &mut ctx);
        Ok(())
    }

    /// Best-effort removal of the active NAT/firewall port mapping.
    pub fn stop_port_mapping(&mut self) {
        if let Some(pm) = self.portmap.as_mut() {
            let now = self.host.now_ms();
            pm.unmap(now);
        }
    }

    /// Drain engine events (call frequently).
    pub fn take_events(&mut self) -> Vec<EngineEvent> {
        core::mem::take(&mut self.events)
    }

    /// Feed a completed inbound TCP connection.
    pub fn on_inbound_connection(&mut self, conn: ConnId, addr: NetAddr) {
        if self.cfg.proxy.is_some() {
            self.host.tcp_close(conn);
            return;
        }
        // connection flood bounds (global + per-IP)
        let total = self.conn_owner.len() + self.connecting.len() + self.inbound.len();
        if total >= self.cfg.global_max_connections
            || self.ip_count(&addr) >= self.cfg.max_connections_per_ip
        {
            self.host.tcp_close(conn);
            return;
        }
        if self.inbound.len() >= Self::MAX_INBOUND {
            self.host.tcp_close(conn);
            return;
        }
        self.inbound.insert(
            conn,
            InboundPeer {
                addr,
                buf: Vec::new(),
            },
        );
    }

    /// 16-byte key for an address (IPv4 normalized into the leading 4 bytes).
    fn ip_key(addr: &NetAddr) -> [u8; 16] {
        match *addr {
            NetAddr::V4(ip, _) => {
                let mut k = [0u8; 16];
                k[..4].copy_from_slice(&ip);
                k
            }
            NetAddr::V6(ip, _) => ip,
        }
    }

    /// Count of open connections (session peers + pending inbound) sharing
    /// the IP of `addr`. Derived each call, so it can never drift.
    fn ip_count(&self, addr: &NetAddr) -> u32 {
        let key = Self::ip_key(addr);
        let mut n = 0u32;
        for s in self.sessions.values() {
            for p in s.peers.values() {
                if Self::ip_key(&p.addr) == key {
                    n += 1;
                }
            }
        }
        for ib in self.inbound.values() {
            if Self::ip_key(&ib.addr) == key {
                n += 1;
            }
        }
        n
    }

    fn ensure_udp(&mut self, now: u64) -> Result<()> {
        if self.cfg.proxy.is_some() {
            return Ok(());
        }
        if !self.udp_open {
            self.host.udp_open(self.cfg.listen_port)?;
            self.udp_open = true;
            // LSD (BEP-14) needs multicast membership so LAN announces
            // reach us; failure to join is best-effort (still announce out).
            let _ = self.host.udp_join_multicast(crate::lsd::LSD_GROUP_V4);
            let _ = self.host.udp_join_multicast(crate::lsd::LSD_GROUP_V6);
            if self.cfg.lsd_enabled {
                // BEP-14 datagrams arrive on the FIXED multicast port 6771,
                // but the shared UDP socket is bound to the BT listen port
                // and can NEVER receive them — LSD must listen on 6771 too.
                // Open a dedicated LSD socket and join the groups on it;
                // otherwise LAN discovery only half-works (we announce out
                // but never hear our neighbours). All best-effort.
                let _ = self.host.udp_open_lsd(crate::lsd::LSD_PORT);
                let _ = self.host.udp_join_multicast_lsd(crate::lsd::LSD_GROUP_V4);
                let _ = self.host.udp_join_multicast_lsd(crate::lsd::LSD_GROUP_V6);
            }
        }
        let _ = now;
        Ok(())
    }

    /// Whether the engine currently needs a UDP socket: DHT enabled, port
    /// mapping, any live UDP tracker across the sessions, or active torrents
    /// (LSD needs the socket to announce/receive on the LAN). In proxy mode
    /// the socket is never opened (outbound-only).
    fn wants_udp(&self) -> bool {
        if self.cfg.proxy.is_some() {
            return false;
        }
        if self.cfg.dht_enabled || self.cfg.port_mapping {
            return true;
        }
        if self.sessions.values().any(|s| s.is_active()) {
            return true;
        }
        self.sessions.values().any(|s| {
            s.trackers
                .iter()
                .any(|t| t.kind == TrackerKind::Udp && t.fails < 3)
        })
    }

    /// Open the UDP socket when it is actually needed. A failure here is
    /// **not fatal** to torrents: the engine degrades to HTTP-tracker-only
    /// operation (DHT and UDP trackers are disabled) and emits an
    /// [`EngineEvent::Error`] so the host knows exactly why, instead of
    /// surfacing a bare `-1`. Torrents with HTTP trackers keep working
    /// without any UDP socket.
    fn start_udp_if_needed(&mut self, now: u64) {
        if self.cfg.proxy.is_some() || self.udp_open || self.udp_failed {
            return;
        }
        if !self.wants_udp() {
            return;
        }
        if self.ensure_udp(now).is_err() {
            self.udp_failed = true;
            self.dht = None;
            self.cfg.dht_enabled = false;
            for s in self.sessions.values_mut() {
                for t in s.trackers.iter_mut() {
                    if t.kind == TrackerKind::Udp {
                        t.fails = t.fails.saturating_add(1).max(3);
                        if t.failure.is_none() {
                            t.failure = Some(String::from("udp unavailable"));
                        }
                    }
                }
            }
            self.host.log(
                LogLevel::Error,
                "udp_open failed: DHT and UDP trackers disabled; HTTP trackers still work",
            );
            self.events.push(EngineEvent::Error {
                code: 0,
                detail: "udp_open_failed",
            });
        }
    }

    // ---------- main tick ----------

    /// Advance the whole engine. Call on a fixed cadence.
    pub fn tick(&mut self) -> Result<()> {
        let now = self.host.now_ms();
        self.start_udp_if_needed(now);
        let stale: Vec<ConnId> = self
            .conn_owner
            .iter()
            .filter(|(c, h)| {
                self.sessions
                    .get(h)
                    .map(|s| !s.peers.contains_key(c))
                    .unwrap_or(true)
            })
            .map(|(c, _)| *c)
            .collect();
        for c in stale {
            self.socks.remove(&c);
            self.socks_target.remove(&c);
            self.connect_deadline.remove(&c);
            self.conn_owner.remove(&c);
            self.host.tcp_close(c);
        }
        if let Some(pm) = self.portmap.as_mut() {
            if pm.status().phase == PortMapPhase::Idle {
                pm.start(now);
            }
            pm.tick(&mut self.host, now);
            let phase = pm.status().phase;
            if phase != self.last_pm_phase {
                self.last_pm_phase = phase;
                let status = pm.status();
                self.events.push(EngineEvent::PortMapping {
                    phase: status.phase,
                    external_port: status.external_port,
                });
            }
        }
        let active = self
            .sessions
            .values()
            .filter(|s| s.is_active())
            .count()
            .max(1) as u64;
        let up_avail = self.global_up.available(now);
        let down_avail = self.global_down.available(now);
        let up_slice = up_avail / active;
        let down_slice = down_avail / active;
        for s in self.sessions.values_mut() {
            if s.is_active() {
                s.tick_up_allowance = up_slice;
                s.tick_down_remaining = down_slice;
            } else {
                s.tick_up_allowance = 0;
                s.tick_down_remaining = 0;
            }
        }
        self.drive_tcp(now);
        self.drive_udp(now);
        if self.udp_open {
            let now_us = now.saturating_mul(1000);
            self.utp.tick(&mut self.host, now_us);
            for (conn, addr) in self.utp.take_accepted() {
                self.inbound.insert(
                    conn,
                    InboundPeer {
                        addr,
                        buf: Vec::new(),
                    },
                );
            }
            for conn in self.utp.take_reaped() {
                let was_connecting = self.connecting.contains(&conn);
                self.cleanup_utp_conn(conn, now, was_connecting);
            }
        }
        let dht_refresh_ready = self
            .dht
            .as_ref()
            .map(|d| {
                let real = d.table().real_size();
                let interval = if real < 32 {
                    5_000
                } else if real < 128 {
                    15_000
                } else {
                    60_000
                };
                real > 0 && now.saturating_sub(self.last_dht_find_node) >= interval
            })
            .unwrap_or(false);
        let dht_refresh_targets = if dht_refresh_ready {
            let mut out = Vec::with_capacity(3);
            for _ in 0..3 {
                self.dht_refresh_serial = self.dht_refresh_serial.wrapping_add(1);
                out.push(crate::dht::NodeId(self.dht_refresh_target(now)));
            }
            out
        } else {
            Vec::new()
        };
        if let Some(dht) = self.dht.as_mut() {
            dht.tick(now);
            for (addr, payload) in dht.outgoing() {
                if let Err(e) = self.host.udp_send(&addr, &payload) {
                    self.host.log(
                        LogLevel::Debug,
                        &alloc::format!("dht udp_send to {} failed: {}", addr, e),
                    );
                }
            }
            if !dht_refresh_targets.is_empty() {
                self.last_dht_find_node = now;
                for target in dht_refresh_targets {
                    dht.find_node(target, now);
                }
            }
        }
        self.collect_dht_seeds(now);
        let needs_bootstrap = self
            .dht
            .as_ref()
            .map(|d| {
                d.table().real_size() < DHT_REBOOTSTRAP_THRESHOLD
                    && now.saturating_sub(self.last_bootstrap_at) >= BOOTSTRAP_RETRY_MS
            })
            .unwrap_or(false);
        if needs_bootstrap {
            self.bootstrap_dht(now);
        }
        self.pump_http_jobs(now);
        let hashes: Vec<InfoHash> = self.sessions.keys().copied().collect();
        for h in hashes {
            self.drive_connect_queue(h, now);
            let mut ctx = SessionCtx {
                host: &mut self.host,
                cache: &mut self.cache,
                peer_id: self.peer_id,
                port: self.cfg.listen_port,
                now,
                dht: self.dht.as_mut(),
                events: &mut self.events,
            };
            if let Some(s) = self.sessions.get_mut(&h) {
                s.tick(&mut ctx);
            }
        }
        let pending: Vec<(InfoHash, u32, Vec<u8>)> = self
            .sessions
            .iter_mut()
            .flat_map(|(h, s)| {
                let h = *h;
                s.take_pending_verify()
                    .into_iter()
                    .map(move |(p, b)| (h, p, b))
            })
            .collect();
        if !pending.is_empty() {
            let mut ctx = SessionCtx {
                host: &mut self.host,
                cache: &mut self.cache,
                peer_id: self.peer_id,
                port: self.cfg.listen_port,
                now,
                dht: self.dht.as_mut(),
                events: &mut self.events,
            };
            for (h, piece, buf) in pending {
                if let Some(s) = self.sessions.get_mut(&h) {
                    if let Some(pool) = self.verify_pool.as_ref() {
                        let (job, buf) = s.build_verify_job(piece, buf);
                        if let Some(job) = job {
                            pool.submit(job);
                            continue;
                        }
                        // job could not be built → fall through to inline
                        let (ok, data) = s.verify_inline(piece, buf);
                        let _ = s.on_verified(piece, ok, data, &mut ctx);
                        continue;
                    }
                    let (ok, data) = s.verify_inline(piece, buf);
                    let _ = s.on_verified(piece, ok, data, &mut ctx);
                }
            }
        }
        if let Some(pool) = self.verify_pool.as_ref() {
            while let Some(res) = pool.poll() {
                let mut ctx = SessionCtx {
                    host: &mut self.host,
                    cache: &mut self.cache,
                    peer_id: self.peer_id,
                    port: self.cfg.listen_port,
                    now,
                    dht: self.dht.as_mut(),
                    events: &mut self.events,
                };
                if let Some(s) = self.sessions.get_mut(&res.torrent) {
                    let _ = s.on_verified(res.piece, res.ok, res.data, &mut ctx);
                }
            }
        }
        if now.saturating_sub(self.last_cache_flush) >= 1_000 {
            let _ = self
                .cache
                .flush_bounded(&mut self.host, CACHE_FLUSH_BUDGET_BYTES);
            self.last_cache_flush = now;
        }
        // LSD (BEP-14): announce one active torrent to the LAN per minute.
        self.announce_lsd(now);
        if let Some(dht) = self.dht.as_ref() {
            self.events
                .push(EngineEvent::DhtNodeCount(dht.table().size()));
        }
        Ok(())
    }

    fn drive_connect_queue(&mut self, hash: InfoHash, now: u64) {
        let queued: Vec<(NetAddr, DiscoverySource)> = self
            .sessions
            .get_mut(&hash)
            .map(|s| s.take_connect_queue())
            .unwrap_or_default();
        let proxy = self.cfg.proxy.clone();
        for (addr, source) in queued {
            let total = self.conn_owner.len() + self.connecting.len() + self.inbound.len();
            if total >= self.cfg.global_max_connections {
                continue;
            }
            if self.ip_count(&addr) >= self.cfg.max_connections_per_ip {
                continue;
            }
            if !self.cfg.proxy.is_some() && self.udp_open {
                let conn = self.utp.connect(addr, now.saturating_mul(1000));
                self.conn_owner.insert(conn, hash);
                self.connecting.push(conn);
                self.connect_deadline
                    .insert(conn, now.saturating_add(self.cfg.connect_timeout_ms));
                let mut ctx = SessionCtx {
                    host: &mut self.host,
                    cache: &mut self.cache,
                    peer_id: self.peer_id,
                    port: self.cfg.listen_port,
                    now,
                    dht: self.dht.as_mut(),
                    events: &mut self.events,
                };
                if let Some(s) = self.sessions.get_mut(&hash) {
                    s.attach_peer(conn, addr, true, source, &mut ctx);
                }
                continue;
            }
            let dial = match &proxy {
                Some(p) => p.socks5,
                None => addr,
            };
            if let Ok(conn) = self.host.tcp_connect(&dial) {
                if proxy.is_some() {
                    self.socks_target.insert(conn, SocksTarget::Ip(addr));
                }
                self.conn_owner.insert(conn, hash);
                self.connecting.push(conn);
                self.connect_deadline
                    .insert(conn, now.saturating_add(self.cfg.connect_timeout_ms));
                let mut ctx = SessionCtx {
                    host: &mut self.host,
                    cache: &mut self.cache,
                    peer_id: self.peer_id,
                    port: self.cfg.listen_port,
                    now,
                    dht: self.dht.as_mut(),
                    events: &mut self.events,
                };
                if let Some(s) = self.sessions.get_mut(&hash) {
                    s.attach_peer(conn, addr, true, source, &mut ctx);
                }
            }
        }
    }

    /// Route completed async HTTP jobs (tracker announces, web-seed range
    /// fetches) to their owning sessions. The host's worker performs the
    /// requests on its own thread — the engine thread never blocks on HTTP.
    fn pump_http_jobs(&mut self, now: u64) {
        let jobs = self.host.http_take_done();
        if jobs.is_empty() {
            return;
        }
        let hashes: Vec<InfoHash> = self.sessions.keys().copied().collect();
        for h in hashes {
            let owns: Vec<u64> = jobs
                .iter()
                .filter(|(id, _)| {
                    self.sessions
                        .get(&h)
                        .map(|s| s.owns_http_job(*id))
                        .unwrap_or(false)
                })
                .map(|(id, _)| *id)
                .collect();
            if owns.is_empty() {
                continue;
            }
            let mut ctx = SessionCtx {
                host: &mut self.host,
                cache: &mut self.cache,
                peer_id: self.peer_id,
                port: self.cfg.listen_port,
                now,
                dht: self.dht.as_mut(),
                events: &mut self.events,
            };
            if let Some(s) = self.sessions.get_mut(&h) {
                for id in &owns {
                    if let Some((_, res)) = jobs.iter().find(|(j, _)| j == id) {
                        s.on_http_job_done(*id, res.clone(), &mut ctx);
                        s.on_range_job_done(*id, res.clone(), &mut ctx);
                    }
                }
            }
        }
    }

    /// Drive TCP reads/writes/connects for all connections.
    fn drive_tcp(&mut self, now: u64) {
        let mut still_connecting = Vec::new();
        for conn in core::mem::take(&mut self.connecting) {
            let hash = match self.conn_owner.get(&conn) {
                Some(h) => *h,
                None => continue,
            };
            if crate::utp::is_utp_handle(conn) {
                if self.utp.is_connected(conn) {
                    self.connect_deadline.remove(&conn);
                    let mut ctx = SessionCtx {
                        host: &mut self.host,
                        cache: &mut self.cache,
                        peer_id: self.peer_id,
                        port: self.cfg.listen_port,
                        now,
                        dht: self.dht.as_mut(),
                        events: &mut self.events,
                    };
                    if let Some(s) = self.sessions.get_mut(&hash) {
                        s.on_connect_done(conn, &mut ctx);
                    }
                } else {
                    let deadline = self
                        .connect_deadline
                        .get(&conn)
                        .copied()
                        .unwrap_or(u64::MAX);
                    if now > deadline {
                        self.connect_deadline.remove(&conn);
                        self.cleanup_utp_conn(conn, now, true); // TCP fallback
                    } else {
                        still_connecting.push(conn);
                    }
                }
                continue;
            }
            match self.host.tcp_connect_done(conn) {
                Err(Error::WouldBlock) => {
                    let deadline = self
                        .connect_deadline
                        .get(&conn)
                        .copied()
                        .unwrap_or(u64::MAX);
                    if now > deadline {
                        self.connect_deadline.remove(&conn);
                        self.socks.remove(&conn);
                        self.socks_target.remove(&conn);
                        let mut ctx = SessionCtx {
                            host: &mut self.host,
                            cache: &mut self.cache,
                            peer_id: self.peer_id,
                            port: self.cfg.listen_port,
                            now,
                            dht: self.dht.as_mut(),
                            events: &mut self.events,
                        };
                        if let Some(s) = self.sessions.get_mut(&hash) {
                            s.drop_peer(
                                conn,
                                crate::monitoring::FailureCategory::Unreachable,
                                &mut ctx,
                            );
                        }
                    } else {
                        still_connecting.push(conn);
                    }
                }
                Err(_) => {
                    self.connect_deadline.remove(&conn);
                    self.socks.remove(&conn);
                    self.socks_target.remove(&conn);
                    let mut ctx = SessionCtx {
                        host: &mut self.host,
                        cache: &mut self.cache,
                        peer_id: self.peer_id,
                        port: self.cfg.listen_port,
                        now,
                        dht: self.dht.as_mut(),
                        events: &mut self.events,
                    };
                    if let Some(s) = self.sessions.get_mut(&hash) {
                        s.drop_peer(
                            conn,
                            crate::monitoring::FailureCategory::Unreachable,
                            &mut ctx,
                        );
                    }
                }
                Ok(()) => {
                    self.connect_deadline.remove(&conn);
                    if let Some(target) = self.socks_target.get(&conn).cloned() {
                        let proxy = match &self.cfg.proxy {
                            Some(p) => p.clone(),
                            None => {
                                self.socks_target.remove(&conn);
                                continue;
                            }
                        };
                        self.socks
                            .insert(conn, Socks5Client::new(&target, &proxy, now));
                        continue; // conn now lives in `socks`; pump_socks drives it
                    }
                    let mut ctx = SessionCtx {
                        host: &mut self.host,
                        cache: &mut self.cache,
                        peer_id: self.peer_id,
                        port: self.cfg.listen_port,
                        now,
                        dht: self.dht.as_mut(),
                        events: &mut self.events,
                    };
                    if let Some(s) = self.sessions.get_mut(&hash) {
                        s.on_connect_done(conn, &mut ctx);
                    }
                }
            }
        }
        self.connecting = still_connecting;
        self.pump_socks(now);

        let conns: Vec<ConnId> = self.conn_owner.keys().copied().collect();
        for conn in conns {
            let hash = match self.conn_owner.get(&conn) {
                Some(h) => *h,
                None => continue,
            };
            if self.socks.contains_key(&conn) {
                continue;
            }
            self.pump_connection(conn, hash, now);
        }

        // inbound connections awaiting handshake
        let inbound_conns: Vec<ConnId> = self.inbound.keys().copied().collect();
        for conn in inbound_conns {
            self.pump_inbound(conn, now);
        }
    }

    /// Advance SOCKS5 handshakes on outbound connections. A completed
    /// handshake hands the (now transparent) connection to its session; a
    /// failure or deadline drops it.
    fn pump_socks(&mut self, now: u64) {
        enum Drive {
            InProgress,
            Done,
            Failed,
        }
        let conns: Vec<ConnId> = self.socks.keys().copied().collect();
        for conn in conns {
            let hash = match self.conn_owner.get(&conn) {
                Some(h) => *h,
                None => {
                    self.socks.remove(&conn);
                    self.socks_target.remove(&conn);
                    continue;
                }
            };
            let drive = {
                let client = match self.socks.get_mut(&conn) {
                    Some(c) => c,
                    None => continue,
                };
                let ctx = SessionCtx {
                    host: &mut self.host,
                    cache: &mut self.cache,
                    peer_id: self.peer_id,
                    port: self.cfg.listen_port,
                    now,
                    dht: self.dht.as_mut(),
                    events: &mut self.events,
                };
                match client.pump(ctx.host, conn, now) {
                    Ok(SocksStatus::Done) => Drive::Done,
                    Ok(SocksStatus::InProgress) => {
                        if client.timed_out(now) {
                            Drive::Failed
                        } else {
                            Drive::InProgress
                        }
                    }
                    Err(_) => Drive::Failed,
                }
            };
            match drive {
                Drive::InProgress => {}
                Drive::Done => {
                    self.socks.remove(&conn);
                    self.socks_target.remove(&conn);
                    self.connect_deadline.remove(&conn);
                    let mut ctx = SessionCtx {
                        host: &mut self.host,
                        cache: &mut self.cache,
                        peer_id: self.peer_id,
                        port: self.cfg.listen_port,
                        now,
                        dht: self.dht.as_mut(),
                        events: &mut self.events,
                    };
                    if let Some(s) = self.sessions.get_mut(&hash) {
                        s.on_connect_done(conn, &mut ctx);
                    }
                }
                Drive::Failed => {
                    self.socks.remove(&conn);
                    self.socks_target.remove(&conn);
                    self.connect_deadline.remove(&conn);
                    let mut ctx = SessionCtx {
                        host: &mut self.host,
                        cache: &mut self.cache,
                        peer_id: self.peer_id,
                        port: self.cfg.listen_port,
                        now,
                        dht: self.dht.as_mut(),
                        events: &mut self.events,
                    };
                    if let Some(s) = self.sessions.get_mut(&hash) {
                        s.drop_peer(
                            conn,
                            crate::monitoring::FailureCategory::Unreachable,
                            &mut ctx,
                        );
                    }
                }
            }
        }
    }

    /// Read available data for one session-owned connection, dispatch, and
    /// flush its out buffer.
    fn pump_connection(&mut self, conn: ConnId, hash: InfoHash, now: u64) {
        let mut recv_buf = [0u8; 16 * 1024];
        loop {
            match self.stream_recv(conn, &mut recv_buf) {
                Ok(0) => {
                    let mut ctx = SessionCtx {
                        host: &mut self.host,
                        cache: &mut self.cache,
                        peer_id: self.peer_id,
                        port: self.cfg.listen_port,
                        now,
                        dht: self.dht.as_mut(),
                        events: &mut self.events,
                    };
                    if let Some(s) = self.sessions.get_mut(&hash) {
                        s.drop_peer(conn, crate::monitoring::FailureCategory::Timeout, &mut ctx);
                    }
                    return;
                }
                Ok(n) => {
                    let mut ctx = SessionCtx {
                        host: &mut self.host,
                        cache: &mut self.cache,
                        peer_id: self.peer_id,
                        port: self.cfg.listen_port,
                        now,
                        dht: self.dht.as_mut(),
                        events: &mut self.events,
                    };
                    if let Some(s) = self.sessions.get_mut(&hash) {
                        s.on_data(conn, &recv_buf[..n], &mut ctx);
                    }
                }
                Err(Error::WouldBlock) => break,
                Err(Error::NotFound) => {
                    break;
                }
                Err(_) => {
                    let mut ctx = SessionCtx {
                        host: &mut self.host,
                        cache: &mut self.cache,
                        peer_id: self.peer_id,
                        port: self.cfg.listen_port,
                        now,
                        dht: self.dht.as_mut(),
                        events: &mut self.events,
                    };
                    if let Some(s) = self.sessions.get_mut(&hash) {
                        s.drop_peer(conn, crate::monitoring::FailureCategory::Timeout, &mut ctx);
                    }
                    return;
                }
            }
        }
        let out_len = {
            let s = match self.sessions.get(&hash) {
                Some(s) => s,
                None => return,
            };
            s.peers.get(&conn).map(|p| p.out.len()).unwrap_or(0)
        };
        if out_len > 0 {
            loop {
                let allowance = {
                    let s = match self.sessions.get_mut(&hash) {
                        Some(s) => s,
                        None => break,
                    };
                    let own = s.upload_limit.available(now);
                    core::cmp::min(s.tick_up_allowance, own)
                };
                if allowance == 0 {
                    break;
                }
                let chunk = {
                    let s = match self.sessions.get_mut(&hash) {
                        Some(s) => s,
                        None => break,
                    };
                    let p = match s.peers.get_mut(&conn) {
                        Some(p) => p,
                        None => break,
                    };
                    if p.out.is_empty() {
                        break;
                    }
                    let take = core::cmp::min(p.out.len(), 16 * 1024);
                    let (head, _) = p.out.split_at(take);
                    let chunk = head.to_vec();
                    p.out.drain(..take);
                    chunk
                };
                let want = core::cmp::min(chunk.len(), allowance as usize);
                match self.stream_send(conn, &chunk[..want]) {
                    Ok(n) => {
                        if let Some(s) = self.sessions.get_mut(&hash) {
                            s.tick_up_allowance = s.tick_up_allowance.saturating_sub(n as u64);
                            s.upload_limit.consume(n as u64, now);
                        }
                        self.global_up.consume(n as u64, now);
                        if n < chunk.len() {
                            let rest = chunk[n..].to_vec();
                            if let Some(s) = self.sessions.get_mut(&hash) {
                                if let Some(p) = s.peers.get_mut(&conn) {
                                    let mut r = rest;
                                    r.append(&mut p.out);
                                    p.out = r;
                                }
                            }
                            break;
                        }
                    }
                    Err(Error::WouldBlock) => {
                        let rest = chunk[..want].to_vec();
                        if let Some(s) = self.sessions.get_mut(&hash) {
                            if let Some(p) = s.peers.get_mut(&conn) {
                                let mut r = rest;
                                r.append(&mut p.out);
                                p.out = r;
                            }
                        }
                        break;
                    }
                    Err(Error::NotFound) => {
                        if let Some(s) = self.sessions.get_mut(&hash) {
                            if let Some(p) = s.peers.get_mut(&conn) {
                                let mut r = chunk[..want].to_vec();
                                r.append(&mut p.out);
                                p.out = r;
                            }
                        }
                        break;
                    }
                    Err(_) => {
                        let mut ctx = SessionCtx {
                            host: &mut self.host,
                            cache: &mut self.cache,
                            peer_id: self.peer_id,
                            port: self.cfg.listen_port,
                            now,
                            dht: self.dht.as_mut(),
                            events: &mut self.events,
                        };
                        if let Some(s) = self.sessions.get_mut(&hash) {
                            s.drop_peer(
                                conn,
                                crate::monitoring::FailureCategory::Timeout,
                                &mut ctx,
                            );
                        }
                        break;
                    }
                }
            }
        }
    }

    // -------- transport routing (TCP vs uTP) --------

    /// Non-blocking read from either transport (TCP host or uTP manager).
    fn stream_recv(&mut self, conn: ConnId, buf: &mut [u8]) -> Result<usize> {
        if crate::utp::is_utp_handle(conn) {
            if !self.utp.is_live(conn) {
                return Ok(0); // reaped/closed → EOF
            }
            self.utp.recv(conn, buf)
        } else {
            self.host.tcp_recv(conn, buf)
        }
    }

    /// Non-blocking write to either transport.
    fn stream_send(&mut self, conn: ConnId, data: &[u8]) -> Result<usize> {
        if crate::utp::is_utp_handle(conn) {
            if !self.utp.is_live(conn) {
                return Err(Error::NotFound);
            }
            self.utp.send(conn, data)
        } else {
            self.host.tcp_send(conn, data)
        }
    }

    /// Close either transport.
    fn stream_close(&mut self, conn: ConnId) {
        if crate::utp::is_utp_handle(conn) {
            self.utp.close(conn);
        } else {
            self.host.tcp_close(conn);
        }
    }

    /// Tear down a uTP connection (timeout / reap). With `tcp_fallback`, a
    /// peer whose uTP handshake never completed is retried over TCP.
    fn cleanup_utp_conn(&mut self, conn: ConnId, now: u64, tcp_fallback: bool) {
        self.connect_deadline.remove(&conn);
        self.connecting.retain(|&c| c != conn);
        self.inbound.remove(&conn);
        let hash = self.conn_owner.remove(&conn);
        if let Some(hash) = hash {
            let peer_info = self
                .sessions
                .get(&hash)
                .and_then(|s| s.peers.get(&conn))
                .map(|p| (p.addr, p.source));
            let fallback_conn = if tcp_fallback && !self.cfg.proxy.is_some() {
                peer_info.and_then(|(addr, _)| self.host.tcp_connect(&addr).ok())
            } else {
                None
            };
            let mut ctx = SessionCtx {
                host: &mut self.host,
                cache: &mut self.cache,
                peer_id: self.peer_id,
                port: self.cfg.listen_port,
                now,
                dht: self.dht.as_mut(),
                events: &mut self.events,
            };
            if let Some(s) = self.sessions.get_mut(&hash) {
                s.drop_peer(conn, crate::monitoring::FailureCategory::Timeout, &mut ctx);
                if let Some(tcp_conn) = fallback_conn {
                    self.conn_owner.insert(tcp_conn, hash);
                    self.connecting.push(tcp_conn);
                    self.connect_deadline
                        .insert(tcp_conn, now.saturating_add(self.cfg.connect_timeout_ms));
                    if let Some((addr, source)) = peer_info {
                        s.attach_peer(tcp_conn, addr, true, source, &mut ctx);
                    }
                }
            }
        }
    }

    /// Handle an inbound connection until its handshake reveals the hash.
    fn pump_inbound(&mut self, conn: ConnId, now: u64) {
        let mut recv_buf = [0u8; 16 * 1024];
        loop {
            match self.stream_recv(conn, &mut recv_buf) {
                Ok(0) => break,
                Ok(n) => {
                    let overflow = self
                        .inbound
                        .get(&conn)
                        .is_some_and(|p| p.buf.len() + n > Self::MAX_INBOUND_BUF);
                    if overflow {
                        self.inbound.remove(&conn);
                        self.stream_close(conn);
                        return;
                    }
                    if let Some(p) = self.inbound.get_mut(&conn) {
                        p.buf.extend_from_slice(&recv_buf[..n]);
                    }
                }
                Err(Error::WouldBlock) => break,
                Err(_) => {
                    self.inbound.remove(&conn);
                    self.stream_close(conn);
                    return;
                }
            }
        }
        let (infohash, their) = {
            let p = match self.inbound.get(&conn) {
                Some(p) => p,
                None => return,
            };
            if p.buf.len() < crate::wire::HANDSHAKE_LEN {
                return;
            }
            match Handshake::parse(&p.buf[..crate::wire::HANDSHAKE_LEN]) {
                Ok(h) => {
                    let mut ih = [0u8; 32];
                    ih[..20].copy_from_slice(&h.info_hash);
                    let len = if h.has_v2() { 32 } else { 20 };
                    let _ = len;
                    (InfoHash::v1(h.info_hash), h)
                }
                Err(_) => {
                    self.inbound.remove(&conn);
                    self.stream_close(conn);
                    return;
                }
            }
        };
        let session_hash = self
            .sessions
            .keys()
            .copied()
            .find(|h| h.as_bytes() == infohash.as_bytes())
            .or_else(|| {
                self.sessions
                    .keys()
                    .copied()
                    .find(|h| h.as_bytes()[..20] == infohash.as_bytes()[..20])
            });
        let session_hash = match session_hash {
            Some(h) => h,
            None => {
                // unknown torrent: drop
                self.inbound.remove(&conn);
                self.stream_close(conn);
                return;
            }
        };
        let (addr, leftover) = {
            let p = self.inbound.remove(&conn).unwrap();
            (p.addr, p.buf[crate::wire::HANDSHAKE_LEN..].to_vec())
        };
        self.conn_owner.insert(conn, session_hash);
        let mut ctx = SessionCtx {
            host: &mut self.host,
            cache: &mut self.cache,
            peer_id: self.peer_id,
            port: self.cfg.listen_port,
            now,
            dht: self.dht.as_mut(),
            events: &mut self.events,
        };
        if let Some(s) = self.sessions.get_mut(&session_hash) {
            s.attach_peer(conn, addr, false, DiscoverySource::Manual, &mut ctx);
            if !leftover.is_empty() {
                s.on_data(conn, &leftover, &mut ctx);
            }
        }
        let _ = their;
    }

    /// Receive UDP datagrams and route them.
    fn drive_udp(&mut self, now: u64) {
        if !self.udp_open {
            return;
        }
        let mut buf = [0u8; 64 * 1024];
        let mut budget = 256u32;
        loop {
            if budget == 0 {
                break;
            }
            budget -= 1;
            match self.host.udp_recv(&mut buf) {
                Ok((addr, n)) => {
                    let payload = &buf[..n];
                    if let Some(pm) = self.portmap.as_mut() {
                        if pm.handle_datagram(&addr, payload, now) {
                            continue;
                        }
                    }
                    // LSD (BEP-14) announces start with "BT-SEARCH".
                    if payload.starts_with(b"BT-SEARCH") {
                        self.handle_lsd_datagram(addr, payload, now);
                        continue;
                    }
                    if crate::utp::is_utp_datagram(payload) {
                        self.utp.handle_datagram(
                            &mut self.host,
                            addr,
                            payload,
                            now.saturating_mul(1000),
                        );
                        continue;
                    }
                    if payload.first() == Some(&b'd') {
                        if let Some(dht) = self.dht.as_mut() {
                            if let Ok(DatagramOutcome::Reply(reply)) =
                                dht.handle_datagram(addr, payload, now)
                            {
                                if let Err(e) = self.host.udp_send(&addr, &reply) {
                                    self.host.log(
                                        LogLevel::Debug,
                                        &alloc::format!("dht reply to {} failed: {}", addr, e),
                                    );
                                }
                            }
                        }
                    } else {
                        if n >= 8 {
                            let _tid = u32::from_be_bytes([
                                payload[4], payload[5], payload[6], payload[7],
                            ]);
                            for s in self.sessions.values_mut() {
                                let mut ctx = SessionCtx {
                                    host: &mut self.host,
                                    cache: &mut self.cache,
                                    peer_id: self.peer_id,
                                    port: self.cfg.listen_port,
                                    now,
                                    dht: self.dht.as_mut(),
                                    events: &mut self.events,
                                };
                                s.on_udp_tracker_datagram(addr, payload, &mut ctx);
                            }
                        }
                    }
                }
                Err(Error::WouldBlock) => break,
                Err(_) => break,
            }
        }

        if self.cfg.lsd_enabled {
            let mut lsd_buf = [0u8; 64 * 1024];
            let mut lsd_budget = 256u32;
            let mut drained = 0u32;
            loop {
                if lsd_budget == 0 {
                    break;
                }
                lsd_budget -= 1;
                match self.host.udp_recv_lsd(&mut lsd_buf) {
                    Ok((addr, n)) => {
                        drained += 1;
                        let payload = &lsd_buf[..n];
                        if payload.starts_with(b"BT-SEARCH") {
                            self.handle_lsd_datagram(addr, payload, now);
                        }
                        // Only LSD traffic is expected here; ignore
                        // everything else defensively.
                    }
                    Err(Error::WouldBlock) => break,
                    Err(_) => break,
                }
            }

            if drained >= 256 {
                self.host.log(
                    LogLevel::Warn,
                    "LSD multicast group flooded past the per-tick budget (256 datagrams); \
                     additional announces deferred to the next tick",
                );
            }
        }
    }

    /// Deterministic pseudo-random 20-byte target for spontaneous DHT bucket
    /// refresh (derived from the refresh serial + wall clock, so lookups
    /// walk different parts of the keyspace over time without needing an
    /// engine-owned RNG).
    fn dht_refresh_target(&self, now: u64) -> [u8; 20] {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&now.to_be_bytes());
        buf[8..].copy_from_slice(&self.dht_refresh_serial.to_be_bytes());
        let h = crate::crypto::sha256::Sha256::digest(&buf);
        let mut out = [0u8; 20];
        out.copy_from_slice(&h[..20]);
        out
    }

    /// A list of infohashes of currently active sessions, for LSD announces.
    /// Only 20-byte (v1) hashes are announced — LSD cannot carry v2 32-byte
    /// hashes.
    fn lsd_active_hashes(&self) -> Vec<[u8; 20]> {
        let mut out = Vec::new();
        for s in self.sessions.values() {
            if !s.is_active() {
                continue;
            }
            let b = s.info_hash.as_bytes();
            if b.len() == 20 {
                let mut ih = [0u8; 20];
                ih.copy_from_slice(b);
                out.push(ih);
            }
        }
        out
    }

    /// Announce one active torrent to the LAN (BEP-14), rate-limited by the
    /// scheduler to one announce per minute, round-robin across torrents.
    fn announce_lsd(&mut self, now: u64) {
        if !self.cfg.lsd_enabled || self.cfg.proxy.is_some() || !self.udp_open {
            return; // disabled, or outbound-only mode must not leak presence
        }
        if !self.lsd.due(now) {
            return;
        }
        let active = self.lsd_active_hashes();
        let Some(ih) = self.lsd.next_announce(&active, now) else {
            return;
        };
        let port = self.cfg.listen_port;
        let cookie = self.lsd.cookie;
        let msg4 = crate::lsd::build_announce(ih, port, Some(&cookie), crate::lsd::LSD_GROUP_V4);
        let _ = self
            .host
            .udp_multicast_send(&crate::lsd::LSD_GROUP_V4, &msg4);
        let msg6 = crate::lsd::build_announce(ih, port, Some(&cookie), crate::lsd::LSD_GROUP_V6);
        let _ = self
            .host
            .udp_multicast_send(&crate::lsd::LSD_GROUP_V6, &msg6);
    }

    /// Handle one LSD datagram: either a neighbour announcing a torrent we
    /// have (reply with our presence + add them as a peer) or their reply
    /// to our announce (add them as a peer). Our own multicast echoes are
    /// dropped via the cookie.
    ///
    /// Mechanism 4 (anti-amplification): we unicast a reply to a given
    /// source at most once per [`crate::lsd::LSD_REPLY_GAP_MS`]. LSD
    /// multicast groups are shared and unauthenticated — without this gate,
    /// a hostile neighbour could spoof a victim's source address on a burst
    /// of `BT-SEARCH` datagrams and make us reflect traffic at them.
    fn handle_lsd_datagram(&mut self, addr: NetAddr, payload: &[u8], now: u64) {
        let Some(ann) = crate::lsd::parse(payload) else {
            return;
        };
        if ann.cookie == Some(self.lsd.cookie) {
            return; // our own announce looped back
        }
        if ann.port == 0 {
            return;
        }

        if now.saturating_sub(self.lsd_last_reply.get(&addr).copied().unwrap_or(0))
            < crate::lsd::LSD_REPLY_GAP_MS
        {
            return;
        }
        self.lsd_last_reply.insert(addr, now);
        if self.lsd_last_reply.len() > 1024 {
            self.lsd_last_reply
                .retain(|_, t| now.saturating_sub(*t) < crate::lsd::LSD_REPLY_GAP_MS);
        }
        let group = match addr {
            NetAddr::V4(..) => crate::lsd::LSD_GROUP_V4,
            NetAddr::V6(..) => crate::lsd::LSD_GROUP_V6,
        };
        for ih in ann.infohashes {
            let Some(s) = self.sessions.get_mut(&crate::metainfo::InfoHash::v1(ih)) else {
                continue; // we don't have this torrent
            };
            let peer_addr = match addr {
                NetAddr::V4(ip, _) => NetAddr::V4(ip, ann.port),
                NetAddr::V6(ip, _) => NetAddr::V6(ip, ann.port),
            };
            let resp = crate::lsd::build_announce(
                &ih,
                self.cfg.listen_port,
                Some(&self.lsd.cookie),
                group,
            );
            let _ = self.host.udp_send(&addr, &resp);
            // And add them to the swarm for this torrent.
            s.enqueue_peer(peer_addr, crate::monitoring::DiscoverySource::Lsd, now);
            s.monitor
                .record_discovery(crate::monitoring::DiscoverySource::Lsd);
        }
    }

    /// Number of trackers currently considered active across all sessions:
    /// a tracker that has not hit the failure back-off (`fails < 3`, no
    /// recorded failure) is counted. Live gauge for the UI status row.
    pub fn active_trackers(&self) -> usize {
        self.sessions
            .values()
            .map(|s| {
                s.trackers
                    .iter()
                    .filter(|t| t.fails < 3 && t.failure.is_none())
                    .count()
            })
            .sum()
    }

    /// Live peer snapshot for one torrent (address, client tag, phase, seed
    /// flag, smoothed rates, in-flight requests). Best-effort: the engine
    /// knows every peer in its swarm, so the UI can show REAL peers instead
    /// of fabricating a table.
    pub fn peer_snapshot(&self, hash: &InfoHash) -> Vec<crate::session::PeerSnapshot> {
        match self.sessions.get(hash) {
            Some(s) => s
                .peers
                .values()
                .filter(|p| p.phase != crate::swarm::PeerPhase::Closed)
                .map(|p| crate::session::PeerSnapshot {
                    addr: p.addr.to_alloc_string(),
                    client: p
                        .rep
                        .client
                        .as_ref()
                        .map(|c| c.code_str())
                        .unwrap_or_else(|| String::from("未知")),
                    phase: match p.phase {
                        crate::swarm::PeerPhase::Connecting => 0,
                        crate::swarm::PeerPhase::Handshake => 1,
                        crate::swarm::PeerPhase::Ready => 2,
                        crate::swarm::PeerPhase::Closed => 3,
                    },
                    is_seed: p.is_seed,
                    down_rate: p.down_rate,
                    up_rate: p.up_rate,
                    in_flight: p.requests_in_flight,
                })
                .collect(),
            None => Vec::new(),
        }
    }

    /// The parsed metainfo of a torrent, if its metadata is known (file
    /// torrents from add time; magnets once the metadata arrived). Lets the
    /// bridge mirror file tables and clean up staged files on removal.
    pub fn metainfo(&self, hash: &InfoHash) -> Option<&Torrent> {
        self.sessions.get(hash).and_then(|s| s.torrent.as_ref())
    }

    /// Aggregate engine statistics for the UI stats dialog.
    pub fn stats(&self) -> EngineStats {
        let mut discarded = 0u64;
        let mut peers = 0usize;
        for s in self.sessions.values() {
            discarded = discarded.saturating_add(s.discarded_bytes);
            peers += s
                .peers
                .values()
                .filter(|p| p.phase != crate::swarm::PeerPhase::Closed)
                .count();
        }
        EngineStats {
            cache: self.cache.stats,
            cache_bytes: self.cache.total_buffered(),
            cache_budget: self.cache.budget(),
            cache_clean: self.cache.clean_used(),
            cache_clean_budget: crate::disk_cache::DiskCache::CLEAN_BUDGET,
            cache_dirty_entries: self.cache.dirty_entries(),
            discarded_bytes: discarded,
            connected_peers: peers,
        }
    }

    /// Flush dirty pieces to disk so every verified piece actually reaches
    /// stable storage. Call right before persisting resume state — the saved
    /// `have` bitfield must only claim pieces whose bytes are really on disk,
    /// otherwise a crash would "restore" pieces that are missing from the
    /// `.part` files (silent corruption) instead of re-downloading them.
    /// Bounded to 32 MiB so a slow disk can never freeze the engine loop.
    pub fn flush_cache(&mut self) {
        let _ = self.cache.flush_bounded(&mut self.host, 32 * 1024 * 1024);
    }

    /// Save session state for persistence (returns binary bytes).
    pub fn save_state(&self) -> crate::state::SessionState {
        let mut st = crate::state::SessionState {
            version: 1,
            ..Default::default()
        };
        for (h, s) in &self.sessions {
            let (have, partial) = s.pieces.snapshot();
            st.torrents.push(crate::state::TorrentState {
                info_hash: h.as_bytes().to_vec(),
                save_path: s.save_dir.clone(),
                have,
                partial,
                added_at: 0,
                paused: s.status == crate::session::SessionStatus::Paused,
                file_priorities: s.file_priorities().iter().map(|p| p.to_byte()).collect(),
                upload_limit_bps: s.cfg.upload_limit_bps,
                download_limit_bps: s.cfg.download_limit_bps,
                reputation: s.reputation.encode(),
                info_raw: s
                    .torrent
                    .as_ref()
                    .map(|t| t.info_raw.clone())
                    .unwrap_or_default(),
            });
        }
        if let Some(d) = &self.dht {
            st.dht_nodes = d.export_nodes(160);
        }
        st
    }

    /// Restore persisted state. Torrents are not reconstructed here (the
    /// host re-adds them via `add_torrent`); this restores the DHT routing
    /// table so the next session boots with known peers.
    pub fn load_state(&mut self, st: &crate::state::SessionState, now: u64) {
        if let Some(d) = self.dht.as_mut() {
            d.import_nodes(&st.dht_nodes, now);
        }
    }
}

// Re-export the event enum at the crate root of engine.
/// Engine event definitions (re-exported as [`EngineEvent`]).
pub mod engine_events {
    use crate::leech::BanReason;
    use crate::metainfo::InfoHash;
    use crate::platform::NetAddr;
    use crate::portmap::PortMapPhase;

    /// Events emitted by the engine, drained by the host.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum EngineEvent {
        /// A peer connected to a torrent.
        PeerConnected {
            /// Torrent the peer joined.
            info_hash: InfoHash,
            /// Peer network address.
            addr: NetAddr,
            /// Peer id.
            peer_id: [u8; 20],
        },
        /// A piece was downloaded and verified.
        PieceVerified {
            /// Torrent.
            info_hash: InfoHash,
            /// Verified piece index.
            piece: u32,
        },
        /// A piece failed its hash check.
        HashFailure {
            /// Torrent.
            info_hash: InfoHash,
            /// Failed piece index.
            piece: u32,
        },
        /// The torrent finished downloading.
        TorrentComplete {
            /// Torrent.
            info_hash: InfoHash,
        },
        /// Magnet metadata arrived.
        MetadataComplete {
            /// Torrent.
            info_hash: InfoHash,
        },
        /// Magnet metadata could not be obtained.
        MetadataFailed {
            /// Torrent.
            info_hash: InfoHash,
        },
        /// A tracker announce succeeded.
        TrackerAnnounced {
            /// Torrent.
            info_hash: InfoHash,
            /// Peers returned by the tracker.
            peers: usize,
        },
        /// A peer was banned by the anti-leech engine.
        PeerBanned {
            /// Torrent the peer was in.
            info_hash: InfoHash,
            /// Banned address.
            addr: NetAddr,
            /// Why it was banned.
            reason: BanReason,
        },
        /// The NAT/firewall port mapping changed phase (UPnP/NAT-PMP).
        PortMapping {
            /// Current phase.
            phase: PortMapPhase,
            /// External port granted by the gateway, when known.
            external_port: Option<u16>,
        },
        /// DHT node count changed.
        DhtNodeCount(usize),
        /// A non-fatal engine-level failure that degraded operation.
        Error {
            /// Stable machine-readable code: 0 = UDP open failed,
            /// 1 = DHT bootstrap: no router resolvable.
            code: u8,
            /// Human-readable tag (e.g. `"udp_open_failed"`).
            detail: &'static str,
        },
    }
}

/// Marker so the module compiles cleanly when no sessions exist.
#[allow(dead_code)]
fn _assert_send<T: Send>(_: &T) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Sha1;
    use crate::metainfo::Torrent;
    use crate::platform::{ConnId, DiskId};
    use alloc::string::String;

    fn make_torrent() -> Torrent {
        use crate::bencode::{bytes, dict, int};
        let piece: Vec<u8> = (0..16 * 1024u32).map(|i| (i % 251) as u8).collect();
        let sha1 = Sha1::digest(&piece);
        let info = dict(vec![
            (b"name", bytes("hello.bin")),
            (b"piece length", int(16 * 1024)),
            (b"length", int(piece.len() as i64)),
            (b"pieces", bytes(sha1.to_vec())),
        ]);
        let data = crate::bencode::encode_to_vec(&dict(vec![(b"info", info)]));
        Torrent::from_bytes(&data).expect("torrent")
    }

    /// A host whose UDP socket can never open but which can resolve the DHT
    /// routers — exactly the FFI scenario reported: `udp_open` fails, but
    /// DNS works. `start()` must degrade instead of failing the torrent.
    struct UdpFailHost {
        udp_open_calls: u32,
    }

    impl crate::platform::Host for UdpFailHost {
        fn now_ms(&self) -> u64 {
            1_000_000
        }
        fn fill_random(&mut self, b: &mut [u8]) {
            for (i, x) in b.iter_mut().enumerate() {
                *x = (i as u8).wrapping_mul(7);
            }
        }
        fn log(&mut self, _l: crate::platform::LogLevel, _m: &str) {}
        fn http_get(
            &mut self,
            _u: &str,
            _t: u64,
            _o: &mut alloc::vec::Vec<u8>,
        ) -> crate::error::Result<()> {
            Err(crate::error::Error::NotSupported)
        }
        fn resolve_host(&self, host: &str, port: u16) -> Option<NetAddr> {
            if crate::consts::DHT_BOOTSTRAP.iter().any(|(h, _)| *h == host) {
                Some(NetAddr::V4([203, 0, 113, 1], port))
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
            self.udp_open_calls += 1;
            Err(crate::error::Error::Io)
        }
        fn udp_send(&mut self, _a: &NetAddr, _d: &[u8]) -> crate::error::Result<()> {
            Err(crate::error::Error::Io)
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

    #[test]
    fn start_succeeds_when_udp_fails_and_emits_error_event() {
        let host = UdpFailHost { udp_open_calls: 0 };
        let cfg = EngineConfig {
            dht_enabled: true,
            cache_bytes: 1024 * 1024,
            ..Default::default()
        };
        let mut engine = Engine::new(host, cfg);
        let t = make_torrent();
        let hash = t.info_hash;
        engine.add_torrent_obj(t, "/tmp").expect("add");
        assert!(engine.start(&hash).is_ok(), "start must not fail on UDP");
        assert!(
            engine.dht().is_none(),
            "DHT must be disabled after UDP failure"
        );
        let evs = engine.take_events();
        assert!(
            evs.iter()
                .any(|e| matches!(e, EngineEvent::Error { code: 0, .. })),
            "expected udp_open_failed event, got {evs:?}"
        );

        assert!(engine.tick().is_ok());
        assert_eq!(engine.host.udp_open_calls, 1);
    }

    /// Host that records the dedicated LSD socket lifecycle and can feed one
    /// BT-SEARCH announce back through `udp_recv_lsd` (the port-6771 path the
    /// shared socket can never receive).
    struct LsdHost {
        lsd_open: u32,
        lsd_joins: u32,
        feed: Option<(NetAddr, alloc::vec::Vec<u8>)>,
    }

    impl crate::platform::Host for LsdHost {
        fn now_ms(&self) -> u64 {
            1_000_000
        }
        fn fill_random(&mut self, b: &mut [u8]) {
            for (i, x) in b.iter_mut().enumerate() {
                *x = (i as u8).wrapping_mul(7);
            }
        }
        fn log(&mut self, _l: crate::platform::LogLevel, _m: &str) {}
        fn http_get(
            &mut self,
            _u: &str,
            _t: u64,
            _o: &mut alloc::vec::Vec<u8>,
        ) -> crate::error::Result<()> {
            Err(crate::error::Error::NotSupported)
        }
        fn resolve_host(&self, _host: &str, _port: u16) -> Option<NetAddr> {
            None
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
        fn udp_send(&mut self, _a: &NetAddr, _d: &[u8]) -> crate::error::Result<()> {
            Ok(())
        }
        fn udp_multicast_send(&mut self, _a: &NetAddr, _d: &[u8]) -> crate::error::Result<()> {
            Ok(())
        }
        fn udp_join_multicast(&mut self, _a: NetAddr) -> crate::error::Result<()> {
            Ok(())
        }
        fn udp_recv(&mut self, _b: &mut [u8]) -> crate::error::Result<(NetAddr, usize)> {
            Err(crate::error::Error::WouldBlock)
        }
        fn udp_open_lsd(&mut self, _p: u16) -> crate::error::Result<()> {
            self.lsd_open += 1;
            Ok(())
        }
        fn udp_join_multicast_lsd(&mut self, _a: NetAddr) -> crate::error::Result<()> {
            self.lsd_joins += 1;
            Ok(())
        }
        fn udp_recv_lsd(&mut self, b: &mut [u8]) -> crate::error::Result<(NetAddr, usize)> {
            match self.feed.take() {
                Some((addr, data)) => {
                    let n = data.len().min(b.len());
                    b[..n].copy_from_slice(&data[..n]);
                    Ok((addr, n))
                }
                None => Err(crate::error::Error::WouldBlock),
            }
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

    #[test]
    fn lsd_opens_dedicated_socket_and_routes_lan_announces() {
        use crate::lsd;
        let host = LsdHost {
            lsd_open: 0,
            lsd_joins: 0,
            feed: None,
        };
        let mut engine = Engine::new(host, EngineConfig::default());
        let t = make_torrent();
        let hash = t.info_hash;
        engine.add_torrent_obj(t, "/tmp").expect("add");
        engine.start(&hash).expect("start");
        engine.tick().expect("tick");

        // The dedicated LSD socket (port 6771) must have been opened and the
        // multicast groups joined on it — the fix for "local peer never found".
        assert!(
            engine.host.lsd_open >= 1,
            "dedicated LSD socket must be opened"
        );
        assert!(
            engine.host.lsd_joins >= 1,
            "LSD multicast group must be joined on the dedicated socket"
        );

        // A neighbour announces our torrent on the LSD group → its address
        // (from the announce Port header) must be attached to the swarm for
        // connection (drive_connect_queue consumes the queue in the same
        // tick via the uTP/TCP dial, so we assert on the attached peer).
        let mut ih20 = [0u8; 20];
        ih20.copy_from_slice(hash.as_bytes());
        let msg = lsd::build_announce(&ih20, 6882, None, lsd::LSD_GROUP_V4);
        engine.host.feed = Some((NetAddr::V4([192, 168, 1, 50], 6771), msg));
        engine.tick().expect("tick");

        let attached = engine
            .sessions
            .get(&hash)
            .map(|s| {
                s.peers
                    .values()
                    .any(|p| p.addr == NetAddr::V4([192, 168, 1, 50], 6882))
            })
            .unwrap_or(false);
        assert!(
            attached,
            "LSD-discovered LAN peer (192.168.1.50:6882) must be attached to the swarm"
        );
    }

    #[test]
    fn http_only_start_never_touches_udp() {
        let host = UdpFailHost { udp_open_calls: 0 };
        let cfg = EngineConfig {
            dht_enabled: false,
            port_mapping: false,
            cache_bytes: 1024 * 1024,
            session: SessionConfig {
                save_dir: String::from("/tmp"),
                use_default_trackers: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut engine = Engine::new(host, cfg);
        let t = make_torrent();
        let hash = t.info_hash;
        engine.add_torrent_obj(t, "/tmp").expect("add");

        assert!(engine.start(&hash).is_ok());
        assert_eq!(
            engine.host.udp_open_calls, 0,
            "UDP must not be opened for an HTTP-only torrent"
        );
        assert!(engine.tick().is_ok());
    }
}
