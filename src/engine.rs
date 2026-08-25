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
            verify_workers: 0,
            proxy: None,
            connect_timeout_ms: 30_000,
            session: SessionConfig::default(),
        }
    }
}

/// How often the engine retries DHT bootstrap while the routing table is
/// still empty (the construction-time seeds may have been sent before any
/// network was up).
const BOOTSTRAP_RETRY_MS: u64 = 30_000;

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
    /// Piece-verification worker pool (real threads under `std`; `None`
    /// means inline verification).
    verify_pool: Option<VerifyPool>,
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
        let dht = if cfg.dht_enabled {
            let id = NodeId::random(&mut rng);
            let mut d = Dht::new(id, cfg.listen_port, &mut rng);
            // Bootstrap from the well-known BEP-5 routers. Their names are
            // resolved through the host (never hardcoded IPs, which rot);
            // a host without a resolver simply yields no seeds and the DHT
            // stays dormant (HTTP/UDP trackers still work).
            let mut seeds: Vec<NetAddr> = Vec::new();
            for (host, port) in crate::consts::DHT_BOOTSTRAP {
                if let Some(a) = h.resolve_host(host, *port) {
                    seeds.push(a);
                }
            }
            if !seeds.is_empty() {
                d.bootstrap(&seeds, now);
            }
            Some(d)
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
            last_bootstrap_at: now,
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
            verify_pool,
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
        let session = TorrentSession::from_magnet(&magnet, cfg, self.host.now_ms())?;
        self.sessions.insert(hash, session);
        Ok(hash)
    }

    /// Start a torrent.
    pub fn start(&mut self, hash: &InfoHash) -> Result<()> {
        let now = self.host.now_ms();
        // Open UDP only when it is actually needed (DHT / UDP trackers /
        // port mapping). A failure here is non-fatal: the engine degrades
        // to HTTP-tracker-only and the torrent still starts.
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
        // Re-kick DHT bootstrap when the routing table is still empty (the
        // construction-time seeds may have failed, e.g. no connectivity yet).
        // `bootstrap` is idempotent — it only pings, and an existing table
        // is left untouched.
        if let Some(dht) = self.dht.as_mut() {
            if dht.table().size() == 0 {
                let mut seeds: Vec<NetAddr> = Vec::new();
                for (host, port) in crate::consts::DHT_BOOTSTRAP {
                    if let Some(a) = self.host.resolve_host(host, *port) {
                        seeds.push(a);
                    }
                }
                if !seeds.is_empty() {
                    dht.bootstrap(&seeds, now);
                }
            }
        }
        Ok(())
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
        // release connections
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
        // Proxy mode is outbound-only: an inbound connection would reveal
        // our real IP, so it is dropped immediately.
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
        // Proxy mode is outbound-only: never open a UDP socket (DHT and UDP
        // trackers are disabled, so a socket would only leak our real IP).
        if self.cfg.proxy.is_some() {
            return Ok(());
        }
        if !self.udp_open {
            self.host.udp_open(self.cfg.listen_port)?;
            self.udp_open = true;
        }
        let _ = now;
        Ok(())
    }

    /// Whether the engine currently needs a UDP socket: DHT enabled, port
    /// mapping, or any live UDP tracker across the sessions. In proxy mode
    /// the socket is never opened (outbound-only).
    fn wants_udp(&self) -> bool {
        if self.cfg.proxy.is_some() {
            return false;
        }
        if self.cfg.dht_enabled || self.cfg.port_mapping {
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
            // DHT and UDP trackers cannot work without the socket. Drop the
            // DHT and park UDP trackers so the engine stays in a consistent,
            // observable state; HTTP trackers and peer transport are
            // unaffected.
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
        // Open the UDP socket lazily (only when needed); a failure degrades
        // the engine instead of failing the whole tick.
        self.start_udp_if_needed(now);
        // Sweep dead connection bookkeeping: a peer dropped by its session
        // (timeout, ban, eviction, SOCKS failure…) must also leave
        // `conn_owner`/`socks`/`socks_target`, otherwise dead entries inflate
        // the global connection budget forever and the maps grow unbounded.
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
        // Port mapping (NAT-PMP / UPnP IGD): start once the socket is up,
        // then pump the state machine.
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
        // Per-tick rate budgets: slice the global buckets fairly among the
        // active sessions *before* any I/O is driven, so upload draining and
        // download request generation both respect the global caps.
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
        // 1) drive all TCP I/O
        self.drive_tcp(now);
        // 2) UDP: DHT + UDP trackers
        self.drive_udp(now);
        // 3) DHT maintenance
        if let Some(dht) = self.dht.as_mut() {
            dht.tick(now);
            for (addr, payload) in dht.outgoing() {
                if let Err(e) = self.host.udp_send(&addr, &payload) {
                    // Never fatal, but a dead UDP path must be visible in
                    // the host log instead of failing silently.
                    self.host.log(
                        LogLevel::Debug,
                        &alloc::format!("dht udp_send to {} failed: {}", addr, e),
                    );
                }
            }
            // Re-bootstrap on a cadence while the routing table is empty:
            // the construction-time seeds may have failed (no connectivity
            // yet, DNS temporarily down…). `bootstrap` is idempotent — it
            // only pings and leaves an existing table untouched.
            if dht.table().size() == 0
                && now.saturating_sub(self.last_bootstrap_at) >= BOOTSTRAP_RETRY_MS
            {
                self.last_bootstrap_at = now;
                let mut seeds: Vec<NetAddr> = Vec::new();
                for (host, port) in crate::consts::DHT_BOOTSTRAP {
                    if let Some(a) = self.host.resolve_host(host, *port) {
                        seeds.push(a);
                    }
                }
                if !seeds.is_empty() {
                    dht.bootstrap(&seeds, now);
                    self.dht_no_seed_emitted = false;
                } else if !self.dht_no_seed_emitted {
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
        }
        // 4) session logic
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
        // 4.5) piece verification: drain assembled pieces and verify them —
        //      async via the worker pool when available, inline otherwise.
        //      Either way the event loop never blocks on hashing.
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
        // 4.6) async verification results
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
        // 5) cache flush on a slow cadence
        if now.saturating_sub(self.last_cache_flush) >= 5_000 {
            let _ = self.cache.flush(&mut self.host);
            self.last_cache_flush = now;
        }
        // 6) periodic DHT node-count event
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
            // connection flood bounds (global + per-IP)
            let total = self.conn_owner.len() + self.connecting.len() + self.inbound.len();
            if total >= self.cfg.global_max_connections {
                continue;
            }
            if self.ip_count(&addr) >= self.cfg.max_connections_per_ip {
                continue;
            }
            // In proxy mode we dial the proxy; the real peer endpoint is
            // remembered for the SOCKS CONNECT and the session bookkeeping.
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

    /// Drive TCP reads/writes/connects for all connections.
    fn drive_tcp(&mut self, now: u64) {
        // outbound connects (directly, or to the SOCKS proxy first)
        let mut still_connecting = Vec::new();
        for conn in core::mem::take(&mut self.connecting) {
            let hash = match self.conn_owner.get(&conn) {
                Some(h) => *h,
                None => continue,
            };
            match self.host.tcp_connect_done(conn) {
                Err(Error::WouldBlock) => {
                    // enforce the connect deadline: a dead proxy or a host
                    // stuck mid-connect must not hold the slot forever.
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
                    // TCP connect to the proxy (or target) failed
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
                    // TCP established; the connect deadline no longer applies.
                    self.connect_deadline.remove(&conn);
                    // If we are proxied this socket is the proxy; run the
                    // SOCKS5 handshake before the peer's BitTorrent handshake
                    // is allowed through.
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
        // drive any active SOCKS handshakes
        self.pump_socks(now);

        // reads/writes for owned connections
        let conns: Vec<ConnId> = self.conn_owner.keys().copied().collect();
        for conn in conns {
            let hash = match self.conn_owner.get(&conn) {
                Some(h) => *h,
                None => continue,
            };
            // connections still in their SOCKS handshake are driven by
            // pump_socks; feeding them BitTorrent frames would corrupt the
            // proxy protocol exchange.
            if self.socks.contains_key(&conn) {
                continue;
            }
            // inbound handshake buffer flushing for inbound conns handled
            // separately below; for session-owned conns:
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
            match self.host.tcp_recv(conn, &mut recv_buf) {
                Ok(0) => {
                    // Orderly EOF: the peer closed the connection. Release
                    // the slot (and any in-flight block bookkeeping) instead
                    // of pinning a dead peer forever.
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
        // flush outgoing (through the upload rate budgets)
        let out_len = {
            let s = match self.sessions.get(&hash) {
                Some(s) => s,
                None => return,
            };
            s.peers.get(&conn).map(|p| p.out.len()).unwrap_or(0)
        };
        if out_len > 0 {
            // drain in chunks, bounded by the global slice for this session
            // and the session's own upload bucket
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
                match self.host.tcp_send(conn, &chunk[..want]) {
                    Ok(n) => {
                        // account the sent bytes against the rate budgets
                        if let Some(s) = self.sessions.get_mut(&hash) {
                            s.tick_up_allowance = s.tick_up_allowance.saturating_sub(n as u64);
                            s.upload_limit.consume(n as u64, now);
                        }
                        self.global_up.consume(n as u64, now);
                        // re-queue whatever was not accepted (partial send or
                        // allowance-limited)
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
                        // re-queue the whole chunk
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

    /// Handle an inbound connection until its handshake reveals the hash.
    fn pump_inbound(&mut self, conn: ConnId, now: u64) {
        let mut recv_buf = [0u8; 16 * 1024];
        loop {
            match self.host.tcp_recv(conn, &mut recv_buf) {
                Ok(0) => break,
                Ok(n) => {
                    let overflow = self
                        .inbound
                        .get(&conn)
                        .is_some_and(|p| p.buf.len() + n > Self::MAX_INBOUND_BUF);
                    if overflow {
                        self.inbound.remove(&conn);
                        self.host.tcp_close(conn);
                        return;
                    }
                    if let Some(p) = self.inbound.get_mut(&conn) {
                        p.buf.extend_from_slice(&recv_buf[..n]);
                    }
                }
                Err(Error::WouldBlock) => break,
                Err(_) => {
                    self.inbound.remove(&conn);
                    self.host.tcp_close(conn);
                    return;
                }
            }
        }
        // try handshake
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
                    self.host.tcp_close(conn);
                    return;
                }
            }
        };
        // find a session for this infohash (accept v1 or v2)
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
                self.host.tcp_close(conn);
                return;
            }
        };
        // move pending buffers into the session
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
            // feed the leftover bytes (our handshake reply is queued by attach)
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
        loop {
            match self.host.udp_recv(&mut buf) {
                Ok((addr, n)) => {
                    let payload = &buf[..n];
                    // NAT-PMP replies / SSDP responses belong to the port
                    // mapper; consumed there and never touched by DHT/tracker.
                    if let Some(pm) = self.portmap.as_mut() {
                        if pm.handle_datagram(&addr, payload, now) {
                            continue;
                        }
                    }
                    // DHT messages are bencoded dicts ('d' prefix)
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
                        // UDP tracker responses: match by transaction id
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
            });
        }
        if let Some(d) = &self.dht {
            st.dht_nodes = d.export_nodes(64);
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
        /// A non-fatal engine-level failure that degraded operation (e.g.
        /// the UDP socket could not be opened, so DHT and UDP trackers are
        /// off). The engine keeps running — HTTP trackers and peer
        /// transport still work — but the host should surface this to the
        /// user instead of showing a silent `0 B/s`.
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

        // Regression: `start()` used to fail hard (`Error::Io`) when the
        // UDP socket could not be opened, so the frontend got a bare -1 and
        // the torrent never started. It must degrade instead.
        assert!(engine.start(&hash).is_ok(), "start must not fail on UDP");

        // The DHT is disabled and the host is told exactly why.
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

        // The engine keeps ticking (HTTP trackers / peers still work).
        assert!(engine.tick().is_ok());
        // No repeated UDP-open attempts (degradation is sticky).
        assert_eq!(engine.host.udp_open_calls, 1);
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

        // No DHT, no UDP trackers, no port mapping → UDP must never be
        // opened at all; the HTTP-only torrent starts cleanly.
        assert!(engine.start(&hash).is_ok());
        assert_eq!(
            engine.host.udp_open_calls, 0,
            "UDP must not be opened for an HTTP-only torrent"
        );
        assert!(engine.tick().is_ok());
    }
}
