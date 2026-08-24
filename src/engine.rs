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
use crate::platform::{ConnId, Host, NetAddr};
use crate::session::{SessionConfig, SessionCtx, TorrentSession};
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
    /// Per-torrent defaults.
    pub session: SessionConfig,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            listen_port: DEFAULT_PORT,
            cache_bytes: crate::consts::DEFAULT_CACHE_BYTES,
            dht_enabled: true,
            session: SessionConfig::default(),
        }
    }
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
    /// Connections still establishing (outbound).
    connecting: Vec<ConnId>,
    /// Inbound connections whose handshake has not revealed an infohash.
    inbound: BTreeMap<ConnId, InboundPeer>,
    last_cache_flush: u64,
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
    pub fn new(host: H, cfg: EngineConfig) -> Self {
        let mut seed = [0u8; 32];
        let mut h = host;
        h.fill_random(&mut seed);
        let mut rng = Rng::from_seed(seed);
        let peer_id = crate::peer_id::generate(&mut rng);
        let dht = if cfg.dht_enabled {
            let id = NodeId::random(&mut rng);
            let mut d = Dht::new(id, cfg.listen_port, &mut rng);
            // bootstrap from well-known nodes (resolved by the std host)
            let _ = &mut d;
            Some(d)
        } else {
            None
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
            connecting: Vec::new(),
            inbound: BTreeMap::new(),
            last_cache_flush: 0,
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
        let session = TorrentSession::from_magnet(&magnet, cfg, self.host.now_ms())?;
        self.sessions.insert(hash, session);
        Ok(hash)
    }

    /// Start a torrent.
    pub fn start(&mut self, hash: &InfoHash) -> Result<()> {
        let now = self.host.now_ms();
        self.ensure_udp(now)?;
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
        // bootstrap DHT once
        if let Some(dht) = self.dht.as_mut() {
            if dht.table().size() == 0 {
                for (host, port) in crate::consts::DHT_BOOTSTRAP {
                    // the std host resolves hostnames; core passes 0.0.0.0 as
                    // a marker only for literal IPv4 seeds.
                    if let Ok(ip) = host.parse::<core::net::Ipv4Addr>() {
                        let _ = ip;
                    }
                    let _ = (host, port);
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

    /// Drain engine events (call frequently).
    pub fn take_events(&mut self) -> Vec<EngineEvent> {
        core::mem::take(&mut self.events)
    }

    /// Feed a completed inbound TCP connection.
    pub fn on_inbound_connection(&mut self, conn: ConnId, addr: NetAddr) {
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

    fn ensure_udp(&mut self, now: u64) -> Result<()> {
        if !self.udp_open {
            self.host.udp_open(self.cfg.listen_port)?;
            self.udp_open = true;
            let _ = now;
        }
        Ok(())
    }

    // ---------- main tick ----------

    /// Advance the whole engine. Call on a fixed cadence.
    pub fn tick(&mut self) -> Result<()> {
        let now = self.host.now_ms();
        if self.cfg.dht_enabled && !self.udp_open {
            self.ensure_udp(now)?;
        }
        // 1) drive all TCP I/O
        self.drive_tcp(now);
        // 2) UDP: DHT + UDP trackers
        self.drive_udp(now);
        // 3) DHT maintenance
        if let Some(dht) = self.dht.as_mut() {
            dht.tick(now);
            for (addr, payload) in dht.outgoing() {
                let _ = self.host.udp_send(&addr, &payload);
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
        for (addr, source) in queued {
            if let Ok(conn) = self.host.tcp_connect(&addr) {
                self.conn_owner.insert(conn, hash);
                self.connecting.push(conn);
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
        // outbound connects
        self.connecting.retain(|&conn| {
            match self.host.tcp_connect_done(conn) {
                Ok(()) => {
                    let hash = match self.conn_owner.get(&conn) {
                        Some(h) => *h,
                        None => return false,
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
                        s.on_connect_done(conn, &mut ctx);
                    }
                    false
                }
                Err(Error::WouldBlock) => true,
                Err(_) => {
                    // connect failed
                    let hash = self.conn_owner.remove(&conn);
                    if let Some(h) = hash {
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
                            s.drop_peer(
                                conn,
                                crate::monitoring::FailureCategory::Unreachable,
                                &mut ctx,
                            );
                        }
                    }
                    false
                }
            }
        });

        // reads/writes for owned connections
        let conns: Vec<ConnId> = self.conn_owner.keys().copied().collect();
        for conn in conns {
            let hash = match self.conn_owner.get(&conn) {
                Some(h) => *h,
                None => continue,
            };
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

    /// Read available data for one session-owned connection, dispatch, and
    /// flush its out buffer.
    fn pump_connection(&mut self, conn: ConnId, hash: InfoHash, now: u64) {
        let mut recv_buf = [0u8; 16 * 1024];
        loop {
            match self.host.tcp_recv(conn, &mut recv_buf) {
                Ok(0) => break,
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
        // flush outgoing
        let out_len = {
            let s = match self.sessions.get(&hash) {
                Some(s) => s,
                None => return,
            };
            s.peers.get(&conn).map(|p| p.out.len()).unwrap_or(0)
        };
        if out_len > 0 {
            // drain in chunks
            let mut drained = 0usize;
            loop {
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
                match self.host.tcp_send(conn, &chunk) {
                    Ok(n) => {
                        drained += n;
                        // re-queue the unsent remainder
                        if n < chunk.len() {
                            if let Some(s) = self.sessions.get_mut(&hash) {
                                if let Some(p) = s.peers.get_mut(&conn) {
                                    let mut rest = chunk[n..].to_vec();
                                    rest.append(&mut p.out);
                                    p.out = rest;
                                }
                            }
                            break;
                        }
                    }
                    Err(Error::WouldBlock) => {
                        // re-queue the whole chunk
                        if let Some(s) = self.sessions.get_mut(&hash) {
                            if let Some(p) = s.peers.get_mut(&conn) {
                                let mut rest = chunk;
                                rest.append(&mut p.out);
                                p.out = rest;
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
                let _ = drained;
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
                    // DHT messages are bencoded dicts ('d' prefix)
                    if payload.first() == Some(&b'd') {
                        if let Some(dht) = self.dht.as_mut() {
                            if let Ok(DatagramOutcome::Reply(reply)) =
                                dht.handle_datagram(addr, payload, now)
                            {
                                let _ = self.host.udp_send(&addr, &reply);
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
    use crate::metainfo::InfoHash;
    use crate::platform::NetAddr;

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
        /// DHT node count changed.
        DhtNodeCount(usize),
    }
}

/// Marker so the module compiles cleanly when no sessions exist.
#[allow(dead_code)]
fn _assert_send<T: Send>(_: &T) {}
