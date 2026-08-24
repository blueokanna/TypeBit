//! Swarm availability monitoring ("the downloader as a measurement probe").
//!
//! Treats the torrent as a time-varying replication graph and continuously
//! estimates content recoverability:
//!
//! ```text
//! A(t, B) = Pr[ obtain and verify all required pieces within budget B ]
//! ```
//!
//! The monitor tracks per-peer coverage, discovery-source effectiveness,
//! failure taxonomy and produces an evidence-backed [`SwarmReport`]
//! (JSON via `nextjson`). This powers early-warning for content that is
//! drifting from "healthy" to "unrecoverable".

use crate::platform::NetAddr;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use nextjson::{NsonDeserialize, NsonSerialize};

/// How a peer was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, NsonSerialize, NsonDeserialize)]
pub enum DiscoverySource {
    /// Tracker (HTTP/UDP announce).
    Tracker,
    /// DHT lookup.
    Dht,
    /// Peer exchange (BEP-11).
    Pex,
    /// Manually added / magnet `x.pe`.
    Manual,
    /// Web seed (BEP-19).
    WebSeed,
}

impl DiscoverySource {
    /// String tag for reports.
    pub fn tag(&self) -> &'static str {
        match self {
            DiscoverySource::Tracker => "tracker",
            DiscoverySource::Dht => "dht",
            DiscoverySource::Pex => "pex",
            DiscoverySource::Manual => "manual",
            DiscoverySource::WebSeed => "webseed",
        }
    }
}

/// Per-source effectiveness.
#[derive(Debug, Clone, Copy, Default, NsonSerialize, NsonDeserialize)]
pub struct SourceStats {
    /// Peers discovered via this source.
    pub discovered: u32,
    /// Successfully connected.
    pub connected: u32,
    /// Failed to connect / dropped.
    pub failed: u32,
}

/// Failure taxonomy.
#[derive(Debug, Clone, Copy, Default, NsonSerialize, NsonDeserialize)]
pub struct FailureTotals {
    /// Connect/handshake timeouts.
    pub timeout: u32,
    /// Peers that choked us out.
    pub choke: u32,
    /// Piece hash failures.
    pub hash_failure: u32,
    /// Metadata mismatch.
    pub metadata_mismatch: u32,
    /// Unreachable / connection refused.
    pub unreachable: u32,
}

/// Per-peer observation.
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct PeerInfo {
    /// `ip:port`.
    pub addr: String,
    /// Discovery source.
    pub source: DiscoverySource,
    /// First seen (ms).
    pub first_seen: u64,
    /// Last activity (ms).
    pub last_seen: u64,
    /// Download rate (bytes/s).
    pub down_rate: u32,
    /// Upload rate (bytes/s).
    pub up_rate: u32,
    /// Pieces seen offered.
    pub pieces_seen: u32,
    /// Currently connected.
    pub connected: bool,
}

/// The evidence-backed swarm report.
#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct SwarmReport {
    /// Content root (hex infohash).
    pub content_root: String,
    /// Measurement window start (ms).
    pub window_start: u64,
    /// Measurement window end (ms).
    pub window_end: u64,
    /// Total content size.
    pub total_size: u64,
    /// Bytes downloaded so far.
    pub downloaded: u64,
    /// Seeders observed.
    pub seeders: u32,
    /// Leechers observed.
    pub leechers: u32,
    /// Per-source stats (tagged).
    pub tracker: SourceStats,
    /// Stats for peers found via DHT.
    pub dht: SourceStats,
    /// Stats for peers found via PEX.
    pub pex: SourceStats,
    /// Stats for manually added peers.
    pub manual: SourceStats,
    /// Stats for web-seed sources.
    pub webseed: SourceStats,
    /// Failure totals.
    pub failures: FailureTotals,
    /// Per-peer detail.
    pub peers: Vec<PeerInfo>,
    /// A(t,B): recoverability within budget, permyriad (0..=10000).
    pub recovery_permyriad: u32,
    /// Estimated cost to rebuild the remaining content (bytes).
    pub estimated_cost_bytes: u64,
    /// Budget assumed for the estimate.
    pub budget_bytes: u64,
    /// Early-warning flag: content drifting unrecoverable.
    pub degraded: bool,
}

struct PeerEntry {
    source: DiscoverySource,
    first_seen: u64,
    last_seen: u64,
    down_rate: u32,
    up_rate: u32,
    pieces_seen: u32,
    connected: bool,
    seed: bool,
}

impl core::fmt::Debug for PeerEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PeerEntry")
            .field("source", &self.source)
            .field("first_seen", &self.first_seen)
            .field("last_seen", &self.last_seen)
            .field("down_rate", &self.down_rate)
            .field("up_rate", &self.up_rate)
            .field("pieces_seen", &self.pieces_seen)
            .field("connected", &self.connected)
            .field("seed", &self.seed)
            .finish()
    }
}

impl Clone for PeerEntry {
    fn clone(&self) -> Self {
        PeerEntry {
            source: self.source,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            down_rate: self.down_rate,
            up_rate: self.up_rate,
            pieces_seen: self.pieces_seen,
            connected: self.connected,
            seed: self.seed,
        }
    }
}

/// Continuous swarm availability monitor for one torrent.
#[derive(Debug, Clone)]
pub struct SwarmMonitor {
    content_root: String,
    total_size: u64,
    downloaded: u64,
    start: u64,
    last_tick: u64,
    seeders: u32,
    leechers: u32,
    sources: [SourceStats; 5],
    failures: FailureTotals,
    peers: BTreeMap<NetAddr, PeerEntry>,
    /// piece → number of distinct peers offering it.
    piece_cover: BTreeMap<u32, u32>,
    budget_bytes: u64,
}

impl SwarmMonitor {
    /// New monitor.
    pub fn new(content_root: String, total_size: u64, now_ms: u64, budget_bytes: u64) -> Self {
        SwarmMonitor {
            content_root,
            total_size,
            downloaded: 0,
            start: now_ms,
            last_tick: now_ms,
            seeders: 0,
            leechers: 0,
            sources: [SourceStats::default(); 5],
            failures: FailureTotals::default(),
            peers: BTreeMap::new(),
            piece_cover: BTreeMap::new(),
            budget_bytes,
        }
    }

    fn src_idx(s: DiscoverySource) -> usize {
        match s {
            DiscoverySource::Tracker => 0,
            DiscoverySource::Dht => 1,
            DiscoverySource::Pex => 2,
            DiscoverySource::Manual => 3,
            DiscoverySource::WebSeed => 4,
        }
    }

    /// A peer was discovered via a source.
    pub fn record_discovery(&mut self, source: DiscoverySource) {
        self.sources[Self::src_idx(source)].discovered += 1;
    }

    /// A peer connected.
    pub fn record_connect(
        &mut self,
        addr: NetAddr,
        source: DiscoverySource,
        now_ms: u64,
        is_seed: bool,
    ) {
        self.sources[Self::src_idx(source)].connected += 1;
        let e = self.peers.entry(addr).or_insert(PeerEntry {
            source,
            first_seen: now_ms,
            last_seen: now_ms,
            down_rate: 0,
            up_rate: 0,
            pieces_seen: 0,
            connected: true,
            seed: is_seed,
        });
        e.connected = true;
        e.last_seen = now_ms;
        e.source = source;
        if is_seed {
            self.seeders += 1;
        } else {
            self.leechers += 1;
        }
    }

    /// A peer disconnected with a failure category.
    pub fn record_disconnect(&mut self, addr: NetAddr, category: FailureCategory) {
        if let Some(e) = self.peers.get_mut(&addr) {
            e.connected = false;
            if e.seed {
                self.seeders = self.seeders.saturating_sub(1);
            } else {
                self.leechers = self.leechers.saturating_sub(1);
            }
        }
        self.sources[Self::src_idx(DiscoverySource::Manual)].failed += 0; // keep source intact
        let src = self.peers.get(&addr).map(|e| e.source);
        if let Some(s) = src {
            self.sources[Self::src_idx(s)].failed += 1;
        }
        match category {
            FailureCategory::Timeout => self.failures.timeout += 1,
            FailureCategory::Choke => self.failures.choke += 1,
            FailureCategory::HashFailure => self.failures.hash_failure += 1,
            FailureCategory::MetadataMismatch => self.failures.metadata_mismatch += 1,
            FailureCategory::Unreachable => self.failures.unreachable += 1,
        }
    }

    /// Record a hash failure (piece `piece`).
    pub fn record_hash_failure(&mut self, _piece: u32) {
        self.failures.hash_failure += 1;
    }

    /// A peer offered piece `piece`.
    pub fn record_piece_cover(&mut self, addr: NetAddr, piece: u32) {
        if let Some(e) = self.peers.get_mut(&addr) {
            e.pieces_seen += 1;
        }
        *self.piece_cover.entry(piece).or_insert(0) += 1;
    }

    /// Update per-peer rates.
    pub fn record_rates(&mut self, addr: NetAddr, down: u32, up: u32, now_ms: u64) {
        if let Some(e) = self.peers.get_mut(&addr) {
            e.down_rate = down;
            e.up_rate = up;
            e.last_seen = now_ms;
        }
    }

    /// Update download progress.
    pub fn set_downloaded(&mut self, bytes: u64, now_ms: u64) {
        self.downloaded = bytes;
        self.last_tick = now_ms;
    }

    /// Current recovery probability estimate within the budget.
    /// Returns permyriad (0..=10000).
    pub fn recovery_permyriad(&self) -> u32 {
        let needed = self.total_size.saturating_sub(self.downloaded);
        if needed == 0 {
            return 10000;
        }
        // availability factor: seeders ≫ leechers-with-pieces > none
        let avail = if self.seeders > 0 {
            100
        } else if self.leechers > 0 {
            70
        } else {
            20
        };
        // budget factor: how much of the needed bytes the budget can cover
        let budget = self.budget_bytes.max(1);
        let budget_factor = (budget.saturating_mul(100) / needed).min(100) as u32;
        // also account for observed rate capacity
        let rate_capacity = self.aggregate_down_rate();
        let rate_factor = if rate_capacity == 0 {
            100
        } else {
            // time-to-complete vs a default 1h window
            let window_ms = 3_600_000u64;
            let rate_bytes_per_ms = rate_capacity as u64 / 1000;
            let ttc_ms = needed / rate_bytes_per_ms.max(1);
            if ttc_ms <= window_ms {
                100
            } else {
                let f = window_ms.saturating_mul(100) / ttc_ms.max(1);
                f.min(100) as u32
            }
        };
        let mut r = budget_factor.saturating_mul(avail) / 100; // percent
        r = r.saturating_mul(rate_factor) / 100; // percent
        r.saturating_mul(100) // → permyriad
    }

    fn aggregate_down_rate(&self) -> u32 {
        self.peers
            .values()
            .filter(|p| p.connected)
            .map(|p| p.down_rate)
            .sum()
    }

    /// Estimated cost (bytes) to rebuild the remaining content.
    pub fn estimated_cost_bytes(&self) -> u64 {
        self.total_size.saturating_sub(self.downloaded)
    }

    /// Assemble the JSON-ready report.
    pub fn report(&self, now_ms: u64) -> SwarmReport {
        let rp = self.recovery_permyriad();
        let peers: Vec<PeerInfo> = self
            .peers
            .iter()
            .map(|(addr, e)| PeerInfo {
                addr: addr.to_string(),
                source: e.source,
                first_seen: e.first_seen,
                last_seen: e.last_seen,
                down_rate: e.down_rate,
                up_rate: e.up_rate,
                pieces_seen: e.pieces_seen,
                connected: e.connected,
            })
            .collect();
        SwarmReport {
            content_root: self.content_root.clone(),
            window_start: self.start,
            window_end: now_ms,
            total_size: self.total_size,
            downloaded: self.downloaded,
            seeders: self.seeders,
            leechers: self.leechers,
            tracker: self.sources[0],
            dht: self.sources[1],
            pex: self.sources[2],
            manual: self.sources[3],
            webseed: self.sources[4],
            failures: self.failures,
            peers,
            recovery_permyriad: rp,
            estimated_cost_bytes: self.estimated_cost_bytes(),
            budget_bytes: self.budget_bytes,
            degraded: rp < 4000,
        }
    }

    /// Serialize the report to JSON.
    pub fn report_json(&self, now_ms: u64) -> Result<Vec<u8>, nextjson::Error> {
        nextjson::nextencode(&self.report(now_ms))
    }
}

/// Failure category enum (not serialized into the report directly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureCategory {
    /// Timed out.
    Timeout,
    /// Choked us.
    Choke,
    /// Hash mismatch.
    HashFailure,
    /// Metadata mismatch.
    MetadataMismatch,
    /// Unreachable.
    Unreachable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_metric_behaviour() {
        let mut m = SwarmMonitor::new("ab".into(), 1000, 0, 1000);
        // no peers, no budget coverage → low
        assert!(m.recovery_permyriad() < 3000);
        // with seeders and full budget → high
        m.record_connect(
            NetAddr::V4([1, 2, 3, 4], 6881),
            DiscoverySource::Tracker,
            0,
            true,
        );
        m.set_downloaded(0, 0);
        assert!(m.recovery_permyriad() >= 9000);
        // downloaded everything → certain
        m.set_downloaded(1000, 0);
        assert_eq!(m.recovery_permyriad(), 10000);
    }

    #[test]
    fn report_roundtrip_json() {
        let mut m = SwarmMonitor::new(
            "0123456789abcdef0123456789abcdef01234567".into(),
            5000,
            0,
            2000,
        );
        m.record_discovery(DiscoverySource::Tracker);
        m.record_connect(
            NetAddr::V4([10, 0, 0, 1], 6881),
            DiscoverySource::Tracker,
            0,
            false,
        );
        m.record_piece_cover(NetAddr::V4([10, 0, 0, 1], 6881), 3);
        let json = m.report_json(100).unwrap();
        // JSON parses back through nextjson
        let decoded: SwarmReport = nextjson::nextdecode(&json).unwrap();
        assert_eq!(decoded.total_size, 5000);
        assert_eq!(decoded.leechers, 1);
        assert_eq!(decoded.peers.len(), 1);
    }
}
