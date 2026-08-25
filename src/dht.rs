//! Kademlia DHT (BEP-5/42): pure `no_std` KRPC engine — routing table,
//! transactions, announce tokens, iterative lookups. BEP-5 token auth for
//! `announce_peer`; iterative `get_peers`/`find_node` with K-closest pruning.

use crate::crypto::{hmac_sha256, Rng};
use crate::error::{Error, Result};
use crate::platform::NetAddr;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

/// Bucket size.
pub const K: usize = 8;
/// Parallelism factor.
pub const ALPHA: usize = 3;
/// Lookup timeout (ms).
pub const LOOKUP_TIMEOUT_MS: u64 = 60_000;

/// A 160-bit Kademlia node id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub [u8; 20]);

impl NodeId {
    /// Random node id.
    pub fn random(rng: &mut Rng) -> Self {
        NodeId(rng.bytes20())
    }
    /// The all-zero node id (placeholder / unset).
    pub const ZERO: NodeId = NodeId([0u8; 20]);
    /// XOR distance to another id (used by the routing table).
    pub fn distance(&self, other: &NodeId) -> [u8; 20] {
        let mut d = [0u8; 20];
        for i in 0..20 {
            d[i] = self.0[i] ^ other.0[i];
        }
        d
    }
    /// Hex string.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(40);
        for b in self.0 {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}

impl Default for NodeId {
    fn default() -> Self {
        NodeId::ZERO
    }
}

/// A node known to the routing table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeEntry {
    /// Node id.
    pub id: NodeId,
    /// Endpoint.
    pub addr: NetAddr,
    /// Last time we heard from it.
    pub last_seen: u64,
    /// Consecutive failures.
    pub failed: u32,
}

impl NodeEntry {
    fn is_good(&self, now: u64) -> bool {
        self.failed == 0 && now.saturating_sub(self.last_seen) < 15 * 60 * 1000
    }
}

/// One k-bucket.
#[derive(Debug, Clone)]
struct Bucket {
    nodes: Vec<NodeEntry>,
}

impl Bucket {
    fn new() -> Self {
        Bucket { nodes: Vec::new() }
    }
    fn get(&self, id: &NodeId) -> Option<usize> {
        self.nodes.iter().position(|n| n.id == *id)
    }
    fn get_mut(&mut self, id: &NodeId) -> Option<&mut NodeEntry> {
        self.nodes.iter_mut().find(|n| n.id == *id)
    }
    /// Insert or refresh; returns whether the table changed.
    fn insert(&mut self, e: NodeEntry, now: u64, k: usize) -> bool {
        if let Some(pos) = self.get(&e.id) {
            let mut node = self.nodes.remove(pos);
            node.last_seen = now;
            node.failed = 0;
            node.addr = e.addr;
            self.nodes.push(node);
            return true;
        }
        if self.nodes.len() < k {
            self.nodes.push(e);
            return true;
        }
        // bucket full: replace the oldest non-good node
        if let Some(pos) = self.nodes.iter().position(|n| !n.is_good(now)) {
            self.nodes.remove(pos);
            self.nodes.push(e);
            return true;
        }
        false
    }
    fn remove(&mut self, id: &NodeId) {
        if let Some(pos) = self.get(id) {
            self.nodes.remove(pos);
        }
    }
}

/// The 160-bucket routing table.
#[derive(Debug, Clone)]
pub struct RoutingTable {
    id: NodeId,
    buckets: Vec<Bucket>,
    k: usize,
}

impl RoutingTable {
    /// Create a table for our node id.
    pub fn new(id: NodeId, k: usize) -> Self {
        let mut buckets = Vec::with_capacity(160);
        for _ in 0..160 {
            buckets.push(Bucket::new());
        }
        RoutingTable { id, buckets, k }
    }

    /// Bucket index = length of the common prefix between our id and `id`.
    fn bucket_index(&self, id: &NodeId) -> usize {
        for i in 0..20 {
            let diff = self.id.0[i] ^ id.0[i];
            if diff != 0 {
                return i * 8 + (7 - diff.leading_zeros() as usize);
            }
        }
        159
    }

    /// Insert a node; returns true if stored/refreshed.
    pub fn insert(&mut self, e: NodeEntry, now: u64) -> bool {
        if e.id == self.id {
            return false;
        }
        // Drop same-endpoint entries (bootstrap ZERO placeholder / stale) so the real id re-inserts into the correct bucket exactly once.
        if e.id != NodeId::ZERO {
            for b in &mut self.buckets {
                b.nodes.retain(|n| n.addr != e.addr);
            }
        }
        let idx = self.bucket_index(&e.id);
        self.buckets[idx].insert(e, now, self.k)
    }

    /// Does the table know this id?
    pub fn contains(&self, id: &NodeId) -> bool {
        let idx = self.bucket_index(id);
        self.buckets[idx].get(id).is_some()
    }

    /// Mark a node as failed (increment failure count, evict when > 3).
    pub fn on_failure(&mut self, id: &NodeId, now: u64) {
        let idx = self.bucket_index(id);
        let mut evict = false;
        if let Some(n) = self.buckets[idx].get_mut(id) {
            n.failed = n.failed.saturating_add(1);
            n.last_seen = now;
            evict = n.failed > 3;
        }
        if evict {
            self.buckets[idx].remove(id);
        }
    }

    /// Mark a node as alive (insert/refresh).
    pub fn on_response(&mut self, id: &NodeId, addr: NetAddr, now: u64) {
        self.insert(
            NodeEntry {
                id: *id,
                addr,
                last_seen: now,
                failed: 0,
            },
            now,
        );
    }

    /// The `n` closest known nodes to `target` (sorted by XOR distance).
    pub fn closest(&self, target: &NodeId, n: usize) -> Vec<NodeEntry> {
        let mut all: Vec<NodeEntry> = Vec::new();
        for b in &self.buckets {
            all.extend(b.nodes.iter().cloned());
        }
        all.sort_by_key(|a| a.id.distance(target));
        all.truncate(n);
        all
    }

    /// Number of known nodes.
    pub fn size(&self) -> usize {
        self.buckets.iter().map(|b| b.nodes.len()).sum()
    }

    /// Collect up to `limit` known nodes spread across buckets — one per
    /// bucket — for persistence / bootstrap (good geographic coverage).
    pub fn export(&self, limit: usize) -> Vec<NodeEntry> {
        let mut out = Vec::new();
        for b in &self.buckets {
            if let Some(n) = b.nodes.first() {
                out.push(n.clone());
                if out.len() >= limit {
                    break;
                }
            }
        }
        out
    }
}

// ---------- KRPC ----------

/// A parsed KRPC message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KrpcBody {
    /// A query.
    Query {
        /// Query method name (`ping`, `find_node`, `get_peers`, `announce_peer`).
        q: &'static str,
        /// Method arguments.
        args: Args,
    },
    /// A response.
    Response {
        /// Responding node id.
        id: NodeId,
        /// Response payload.
        resp: Resp,
        /// BEP-42: the responder's observation of the **sender's** address,
        /// compact-encoded (4 bytes IPv4 / 16 bytes IPv6). Lets a node
        /// behind NAT learn its external endpoint from well-behaved peers.
        ip: Option<Vec<u8>>,
    },
    /// An error `[code, message]`.
    Error {
        /// BEP-5 error code.
        code: i32,
        /// Error description.
        msg: String,
    },
}

/// Query arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Args {
    /// Querying node id.
    pub id: NodeId,
    /// `find_node` target.
    pub target: Option<NodeId>,
    /// `get_peers` / `announce_peer` infohash.
    pub info_hash: Option<[u8; 20]>,
    /// `announce_peer` port.
    pub port: Option<u16>,
    /// `announce_peer` token.
    pub token: Option<Vec<u8>>,
    /// `announce_peer` implied_port.
    pub implied_port: Option<u8>,
}

/// Response payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resp {
    /// `ping`
    Ping {
        /// Responding node id.
        id: NodeId,
    },
    /// `find_node`
    FindNode {
        /// Responding node id.
        id: NodeId,
        /// Closest nodes found.
        nodes: Vec<NodeEntry>,
    },
    /// `get_peers`
    GetPeers {
        /// Responding node id.
        id: NodeId,
        /// Token required for `announce_peer`.
        token: Vec<u8>,
        /// Peer addresses (compact encoding).
        values: Vec<NetAddr>,
        /// Closest nodes.
        nodes: Vec<NodeEntry>,
    },
    /// `announce_peer`
    AnnouncePeer {
        /// Responding node id.
        id: NodeId,
    },
}

/// A full KRPC message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KrpcMsg {
    /// Transaction id (bytes).
    pub t: Vec<u8>,
    /// Body.
    pub body: KrpcBody,
}

fn node_to_compact4(n: &NodeEntry) -> [u8; 26] {
    let mut out = [0u8; 26];
    out[..20].copy_from_slice(&n.id.0);
    if let Some(b) = n.addr.to_compact6() {
        out[20..].copy_from_slice(&b);
    }
    out
}

fn node_to_compact6(n: &NodeEntry) -> [u8; 38] {
    let mut out = [0u8; 38];
    out[..20].copy_from_slice(&n.id.0);
    if let Some(b) = n.addr.to_compact18() {
        out[20..].copy_from_slice(&b);
    }
    out
}

fn compact_peers(values: &[NetAddr]) -> (Vec<u8>, Vec<u8>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for v in values {
        match v {
            NetAddr::V4(_, _) => {
                if let Some(b) = v.to_compact6() {
                    v4.extend_from_slice(&b);
                }
            }
            NetAddr::V6(_, _) => {
                if let Some(b) = v.to_compact18() {
                    v6.extend_from_slice(&b);
                }
            }
        }
    }
    (v4, v6)
}

fn compact_nodes(nodes: &[NodeEntry]) -> (Vec<u8>, Vec<u8>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for n in nodes {
        match n.addr {
            NetAddr::V4(_, _) => v4.extend_from_slice(&node_to_compact4(n)),
            NetAddr::V6(_, _) => v6.extend_from_slice(&node_to_compact6(n)),
        }
    }
    (v4, v6)
}

/// Encode a KRPC message to bencode.
pub fn encode(msg: &KrpcMsg) -> Vec<u8> {
    use crate::bencode::{bytes, dict, int, list, BVal};
    let mut root: Vec<(&[u8], BVal)> = vec![(b"t", bytes(msg.t.clone()))];
    match &msg.body {
        KrpcBody::Query { q, args } => {
            root.push((b"y", bytes("q")));
            root.push((b"q", bytes(q.as_bytes())));
            let mut a: Vec<(&[u8], BVal)> = vec![(b"id", bytes(args.id.0.to_vec()))];
            if let Some(t) = &args.target {
                a.push((b"target", bytes(t.0.to_vec())));
            }
            if let Some(h) = &args.info_hash {
                a.push((b"info_hash", bytes(h.to_vec())));
            }
            if let Some(p) = args.port {
                a.push((b"port", int(p as i64)));
            }
            if let Some(t) = &args.token {
                a.push((b"token", bytes(t.clone())));
            }
            if let Some(ip) = args.implied_port {
                a.push((b"implied_port", int(ip as i64)));
            }
            root.push((b"a", dict(a)));
        }
        KrpcBody::Response { id, resp, ip } => {
            root.push((b"y", bytes("r")));
            let mut r: Vec<(&[u8], BVal)> = vec![(b"id", bytes(id.0.to_vec()))];
            // BEP-42: report the sender's address as observed (only when the
            // request came from a routable endpoint — never a private/loopback
            // one, which would leak a LAN address and poison NAT detection).
            if let Some(ipv) = ip {
                if ipv.len() == 4 || ipv.len() == 16 {
                    r.push((b"ip", bytes(ipv.clone())));
                }
            }
            match resp {
                Resp::Ping { .. } => {}
                Resp::AnnouncePeer { .. } => {}
                Resp::FindNode { nodes, .. } => {
                    let (v4, v6) = compact_nodes(nodes);
                    r.push((b"nodes", bytes(v4)));
                    if !v6.is_empty() {
                        r.push((b"nodes6", bytes(v6)));
                    }
                }
                Resp::GetPeers {
                    token,
                    values,
                    nodes,
                    ..
                } => {
                    r.push((b"token", bytes(token.clone())));
                    let (v4, v6) = compact_peers(values);
                    if !v4.is_empty() {
                        r.push((b"values", bytes(v4)));
                    }
                    if !v6.is_empty() {
                        r.push((b"values6", bytes(v6)));
                    }
                    let (n4, n6) = compact_nodes(nodes);
                    if !n4.is_empty() {
                        r.push((b"nodes", bytes(n4)));
                    }
                    if !n6.is_empty() {
                        r.push((b"nodes6", bytes(n6)));
                    }
                }
            }
            root.push((b"r", dict(r)));
        }
        KrpcBody::Error { code, msg } => {
            root.push((b"y", bytes("e")));
            root.push((
                b"e",
                list(vec![int(*code as i64), bytes(msg.as_bytes().to_vec())]),
            ));
        }
    }
    crate::bencode::encode_to_vec(&dict(root))
}

/// Decode a KRPC message.
pub fn decode(payload: &[u8]) -> Result<KrpcMsg> {
    use crate::bencode::BVal;
    let v = BVal::parse(payload)?;
    let d = v.as_dict().ok_or(Error::Dht)?;
    let t = d
        .get(&b"t"[..])
        .and_then(|x| x.as_bytes())
        .ok_or(Error::Dht)?
        .to_vec();
    let y = d
        .get(&b"y"[..])
        .and_then(|x| x.as_bytes())
        .ok_or(Error::Dht)?;
    match y {
        b"q" => {
            let q = d
                .get(&b"q"[..])
                .and_then(|x| x.as_str())
                .ok_or(Error::Dht)?;
            let a = d
                .get(&b"a"[..])
                .and_then(|x| x.as_dict())
                .ok_or(Error::Dht)?;
            let id = NodeId(read20(
                a.get(&b"id"[..])
                    .and_then(|x| x.as_bytes())
                    .ok_or(Error::Dht)?,
            )?);
            let mut args = Args {
                id,
                ..Default::default()
            };
            args.target = a
                .get(&b"target"[..])
                .and_then(|x| x.as_bytes())
                .and_then(|b| read20(b).ok())
                .map(NodeId);
            args.info_hash = a
                .get(&b"info_hash"[..])
                .and_then(|x| x.as_bytes())
                .and_then(|b| read20(b).ok());
            args.port = a
                .get(&b"port"[..])
                .and_then(|x| x.as_int())
                .map(|i| i as u16);
            args.token = a
                .get(&b"token"[..])
                .and_then(|x| x.as_bytes())
                .map(|b| b.to_vec());
            args.implied_port = a
                .get(&b"implied_port"[..])
                .and_then(|x| x.as_int())
                .map(|i| i as u8);
            let qname: &'static str = match q {
                "ping" => "ping",
                "find_node" => "find_node",
                "get_peers" => "get_peers",
                "announce_peer" => "announce_peer",
                _ => return Err(Error::Dht),
            };
            Ok(KrpcMsg {
                t,
                body: KrpcBody::Query { q: qname, args },
            })
        }
        b"r" => {
            let r = d
                .get(&b"r"[..])
                .and_then(|x| x.as_dict())
                .ok_or(Error::Dht)?;
            let id = NodeId(read20(
                r.get(&b"id"[..])
                    .and_then(|x| x.as_bytes())
                    .ok_or(Error::Dht)?,
            )?);
            // BEP-42: the sender's observation of OUR address (4/16 bytes;
            // tolerate the 6/18-byte ip:port form some clients use).
            let ip = r
                .get(&b"ip"[..])
                .and_then(|x| x.as_bytes())
                .map(|b| b.to_vec())
                .filter(|b| b.len() == 4 || b.len() == 6 || b.len() == 16 || b.len() == 18);
            let body = if r.contains_key(&b"token"[..]) {
                let token = r
                    .get(&b"token"[..])
                    .and_then(|x| x.as_bytes())
                    .unwrap_or(&[])
                    .to_vec();
                let mut peers = parse_compact_peers(r.get(&b"values"[..]));
                peers.extend(parse_compact_peers6(r.get(&b"values6"[..])));
                let mut nodes = parse_compact_nodes(r.get(&b"nodes"[..]));
                nodes.extend(parse_compact_nodes6(r.get(&b"nodes6"[..])));
                KrpcBody::Response {
                    id,
                    resp: Resp::GetPeers {
                        id,
                        token,
                        values: peers,
                        nodes,
                    },
                    ip,
                }
            } else if r.contains_key(&b"nodes"[..]) {
                let mut nodes = parse_compact_nodes(r.get(&b"nodes"[..]));
                nodes.extend(parse_compact_nodes6(r.get(&b"nodes6"[..])));
                KrpcBody::Response {
                    id,
                    resp: Resp::FindNode { id, nodes },
                    ip,
                }
            } else {
                KrpcBody::Response {
                    id,
                    resp: Resp::Ping { id },
                    ip,
                }
            };
            Ok(KrpcMsg { t, body })
        }
        b"e" => {
            let e = d
                .get(&b"e"[..])
                .and_then(|x| x.as_list())
                .ok_or(Error::Dht)?;
            let code = e.first().and_then(|x| x.as_int()).unwrap_or(-1) as i32;
            let msg = e.get(1).and_then(|x| x.as_str()).unwrap_or("").to_string();
            Ok(KrpcMsg {
                t,
                body: KrpcBody::Error { code, msg },
            })
        }
        _ => Err(Error::Dht),
    }
}

fn read20(b: &[u8]) -> Result<[u8; 20]> {
    if b.len() != 20 {
        return Err(Error::Dht);
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(b);
    Ok(out)
}

fn parse_compact_nodes(v: Option<&crate::bencode::BVal>) -> Vec<NodeEntry> {
    let mut out = Vec::new();
    if let Some(b) = v.and_then(|x| x.as_bytes()) {
        for c in b.as_chunks::<26>().0 {
            let mut id = [0u8; 20];
            id.copy_from_slice(&c[..20]);
            if let Some(addr) = NetAddr::from_compact6(&c[20..]) {
                out.push(NodeEntry {
                    id: NodeId(id),
                    addr,
                    last_seen: 0,
                    failed: 0,
                });
            }
        }
    }
    out
}

fn parse_compact_nodes6(v: Option<&crate::bencode::BVal>) -> Vec<NodeEntry> {
    let mut out = Vec::new();
    if let Some(b) = v.and_then(|x| x.as_bytes()) {
        for c in b.as_chunks::<38>().0 {
            let mut id = [0u8; 20];
            id.copy_from_slice(&c[..20]);
            if let Some(addr) = NetAddr::from_compact18(&c[20..]) {
                out.push(NodeEntry {
                    id: NodeId(id),
                    addr,
                    last_seen: 0,
                    failed: 0,
                });
            }
        }
    }
    out
}

fn parse_compact_peers(v: Option<&crate::bencode::BVal>) -> Vec<NetAddr> {
    let mut out = Vec::new();
    if let Some(b) = v.and_then(|x| x.as_bytes()) {
        for c in b.as_chunks::<6>().0 {
            if let Some(a) = NetAddr::from_compact6(c) {
                out.push(a);
            }
        }
    }
    out
}

fn parse_compact_peers6(v: Option<&crate::bencode::BVal>) -> Vec<NetAddr> {
    let mut out = Vec::new();
    if let Some(b) = v.and_then(|x| x.as_bytes()) {
        for c in b.as_chunks::<18>().0 {
            if let Some(a) = NetAddr::from_compact18(c) {
                out.push(a);
            }
        }
    }
    out
}

// ---------- DHT core ----------

/// Result of processing a datagram.
pub enum DatagramOutcome {
    /// Send this payload back to the sender.
    Reply(Vec<u8>),
    /// Nothing to send.
    None,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    Ping,
    Lookup,
    Announce,
}

struct Pending {
    node: NodeEntry,
    query: Vec<u8>,
    sent_at: u64,
    retries: u32,
    kind: PendingKind,
    /// For Lookup: the lookup target this query serves.
    lookup_target: Option<[u8; 20]>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LookupKind {
    GetPeers,
    FindNode,
}

struct Lookup {
    kind: LookupKind,
    target: [u8; 20],
    closest: Vec<NodeEntry>,
    queried: Vec<NodeId>,
    /// (node addr, token) — token bound to the node that issued it.
    token_nodes: Vec<(NetAddr, Vec<u8>)>,
    values: Vec<NetAddr>,
    announce_port: u16,
    started: u64,
    done: bool,
}

/// The DHT engine.
pub struct Dht {
    /// Our node id.
    pub id: NodeId,
    /// Our listen port.
    pub port: u16,
    table: RoutingTable,
    secret: [u8; 16],
    tx_counter: u32,
    pending: BTreeMap<u32, Pending>,
    lookups: Vec<Lookup>,
    /// Endpoints we have announced to recently (dedupe).
    announced: Vec<NetAddr>,
    /// Peers discovered by `get_peers` lookups, kept **beyond the lookup's
    /// lifetime** (infohash → peers). A lookup that is pruned (timeout or
    /// exhausted before the bootstrap populated the table) must not throw
    /// away peers that arrived late; the session drains this cache every
    /// tick, so late bootstrap results still reach the downloader.
    peer_cache: BTreeMap<[u8; 20], Vec<NetAddr>>,
    /// BEP-5 peer storage served by `get_peers` responses: infohash →
    /// announced (endpoint, expiry). Without this store, `announce_peer`
    /// replies success but drops the peer, and `get_peers` can never answer
    /// with any value — the whole DHT discovery path would be a no-op even
    /// after a successful bootstrap.
    peer_store: BTreeMap<[u8; 20], Vec<(NetAddr, u64)>>,
    /// BEP-42 external-address observations: observed address (16 bytes,
    /// IPv4 in the first 4) → (witness endpoint, observation time). Only
    /// *distinct* witnesses count, so a single malicious/buggy node cannot
    /// poison our NAT-detected endpoint.
    external_witnesses: BTreeMap<[u8; 16], Vec<(NetAddr, u64)>>,
    /// The external address confirmed by >= [`Self::EXTERNAL_MIN_WITNESSES`]
    /// distinct DHT nodes (cross-confirmed, BEP-42).
    confirmed_external: Option<[u8; 16]>,
    /// Externally-observed UDP port candidates (port → witness + time),
    /// cross-confirmed like the IP. Filled from BEP-42 `ip` values that
    /// carry a port (the 6/18-byte forms).
    external_port_witnesses: BTreeMap<u16, Vec<(NetAddr, u64)>>,
    /// The external UDP port confirmed by >= [`Self::EXTERNAL_MIN_WITNESSES`]
    /// distinct DHT nodes.
    confirmed_external_port: Option<u16>,
}

impl Dht {
    /// Distinct nodes that must agree before an external address is trusted.
    const EXTERNAL_MIN_WITNESSES: usize = 3;
    /// How long a witness observation stays valid (10 minutes).
    const EXTERNAL_WITNESS_TTL_MS: u64 = 10 * 60 * 1000;
    /// Cap on tracked observed addresses (flood bound).
    const EXTERNAL_MAX_OBSERVED: usize = 64;
    /// Create with an id (seed from host entropy by the caller).
    pub fn new(id: NodeId, port: u16, rng: &mut Rng) -> Self {
        let mut secret = [0u8; 16];
        rng.fill(&mut secret);
        Dht {
            id,
            port,
            table: RoutingTable::new(id, K),
            secret,
            tx_counter: 0,
            pending: BTreeMap::new(),
            lookups: Vec::new(),
            announced: Vec::new(),
            peer_cache: BTreeMap::new(),
            peer_store: BTreeMap::new(),
            external_witnesses: BTreeMap::new(),
            confirmed_external: None,
            external_port_witnesses: BTreeMap::new(),
            confirmed_external_port: None,
        }
    }

    /// Routing table access (for stats/monitoring).
    pub fn table(&self) -> &RoutingTable {
        &self.table
    }

    /// Export up to `limit` known nodes as compact 26-byte entries
    /// (20-byte id + 6-byte IPv4 endpoint) for persistence/bootstrap.
    pub fn export_nodes(&self, limit: usize) -> Vec<Vec<u8>> {
        self.table
            .export(limit)
            .iter()
            .map(|n| node_to_compact4(n).to_vec())
            .collect()
    }

    /// Import compact 26-byte node entries (as produced by
    /// [`Dht::export_nodes`]). Returns the number of nodes actually stored.
    pub fn import_nodes(&mut self, entries: &[Vec<u8>], now: u64) -> usize {
        let mut stored = 0usize;
        for e in entries {
            if e.len() != 26 {
                continue;
            }
            let mut id = [0u8; 20];
            id.copy_from_slice(&e[..20]);
            if let Some(addr) = NetAddr::from_compact6(&e[20..]) {
                let entry = NodeEntry {
                    id: NodeId(id),
                    addr,
                    last_seen: now,
                    failed: 0,
                };
                if self.table.insert(entry, now) {
                    stored += 1;
                }
            }
        }
        stored
    }

    /// Cap on tracked in-flight transactions (bounds memory under flood).
    const MAX_PENDING: usize = 4096;

    /// Bounds on the discovered-peer cache (memory bound under flood).
    const PEER_CACHE_MAX_HASHES: usize = 256;
    /// Per-infohash cap on cached peers.
    const PEER_CACHE_MAX_PER_HASH: usize = 256;

    /// How long a BEP-5 announced peer stays servable (30 minutes, matching
    /// the mainstream clients).
    const PEER_STORE_TTL_MS: u64 = 30 * 60 * 1000;
    /// Cap on announced peers served per infohash.
    const PEER_STORE_MAX_PER_HASH: usize = 64;
    /// Cap on infohashes in the peer store.
    const PEER_STORE_MAX_HASHES: usize = 1024;

    fn push_pending(&mut self, tx: u32, p: Pending) -> bool {
        if self.pending.len() >= Self::MAX_PENDING {
            return false;
        }
        self.pending.insert(tx, p);
        true
    }

    fn next_tx(&mut self) -> u32 {
        self.tx_counter = self.tx_counter.wrapping_add(1);
        self.tx_counter
    }

    /// BEP-5 token: HMAC(ip, secret), first 8 bytes hex-encoded.
    pub fn make_token(&self, addr: &NetAddr) -> Vec<u8> {
        let ip = match addr {
            NetAddr::V4(ip, _) => ip.to_vec(),
            NetAddr::V6(ip, _) => ip.to_vec(),
        };
        let h = hmac_sha256(&self.secret, &ip);
        let mut t = String::with_capacity(16);
        for b in &h[..8] {
            t.push_str(&format!("{:02x}", b));
        }
        t.into_bytes()
    }

    /// Verify an announce token.
    pub fn verify_token(&self, addr: &NetAddr, token: &[u8]) -> bool {
        self.make_token(addr) == token
    }

    /// Ping a node (bootstrap / bucket refresh).
    pub fn ping(&mut self, node: &NodeEntry, now: u64) -> u32 {
        let tx = self.next_tx();
        let msg = KrpcMsg {
            t: tx.to_be_bytes()[2..].to_vec(),
            body: KrpcBody::Query {
                q: "ping",
                args: Args {
                    id: self.id,
                    ..Default::default()
                },
            },
        };
        if !self.push_pending(
            tx,
            Pending {
                node: node.clone(),
                query: encode(&msg),
                sent_at: now,
                retries: 0,
                kind: PendingKind::Ping,
                lookup_target: None,
            },
        ) {
            return 0;
        }
        tx
    }

    /// Bootstrap: insert resolved seeds into the table immediately (ZERO placeholder) and ping them,
    /// so lookups + bucket refresh start before the ping round-trip; the real id replaces the placeholder.
    pub fn bootstrap(&mut self, seeds: &[NetAddr], now: u64) {
        for s in seeds {
            let e = NodeEntry {
                id: NodeId::ZERO,
                addr: *s,
                last_seen: now,
                failed: 0,
            };
            self.table.insert(e.clone(), now);
            self.ping(&e, now);
        }
    }

    /// Start a `get_peers` lookup for an infohash (with announce port).
    pub fn get_peers(&mut self, info_hash: [u8; 20], announce_port: u16, now: u64) {
        if self
            .lookups
            .iter()
            .any(|l| l.target == info_hash && !l.done)
        {
            return;
        }
        let closest = self.table.closest(&NodeId(info_hash), K);
        self.lookups.push(Lookup {
            kind: LookupKind::GetPeers,
            target: info_hash,
            closest,
            queried: Vec::new(),
            token_nodes: Vec::new(),
            values: Vec::new(),
            announce_port,
            started: now,
            done: false,
        });
    }

    /// Start a `find_node` lookup for routing refresh.
    pub fn find_node(&mut self, target: NodeId, now: u64) {
        let closest = self.table.closest(&target, K);
        self.lookups.push(Lookup {
            kind: LookupKind::FindNode,
            target: target.0,
            closest,
            queried: Vec::new(),
            token_nodes: Vec::new(),
            values: Vec::new(),
            announce_port: 0,
            started: now,
            done: false,
        });
    }

    /// Periodic maintenance: retry pending, drive lookups, prune dedupe.
    pub fn tick(&mut self, now: u64) {
        let expired: Vec<u32> = self
            .pending
            .iter()
            .filter(|(_, p)| now.saturating_sub(p.sent_at) > 2000)
            .map(|(k, _)| *k)
            .collect();
        for tx in expired {
            if let Some(p) = self.pending.get_mut(&tx) {
                if p.retries < 3 {
                    p.retries += 1;
                    p.sent_at = now;
                } else {
                    let node = p.node.clone();
                    self.pending.remove(&tx);
                    self.table.on_failure(&node.id, now);
                }
            }
        }
        let mut idx = 0;
        while idx < self.lookups.len() {
            let done = self.drive_lookup(idx, now);
            if done {
                self.lookups.remove(idx);
            } else {
                idx += 1;
            }
        }
        // Prune BEP-5 announced peers whose TTL expired (and bound the store).
        let expired: Vec<[u8; 20]> = self
            .peer_store
            .iter()
            .filter(|(_, v)| v.iter().all(|(_, exp)| now >= *exp))
            .map(|(k, _)| *k)
            .collect();
        for h in expired {
            if let Some(v) = self.peer_store.get_mut(&h) {
                v.retain(|(_, exp)| now < *exp);
                if v.is_empty() {
                    self.peer_store.remove(&h);
                }
            }
        }
        // Keep only the most recent announce targets (bounded dedupe).
        if self.announced.len() > 200 {
            let excess = self.announced.len() - 200;
            self.announced.drain(..excess);
        }
    }

    /// Advance one lookup: query the closest unqueried nodes.
    fn drive_lookup(&mut self, idx: usize, now: u64) -> bool {
        let target = self.lookups[idx].target;
        let kind = self.lookups[idx].kind;
        {
            let target_id = NodeId(target);
            let fresh = self.table.closest(&target_id, K);
            let lk = &mut self.lookups[idx];
            for n in fresh {
                if !lk.closest.iter().any(|c| c.id == n.id) {
                    lk.closest.push(n);
                }
            }
            lk.closest.sort_by_key(|a| a.id.distance(&target_id));
            lk.closest.truncate(K);
        }
        if now.saturating_sub(self.lookups[idx].started) > LOOKUP_TIMEOUT_MS {
            self.lookups[idx].done = true;
            return true;
        }
        // query up to ALPHA unqueried closest nodes
        let to_query: Vec<NodeEntry> = self.lookups[idx]
            .closest
            .iter()
            .filter(|c| !self.lookups[idx].queried.contains(&c.id) && c.id != self.id)
            .take(ALPHA)
            .cloned()
            .collect();
        if to_query.is_empty() {
            // Nothing to query right now. If we never even queried a single
            // node, the routing table is empty because the bootstrap pings
            // are still in flight — the lookup must NOT die here: each tick
            // refreshes `closest` from the table, so once a bootstrap node
            // answers, the lookup starts querying it. Only a lookup that has
            // actually exhausted its candidate set is finished. (A never-
            // populated table is still bounded by LOOKUP_TIMEOUT_MS above.)
            if self.lookups[idx].queried.is_empty() {
                return false;
            }
            return true; // all queried; no more progress possible
        }
        for node in to_query {
            let tx = self.next_tx();
            let q = match kind {
                LookupKind::GetPeers => "get_peers",
                LookupKind::FindNode => "find_node",
            };
            let mut args = Args {
                id: self.id,
                ..Default::default()
            };
            match kind {
                LookupKind::GetPeers => args.info_hash = Some(target),
                LookupKind::FindNode => args.target = Some(NodeId(target)),
            }
            let msg = KrpcMsg {
                t: tx.to_be_bytes()[2..].to_vec(),
                body: KrpcBody::Query { q, args },
            };
            self.lookups[idx].queried.push(node.id);
            if !self.push_pending(
                tx,
                Pending {
                    node,
                    query: encode(&msg),
                    sent_at: now,
                    retries: 0,
                    kind: PendingKind::Lookup,
                    lookup_target: Some(target),
                },
            ) {
                return false;
            }
        }
        false
    }

    /// Collect outgoing datagrams. The engine sends these via the host UDP.
    ///
    /// Packet pacing: at most 16 datagrams per 100 ms tick (~160/s peak),
    /// so lookup fan-out / bootstrap / announce storms across many sessions
    /// never dump hundreds of packets on the network device; the rest retry next tick.
    pub fn outgoing(&mut self) -> Vec<(NetAddr, Vec<u8>)> {
        const MAX_OUTGOING_PER_TICK: usize = 16;
        let mut out = Vec::with_capacity(MAX_OUTGOING_PER_TICK.min(self.pending.len()));
        let txs: Vec<u32> = self.pending.keys().copied().collect();
        for tx in txs {
            if out.len() >= MAX_OUTGOING_PER_TICK {
                break;
            }
            if let Some(p) = self.pending.get(&tx) {
                out.push((p.node.addr, p.query.clone()));
            }
        }
        out
    }

    /// Process an incoming datagram; returns an optional reply.
    pub fn handle_datagram(
        &mut self,
        from: NetAddr,
        payload: &[u8],
        now: u64,
    ) -> Result<DatagramOutcome> {
        let msg = match decode(payload) {
            Ok(m) => m,
            Err(_) => return Ok(DatagramOutcome::None),
        };
        match msg.body {
            KrpcBody::Query { q, args } => {
                self.table.on_response(&args.id, from, now);
                match q {
                    "ping" => {
                        let reply = KrpcMsg {
                            t: msg.t,
                            body: KrpcBody::Response {
                                id: self.id,
                                resp: Resp::Ping { id: self.id },
                                ip: observed_compact(&from),
                            },
                        };
                        Ok(DatagramOutcome::Reply(encode(&reply)))
                    }
                    "find_node" => {
                        let target = args.target.unwrap_or(self.id);
                        let nodes = self.table.closest(&target, K);
                        let reply = KrpcMsg {
                            t: msg.t,
                            body: KrpcBody::Response {
                                id: self.id,
                                resp: Resp::FindNode { id: self.id, nodes },
                                ip: observed_compact(&from),
                            },
                        };
                        Ok(DatagramOutcome::Reply(encode(&reply)))
                    }
                    "get_peers" => {
                        let token = self.make_token(&from);
                        let ih = args.info_hash.unwrap_or([0; 20]);
                        let nodes = self.table.closest(&NodeId(ih), K);
                        // BEP-5: serve the peers that announced for this
                        // infohash (compact values), alongside the closest
                        // nodes so the querying node can continue its
                        // iterative lookup.
                        let values: Vec<NetAddr> = self
                            .peer_store
                            .get(&ih)
                            .map(|v| v.iter().map(|(a, _)| *a).collect())
                            .unwrap_or_default();
                        let reply = KrpcMsg {
                            t: msg.t,
                            body: KrpcBody::Response {
                                id: self.id,
                                resp: Resp::GetPeers {
                                    id: self.id,
                                    token,
                                    values,
                                    nodes,
                                },
                                ip: observed_compact(&from),
                            },
                        };
                        Ok(DatagramOutcome::Reply(encode(&reply)))
                    }
                    "announce_peer" => {
                        let ok = match (&args.info_hash, &args.token) {
                            (Some(_), Some(tok)) => self.verify_token(&from, tok),
                            _ => false,
                        };
                        if !ok {
                            let reply = KrpcMsg {
                                t: msg.t,
                                body: KrpcBody::Error {
                                    code: 203,
                                    msg: String::from("bad token"),
                                },
                            };
                            return Ok(DatagramOutcome::Reply(encode(&reply)));
                        }
                        // BEP-5: store the announcing peer so later
                        // `get_peers` queries can return it. The port is the
                        // caller's listening port (or the UDP source port
                        // when `implied_port` is set); the IP is the UDP
                        // source address.
                        if let Some(ih) = args.info_hash {
                            let port =
                                if args.implied_port == Some(1) || args.port.unwrap_or(0) == 0 {
                                    from.port()
                                } else {
                                    args.port.unwrap_or_else(|| from.port())
                                };
                            let endpoint = match from {
                                NetAddr::V4(ip, _) => NetAddr::V4(ip, port),
                                NetAddr::V6(ip, _) => NetAddr::V6(ip, port),
                            };
                            let entry = self.peer_store.entry(ih).or_default();
                            entry.retain(|(a, _)| *a != endpoint); // refresh
                            entry.push((endpoint, now + Self::PEER_STORE_TTL_MS));
                            if entry.len() > Self::PEER_STORE_MAX_PER_HASH {
                                entry.drain(..entry.len() - Self::PEER_STORE_MAX_PER_HASH);
                            }
                            while self.peer_store.len() > Self::PEER_STORE_MAX_HASHES {
                                match self.peer_store.keys().next().copied() {
                                    Some(k) => {
                                        self.peer_store.remove(&k);
                                    }
                                    None => break,
                                }
                            }
                        }
                        let reply = KrpcMsg {
                            t: msg.t,
                            body: KrpcBody::Response {
                                id: self.id,
                                resp: Resp::AnnouncePeer { id: self.id },
                                ip: observed_compact(&from),
                            },
                        };
                        Ok(DatagramOutcome::Reply(encode(&reply)))
                    }
                    _ => Ok(DatagramOutcome::None),
                }
            }
            KrpcBody::Response { id, resp, ip } => {
                self.table.on_response(&id, from, now);
                // BEP-42 receive side: a response's `ip` field is the
                // responder's observation of OUR address. Cross-confirm it
                // across distinct nodes before trusting it (防污染).
                if let Some(ipv) = ip {
                    self.observe_external(&ipv, from, now);
                }
                let tx = tx_of(&msg.t);
                if let Some(p) = self.pending.remove(&tx) {
                    match p.kind {
                        PendingKind::Ping => {}
                        PendingKind::Lookup => {
                            self.consume_lookup_response(&p.node, resp, p.lookup_target, now);
                        }
                        PendingKind::Announce => {}
                    }
                }
                Ok(DatagramOutcome::None)
            }
            KrpcBody::Error { .. } => {
                let tx = tx_of(&msg.t);
                if let Some(p) = self.pending.remove(&tx) {
                    self.table.on_failure(&p.node.id, now);
                }
                Ok(DatagramOutcome::None)
            }
        }
    }

    fn consume_lookup_response(
        &mut self,
        node: &NodeEntry,
        resp: Resp,
        target: Option<[u8; 20]>,
        now: u64,
    ) {
        let (values, token, nodes) = match resp {
            Resp::GetPeers {
                token,
                values,
                nodes,
                ..
            } => (values, token, nodes),
            Resp::FindNode { nodes, .. } => (Vec::new(), Vec::new(), nodes),
            _ => return,
        };
        for n in &nodes {
            if n.id != self.id {
                self.table.insert(n.clone(), now);
            }
        }
        let tid = target.unwrap_or([0; 20]);
        for l in self.lookups.iter_mut() {
            if l.target != tid || l.done {
                continue;
            }
            if !l.queried.contains(&node.id) {
                continue;
            }
            for v in &values {
                if !l.values.contains(v) {
                    l.values.push(*v);
                }
            }
            if !token.is_empty() && !l.token_nodes.iter().any(|(a, _)| *a == node.addr) {
                l.token_nodes.push((node.addr, token.clone()));
            }
            for n in nodes.iter() {
                if !l.closest.iter().any(|c| c.id == n.id) {
                    l.closest.push(n.clone());
                }
            }
        }
        // Persist discovered peers beyond the lookup's lifetime, so results
        // that arrive late (e.g. after the bootstrap populated the table) are
        // still delivered to the session even if this lookup is pruned.
        if !values.is_empty() {
            // Scope the entry borrow so the cache can be pruned afterwards.
            {
                let entry = self.peer_cache.entry(tid).or_default();
                for v in &values {
                    if !entry.contains(v) {
                        entry.push(*v);
                    }
                }
                if entry.len() > Self::PEER_CACHE_MAX_PER_HASH {
                    entry.truncate(Self::PEER_CACHE_MAX_PER_HASH);
                }
            }
            while self.peer_cache.len() > Self::PEER_CACHE_MAX_HASHES {
                match self.peer_cache.keys().next().copied() {
                    Some(k) => {
                        self.peer_cache.remove(&k);
                    }
                    None => break,
                }
            }
        }
        self.send_announces_if_ready(tid, now);
    }

    /// Announce to every node we hold a valid token for.
    fn send_announces_if_ready(&mut self, info_hash: [u8; 20], now: u64) {
        let mut targets: Vec<(NetAddr, Vec<u8>, u16)> = Vec::new();
        for l in self.lookups.iter_mut() {
            if l.kind != LookupKind::GetPeers || l.target != info_hash || l.done {
                continue;
            }
            for (addr, token) in l.token_nodes.iter().take(20) {
                targets.push((*addr, token.clone(), l.announce_port));
            }
            break;
        }
        for (addr, token, port) in targets {
            if self.announced.contains(&addr) {
                continue;
            }
            self.announced.push(addr);
            let tx = self.next_tx();
            let args = Args {
                id: self.id,
                info_hash: Some(info_hash),
                port: Some(port),
                token: Some(token),
                implied_port: None,
                ..Default::default()
            };
            let msg = KrpcMsg {
                t: tx.to_be_bytes()[2..].to_vec(),
                body: KrpcBody::Query {
                    q: "announce_peer",
                    args,
                },
            };
            self.push_pending(
                tx,
                Pending {
                    node: NodeEntry {
                        id: NodeId::ZERO,
                        addr,
                        last_seen: now,
                        failed: 0,
                    },
                    query: encode(&msg),
                    sent_at: now,
                    retries: 0,
                    kind: PendingKind::Announce,
                    lookup_target: Some(info_hash),
                },
            );
        }
    }

    /// Peers discovered for an infohash, from live lookups **and** the
    /// persisted cache (so results survive a lookup being pruned).
    pub fn discovered_peers(&self, info_hash: &[u8; 20]) -> Vec<NetAddr> {
        let mut out = Vec::new();
        for l in &self.lookups {
            if l.kind == LookupKind::GetPeers && l.target == *info_hash {
                out.extend(l.values.iter().copied());
            }
        }
        if let Some(cached) = self.peer_cache.get(info_hash) {
            for v in cached {
                if !out.contains(v) {
                    out.push(*v);
                }
            }
        }
        out
    }

    /// Active lookups count.
    pub fn active_lookups(&self) -> usize {
        self.lookups.iter().filter(|l| !l.done).count()
    }

    /// BEP-42: record a node's observation of our external address/port; only distinct witnesses
    /// count, so a single bad node cannot poison the confirmed endpoint (>=3 votes, 10 min TTL).
    fn observe_external(&mut self, compact: &[u8], witness: NetAddr, now: u64) {
        // Accept 4/6/16/18-byte forms (IP, or IP:port); 6/18 also feed the confirmed UDP port.
        let (ip16, port) = match compact.len() {
            4 => {
                let mut b = [0u8; 16];
                b[..4].copy_from_slice(compact);
                (b, None)
            }
            6 => {
                let mut b = [0u8; 16];
                b[..4].copy_from_slice(&compact[..4]);
                (b, Some(u16::from_be_bytes([compact[4], compact[5]])))
            }
            16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(compact);
                (b, None)
            }
            18 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&compact[..16]);
                (b, Some(u16::from_be_bytes([compact[16], compact[17]])))
            }
            _ => return,
        };
        // Ignore non-routable observations (a broken/malicious node feeding us a private address).
        if !is_routable(&ip16) {
            return;
        }
        // One vote per witness address per observed IP.
        let entry = self.external_witnesses.entry(ip16).or_default();
        let witness_key = match witness {
            NetAddr::V4(ip, _) => {
                let mut b = [0u8; 16];
                b[..4].copy_from_slice(&ip);
                b
            }
            NetAddr::V6(ip, _) => ip,
        };
        if !entry.iter().any(|(w, _)| {
            let wk = match *w {
                NetAddr::V4(ip, _) => {
                    let mut b = [0u8; 16];
                    b[..4].copy_from_slice(&ip);
                    b
                }
                NetAddr::V6(ip, _) => ip,
            };
            wk == witness_key
        }) {
            entry.push((witness, now));
        }
        entry.retain(|(_, t)| now.saturating_sub(*t) < Self::EXTERNAL_WITNESS_TTL_MS);
        if entry.len() >= Self::EXTERNAL_MIN_WITNESSES {
            self.confirmed_external = Some(ip16);
        }
        // bound the observation map
        while self.external_witnesses.len() > Self::EXTERNAL_MAX_OBSERVED {
            match self.external_witnesses.keys().next().copied() {
                Some(k) => {
                    self.external_witnesses.remove(&k);
                }
                None => break,
            }
        }
        // Cross-confirm the observed UDP port (BEP-42 6/18-byte forms).
        if let Some(port) = port {
            if port != 0 {
                let entry = self.external_port_witnesses.entry(port).or_default();
                if !entry.iter().any(|(w, _)| addr_key(*w) == addr_key(witness)) {
                    entry.push((witness, now));
                }
                entry.retain(|(_, t)| now.saturating_sub(*t) < Self::EXTERNAL_WITNESS_TTL_MS);
                if entry.len() >= Self::EXTERNAL_MIN_WITNESSES {
                    self.confirmed_external_port = Some(port);
                }
                while self.external_port_witnesses.len() > 32 {
                    match self.external_port_witnesses.keys().next().copied() {
                        Some(k) => {
                            self.external_port_witnesses.remove(&k);
                        }
                        None => break,
                    }
                }
            }
        }
    }

    /// The externally-visible IP confirmed by >=3 distinct DHT nodes (BEP-42); IPv4 in the first 4 bytes.
    pub fn confirmed_external_ip(&self) -> Option<[u8; 16]> {
        self.confirmed_external
    }

    /// The externally-visible UDP port confirmed by >=3 distinct DHT nodes (BEP-42 ip:port forms).
    pub fn confirmed_external_port(&self) -> Option<u16> {
        self.confirmed_external_port
    }
}

/// Normalize a witness endpoint to a 16-byte key (IPv4 in the leading 4).
fn addr_key(a: NetAddr) -> [u8; 16] {
    match a {
        NetAddr::V4(ip, _) => {
            let mut b = [0u8; 16];
            b[..4].copy_from_slice(&ip);
            b
        }
        NetAddr::V6(ip, _) => ip,
    }
}

fn tx_of(t: &[u8]) -> u32 {
    match t.len() {
        2 => u32::from_be_bytes([0, 0, t[0], t[1]]),
        1 => t[0] as u32,
        _ => 0,
    }
}

/// Compact-encode the sender address for a BEP-42 `ip` response field.
/// Only routable endpoints are reported — reflecting a private/loopback
/// source would teach the caller a useless (or harmful) address.
fn observed_compact(from: &NetAddr) -> Option<Vec<u8>> {
    match *from {
        NetAddr::V4(ip, _) => {
            if !is_routable(&{
                let mut b = [0u8; 16];
                b[..4].copy_from_slice(&ip);
                b
            }) {
                return None;
            }
            Some(ip.to_vec())
        }
        NetAddr::V6(ip, _) => {
            if !is_routable(&ip) {
                return None;
            }
            Some(ip.to_vec())
        }
    }
}

/// Whether a 16-byte address is publicly routable (not private/loopback/
/// link-local/ULA — per RFC 1918 / 4193 / 4291 and friends). Accepts three
/// shapes: a true IPv6 address, an IPv4-mapped IPv6 (`::ffff:a.b.c.d`), and
/// a plain IPv4 stored in the first 4 bytes with the rest zero (the form
/// the BEP-42 4/6-byte `ip` values are expanded to internally).
fn is_routable(ip: &[u8; 16]) -> bool {
    // IPv4-mapped: bytes 0..10 zero, bytes 10..12 0xFF
    let mapped = ip[0..10].iter().all(|&b| b == 0) && ip[10] == 0xFF && ip[11] == 0xFF;
    if mapped {
        return is_routable_v4([ip[12], ip[13], ip[14], ip[15]]);
    }
    // Plain IPv4 in the first 4 bytes (rest zero) — as produced when
    // expanding a compact 4/6-byte BEP-42 value.
    if ip[4..].iter().all(|&b| b == 0) {
        return is_routable_v4([ip[0], ip[1], ip[2], ip[3]]);
    }
    // true IPv6: skip the unspecified address, loopback, ULA (fc00::/7),
    // link-local (fe80::/10) and multicast.
    if ip.iter().all(|&b| b == 0) {
        return false; // ::
    }
    if ip[0..15].iter().all(|&b| b == 0) && ip[15] == 1 {
        return false; // ::1
    }
    if ip[0] & 0xfe == 0xfc {
        return false; // fc00::/7 ULA
    }
    if ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80 {
        return false; // fe80::/10 link-local
    }
    if ip[0] == 0xff {
        return false; // multicast
    }
    true
}

/// RFC 1918 / loopback / link-local classification for a plain IPv4.
fn is_routable_v4(v4: [u8; 4]) -> bool {
    match v4[0] {
        0 => false,                                 // 0.0.0.0/8
        10 => false,                                // 10/8
        127 => false,                               // loopback
        169 if v4[1] == 254 => false,               // link-local
        172 if (16..=31).contains(&v4[1]) => false, // 172.16/12
        192 if v4[1] == 168 => false,               // 192.168/16
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t2(v: u32) -> Vec<u8> {
        v.to_be_bytes()[2..].to_vec()
    }

    #[test]
    fn krpc_roundtrip_ping() {
        let msg = KrpcMsg {
            t: t2(0x0102),
            body: KrpcBody::Query {
                q: "ping",
                args: Args {
                    id: NodeId([7u8; 20]),
                    ..Default::default()
                },
            },
        };
        let bytes = encode(&msg);
        let dec = decode(&bytes).unwrap();
        assert_eq!(dec.t, msg.t);
        match dec.body {
            KrpcBody::Query { q, args } => {
                assert_eq!(q, "ping");
                assert_eq!(args.id, NodeId([7u8; 20]));
            }
            _ => panic!("wrong body"),
        }
    }

    #[test]
    fn krpc_roundtrip_get_peers_response() {
        let msg = KrpcMsg {
            t: t2(3),
            body: KrpcBody::Response {
                id: NodeId([1u8; 20]),
                resp: Resp::GetPeers {
                    id: NodeId([1u8; 20]),
                    token: b"tok123".to_vec(),
                    values: vec![NetAddr::V4([1, 2, 3, 4], 6881)],
                    nodes: Vec::new(),
                },
                ip: Some(vec![203, 0, 113, 9]),
            },
        };
        let bytes = encode(&msg);
        let dec = decode(&bytes).unwrap();
        match dec.body {
            KrpcBody::Response {
                resp: Resp::GetPeers { token, values, .. },
                ip,
                ..
            } => {
                assert_eq!(token, b"tok123");
                assert_eq!(values, vec![NetAddr::V4([1, 2, 3, 4], 6881)]);
                assert_eq!(ip, Some(vec![203, 0, 113, 9]));
            }
            _ => panic!("wrong body"),
        }
    }

    #[test]
    fn routing_table_closest() {
        let mut rng = Rng::from_seed([5u8; 32]);
        let id = NodeId::random(&mut rng);
        let mut t = RoutingTable::new(id, K);
        for i in 0..30u8 {
            t.insert(
                NodeEntry {
                    id: NodeId([i; 20]),
                    addr: NetAddr::V4([1, 2, 3, i], 6881),
                    last_seen: 1,
                    failed: 0,
                },
                1,
            );
        }
        // random ids collide in k-buckets, so some drops are expected
        assert!(t.size() >= 8);
        let target = NodeId([0u8; 20]);
        let closest = t.closest(&target, 8);
        assert!(closest.len() >= 8);
        for w in closest.windows(2) {
            assert!(w[0].id.distance(&target) <= w[1].id.distance(&target));
        }
    }

    #[test]
    fn token_auth() {
        let mut rng = Rng::from_seed([9u8; 32]);
        let dht = Dht::new(NodeId::random(&mut rng), 6881, &mut rng);
        let a = NetAddr::V4([10, 0, 0, 1], 6881);
        let tok = dht.make_token(&a);
        assert!(dht.verify_token(&a, &tok));
        let b = NetAddr::V4([10, 0, 0, 2], 6881);
        assert!(!dht.verify_token(&b, &tok));
    }

    #[test]
    fn ping_query_response_flow() {
        let mut rng = Rng::from_seed([11u8; 32]);
        let mut alice = Dht::new(NodeId::random(&mut rng), 6881, &mut rng);
        let mut bob = Dht::new(NodeId::random(&mut rng), 6882, &mut rng);
        alice.bootstrap(&[NetAddr::V4([127, 0, 0, 1], 6882)], 0);
        let out = alice.outgoing();
        assert_eq!(out.len(), 1);
        let (addr, payload) = out[0].clone();
        let reply = match bob.handle_datagram(addr, &payload, 0).unwrap() {
            DatagramOutcome::Reply(b) => b,
            _ => panic!("expected reply"),
        };
        alice
            .handle_datagram(NetAddr::V4([127, 0, 0, 1], 6882), &reply, 0)
            .unwrap();
        assert!(alice.table().contains(&bob.id));
        assert!(bob.table().contains(&alice.id));
    }

    #[test]
    fn get_peers_announce_flow() {
        let mut rng = Rng::from_seed([13u8; 32]);
        let mut alice = Dht::new(NodeId::random(&mut rng), 6881, &mut rng);
        let mut bob = Dht::new(NodeId::random(&mut rng), 6882, &mut rng);
        let ih = [0xABu8; 20];
        let bob_addr = NetAddr::V4([127, 0, 0, 1], 6882);
        let alice_addr = NetAddr::V4([127, 0, 0, 1], 6881);

        // bob learns alice through a bootstrap ping
        alice.bootstrap(&[bob_addr], 0);
        for (addr, payload) in alice.outgoing() {
            if let Ok(DatagramOutcome::Reply(reply)) = bob.handle_datagram(addr, &payload, 0) {
                alice.handle_datagram(alice_addr, &reply, 0).unwrap();
            }
        }
        assert!(bob.table().contains(&alice.id));

        // bob starts a get_peers lookup for ih
        bob.get_peers(ih, 7777, 1);
        bob.tick(2); // drive the lookup so pending queries exist
        let out = bob.outgoing();
        assert!(!out.is_empty());

        // relay bob's queries to alice, collect replies
        let mut alice_replies: Vec<(NetAddr, Vec<u8>)> = Vec::new();
        for (addr, payload) in out {
            if let Ok(DatagramOutcome::Reply(reply)) = alice.handle_datagram(addr, &payload, 2) {
                alice_replies.push((addr, reply));
            }
        }
        assert!(!alice_replies.is_empty());
        for (addr, reply) in alice_replies {
            bob.handle_datagram(addr, &reply, 2).unwrap();
        }
        assert!(bob.table().contains(&alice.id));
        // bob should now announce (it has a token from alice)
        bob.tick(3);
        let out2 = bob.outgoing();
        assert!(!out2.is_empty());
        // alice must accept bob's announce (valid token)
        let mut accepted = false;
        for (addr, payload) in out2 {
            if let Ok(DatagramOutcome::Reply(_)) = alice.handle_datagram(addr, &payload, 3) {
                accepted = true;
            }
        }
        assert!(accepted);
    }

    #[test]
    fn lookup_survives_empty_table_until_bootstrap() {
        let mut rng = Rng::from_seed([17u8; 32]);
        let mut alice = Dht::new(NodeId::random(&mut rng), 6881, &mut rng);
        let mut bob = Dht::new(NodeId::random(&mut rng), 6882, &mut rng);
        let ih = [0xCDu8; 20];
        let bob_addr = NetAddr::V4([127, 0, 0, 1], 6882);
        let alice_addr = NetAddr::V4([127, 0, 0, 1], 6881);

        // 1) bob starts a get_peers lookup while its routing table is EMPTY
        //    (the "session started before bootstrap answered" race).
        bob.get_peers(ih, 7777, 1);

        // 2) Driving the lookup must NOT prune it: nothing was queried yet
        //    and the table may still be populated by in-flight bootstrap
        //    pings. (Regression: it used to end immediately.)
        bob.tick(2);
        assert_eq!(
            bob.active_lookups(),
            1,
            "empty-table lookup must stay alive"
        );

        // 3) bob learns alice through a bootstrap ping.
        alice.bootstrap(&[bob_addr], 3);
        for (addr, payload) in alice.outgoing() {
            if let Ok(DatagramOutcome::Reply(reply)) = bob.handle_datagram(addr, &payload, 3) {
                alice.handle_datagram(alice_addr, &reply, 3).unwrap();
            }
        }
        assert!(bob.table().contains(&alice.id));

        // 4) The SAME lookup must now query the newly learned node.
        bob.tick(4);
        let out = bob.outgoing();
        assert!(!out.is_empty(), "lookup must query the newly learned node");
    }

    #[test]
    fn announce_then_get_peers_returns_peer() {
        let mut rng = Rng::from_seed([19u8; 32]);
        let mut node = Dht::new(NodeId::random(&mut rng), 6881, &mut rng);
        let ih = [0xEEu8; 20];
        let announcer = NetAddr::V4([10, 0, 0, 9], 9000);

        // BEP-5 token for the announcer's IP.
        let token = node.make_token(&announcer);
        let ann = KrpcMsg {
            t: t2(9),
            body: KrpcBody::Query {
                q: "announce_peer",
                args: Args {
                    id: NodeId::random(&mut rng),
                    info_hash: Some(ih),
                    port: Some(6882),
                    token: Some(token.clone()),
                    implied_port: None,
                    ..Default::default()
                },
            },
        };
        match node.handle_datagram(announcer, &encode(&ann), 5).unwrap() {
            DatagramOutcome::Reply(_) => {}
            _ => panic!("expected announce reply"),
        }

        // A querying node asks for peers of ih → gets the announcer back.
        let q = KrpcMsg {
            t: t2(10),
            body: KrpcBody::Query {
                q: "get_peers",
                args: Args {
                    id: NodeId::random(&mut rng),
                    info_hash: Some(ih),
                    ..Default::default()
                },
            },
        };
        let reply = match node
            .handle_datagram(NetAddr::V4([10, 0, 0, 7], 7000), &encode(&q), 6)
            .unwrap()
        {
            DatagramOutcome::Reply(b) => b,
            _ => panic!("expected get_peers reply"),
        };
        let dec = decode(&reply).unwrap();
        match dec.body {
            KrpcBody::Response {
                resp: Resp::GetPeers { values, .. },
                ..
            } => {
                assert!(
                    values.contains(&NetAddr::V4([10, 0, 0, 9], 6882)),
                    "get_peers must return the announced peer, got {values:?}"
                );
            }
            _ => panic!("expected get_peers response"),
        }
    }

    #[test]
    fn discovered_peers_survive_lookup_prune() {
        let mut rng = Rng::from_seed([23u8; 32]);
        let mut alice = Dht::new(NodeId::random(&mut rng), 6881, &mut rng);
        let mut bob = Dht::new(NodeId::random(&mut rng), 6882, &mut rng);
        let ih = [0x11u8; 20];
        let bob_addr = NetAddr::V4([127, 0, 0, 1], 6882);
        let alice_addr = NetAddr::V4([127, 0, 0, 1], 6881);
        let seed_peer = NetAddr::V4([192, 168, 1, 50], 6883);

        // bob learns alice (bootstrap ping).
        alice.bootstrap(&[bob_addr], 1);
        for (addr, payload) in alice.outgoing() {
            if let Ok(DatagramOutcome::Reply(reply)) = bob.handle_datagram(addr, &payload, 1) {
                alice.handle_datagram(alice_addr, &reply, 1).unwrap();
            }
        }
        // alice stores a peer for ih (the seed announces to alice).
        let token = alice.make_token(&seed_peer);
        let ann = KrpcMsg {
            t: t2(7),
            body: KrpcBody::Query {
                q: "announce_peer",
                args: Args {
                    id: NodeId::random(&mut rng),
                    info_hash: Some(ih),
                    port: Some(6883),
                    token: Some(token),
                    implied_port: None,
                    ..Default::default()
                },
            },
        };
        alice.handle_datagram(seed_peer, &encode(&ann), 2).unwrap();

        // bob starts a lookup and relays its queries to alice.
        bob.get_peers(ih, 7777, 2);
        bob.tick(3);
        for (addr, payload) in bob.outgoing() {
            if let Ok(DatagramOutcome::Reply(reply)) = alice.handle_datagram(addr, &payload, 3) {
                bob.handle_datagram(addr, &reply, 3).unwrap();
            }
        }
        assert!(
            bob.discovered_peers(&ih).contains(&seed_peer),
            "live lookup must surface the discovered peer"
        );

        // Let the lookup be pruned by timeout.
        bob.tick(LOOKUP_TIMEOUT_MS + 10);
        assert_eq!(bob.active_lookups(), 0, "lookup pruned by timeout");
        // The peers survive in the persisted cache.
        assert!(
            bob.discovered_peers(&ih).contains(&seed_peer),
            "discovered peers must survive lookup pruning"
        );
    }

    #[test]
    fn bep42_response_includes_observed_ip_only_for_routable() {
        let mut rng = Rng::from_seed([31u8; 32]);
        let mut node = Dht::new(NodeId::random(&mut rng), 6881, &mut rng);
        // A routable source → the reply carries the observed `ip`.
        let from = NetAddr::V4([203, 0, 113, 9], 40000);
        let ping = KrpcMsg {
            t: t2(1),
            body: KrpcBody::Query {
                q: "ping",
                args: Args {
                    id: NodeId::random(&mut rng),
                    ..Default::default()
                },
            },
        };
        let reply = match node.handle_datagram(from, &encode(&ping), 1).unwrap() {
            DatagramOutcome::Reply(b) => b,
            _ => panic!("expected reply"),
        };
        match decode(&reply).unwrap().body {
            KrpcBody::Response { ip, .. } => {
                assert_eq!(
                    ip,
                    Some(vec![203, 0, 113, 9]),
                    "BEP-42 ip must be the observed source"
                );
            }
            _ => panic!("expected response"),
        }
        // A private source → no `ip` field (would teach a useless LAN addr).
        let private = NetAddr::V4([192, 168, 1, 50], 40001);
        let reply = match node.handle_datagram(private, &encode(&ping), 2).unwrap() {
            DatagramOutcome::Reply(b) => b,
            _ => panic!("expected reply"),
        };
        match decode(&reply).unwrap().body {
            KrpcBody::Response { ip, .. } => {
                assert_eq!(ip, None, "private source must not be echoed")
            }
            _ => panic!("expected response"),
        }
    }

    #[test]
    fn bep42_external_ip_requires_cross_confirmation() {
        let mut rng = Rng::from_seed([37u8; 32]);
        let mut node = Dht::new(NodeId::random(&mut rng), 6881, &mut rng);
        let our_ip = [203, 0, 113, 9];
        let ipv = vec![our_ip[0], our_ip[1], our_ip[2], our_ip[3]];

        // A single node claiming our external IP is NOT enough.
        node.observe_external(&ipv, NetAddr::V4([1, 2, 3, 4], 6881), 1);
        assert_eq!(
            node.confirmed_external_ip(),
            None,
            "one witness is not enough"
        );

        // Two nodes claiming the SAME IP are still not enough.
        node.observe_external(&ipv, NetAddr::V4([1, 2, 3, 5], 6881), 2);
        assert_eq!(
            node.confirmed_external_ip(),
            None,
            "two witnesses are not enough"
        );

        // Three distinct nodes agreeing → confirmed.
        node.observe_external(&ipv, NetAddr::V4([1, 2, 3, 6], 6881), 3);
        let mut got = [0u8; 16];
        got[..4].copy_from_slice(&our_ip);
        assert_eq!(
            node.confirmed_external_ip(),
            Some(got),
            "three witnesses confirm"
        );

        // A conflicting claim from a fourth node must NOT flip the result.
        let evil = vec![8, 8, 8, 8];
        node.observe_external(&evil, NetAddr::V4([9, 9, 9, 9], 6881), 4);
        assert_eq!(
            node.confirmed_external_ip(),
            Some(got),
            "minority claim must not override the confirmed address"
        );
    }

    #[test]
    fn is_routable_filters_private_addresses() {
        // Proper IPv4-mapped form: ::ffff:a.b.c.d
        let mapped_v4 = |a: [u8; 4]| -> [u8; 16] {
            let mut b = [0u8; 16];
            b[10] = 0xFF;
            b[11] = 0xFF;
            b[12..].copy_from_slice(&a);
            b
        };
        assert!(is_routable(&mapped_v4([8, 8, 8, 8])));
        assert!(is_routable(&mapped_v4([203, 0, 113, 9])));
        assert!(!is_routable(&mapped_v4([10, 1, 2, 3])));
        assert!(!is_routable(&mapped_v4([192, 168, 1, 1])));
        assert!(!is_routable(&mapped_v4([172, 16, 0, 1])));
        assert!(!is_routable(&mapped_v4([127, 0, 0, 1])));
        assert!(!is_routable(&mapped_v4([169, 254, 1, 1])));
        // Plain IPv4 stored in the first 4 bytes (rest zero) — the form the
        // compact 4-byte BEP-42 value expands to internally.
        let plain_v4 = |a: [u8; 4]| -> [u8; 16] {
            let mut b = [0u8; 16];
            b[0..4].copy_from_slice(&a);
            b
        };
        assert!(is_routable(&plain_v4([8, 8, 8, 8])));
        assert!(!is_routable(&plain_v4([192, 168, 1, 1])));
        assert!(!is_routable(&plain_v4([10, 9, 9, 9])));
        // pure IPv6 cases
        assert!(is_routable(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]));
        assert!(!is_routable(&[
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]));
        assert!(!is_routable(&[
            0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]));
        assert!(!is_routable(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]));
    }

    #[test]
    fn bootstrap_inserts_seed_immediately() {
        let mut rng = Rng::from_seed([41u8; 32]);
        let mut dht = Dht::new(NodeId::random(&mut rng), 6881, &mut rng);
        let seed = NetAddr::V4([1, 2, 3, 4], 6881);
        // A resolved domain node enters the routing table BEFORE any reply.
        dht.bootstrap(&[seed], 0);
        assert_eq!(
            dht.table().size(),
            1,
            "resolved bootstrap node must be in the table right away"
        );
        // And a ping is on the wire for it.
        assert_eq!(dht.outgoing().len(), 1);
    }

    #[test]
    fn bootstrap_placeholder_replaced_by_real_id() {
        let mut rng = Rng::from_seed([43u8; 32]);
        let mut alice = Dht::new(NodeId::random(&mut rng), 6881, &mut rng);
        let mut bob = Dht::new(NodeId::random(&mut rng), 6882, &mut rng);
        let bob_addr = NetAddr::V4([127, 0, 0, 1], 6882);
        // alice bootstraps: bob enters her table with a ZERO placeholder id.
        alice.bootstrap(&[bob_addr], 0);
        assert_eq!(alice.table().size(), 1);
        // bob answers the ping with his real id.
        for (addr, payload) in alice.outgoing() {
            if let Ok(DatagramOutcome::Reply(reply)) = bob.handle_datagram(addr, &payload, 0) {
                alice
                    .handle_datagram(NetAddr::V4([127, 0, 0, 1], 6882), &reply, 0)
                    .unwrap();
            }
        }
        // Real id in, placeholder gone: exactly one entry with bob's id.
        assert_eq!(alice.table().size(), 1, "no duplicate after real id");
        assert!(alice.table().contains(&bob.id));
    }

    #[test]
    fn external_port_requires_cross_confirmation() {
        let mut rng = Rng::from_seed([47u8; 32]);
        let mut node = Dht::new(NodeId::random(&mut rng), 6881, &mut rng);
        // 6-byte ip:port form — one witness is not enough.
        let mut ip_port = vec![203, 0, 113, 9, 0x1b, 0x39]; // :6969
        node.observe_external(&ip_port, NetAddr::V4([1, 2, 3, 4], 6881), 1);
        assert_eq!(node.confirmed_external_port(), None, "one witness");
        // Two distinct witnesses agreeing.
        node.observe_external(&ip_port, NetAddr::V4([1, 2, 3, 5], 6881), 2);
        assert_eq!(node.confirmed_external_port(), None, "two witnesses");
        // Three distinct witnesses → confirmed.
        node.observe_external(&ip_port, NetAddr::V4([1, 2, 3, 6], 6881), 3);
        assert_eq!(node.confirmed_external_port(), Some(6969));
        // A minority claim for a different port must not flip the result.
        ip_port[4] = 0x1c;
        ip_port[5] = 0x20;
        node.observe_external(&ip_port, NetAddr::V4([9, 9, 9, 9], 6881), 4);
        assert_eq!(node.confirmed_external_port(), Some(6969));
    }
}
