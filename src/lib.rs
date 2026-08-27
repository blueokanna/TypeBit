//! `no_std + alloc` universal download engine: BitTorrent (v1/v2, DHT, PEX,
//! web seeds), eD2k, Xunlei, IPFS, Kad, direct HTTP(S) — plus provable
//! download receipts, a utility scheduler and a disk cache. Transport is
//! injected via [`platform::Host`]; crypto is in-tree under [`crypto`].

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "ffi"), deny(unsafe_code))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

#[macro_use]
extern crate alloc;

pub mod bencode;
pub mod bitfield;
pub mod crypto;
pub mod dht;
pub mod disk_cache;
pub mod engine;
pub mod error;
pub mod leech;
pub mod links;
pub mod lsd;
pub mod magnet;
pub mod metainfo;
pub mod monitoring;
pub mod peer_id;
pub mod pex;
pub mod picker;
pub mod piece;
pub mod platform;
pub mod portmap;
pub mod ratelimit;
pub mod receipt;
pub mod scheduler;
pub mod session;
pub mod socks;
pub mod state;
pub mod swarm;
pub mod tracker;
pub mod trackerlist;
pub mod utp;
pub mod verify;
pub mod wire;

// OS-backed host (feature "std") and C ABI bridge (feature "ffi") are
// compiled into the same crate so the whole engine ships as one package.
#[cfg(feature = "ffi")]
#[cfg_attr(docsrs, doc(cfg(feature = "ffi")))]
pub mod ffi;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod host_std;

pub use engine::{Engine, EngineConfig, EngineEvent};
pub use error::{Error, Result};
pub use metainfo::InfoHash;
pub use platform::{Host, LogLevel, NetAddr};

/// Protocol constants.
pub mod consts {
    /// Standard BitTorrent piece block size.
    pub const BLOCK_LEN: u32 = 16 * 1024;
    /// The peer-wire handshake protocol identifier (BEP-3).
    pub const PSTR: &[u8] = b"BitTorrent protocol";
    /// Default listen port advertised to the swarm.
    pub const DEFAULT_PORT: u16 = 6881;
    /// Default piece length used by v1 torrents when absent.
    pub const DEFAULT_PIECE_LEN: u32 = 256 * 1024;
    /// Version tag embedded in the peer id.
    pub const VERSION_TAG: &str = "TB10";
    /// DHT bootstrap nodes (BEP-5) — the well-known, permanently online
    /// routers used by the mainstream clients (uTorrent, qBittorrent,
    /// Aria2, Transmission, BitComet). More seeds = more initial diversity:
    /// a client that only pings a couple of alive routers snowballs far
    /// slower than qBittorrent/libtorrent (which also carry a large
    /// persisted table across restarts).
    pub const DHT_BOOTSTRAP: &[(&str, u16)] = &[
        ("router.bittorrent.com", 6881),
        ("dht.transmissionbt.com", 6881),
        ("router.utorrent.com", 6881),
        ("router.transmissionbt.com", 6881),
        ("dht.libtorrent.org", 25401),
        ("dht.aelitis.com", 6881),
        ("dht.bitcomet.com", 6881),
        ("router.bitcomet.com", 6881),
        ("dht.dhtool.com", 6881),
    ];
    /// Source for the community tracker list (qBittorrent/BitComet
    /// compatible; the host refreshes it at runtime via `http_get`).
    pub const TRACKERS_LIST_URL: &str = "https://cf.trackerslist.com/all.txt";
    /// Maximum number of outstanding request blocks per peer connection.
    pub const REQUEST_PIPELINE: u32 = 256;
    /// Recommended write-back cache budget (bytes).
    pub const DEFAULT_CACHE_BYTES: u64 = 256 * 1024 * 1024;
    /// Upper bound on magnet metadata size (a .torrent info dict is small).
    pub const MAX_METADATA_SIZE: u32 = 64 * 1024 * 1024;
}
