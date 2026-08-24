//! `no_std + alloc` universal download engine: BitTorrent (v1/v2, DHT, PEX,
//! web seeds), eD2k, Xunlei, IPFS, Kad, direct HTTP(S) — plus provable
//! download receipts, a utility scheduler and a disk cache. Transport is
//! injected via [`platform::Host`]; crypto is in-tree under [`crypto`].

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "ffi"), deny(unsafe_code))]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
// Indexed loops in crypto / bit-twiddling hot paths read clearer (SHA,
// Ed25519, bitfields) and match the reference implementations.
#![allow(clippy::needless_range_loop)]

#[macro_use]
extern crate alloc;

pub mod bencode;
pub mod bitfield;
pub mod crypto;
pub mod dht;
pub mod disk_cache;
pub mod engine;
pub mod error;
pub mod links;
pub mod magnet;
pub mod metainfo;
pub mod monitoring;
pub mod peer_id;
pub mod pex;
pub mod picker;
pub mod piece;
pub mod platform;
pub mod receipt;
pub mod scheduler;
pub mod session;
pub mod state;
pub mod swarm;
pub mod tracker;
pub mod wire;

// OS-backed host (feature "std") and C ABI bridge (feature "ffi") are
// compiled into the same crate so the whole engine ships as one package.
#[cfg(feature = "ffi")]
pub mod ffi;
#[cfg(feature = "std")]
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
    /// Aria2, Transmission, BitComet).
    pub const DHT_BOOTSTRAP: &[(&str, u16)] = &[
        ("router.bittorrent.com", 6881),
        ("router.utorrent.com", 6881),
        ("router.transmissionbt.com", 6881),
        ("dht.bitcomet.com", 6881),
        ("dht.libtorrent.org", 25401),
    ];
    /// Source for the community tracker list (qBittorrent/BitComet
    /// compatible; the host refreshes it at runtime via `http_get`).
    pub const TRACKERS_LIST_URL: &str = "https://cf.trackerslist.com/best.txt";
    /// Built-in default trackers (stable public subset of the community
    /// list). Session configs can override with `DEFAULT_TRACKERS`.
    pub const DEFAULT_TRACKERS: &[&str] = &[
        "udp://tracker.opentrackr.org:1337/announce",
        "https://tracker.tamersunion.org:443/announce",
        "udp://open.stealth.si:80/announce",
        "udp://exodus.desync.com:6969/announce",
        "udp://tracker.torrent.eu.org:451/announce",
        "http://tracker.openbittorrent.com:80/announce",
        "udp://tracker.moeking.me:6969/announce",
        "udp://explodie.org:6969/announce",
        "https://opentracker.i2p.rocks:443/announce",
        "udp://tracker.tiny-vps.com:6969/announce",
        "udp://open.demonii.com:1337/announce",
        "udp://tracker.openbittorrent.com:6969/announce",
        "https://tracker.nanoha.org:443/announce",
        "http://tracker.gbitt.info:80/announce",
    ];
    /// Maximum number of outstanding request blocks per peer connection.
    pub const REQUEST_PIPELINE: u32 = 256;
    /// Recommended write-back cache budget (bytes).
    pub const DEFAULT_CACHE_BYTES: u64 = 64 * 1024 * 1024;
}
