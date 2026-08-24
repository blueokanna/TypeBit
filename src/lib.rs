//! # TypeBit Core
//!
//! A `no_std + alloc` BitTorrent engine core. This crate contains the entire
//! protocol logic (v1/v2 metainfo, peer wire, DHT, PEX, tracker codecs),
//! the transfer machinery (piece picker, utility scheduler, disk cache),
//! and the research-grade **provable download / availability receipt** layer.
//!
//! The crate is transport- and storage-agnostic: every external effect goes
//! through the [`platform::Host`] trait, so the same core binary can be
//! embedded on desktop (via `typebit-std`), Android/Kotlin, iOS/Swift, or
//! any embedded target (via `typebit-ffi`).
//!
//! The only third-party dependencies are the four crates of the TypeBit
//! ecosystem: `nextjson` (data-contract engine), `rustbinary` (binary codec),
//! `tzcraft` (128-bit time timeline) and `courierust` (no_std HTTP/gRPC
//! protocol core used by the std host for tracker/web-seed transports).
//! All cryptography (SHA-1/SHA-256/SHA-512/Ed25519/ChaCha20) is implemented
//! in-tree under [`crypto`].

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "ffi"), deny(unsafe_code))]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
// Indexed loops in cryptographic / bit-twiddling hot paths are clearer and
// match the reference implementations (SHA-1/256/512, Ed25519, bitfields).
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
    /// DHT bootstrap nodes (BEP-5).
    pub const DHT_BOOTSTRAP: &[(&str, u16)] = &[
        ("router.bittorrent.com", 6881),
        ("router.utorrent.com", 6881),
        ("dht.transmissionbt.com", 6881),
        ("dht.libtorrent.org", 25401),
    ];
    /// Maximum number of outstanding request blocks per peer connection.
    pub const REQUEST_PIPELINE: u32 = 256;
    /// Recommended write-back cache budget (bytes).
    pub const DEFAULT_CACHE_BYTES: u64 = 64 * 1024 * 1024;
}
