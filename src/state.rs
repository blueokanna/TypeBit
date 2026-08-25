//! Session persistence with the ecosystem codecs: binary via `rustbinary`,
//! human via `nextjson`, wall-clock via `tzcraft::Ticks`. The host stores
//! the produced bytes (file, KV store, mobile keychain).

use crate::error::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;
use nextjson::{NsonDeserialize, NsonSerialize};

/// Persisted state of one torrent.
#[derive(Debug, Clone, PartialEq, Eq, NsonSerialize, NsonDeserialize)]
pub struct TorrentState {
    /// Info hash (20 or 32 bytes).
    pub info_hash: Vec<u8>,
    /// Save path.
    pub save_path: String,
    /// Verified piece bitfield (network bytes).
    pub have: Vec<u8>,
    /// Partially received blocks: (piece, block bitfield).
    pub partial: Vec<(u32, Vec<u8>)>,
    /// When added (unix epoch seconds, from the `tzcraft` timeline).
    pub added_at: i64,
    /// Paused flag.
    pub paused: bool,
    /// Per-file priority bytes (0=Skip, 1=Normal, 2=High); empty = all Normal.
    pub file_priorities: Vec<u8>,
    /// Per-task upload limit (bytes/s; 0 = unlimited).
    pub upload_limit_bps: u64,
    /// Per-task download limit (bytes/s; 0 = unlimited).
    pub download_limit_bps: u64,
    /// Anti-leech reputation ledger (`leech::ReputationStore`, opaque bytes).
    pub reputation: Vec<u8>,
}

/// Whole-session state.
#[derive(Debug, Clone, Default, PartialEq, Eq, NsonSerialize, NsonDeserialize)]
pub struct SessionState {
    /// Format version.
    pub version: u32,
    /// Torrents.
    pub torrents: Vec<TorrentState>,
    /// DHT nodes to re-bootstrap from (compact 26-byte entries).
    pub dht_nodes: Vec<Vec<u8>>,
}

impl SessionState {
    /// Binary encode (rustbinary).
    pub fn to_binary(&self) -> Result<Vec<u8>> {
        let config = rustbinary::options().with_limit(64 * 1024 * 1024);
        config.serialize(self).map_err(|_| Error::InvalidInput)
    }

    /// Binary decode (rustbinary).
    pub fn from_binary(bytes: &[u8]) -> Result<SessionState> {
        let config = rustbinary::options().with_limit(64 * 1024 * 1024);
        config.deserialize(bytes).map_err(|_| Error::InvalidInput)
    }

    /// JSON encode (nextjson).
    pub fn to_json(&self) -> Result<Vec<u8>> {
        nextjson::nextencode(self).map_err(|_| Error::InvalidInput)
    }

    /// JSON decode (nextjson).
    pub fn from_json(bytes: &[u8]) -> Result<SessionState> {
        nextjson::nextdecode(bytes).map_err(|_| Error::InvalidInput)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SessionState {
        SessionState {
            version: 1,
            torrents: vec![TorrentState {
                info_hash: vec![1u8; 20],
                save_path: String::from("/data/downloads"),
                have: vec![0b1010_0000, 0],
                partial: vec![(3, vec![0b1000_0000])],
                added_at: 1_700_000_000,
                paused: false,
                file_priorities: vec![1, 0, 2],
                upload_limit_bps: 0,
                download_limit_bps: 1_000_000,
                reputation: vec![1, 2, 3],
            }],
            dht_nodes: vec![vec![2u8; 26]],
        }
    }

    #[test]
    fn binary_roundtrip() {
        let s = sample();
        let bytes = s.to_binary().unwrap();
        let back = SessionState::from_binary(&bytes).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn json_roundtrip() {
        let s = sample();
        let bytes = s.to_json().unwrap();
        let back = SessionState::from_json(&bytes).unwrap();
        assert_eq!(back, s);
    }
}
