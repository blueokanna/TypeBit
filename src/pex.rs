//! Peer exchange (BEP-11 / BEP-11.1) — facade over the wire codec
//! ([`crate::wire::PexMsg`]): adds swarm-level helpers for compact peer
//! list encoding with flags.

pub use crate::wire::PexMsg;

use crate::platform::NetAddr;
use alloc::vec::Vec;

/// Peer flags (BEP-11.1).
pub mod flags {
    /// Prefers encryption.
    pub const PREFER_ENCRYPTION: u8 = 0x01;
    /// Seeder (has the whole content).
    pub const SEED: u8 = 0x02;
    /// Supports uTP.
    pub const UTP: u8 = 0x04;
    /// Supports hole punching.
    pub const HOLE_PUNCH: u8 = 0x08;
    /// Outgoing connection.
    pub const OUTGOING: u8 = 0x10;
}

/// Build a PEX "added" section from peers, with a flags byte per peer.
pub fn encode_added(peers: &[(NetAddr, u8)]) -> Vec<u8> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut f4 = Vec::new();
    let mut f6 = Vec::new();
    for (addr, flags) in peers {
        match addr {
            NetAddr::V4(_, _) => {
                if let Some(b) = addr.to_compact6() {
                    v4.extend_from_slice(&b);
                    f4.push(*flags);
                }
            }
            NetAddr::V6(_, _) => {
                if let Some(b) = addr.to_compact18() {
                    v6.extend_from_slice(&b);
                    f6.push(*flags);
                }
            }
        }
    }
    PexMsg {
        added: v4,
        added_f: f4,
        added6: v6,
        added6_f: f6,
        ..PexMsg::default()
    }
    .encode()
}

/// Parse a PEX message into (peer, flags) pairs.
pub fn decode_added(msg: &PexMsg) -> Vec<(NetAddr, u8)> {
    let mut out = Vec::new();
    for (i, c) in msg.added.as_chunks::<6>().0.iter().enumerate() {
        let flags = msg.added_f.get(i).copied().unwrap_or(0);
        if let Some(a) = NetAddr::from_compact6(c) {
            out.push((a, flags));
        }
    }
    for (i, c) in msg.added6.as_chunks::<18>().0.iter().enumerate() {
        let flags = msg.added6_f.get(i).copied().unwrap_or(0);
        if let Some(a) = NetAddr::from_compact18(c) {
            out.push((a, flags));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pex_added_roundtrip() {
        let peers = vec![
            (
                NetAddr::V4([192, 168, 1, 1], 6881),
                flags::SEED | flags::UTP,
            ),
            (
                NetAddr::V6(
                    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    6882,
                ),
                flags::UTP,
            ),
        ];
        let bytes = encode_added(&peers);
        let msg = PexMsg::parse(&bytes).unwrap();
        let back = decode_added(&msg);
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].0, peers[0].0);
        assert_eq!(back[0].1, peers[0].1);
        assert_eq!(back[1].0, peers[1].0);
    }
}
