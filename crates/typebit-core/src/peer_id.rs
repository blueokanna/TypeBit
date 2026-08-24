//! Peer id generation and client identification.

use crate::crypto::Rng;
use alloc::string::String;

/// Length of a peer id.
pub const PEER_ID_LEN: usize = 20;

/// Generate a v1-style peer id: `-TB1000-` + 12 random hex chars.
pub fn generate(rng: &mut Rng) -> [u8; 20] {
    let mut id = [0u8; 20];
    // BEP-20 layout: '-' + client(2) + version(4) + '-' + 12 hex = 20 bytes.
    // VERSION_TAG ("TB10") supplies the client code + leading version digits;
    // remaining version digits are zero-padded to 4 places.
    let tag = crate::consts::VERSION_TAG.as_bytes();
    let n = tag.len().min(4);
    id[0] = b'-';
    id[1..1 + n].copy_from_slice(&tag[..n]);
    for k in (1 + n)..5 {
        id[k] = b'0';
    }
    id[5] = b'0';
    id[6] = b'0';
    id[7] = b'-';
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in 0..12 {
        id[8 + i] = HEX[(rng.next_u32() & 0xf) as usize];
    }
    id
}

/// A v2-style (BEP-52 hybrid) 26-byte key is out of scope; v1 20-byte id
/// remains interoperable everywhere.

/// Try to identify a peer's client from its 20-byte peer id.
/// Returns e.g. `("qB", "4300")` for `-qB4300-...`.
pub fn identify(id: &[u8; 20]) -> Option<(String, String)> {
    if id.len() != PEER_ID_LEN || id[0] != b'-' {
        return None;
    }
    // run of alphanumeric chars after the leading '-'
    let run_end = id
        .iter()
        .skip(1)
        .position(|&b| !b.is_ascii_alphanumeric())
        .map(|p| p + 1)
        .unwrap_or(20);
    let run = &id[1..run_end];
    if run.len() < 2 {
        return None;
    }
    // client code = first 2 chars, version = next up to 4 chars
    let name = String::from_utf8_lossy(&run[..2]).into_owned();
    let ver_len = core::cmp::min(run.len() - 2, 4);
    let ver = String::from_utf8_lossy(&run[2..2 + ver_len]).into_owned();
    Some((name, ver))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_and_identify() {
        let mut rng = Rng::from_seed([42u8; 32]);
        let id = generate(&mut rng);
        assert_eq!(id.len(), 20);
        let (name, ver) = identify(&id).unwrap();
        assert_eq!(name, "TB");
        assert_eq!(ver, "1000");
    }

    #[test]
    fn identify_known() {
        let mut id = [0u8; 20];
        id.copy_from_slice(b"-qB4300-abcdefghijkl");
        let (name, ver) = identify(&id).unwrap();
        assert_eq!(name, "qB");
        assert_eq!(ver, "4300");
    }
}
