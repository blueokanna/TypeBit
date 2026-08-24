//! Torrent metainfo: v1 (BEP-3), v2 (BEP-52) and hybrid parsing.
//!
//! Also provides the canonical per-piece layout (v1 pieces may cross file
//! boundaries; v2 pieces never do) and per-piece hash verification.

use crate::bencode::{bytes, dict, int};
use crate::bencode::{BVal, Parser};
use crate::consts::BLOCK_LEN;
use crate::crypto::{Sha1, Sha256};
use crate::error::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// A torrent identity: 20 bytes for v1, 32 bytes for v2/hybrid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InfoHash {
    bytes: [u8; 32],
    len: u8,
}

impl InfoHash {
    /// v1 infohash (20 bytes).
    pub fn v1(h: [u8; 20]) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..20].copy_from_slice(&h);
        InfoHash { bytes, len: 20 }
    }
    /// v2 infohash (32 bytes).
    pub fn v2(h: [u8; 32]) -> Self {
        InfoHash { bytes: h, len: 32 }
    }
    /// Raw bytes (20 or 32).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
    /// Byte length.
    pub fn len(&self) -> usize {
        self.len as usize
    }
    /// True for v1 (20-byte) hashes.
    pub fn is_v1(&self) -> bool {
        self.len == 20
    }
    /// True for v2 (32-byte) hashes.
    pub fn is_v2(&self) -> bool {
        self.len == 32
    }
    /// Full 32-byte backing array (zero-padded for v1).
    pub fn full(&self) -> [u8; 32] {
        self.bytes
    }
    /// Hex encoding (allocating).
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(self.len as usize * 2);
        for b in self.as_bytes() {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
    /// Parse 40-hex (v1) or 64-hex (v2) string.
    pub fn from_hex(s: &str) -> Result<InfoHash> {
        match s.len() {
            40 => {
                let mut h = [0u8; 20];
                hex_decode_into(s, &mut h)?;
                Ok(InfoHash::v1(h))
            }
            64 => {
                let mut h = [0u8; 32];
                hex_decode_into(s, &mut h)?;
                Ok(InfoHash::v2(h))
            }
            _ => Err(Error::Magnet),
        }
    }
    /// Parse a `btmh` multihash (`1220` + 64 hex) as used in magnet links.
    pub fn from_multihash(s: &str) -> Result<InfoHash> {
        if let Some(rest) = s.strip_prefix("1220") {
            return InfoHash::from_hex(rest);
        }
        // tolerate raw 64-hex too
        InfoHash::from_hex(s)
    }
}

fn hex_decode_into(s: &str, out: &mut [u8]) -> Result<()> {
    let bytes = s.as_bytes();
    if bytes.len() != out.len() * 2 {
        return Err(Error::Magnet);
    }
    for (i, o) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[i * 2]).ok_or(Error::Magnet)?;
        let lo = hex_nibble(bytes[i * 2 + 1]).ok_or(Error::Magnet)?;
        *o = (hi << 4) | lo;
    }
    Ok(())
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Torrent version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorrentKind {
    /// v1 only.
    V1,
    /// v2 only.
    V2,
    /// Hybrid (v1 + v2).
    Hybrid,
}

/// A single file inside a torrent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Path components (bytes; directories then file name).
    pub path: Vec<Vec<u8>>,
    /// Size in bytes.
    pub length: u64,
    /// v2 per-file Merkle root over 16 KiB blocks (BEP-52).
    pub root: Option<[u8; 32]>,
}

impl FileEntry {
    /// Lossy UTF-8 display path joined with '/'.
    pub fn display_path(&self) -> String {
        let mut s = String::new();
        for (i, c) in self.path.iter().enumerate() {
            if i > 0 {
                s.push('/');
            }
            s.push_str(&String::from_utf8_lossy(c));
        }
        s
    }
}

/// A fully parsed torrent.
#[derive(Debug, Clone)]
pub struct Torrent {
    /// Display name.
    pub name: String,
    /// Piece size in bytes (power of two for v2).
    pub piece_length: u32,
    /// Total payload size.
    pub total_size: u64,
    /// File list (single-file torrents have one entry).
    pub files: Vec<FileEntry>,
    /// Kind.
    pub kind: TorrentKind,
    /// The infohash used on the wire (v1: 20B, v2/hybrid: 32B).
    pub info_hash: InfoHash,
    /// v1 per-piece SHA-1 (only for V1/Hybrid).
    pub v1_hashes: Option<Vec<[u8; 20]>>,
    /// v2 per-piece SHA-256 (only for V2/Hybrid), from the piece layer.
    pub v2_hashes: Option<Vec<[u8; 32]>>,
    /// Single announce URL (may be empty).
    pub announce: Option<Vec<u8>>,
    /// Tracker tiers (`announce-list`).
    pub announce_list: Vec<Vec<Vec<u8>>>,
    /// Web seeds (`url-list` / `httpseeds`).
    pub web_seeds: Vec<Vec<u8>>,
    /// DHT enabled (`nodes` in torrent or default).
    pub private: bool,
    /// BEP-52 piece layers: file pieces-root → per-piece hashes.
    pub piece_layers: Vec<(InfoHash, Vec<[u8; 32]>)>,
    /// Raw bencoded `info` dictionary (infohash source).
    pub info_raw: Vec<u8>,
    /// Comment.
    pub comment: Option<Vec<u8>>,
    /// `created by` string.
    pub created_by: Option<Vec<u8>>,
    /// Creation epoch seconds.
    pub creation_date: Option<i64>,
}

/// One piece's placement in the file layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PieceInfo {
    /// File index.
    pub file: u32,
    /// Offset inside that file.
    pub offset: u64,
    /// Piece length in bytes.
    pub len: u32,
}

impl Torrent {
    /// Parse a `.torrent` file from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Torrent> {
        let root = BVal::parse(data)?;
        let dict = root.as_dict().ok_or(Error::MetaInfo)?;

        let info = dict.get(&b"info"[..]).ok_or(Error::MetaInfo)?;
        // capture raw info bytes for infohash
        let mut p = Parser::new(data);
        let _ = p.value(0)?;
        let info_raw = capture_info_raw(data)?;

        let info_dict = info.as_dict().ok_or(Error::MetaInfo)?;

        let meta_version = info_dict
            .get(&b"meta version"[..])
            .and_then(|v| v.as_int())
            .unwrap_or(1);

        let name = info_dict
            .get(&b"name"[..])
            .and_then(|v| v.as_bytes())
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();

        let piece_length = info_dict
            .get(&b"piece length"[..])
            .and_then(|v| v.as_int())
            .ok_or(Error::MetaInfo)? as u32;
        if piece_length == 0 {
            return Err(Error::MetaInfo);
        }

        // v2 piece length must be a power of two in [2^14, 2^26]
        if meta_version == 2
            && (!piece_length.is_power_of_two()
                || !(14..=26).contains(&piece_length.trailing_zeros()))
        {
            return Err(Error::MetaInfo);
        }

        // files
        let (files, v1_hashes, v2_hashes, piece_layers, total) = if meta_version == 1 {
            let single = info_dict.get(&b"length"[..]).and_then(|v| v.as_int());
            let files = if let Some(len) = single {
                if len < 0 {
                    return Err(Error::MetaInfo);
                }
                let path = vec![info_dict
                    .get(&b"name.utf-8"[..])
                    .or_else(|| info_dict.get(&b"name"[..]))
                    .and_then(|v| v.as_bytes())
                    .unwrap_or(&[])
                    .to_vec()];
                vec![FileEntry {
                    path,
                    length: len as u64,
                    root: None,
                }]
            } else {
                let list = info_dict
                    .get(&b"files"[..])
                    .and_then(|v| v.as_list())
                    .ok_or(Error::MetaInfo)?;
                let mut out = Vec::new();
                for f in list {
                    let fd = f.as_dict().ok_or(Error::MetaInfo)?;
                    let len = fd
                        .get(&b"length"[..])
                        .and_then(|v| v.as_int())
                        .ok_or(Error::MetaInfo)?;
                    if len < 0 {
                        return Err(Error::MetaInfo);
                    }
                    let path = fd
                        .get(&b"path.utf-8"[..])
                        .or_else(|| fd.get(&b"path"[..]))
                        .and_then(|v| v.as_list())
                        .ok_or(Error::MetaInfo)?;
                    let mut comps = Vec::new();
                    for c in path {
                        comps.push(c.as_bytes().ok_or(Error::MetaInfo)?.to_vec());
                    }
                    if comps.is_empty() {
                        return Err(Error::MetaInfo);
                    }
                    out.push(FileEntry {
                        path: comps,
                        length: len as u64,
                        root: None,
                    });
                }
                out
            };
            let pieces = info_dict
                .get(&b"pieces"[..])
                .and_then(|v| v.as_bytes())
                .ok_or(Error::MetaInfo)?;
            if pieces.len() % 20 != 0 {
                return Err(Error::MetaInfo);
            }
            let mut hashes = Vec::with_capacity(pieces.len() / 20);
            for c in pieces.chunks_exact(20) {
                let mut h = [0u8; 20];
                h.copy_from_slice(c);
                hashes.push(h);
            }
            let total: u64 = files.iter().map(|f| f.length).sum();
            (files, Some(hashes), None, Vec::new(), total)
        } else {
            // v2 / hybrid
            let tree = info_dict
                .get(&b"file tree"[..])
                .and_then(|v| v.as_dict())
                .ok_or(Error::MetaInfo)?;
            let mut files = Vec::new();
            parse_v2_tree(tree, &mut Vec::new(), &mut files)?;
            let total: u64 = files.iter().map(|f| f.length).sum();
            // piece layers
            let mut piece_layers = Vec::new();
            if let Some(pl) = dict.get(&b"piece layers"[..]).and_then(|v| v.as_dict()) {
                for (root_bytes, hashes) in pl {
                    let mut root = [0u8; 32];
                    if root_bytes.len() != 32 {
                        return Err(Error::MetaInfo);
                    }
                    root.copy_from_slice(root_bytes);
                    let hb = hashes.as_bytes().ok_or(Error::MetaInfo)?;
                    if hb.len() % 32 != 0 {
                        return Err(Error::MetaInfo);
                    }
                    let mut hs = Vec::with_capacity(hb.len() / 32);
                    for c in hb.chunks_exact(32) {
                        let mut h = [0u8; 32];
                        h.copy_from_slice(c);
                        hs.push(h);
                    }
                    piece_layers.push((InfoHash::v2(root), hs));
                }
            }
            // build per-file piece hash lists from the piece layer
            let v2_hashes = build_v2_piece_hashes(&files, piece_length, &piece_layers)?;
            // v1 pieces (hybrid)
            let v1_hashes =
                if let Some(pieces) = info_dict.get(&b"pieces"[..]).and_then(|v| v.as_bytes()) {
                    if pieces.len() % 20 != 0 {
                        return Err(Error::MetaInfo);
                    }
                    let mut hs = Vec::with_capacity(pieces.len() / 20);
                    for c in pieces.chunks_exact(20) {
                        let mut h = [0u8; 20];
                        h.copy_from_slice(c);
                        hs.push(h);
                    }
                    Some(hs)
                } else {
                    None
                };
            (files, v1_hashes, Some(v2_hashes), piece_layers, total)
        };

        let kind = match (meta_version, v1_hashes.is_some()) {
            (1, _) => TorrentKind::V1,
            (2, true) => TorrentKind::Hybrid,
            (2, false) => TorrentKind::V2,
            _ => return Err(Error::MetaInfo),
        };

        let info_hash = if kind == TorrentKind::V1 {
            InfoHash::v1(Sha1::digest(&info_raw))
        } else {
            InfoHash::v2(Sha256::digest(&info_raw))
        };

        let announce = dict
            .get(&b"announce"[..])
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec());
        let mut announce_list = Vec::new();
        if let Some(tiers) = dict.get(&b"announce-list"[..]).and_then(|v| v.as_list()) {
            for t in tiers {
                if let Some(list) = t.as_list() {
                    let mut tier = Vec::new();
                    for u in list {
                        if let Some(b) = u.as_bytes() {
                            tier.push(b.to_vec());
                        }
                    }
                    if !tier.is_empty() {
                        announce_list.push(tier);
                    }
                }
            }
        }
        let mut web_seeds = Vec::new();
        if let Some(ul) = dict.get(&b"url-list"[..]).and_then(|v| v.as_list()) {
            for u in ul {
                if let Some(b) = u.as_bytes() {
                    web_seeds.push(b.to_vec());
                }
            }
        } else if let Some(hs) = dict.get(&b"httpseeds"[..]).and_then(|v| v.as_list()) {
            for u in hs {
                if let Some(b) = u.as_bytes() {
                    web_seeds.push(b.to_vec());
                }
            }
        }

        let private = info_dict
            .get(&b"private"[..])
            .and_then(|v| v.as_int())
            .unwrap_or(0)
            != 0;

        Ok(Torrent {
            name,
            piece_length,
            total_size: total,
            files,
            kind,
            info_hash,
            v1_hashes,
            v2_hashes,
            announce,
            announce_list,
            web_seeds,
            private,
            piece_layers,
            info_raw,
            comment: dict
                .get(&b"comment"[..])
                .and_then(|v| v.as_bytes())
                .map(|b| b.to_vec()),
            created_by: dict
                .get(&b"created by"[..])
                .and_then(|v| v.as_bytes())
                .map(|b| b.to_vec()),
            creation_date: dict.get(&b"creation date"[..]).and_then(|v| v.as_int()),
        })
    }

    /// Number of pieces.
    pub fn piece_count(&self) -> u32 {
        match self.kind {
            TorrentKind::V1 => {
                let n = self.total_size.div_ceil(self.piece_length as u64);
                n as u32
            }
            _ => self.v2_hashes.as_ref().map(|h| h.len() as u32).unwrap_or(0),
        }
    }

    /// The hash expected for a piece (v1 or v2 depending on kind).
    pub fn piece_hash(&self, index: u32) -> Option<&[u8]> {
        let i = index as usize;
        match self.kind {
            TorrentKind::V1 => self
                .v1_hashes
                .as_ref()
                .and_then(|h| h.get(i))
                .map(|h| &h[..]),
            _ => self
                .v2_hashes
                .as_ref()
                .and_then(|h| h.get(i))
                .map(|h| &h[..]),
        }
    }

    /// Per-piece layout. v1: uniform except last; v2: never crosses files.
    pub fn piece_info(&self, index: u32) -> Result<PieceInfo> {
        let pl = self.piece_length as u64;
        match self.kind {
            TorrentKind::V1 => {
                let n = self.total_size.div_ceil(pl) as u64;
                if (index as u64) >= n {
                    return Err(Error::Range);
                }
                let start = (index as u64) * pl;
                let len = core::cmp::min(pl, self.total_size - start) as u32;
                // locate file
                let mut off = 0u64;
                for (fi, f) in self.files.iter().enumerate() {
                    if start < off + f.length {
                        return Ok(PieceInfo {
                            file: fi as u32,
                            offset: start - off,
                            len,
                        });
                    }
                    off += f.length;
                }
                Err(Error::Range)
            }
            _ => {
                let mut idx = 0u64;
                for (fi, f) in self.files.iter().enumerate() {
                    if f.length == 0 {
                        continue;
                    }
                    let np = f.length.div_ceil(pl);
                    if (index as u64) < idx + np {
                        let off = (index as u64 - idx) * pl;
                        let len = core::cmp::min(pl, f.length - off) as u32;
                        return Ok(PieceInfo {
                            file: fi as u32,
                            offset: off,
                            len,
                        });
                    }
                    idx += np;
                }
                Err(Error::Range)
            }
        }
    }

    /// Absolute payload offset of a piece's first byte.
    pub fn piece_abs_offset(&self, index: u32) -> Result<u64> {
        let pl = self.piece_length as u64;
        match self.kind {
            TorrentKind::V1 => Ok((index as u64) * pl),
            _ => {
                let mut idx = 0u64;
                for f in &self.files {
                    if f.length == 0 {
                        continue;
                    }
                    let np = f.length.div_ceil(pl);
                    if (index as u64) < idx + np {
                        let rel = index as u64 - idx;
                        return Ok(abs_file_offset(self, rel * pl, f));
                    }
                    idx += np;
                }
                Err(Error::Range)
            }
        }
    }

    /// Map an absolute payload offset to a (file index, file offset).
    pub fn locate_offset(&self, abs: u64) -> Result<(u32, u64)> {
        let mut off = 0u64;
        for (i, f) in self.files.iter().enumerate() {
            if abs < off + f.length {
                return Ok((i as u32, abs - off));
            }
            off += f.length;
        }
        Err(Error::Range)
    }

    /// Verify a piece's bytes against its expected hash.
    /// For v2, computes the piece's block Merkle root per BEP-52.
    pub fn verify_piece(&self, index: u32, data: &[u8]) -> Result<()> {
        let pi = self.piece_info(index)?;
        if data.len() as u32 != pi.len {
            return Err(Error::Range);
        }
        match self.kind {
            TorrentKind::V1 => {
                let h = Sha1::digest(data);
                let expect = self.piece_hash(index).ok_or(Error::Range)?;
                if h != expect[..20] {
                    return Err(Error::HashMismatch);
                }
            }
            _ => {
                let blocks: Vec<[u8; 32]> = data
                    .chunks(BLOCK_LEN as usize)
                    .map(|c| Sha256::digest(c))
                    .collect();
                let root = merkle_root(&blocks);
                let expect = self.piece_hash(index).ok_or(Error::Range)?;
                if root != expect[..32] {
                    return Err(Error::HashMismatch);
                }
            }
        }
        Ok(())
    }
}

/// Absolute payload offset of a file-relative piece.
fn abs_file_offset(t: &Torrent, file_rel: u64, file: &FileEntry) -> u64 {
    let mut off = 0u64;
    for f in &t.files {
        if core::ptr::eq(f, file) {
            return off + file_rel;
        }
        off += f.length;
    }
    off
}

/// Walk the top-level dict of a raw `.torrent` and return the exact raw
/// bytes of the `info` value (the infohash preimage).
fn capture_info_raw(data: &[u8]) -> Result<Vec<u8>> {
    if data.first() != Some(&b'd') {
        return Err(Error::MetaInfo);
    }
    let mut p = Parser::new(data);
    p.pos = 1;
    loop {
        if *data.get(p.pos).ok_or(Error::MetaInfo)? == b'e' {
            return Err(Error::MetaInfo);
        }
        let key = match p.string() {
            Ok(BVal::Bytes(k)) => k,
            _ => return Err(Error::MetaInfo),
        };
        let val_start = p.pos;
        p.skip_value(0)?;
        let val_end = p.pos;
        if key == b"info" {
            return Ok(data[val_start..val_end].to_vec());
        }
    }
}

/// Recursively parse a v2 file tree dict.
fn parse_v2_tree(
    node: &BTreeMap<Vec<u8>, BVal>,
    prefix: &mut Vec<Vec<u8>>,
    out: &mut Vec<FileEntry>,
) -> Result<()> {
    for (name, v) in node {
        let d = v.as_dict().ok_or(Error::MetaInfo)?;
        if let Some(file_meta) = d.get(&b""[..]) {
            let meta = file_meta.as_dict().ok_or(Error::MetaInfo)?;
            let len = meta
                .get(&b"length"[..])
                .and_then(|x| x.as_int())
                .ok_or(Error::MetaInfo)?;
            if len < 0 {
                return Err(Error::MetaInfo);
            }
            let root = match meta.get(&b"pieces root"[..]).and_then(|x| x.as_bytes()) {
                Some(r) if r.len() == 32 => {
                    let mut rr = [0u8; 32];
                    rr.copy_from_slice(r);
                    Some(rr)
                }
                _ => None,
            };
            let mut path = prefix.clone();
            path.push(name.clone());
            out.push(FileEntry {
                path,
                length: len as u64,
                root,
            });
        } else {
            prefix.push(name.clone());
            parse_v2_tree(d, prefix, out)?;
            prefix.pop();
        }
    }
    Ok(())
}

/// Build the global v2 piece-hash list by concatenating each file's piece
/// hashes (from the piece layer) in file-tree order.
fn build_v2_piece_hashes(
    files: &[FileEntry],
    piece_length: u32,
    layers: &[(InfoHash, Vec<[u8; 32]>)],
) -> Result<Vec<[u8; 32]>> {
    let pl = piece_length as u64;
    let mut out = Vec::new();
    for f in files {
        if f.length == 0 {
            continue;
        }
        let root = match f.root {
            Some(r) => r,
            None => continue,
        };
        let found = layers.iter().find(|(r, _)| r.as_bytes() == &root[..]);
        match found {
            Some((_, hashes)) => {
                let np = f.length.div_ceil(pl) as usize;
                if hashes.len() != np {
                    return Err(Error::MetaInfo);
                }
                out.extend_from_slice(hashes);
            }
            None => {
                // fall back to computing piece hashes from the file merkle root
                // (only possible if we could reconstruct leaves, which we cannot
                // from the root alone) → derive per-piece roots is not possible;
                // treat as empty.
                return Err(Error::MetaInfo);
            }
        }
    }
    Ok(out)
}

/// BEP-52 Merkle root over block hashes: parents hash the concatenation of
/// children; a lone child is promoted unchanged.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for c in level.chunks(2) {
            if c.len() == 2 {
                next.push(Sha256::digest2(&c[0], &c[1]));
            } else {
                next.push(c[0]);
            }
        }
        level = next;
    }
    level[0]
}

/// Build a torrent from a metainfo-like info dict (used by tests/tools).
pub fn compute_v1_hashes(pieces: &[u8]) -> Result<Vec<[u8; 20]>> {
    if pieces.len() % 20 != 0 {
        return Err(Error::MetaInfo);
    }
    let mut out = Vec::with_capacity(pieces.len() / 20);
    for c in pieces.chunks_exact(20) {
        let mut h = [0u8; 20];
        h.copy_from_slice(c);
        out.push(h);
    }
    Ok(out)
}

impl Torrent {
    /// Construct a torrent from a raw bencoded `info` dictionary (fetched
    /// from peers via BEP-9 metadata exchange).
    pub fn from_info(info_raw: &[u8]) -> Result<Torrent> {
        let mut wrapper = Vec::with_capacity(info_raw.len() + 8);
        wrapper.extend_from_slice(b"d4:info");
        wrapper.extend_from_slice(info_raw);
        wrapper.push(b'e');
        Torrent::from_bytes(&wrapper)
    }

    /// A zero-content placeholder used before metadata arrives (keeps the
    /// scheduler and monitors constructible).
    pub fn empty_placeholder() -> Torrent {
        let info = dict(vec![
            (b"name", bytes("metadata")),
            (b"piece length", int(16384)),
            (b"pieces", bytes(Vec::new())),
            (b"length", int(0)),
        ]);
        let t = dict(vec![(b"info", info)]);
        let mut data = Vec::new();
        t.encode(&mut data);
        Torrent::from_bytes(&data).unwrap_or_else(|_| panic!("placeholder torrent must parse"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bencode::{bytes, dict, int};

    fn build_v1_torrent() -> Vec<u8> {
        let info = dict(vec![
            (b"name", bytes("hello.txt")),
            (b"piece length", int(16 * 1024)),
            (b"pieces", bytes(vec![0u8; 40])), // 2 pieces
            (b"length", int(32768)),
        ]);
        let t = dict(vec![
            (b"announce", bytes("http://t.example/announce")),
            (b"info", info),
        ]);
        let mut out = Vec::new();
        t.encode(&mut out);
        out
    }

    #[test]
    fn parse_v1_single_file() {
        let data = build_v1_torrent();
        let t = Torrent::from_bytes(&data).unwrap();
        assert_eq!(t.kind, TorrentKind::V1);
        assert_eq!(t.name, "hello.txt");
        assert_eq!(t.piece_count(), 2);
        assert_eq!(t.total_size, 32768);
        assert_eq!(t.files.len(), 1);
        assert!(t.info_hash.is_v1());
        let pi = t.piece_info(0).unwrap();
        assert_eq!(pi.file, 0);
        assert_eq!(pi.offset, 0);
        assert_eq!(pi.len, 16384);
        let pi = t.piece_info(1).unwrap();
        assert_eq!(pi.len, 16384);
    }

    #[test]
    fn verify_piece_v1() {
        // build a torrent whose v1 piece hashes match real piece data
        let piece_data: Vec<u8> = (0..16384).map(|i| (i % 251) as u8).collect();
        let mut pieces = Vec::new();
        pieces.extend_from_slice(&crate::crypto::Sha1::digest(&piece_data));
        pieces.extend_from_slice(&crate::crypto::Sha1::digest(&piece_data));
        let info = dict(vec![
            (b"name", bytes("hello.txt")),
            (b"piece length", int(16 * 1024)),
            (b"pieces", bytes(pieces)),
            (b"length", int(32768)),
        ]);
        let t = dict(vec![
            (b"announce", bytes("http://t.example/announce")),
            (b"info", info),
        ]);
        let mut data = Vec::new();
        t.encode(&mut data);
        let tor = Torrent::from_bytes(&data).unwrap();
        assert!(tor.verify_piece(0, &piece_data).is_ok());
        let mut bad = piece_data.clone();
        bad[0] ^= 0xff;
        assert!(tor.verify_piece(0, &bad).is_err());
    }

    #[test]
    fn v2_layout_does_not_cross_files() {
        // two files: 10KiB and 30KiB, piece 16KiB → file0:1 piece(10KiB), file1:2 pieces(16+14KiB)
        let pl = dict(vec![
            (b"root1", bytes(vec![0u8; 32])),
            (b"root2", bytes(vec![1u8; 32])),
        ]);
        let _ = pl;
        // Build a v2 torrent by hand with piece layers.
        let info = dict(vec![
            (b"name", bytes("dir")),
            (b"meta version", int(2)),
            (b"piece length", int(16384)),
            (
                b"file tree",
                dict(vec![
                    (
                        b"a.bin",
                        dict(vec![(
                            b"",
                            dict(vec![
                                (b"length", int(10240)),
                                (b"pieces root", bytes(vec![0xAA; 32])),
                            ]),
                        )]),
                    ),
                    (
                        b"b.bin",
                        dict(vec![(
                            b"",
                            dict(vec![
                                (b"length", int(30720)),
                                (b"pieces root", bytes(vec![0xBB; 32])),
                            ]),
                        )]),
                    ),
                ]),
            ),
        ]);
        // piece layers: file0 root → 1 hash; file1 root → 2 hashes
        let mut pl0 = Vec::new();
        let mut pl1 = Vec::new();
        pl0.extend_from_slice(&[0u8; 32]);
        pl1.extend_from_slice(&[1u8; 32]);
        pl1.extend_from_slice(&[2u8; 32]);
        let mut piece_layers = alloc::collections::BTreeMap::new();
        piece_layers.insert(vec![0xAAu8; 32], bytes(pl0));
        piece_layers.insert(vec![0xBBu8; 32], bytes(pl1));
        let t = dict(vec![
            (b"announce", bytes("http://t.example/announce")),
            (b"info", info),
            (b"piece layers", BVal::Dict(piece_layers)),
        ]);
        let mut data = Vec::new();
        t.encode(&mut data);
        let tor = Torrent::from_bytes(&data).unwrap();
        assert_eq!(tor.kind, TorrentKind::V2);
        assert!(tor.info_hash.is_v2());
        assert_eq!(tor.piece_count(), 3);
        let p0 = tor.piece_info(0).unwrap();
        assert_eq!((p0.file, p0.len), (0, 10240));
        let p1 = tor.piece_info(1).unwrap();
        assert_eq!((p1.file, p1.len), (1, 16384));
        let p2 = tor.piece_info(2).unwrap();
        assert_eq!((p2.file, p2.len), (1, 14336));
    }
}
