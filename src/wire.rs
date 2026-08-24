//! Peer wire protocol (BEP-3) with extensions:
//! - BEP-6 fast extension (`have_all`/`have_none`/`suggest`/`reject`/`allowed_fast`)
//! - BEP-10 extended handshake
//! - BEP-9 metadata exchange (`ut_metadata`)
//! - BEP-11 peer exchange (`ut_pex`)
//! - BEP-52 v2 reserved bit
//!
//! All codecs are allocation-bounded and reject malformed frames.

use crate::bencode::{dict, BVal};
use crate::error::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Protocol string.
pub const PROTOCOL: &[u8] = b"BitTorrent protocol";
/// Handshake frame length (pstrlen + pstr + reserved + infohash + peerid).
pub const HANDSHAKE_LEN: usize = 68;

/// Reserved bits (byte index, mask).
pub mod reserved {
    /// Extension protocol (BEP-10).
    pub const EXTENSION: (usize, u8) = (5, 0x10);
    /// DHT (BEP-5).
    pub const DHT: (usize, u8) = (7, 0x01);
    /// Fast extension (BEP-6).
    pub const FAST: (usize, u8) = (7, 0x04);
    /// Metadata exchange (BEP-9).
    pub const METADATA: (usize, u8) = (7, 0x08);
    /// BEP-52 v2 support.
    pub const V2: (usize, u8) = (7, 0x80);
}

/// A peer handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    /// Reserved bits.
    pub reserved: [u8; 8],
    /// Info hash (20 bytes; v2 peers send the truncated 20-byte infohash).
    pub info_hash: [u8; 20],
    /// Peer id.
    pub peer_id: [u8; 20],
}

impl Handshake {
    /// Encode the handshake frame.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HANDSHAKE_LEN);
        out.push(PROTOCOL.len() as u8);
        out.extend_from_slice(PROTOCOL);
        out.extend_from_slice(&self.reserved);
        out.extend_from_slice(&self.info_hash);
        out.extend_from_slice(&self.peer_id);
        out
    }

    /// Parse a full 68-byte handshake.
    pub fn parse(buf: &[u8]) -> Result<Handshake> {
        if buf.len() != HANDSHAKE_LEN {
            return Err(Error::Handshake);
        }
        let pstrlen = buf[0] as usize;
        if pstrlen != PROTOCOL.len() || &buf[1..1 + pstrlen] != PROTOCOL {
            return Err(Error::Handshake);
        }
        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&buf[1 + pstrlen..1 + pstrlen + 8]);
        let mut info_hash = [0u8; 20];
        info_hash.copy_from_slice(&buf[1 + pstrlen + 8..1 + pstrlen + 8 + 20]);
        let mut peer_id = [0u8; 20];
        peer_id.copy_from_slice(&buf[1 + pstrlen + 8 + 20..]);
        Ok(Handshake {
            reserved,
            info_hash,
            peer_id,
        })
    }

    /// Extension protocol supported?
    pub fn has_extension(&self) -> bool {
        self.reserved[reserved::EXTENSION.0] & reserved::EXTENSION.1 != 0
    }
    /// DHT supported?
    pub fn has_dht(&self) -> bool {
        self.reserved[reserved::DHT.0] & reserved::DHT.1 != 0
    }
    /// Fast extension supported?
    pub fn has_fast(&self) -> bool {
        self.reserved[reserved::FAST.0] & reserved::FAST.1 != 0
    }
    /// Metadata exchange supported?
    pub fn has_metadata(&self) -> bool {
        self.reserved[reserved::METADATA.0] & reserved::METADATA.1 != 0
    }
    /// v2 supported?
    pub fn has_v2(&self) -> bool {
        self.reserved[reserved::V2.0] & reserved::V2.1 != 0
    }
}

/// Wire message ids.
pub mod msgid {
    /// 0 — choke.
    pub const CHOKE: u8 = 0;
    /// 1 — unchoke.
    pub const UNCHOKE: u8 = 1;
    /// 2 — interested.
    pub const INTERESTED: u8 = 2;
    /// 3 — not interested.
    pub const NOT_INTERESTED: u8 = 3;
    /// 4 — have(piece).
    pub const HAVE: u8 = 4;
    /// 5 — bitfield.
    pub const BITFIELD: u8 = 5;
    /// 6 — request.
    pub const REQUEST: u8 = 6;
    /// 7 — piece data.
    pub const PIECE: u8 = 7;
    /// 8 — cancel.
    pub const CANCEL: u8 = 8;
    /// 9 — DHT port.
    pub const PORT: u8 = 9;
    /// 20 — extended message.
    pub const EXTENDED: u8 = 20;
    // fast extension
    /// 0x0E — suggest.
    pub const SUGGEST: u8 = 0x0E;
    /// 0x0F — have_all.
    pub const HAVE_ALL: u8 = 0x0F;
    /// 0x10 — have_none.
    pub const HAVE_NONE: u8 = 0x10;
    /// 0x11 — reject.
    pub const REJECT: u8 = 0x11;
    /// 0x12 — allowed_fast.
    pub const ALLOWED_FAST: u8 = 0x12;
}

/// A decoded peer-wire message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Keep-alive (zero-length frame).
    KeepAlive,
    /// 0 — choke.
    Choke,
    /// 1 — unchoke.
    Unchoke,
    /// 2 — interested.
    Interested,
    /// 3 — not interested.
    NotInterested,
    /// 4 — have(piece).
    Have(u32),
    /// 5 — bitfield bytes.
    Bitfield(Vec<u8>),
    /// 6 — request.
    Request {
        /// Piece index.
        index: u32,
        /// Byte offset within the piece.
        begin: u32,
        /// Requested length (≤ 16 KiB).
        length: u32,
    },
    /// 7 — piece data.
    Piece {
        /// Piece index.
        index: u32,
        /// Byte offset within the piece.
        begin: u32,
        /// Payload bytes.
        data: Vec<u8>,
    },
    /// 8 — cancel.
    Cancel {
        /// Piece index.
        index: u32,
        /// Byte offset within the piece.
        begin: u32,
        /// Length.
        length: u32,
    },
    /// 9 — DHT port.
    Port(u16),
    /// 20 — extended message (extended id + payload).
    Extended {
        /// Extended message id (0 = handshake, ut_metadata, ut_pex…).
        id: u8,
        /// Extended payload.
        payload: Vec<u8>,
    },
    /// 0x0E — suggest.
    Suggest(u32),
    /// 0x0F — have_all.
    HaveAll,
    /// 0x10 — have_none.
    HaveNone,
    /// 0x11 — reject.
    Reject {
        /// Piece index.
        index: u32,
        /// Byte offset within the piece.
        begin: u32,
        /// Length.
        length: u32,
    },
    /// 0x12 — allowed_fast.
    AllowedFast(u32),
}

impl Message {
    /// Encode with the 4-byte length prefix.
    pub fn encode(&self) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        match self {
            Message::KeepAlive => return vec![0, 0, 0, 0],
            Message::Choke => body.push(msgid::CHOKE),
            Message::Unchoke => body.push(msgid::UNCHOKE),
            Message::Interested => body.push(msgid::INTERESTED),
            Message::NotInterested => body.push(msgid::NOT_INTERESTED),
            Message::Have(p) => {
                body.push(msgid::HAVE);
                body.extend_from_slice(&p.to_be_bytes());
            }
            Message::Bitfield(b) => {
                body.push(msgid::BITFIELD);
                body.extend_from_slice(b);
            }
            Message::Request {
                index,
                begin,
                length,
            } => {
                body.push(msgid::REQUEST);
                body.extend_from_slice(&index.to_be_bytes());
                body.extend_from_slice(&begin.to_be_bytes());
                body.extend_from_slice(&length.to_be_bytes());
            }
            Message::Piece { index, begin, data } => {
                body.push(msgid::PIECE);
                body.extend_from_slice(&index.to_be_bytes());
                body.extend_from_slice(&begin.to_be_bytes());
                body.extend_from_slice(data);
            }
            Message::Cancel {
                index,
                begin,
                length,
            } => {
                body.push(msgid::CANCEL);
                body.extend_from_slice(&index.to_be_bytes());
                body.extend_from_slice(&begin.to_be_bytes());
                body.extend_from_slice(&length.to_be_bytes());
            }
            Message::Port(p) => {
                body.push(msgid::PORT);
                body.extend_from_slice(&p.to_be_bytes());
            }
            Message::Extended { id, payload } => {
                body.push(msgid::EXTENDED);
                body.push(*id);
                body.extend_from_slice(payload);
            }
            Message::Suggest(p) => {
                body.push(msgid::SUGGEST);
                body.extend_from_slice(&p.to_be_bytes());
            }
            Message::HaveAll => body.push(msgid::HAVE_ALL),
            Message::HaveNone => body.push(msgid::HAVE_NONE),
            Message::Reject {
                index,
                begin,
                length,
            } => {
                body.push(msgid::REJECT);
                body.extend_from_slice(&index.to_be_bytes());
                body.extend_from_slice(&begin.to_be_bytes());
                body.extend_from_slice(&length.to_be_bytes());
            }
            Message::AllowedFast(p) => {
                body.push(msgid::ALLOWED_FAST);
                body.extend_from_slice(&p.to_be_bytes());
            }
        }
        let mut out = Vec::with_capacity(body.len() + 4);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Decode one message body (after the length prefix) with an id.
    pub fn decode(id: u8, payload: &[u8]) -> Result<Message> {
        match id {
            msgid::CHOKE => Ok(Message::Choke),
            msgid::UNCHOKE => Ok(Message::Unchoke),
            msgid::INTERESTED => Ok(Message::Interested),
            msgid::NOT_INTERESTED => Ok(Message::NotInterested),
            msgid::HAVE => {
                if payload.len() != 4 {
                    return Err(Error::Protocol);
                }
                Ok(Message::Have(be32(payload)))
            }
            msgid::BITFIELD => Ok(Message::Bitfield(payload.to_vec())),
            msgid::REQUEST => {
                if payload.len() != 12 {
                    return Err(Error::Protocol);
                }
                Ok(Message::Request {
                    index: be32(&payload[0..4]),
                    begin: be32(&payload[4..8]),
                    length: be32(&payload[8..12]),
                })
            }
            msgid::PIECE => {
                if payload.len() < 8 {
                    return Err(Error::Protocol);
                }
                Ok(Message::Piece {
                    index: be32(&payload[0..4]),
                    begin: be32(&payload[4..8]),
                    data: payload[8..].to_vec(),
                })
            }
            msgid::CANCEL => {
                if payload.len() != 12 {
                    return Err(Error::Protocol);
                }
                Ok(Message::Cancel {
                    index: be32(&payload[0..4]),
                    begin: be32(&payload[4..8]),
                    length: be32(&payload[8..12]),
                })
            }
            msgid::PORT => {
                if payload.len() != 2 {
                    return Err(Error::Protocol);
                }
                Ok(Message::Port(u16::from_be_bytes([payload[0], payload[1]])))
            }
            msgid::EXTENDED => {
                if payload.is_empty() {
                    return Err(Error::Protocol);
                }
                Ok(Message::Extended {
                    id: payload[0],
                    payload: payload[1..].to_vec(),
                })
            }
            msgid::SUGGEST => {
                if payload.len() != 4 {
                    return Err(Error::Protocol);
                }
                Ok(Message::Suggest(be32(payload)))
            }
            msgid::HAVE_ALL => Ok(Message::HaveAll),
            msgid::HAVE_NONE => Ok(Message::HaveNone),
            msgid::REJECT => {
                if payload.len() != 12 {
                    return Err(Error::Protocol);
                }
                Ok(Message::Reject {
                    index: be32(&payload[0..4]),
                    begin: be32(&payload[4..8]),
                    length: be32(&payload[8..12]),
                })
            }
            msgid::ALLOWED_FAST => {
                if payload.len() != 4 {
                    return Err(Error::Protocol);
                }
                Ok(Message::AllowedFast(be32(payload)))
            }
            _ => Err(Error::Protocol),
        }
    }
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Streaming message parser with an explicit max frame size.
#[derive(Debug)]
pub struct MessageStream {
    buf: Vec<u8>,
    max_frame: usize,
}

impl MessageStream {
    /// Create with a frame-size cap (default 4 MiB, enough for a 16 MiB
    /// piece split into 16 KiB blocks and large bitfields).
    pub fn new() -> Self {
        MessageStream {
            buf: Vec::with_capacity(64 * 1024),
            max_frame: 4 * 1024 * 1024,
        }
    }

    /// Append incoming bytes.
    pub fn feed(&mut self, data: &[u8]) {
        if self.buf.capacity() - self.buf.len() < data.len() {
            self.buf.reserve(data.len());
        }
        self.buf.extend_from_slice(data);
    }

    /// Pop the next message. `Ok(None)` = need more data.
    pub fn poll(&mut self) -> Result<Option<Message>> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = be32(&self.buf[0..4]) as usize;
        if len == 0 {
            self.buf.drain(..4);
            return Ok(Some(Message::KeepAlive));
        }
        if len > self.max_frame {
            return Err(Error::TooLarge);
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let id = self.buf[4];
        let payload = self.buf[5..4 + len].to_vec();
        self.buf.drain(..4 + len);
        Message::decode(id, &payload).map(Some)
    }

    /// Bytes buffered.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Cap on a single frame.
    pub fn max_frame(&self) -> usize {
        self.max_frame
    }

    /// Adjust the frame cap (e.g. for metadata pieces).
    pub fn set_max_frame(&mut self, max: usize) {
        self.max_frame = max;
    }
}

impl Default for MessageStream {
    fn default() -> Self {
        Self::new()
    }
}

/// BEP-10 extended handshake.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtHandshake {
    /// Extended message ids offered by the peer: name → id.
    pub m: BTreeMap<String, u8>,
    /// Client version string.
    pub v: Option<String>,
    /// Request queue size.
    pub reqq: Option<u32>,
    /// Metadata size (BEP-9).
    pub metadata_size: Option<u32>,
    /// DHT port.
    pub p: Option<u32>,
}

impl ExtHandshake {
    /// Encode to bencode (id 0 payload).
    pub fn encode(&self) -> Vec<u8> {
        let mut entries: Vec<(&[u8], BVal)> = Vec::new();
        if !self.m.is_empty() {
            let mut md = BTreeMap::new();
            for (k, v) in &self.m {
                md.insert(k.as_bytes().to_vec(), BVal::Int(*v as i64));
            }
            entries.push((b"m", BVal::Dict(md)));
        }
        if let Some(v) = &self.v {
            entries.push((b"v", BVal::Bytes(v.as_bytes().to_vec())));
        }
        if let Some(r) = self.reqq {
            entries.push((b"reqq", BVal::Int(r as i64)));
        }
        if let Some(ms) = self.metadata_size {
            entries.push((b"metadata_size", BVal::Int(ms as i64)));
        }
        if let Some(p) = self.p {
            entries.push((b"p", BVal::Int(p as i64)));
        }
        let mut out = Vec::new();
        dict(entries).encode(&mut out);
        out
    }

    /// Parse from payload bytes.
    pub fn parse(payload: &[u8]) -> Result<ExtHandshake> {
        let v = BVal::parse(payload)?;
        let d = v.as_dict().ok_or(Error::Protocol)?;
        let mut out = ExtHandshake::default();
        if let Some(m) = d.get(&b"m"[..]).and_then(|x| x.as_dict()) {
            for (k, val) in m {
                if let Some(id) = val.as_int() {
                    out.m
                        .insert(String::from_utf8_lossy(k).into_owned(), id as u8);
                }
            }
        }
        out.v = d.get(&b"v"[..]).and_then(|x| x.as_str()).map(String::from);
        out.reqq = d
            .get(&b"reqq"[..])
            .and_then(|x| x.as_int())
            .map(|i| i as u32);
        out.metadata_size = d
            .get(&b"metadata_size"[..])
            .and_then(|x| x.as_int())
            .map(|i| i as u32);
        out.p = d.get(&b"p"[..]).and_then(|x| x.as_int()).map(|i| i as u32);
        Ok(out)
    }
}

/// BEP-9 metadata exchange message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataMsg {
    /// Request a metadata piece.
    Request {
        /// Metadata piece index.
        piece: u32,
    },
    /// Metadata piece data.
    Data {
        /// Metadata piece index.
        piece: u32,
        /// Total metadata size in bytes.
        total_size: u32,
        /// Piece bytes.
        data: Vec<u8>,
    },
    /// Reject.
    Reject {
        /// Metadata piece index.
        piece: u32,
    },
}

impl MetadataMsg {
    /// Encode (extended payload, without the extended id byte).
    pub fn encode(&self) -> Vec<u8> {
        let (msg_type, piece, total, data): (i64, i64, i64, Vec<u8>) = match self {
            MetadataMsg::Request { piece } => (0, *piece as i64, 0, Vec::new()),
            MetadataMsg::Data {
                piece,
                total_size,
                data,
            } => (1, *piece as i64, *total_size as i64, data.clone()),
            MetadataMsg::Reject { piece } => (2, *piece as i64, 0, Vec::new()),
        };
        let mut entries: Vec<(&[u8], BVal)> = vec![
            (b"msg_type", BVal::Int(msg_type)),
            (b"piece", BVal::Int(piece)),
        ];
        if msg_type == 1 {
            entries.push((b"total_size", BVal::Int(total)));
        }
        let mut out = Vec::new();
        dict(entries).encode(&mut out);
        if msg_type == 1 {
            out.extend_from_slice(&data);
        }
        out
    }

    /// Parse payload (excluding the extended id byte).
    pub fn parse(payload: &[u8]) -> Result<MetadataMsg> {
        // find the end of the bencoded dict (bounded scan)
        let mut p = crate::bencode::Parser::new(payload);
        let v = p.value(0)?;
        let consumed = p.position();
        let d = v.as_dict().ok_or(Error::Protocol)?;
        let msg_type = d
            .get(&b"msg_type"[..])
            .and_then(|x| x.as_int())
            .ok_or(Error::Protocol)?;
        let piece = d
            .get(&b"piece"[..])
            .and_then(|x| x.as_int())
            .ok_or(Error::Protocol)? as u32;
        match msg_type {
            0 => Ok(MetadataMsg::Request { piece }),
            1 => {
                let total = d
                    .get(&b"total_size"[..])
                    .and_then(|x| x.as_int())
                    .ok_or(Error::Protocol)? as u32;
                let data = payload[consumed..].to_vec();
                Ok(MetadataMsg::Data {
                    piece,
                    total_size: total,
                    data,
                })
            }
            2 => Ok(MetadataMsg::Reject { piece }),
            _ => Err(Error::Protocol),
        }
    }
}

/// BEP-11 peer exchange message (ut_pex).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PexMsg {
    /// Added peers (compact IPv4 6-byte each).
    pub added: Vec<u8>,
    /// Flags for added peers.
    pub added_f: Vec<u8>,
    /// Dropped peers (compact IPv4).
    pub dropped: Vec<u8>,
    /// Added IPv6 peers (18-byte each).
    pub added6: Vec<u8>,
    /// Flags for added6.
    pub added6_f: Vec<u8>,
    /// Dropped IPv6.
    pub dropped6: Vec<u8>,
}

impl PexMsg {
    /// Encode to bencoded payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut entries: Vec<(&[u8], BVal)> = Vec::new();
        if !self.added.is_empty() {
            entries.push((b"added", BVal::Bytes(self.added.clone())));
        }
        if !self.added_f.is_empty() {
            entries.push((b"added.f", BVal::Bytes(self.added_f.clone())));
        }
        if !self.dropped.is_empty() {
            entries.push((b"dropped", BVal::Bytes(self.dropped.clone())));
        }
        if !self.added6.is_empty() {
            entries.push((b"added6", BVal::Bytes(self.added6.clone())));
        }
        if !self.added6_f.is_empty() {
            entries.push((b"added6.f", BVal::Bytes(self.added6_f.clone())));
        }
        if !self.dropped6.is_empty() {
            entries.push((b"dropped6", BVal::Bytes(self.dropped6.clone())));
        }
        let mut out = Vec::new();
        dict(entries).encode(&mut out);
        out
    }

    /// Parse bencoded payload.
    pub fn parse(payload: &[u8]) -> Result<PexMsg> {
        let v = BVal::parse(payload)?;
        let d = v.as_dict().ok_or(Error::Protocol)?;
        let mut out = PexMsg::default();
        if let Some(a) = d.get(&b"added"[..]).and_then(|x| x.as_bytes()) {
            if a.len() % 6 == 0 {
                out.added = a.to_vec();
            }
        }
        if let Some(a) = d.get(&b"added.f"[..]).and_then(|x| x.as_bytes()) {
            if a.len() == out.added.len() / 6 {
                out.added_f = a.to_vec();
            }
        }
        if let Some(a) = d.get(&b"dropped"[..]).and_then(|x| x.as_bytes()) {
            if a.len() % 6 == 0 {
                out.dropped = a.to_vec();
            }
        }
        if let Some(a) = d.get(&b"added6"[..]).and_then(|x| x.as_bytes()) {
            if a.len() % 18 == 0 {
                out.added6 = a.to_vec();
            }
        }
        if let Some(a) = d.get(&b"added6.f"[..]).and_then(|x| x.as_bytes()) {
            if a.len() == out.added6.len() / 18 {
                out.added6_f = a.to_vec();
            }
        }
        if let Some(a) = d.get(&b"dropped6"[..]).and_then(|x| x.as_bytes()) {
            if a.len() % 18 == 0 {
                out.dropped6 = a.to_vec();
            }
        }
        Ok(out)
    }
}

/// Encode IPv4 peers as compact 6-byte entries (BEP-23).
pub fn compact_peers4(list: &[crate::platform::NetAddr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(list.len() * 6);
    for a in list {
        if let Some(b) = a.to_compact6() {
            out.extend_from_slice(&b);
        }
    }
    out
}

/// Encode IPv6 peers as compact 18-byte entries (BEP-23).
pub fn compact_peers6(list: &[crate::platform::NetAddr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(list.len() * 18);
    for a in list {
        if let Some(b) = a.to_compact18() {
            out.extend_from_slice(&b);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_roundtrip() {
        let h = Handshake {
            reserved: {
                let mut r = [0u8; 8];
                r[reserved::EXTENSION.0] |= reserved::EXTENSION.1;
                r[reserved::DHT.0] |= reserved::DHT.1;
                r[reserved::FAST.0] |= reserved::FAST.1;
                r[reserved::METADATA.0] |= reserved::METADATA.1;
                r
            },
            info_hash: [7u8; 20],
            peer_id: [9u8; 20],
        };
        let enc = h.encode();
        assert_eq!(enc.len(), HANDSHAKE_LEN);
        let dec = Handshake::parse(&enc).unwrap();
        assert_eq!(dec, h);
        assert!(dec.has_extension());
        assert!(dec.has_dht());
        assert!(dec.has_fast());
        assert!(dec.has_metadata());
        // wrong protocol
        let mut bad = enc.clone();
        bad[1] = b'X';
        assert!(Handshake::parse(&bad).is_err());
    }

    #[test]
    fn message_roundtrip() {
        for m in [
            Message::Choke,
            Message::Unchoke,
            Message::Interested,
            Message::NotInterested,
            Message::Have(42),
            Message::Bitfield(vec![0b1010_0000, 0]),
            Message::Request {
                index: 1,
                begin: 16384,
                length: 16384,
            },
            Message::Piece {
                index: 2,
                begin: 0,
                data: vec![1, 2, 3],
            },
            Message::Cancel {
                index: 3,
                begin: 0,
                length: 16384,
            },
            Message::Port(6881),
            Message::Extended {
                id: 3,
                payload: vec![9, 9],
            },
            Message::Suggest(1),
            Message::HaveAll,
            Message::HaveNone,
            Message::Reject {
                index: 4,
                begin: 0,
                length: 16384,
            },
            Message::AllowedFast(5),
            Message::KeepAlive,
        ] {
            let enc = m.encode();
            // decode via stream
            let mut s = MessageStream::new();
            s.feed(&enc);
            let out = s.poll().unwrap().unwrap();
            assert_eq!(out, m);
            assert!(s.poll().unwrap().is_none());
        }
    }

    #[test]
    fn streaming_partial_frames() {
        let m = Message::Piece {
            index: 1,
            begin: 0,
            data: vec![9; 100],
        };
        let enc = m.encode();
        let mut s = MessageStream::new();
        for chunk in enc.chunks(7) {
            s.feed(chunk);
        }
        assert_eq!(s.poll().unwrap().unwrap(), m);
    }

    #[test]
    fn extended_handshake_roundtrip() {
        let mut e = ExtHandshake::default();
        e.m.insert("ut_metadata".into(), 3);
        e.m.insert("ut_pex".into(), 5);
        e.v = Some("TypeBit 0.1".into());
        e.reqq = Some(250);
        e.metadata_size = Some(12345);
        let enc = e.encode();
        let dec = ExtHandshake::parse(&enc).unwrap();
        assert_eq!(dec, e);
    }

    #[test]
    fn metadata_msg_roundtrip() {
        let m = MetadataMsg::Data {
            piece: 1,
            total_size: 100,
            data: vec![7; 40],
        };
        let enc = m.encode();
        let dec = MetadataMsg::parse(&enc).unwrap();
        assert_eq!(dec, m);
        let req = MetadataMsg::Request { piece: 0 };
        let enc = req.encode();
        assert_eq!(MetadataMsg::parse(&enc).unwrap(), req);
    }

    #[test]
    fn pex_roundtrip() {
        let p = PexMsg {
            added: vec![192, 168, 1, 1, 0x1A, 0xE1, 10, 0, 0, 2, 0x1A, 0xE1],
            added_f: vec![1, 0],
            dropped: vec![192, 168, 1, 2, 0x1A, 0xE1],
            ..Default::default()
        };
        let enc = p.encode();
        let dec = PexMsg::parse(&enc).unwrap();
        assert_eq!(dec, p);
    }
}
