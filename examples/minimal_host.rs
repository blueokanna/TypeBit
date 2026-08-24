//! TypeBit example: a complete in-memory `Host` driving the engine.
//!
//! Run with:  cargo run --example minimal_host
//!
//! This is the full integration pattern you need for a real app:
//!   1. implement `typebit::Host` for your platform (here: an in-memory fake)
//!   2. build an `Engine` with it
//!   3. feed it a torrent / magnet
//!   4. call `tick()` on a timer, drain events, save/restore state

use std::collections::HashMap;

use typebit::platform::{ConnId, DiskId, Host, LogLevel, NetAddr};
use typebit::{Engine, EngineConfig, Error};

fn main() -> typebit::Result<()> {
    let host = MockHost::new();
    let mut engine = Engine::new(host, EngineConfig::default());

    let piece_data: Vec<u8> = (0..16 * 1024u32).map(|i| (i % 251) as u8).collect();
    let torrent_bytes = make_single_file_torrent(&piece_data);
    let hash = engine.add_torrent(&torrent_bytes, "/tmp/typebit-demo")?;
    println!(
        "added torrent {} ({} bytes metainfo)",
        hash.to_hex(),
        torrent_bytes.len()
    );
    // start() announces to trackers; the mock host can't, so tolerate.
    let _ = engine.start(&hash);

    let conn: ConnId = 1;
    engine.on_inbound_connection(conn, NetAddr::V4([203, 0, 113, 9], 6881));

    for round in 0..20 {
        // The mock host has no UDP/HTTP, so a tick may report NotSupported
        // for DHT/tracker work — that's fine, the engine keeps running.
        let _ = engine.tick();
        for ev in engine.take_events() {
            println!("event: {ev:?}");
        }
        println!(
            "round {round}: progress={:.2}% downloaded={}",
            engine.progress(&hash) * 100.0,
            engine.downloaded(&hash)
        );
    }

    let state = engine.save_state();
    let mut engine2 = Engine::new(MockHost::new(), EngineConfig::default());
    engine2.load_state(&state, 0);
    println!(
        "restored {} torrent(s), {} DHT node(s)",
        state.torrents.len(),
        state.dht_nodes.len()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// A minimal in-memory Host: one file "on disk" and one fake peer that has it.
// ---------------------------------------------------------------------------

struct MockHost {
    files: HashMap<DiskId, Vec<u8>>,
    next_disk: u32,
}

impl MockHost {
    fn new() -> Self {
        MockHost {
            files: HashMap::new(),
            next_disk: 1,
        }
    }
}

impl Host for MockHost {
    fn now_ms(&self) -> u64 {
        0
    }
    fn fill_random(&mut self, buf: &mut [u8]) {
        // Demo only — never do this in production.
        for b in buf.iter_mut() {
            *b = 7;
        }
    }
    fn log(&mut self, _level: LogLevel, _msg: &str) {}
    fn http_get(&mut self, _url: &str, _timeout_ms: u64, _out: &mut Vec<u8>) -> Result<(), Error> {
        Err(Error::NotSupported)
    }
    fn tcp_connect(&mut self, _addr: &NetAddr) -> Result<ConnId, Error> {
        // The "peer" accepts immediately.
        Ok(1)
    }
    fn tcp_connect_done(&mut self, _id: ConnId) -> Result<(), Error> {
        Ok(())
    }
    fn tcp_send(&mut self, _id: ConnId, _data: &[u8]) -> Result<usize, Error> {
        Ok(_data.len())
    }
    fn tcp_recv(&mut self, _id: ConnId, _buf: &mut [u8]) -> Result<usize, Error> {
        Err(Error::WouldBlock)
    }
    fn tcp_close(&mut self, _id: ConnId) {}
    fn udp_open(&mut self, _port: u16) -> Result<(), Error> {
        Err(Error::NotSupported)
    }
    fn udp_send(&mut self, _addr: &NetAddr, _data: &[u8]) -> Result<(), Error> {
        Err(Error::NotSupported)
    }
    fn udp_recv(&mut self, _buf: &mut [u8]) -> Result<(NetAddr, usize), Error> {
        Err(Error::WouldBlock)
    }
    fn disk_open(&mut self, _path: &str) -> Result<DiskId, Error> {
        let id = self.next_disk;
        self.next_disk += 1;
        self.files.insert(id, Vec::new());
        Ok(id)
    }
    fn disk_read(&mut self, id: DiskId, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let f = self.files.get(&id).ok_or(Error::NotFound)?;
        let start = offset as usize;
        let n = buf.len().min(f.len().saturating_sub(start));
        buf[..n].copy_from_slice(&f[start..start + n]);
        Ok(n)
    }
    fn disk_write(&mut self, id: DiskId, offset: u64, data: &[u8]) -> Result<(), Error> {
        let f = self.files.get_mut(&id).ok_or(Error::NotFound)?;
        let end = offset as usize + data.len();
        if f.len() < end {
            f.resize(end, 0);
        }
        f[offset as usize..end].copy_from_slice(data);
        Ok(())
    }
    fn disk_prealloc(&mut self, _id: DiskId, size: u64) -> Result<(), Error> {
        if let Some(f) = self.files.get_mut(&_id) {
            f.resize(size as usize, 0);
        }
        Ok(())
    }
    fn disk_flush(&mut self, _id: DiskId) -> Result<(), Error> {
        Ok(())
    }
    fn disk_close(&mut self, _id: DiskId) {}
}

// ---------------------------------------------------------------------------
// Torrent construction helpers (bencode is dependency-free in TypeBit).
// ---------------------------------------------------------------------------

fn make_single_file_torrent(piece: &[u8]) -> Vec<u8> {
    use typebit::bencode::{bytes, dict, int};
    let info = dict(vec![
        (b"name", bytes("hello.bin")),
        (b"piece length", int(16 * 1024)),
        (b"length", int(piece.len() as i64)),
        (b"pieces", bytes(sha1_of(piece))),
    ]);
    let root = dict(vec![(b"info", info)]);
    typebit::bencode::encode_to_vec(&root)
}

fn sha1_of(data: &[u8]) -> Vec<u8> {
    typebit::crypto::Sha1::digest(data).to_vec()
}
