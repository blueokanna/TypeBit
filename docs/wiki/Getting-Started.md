# Getting Started

This page walks you from an empty project to a running engine that downloads
a torrent, verifies every byte, and survives a restart. All code below is
real, compilable TypeBit API — nothing simplified.

## 1. Add the dependency

```toml
[dependencies]
typebit = { version = "0.1", features = ["std"] }
```

| Feature | Use it when |
|---|---|
| *(default)* | embedded / `no_std` targets; you implement `Host` |
| `std` | desktop/server; use the built-in `StdHost` |
| `ffi` | exposing the engine to Kotlin / Swift / C# / Go |

## 2. Parse links and torrent files

Link parsing is dependency-free and works on every feature combo:

```rust
use typebit::links::parse_link;

let link = parse_link(
    "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=hello",
)?;
match link {
    typebit::links::DownloadLink::BitTorrent(m) => {
        println!("torrent: {}", m.name.as_deref().unwrap_or("<unnamed>"));
        println!("display name: {}", m.display_name.as_deref().unwrap_or("-"));
        for tr in &m.announce_list {
            println!("tracker: {tr}");
        }
    }
    other => println!("not a magnet: {other:?}"),
}
# Ok::<(), typebit::Error>(())
```

A `.torrent` blob parses independently of the engine:

```rust
use typebit::metainfo::Torrent;

let t = Torrent::from_bytes(&torrent_bytes)?;
println!(
    "{}: {} pieces of {} KiB, {} bytes total, kind={:?}",
    t.name,
    t.piece_count(),
    t.piece_length / 1024,
    t.total_size,
    t.kind, // TorrentKind::V1 | V2 | Hybrid
);
// Verify a piece you already have:
t.verify_piece(0, &piece_data)?; // Ok(()) or Err(Error::HashMismatch)
# Ok::<(), typebit::Error>(())
```

## 3. Run an engine with the std host

`StdHost` gives you sockets, files, clock, DNS and RNG — the full transport
seam. Build an engine, add a torrent, start it, and pump it from a timer:

```rust,no_run
use typebit::host_std::StdHost;
use typebit::{Engine, EngineConfig, EngineEvent};

let mut engine = Engine::new(StdHost::new(), EngineConfig::default());

// Add a .torrent file (bytes) or a magnet:
let hash = engine.add_torrent(&torrent_bytes, "/path/to/downloads")?;
// let hash = engine.add_magnet("magnet:?...", "/path/to/downloads")?;

// Start announcing / connecting:
engine.start(&hash)?;

// Your event loop — call tick() on a timer (~100-500 ms), never block long:
loop {
    engine.tick()?; // drives sessions, DHT, UDP, portmap, web seeds, uTP
    for ev in engine.take_events() {
        match ev {
            EngineEvent::PieceVerified { piece, .. } => println!("piece {piece} verified"),
            EngineEvent::TorrentComplete { .. } => println!("download complete!"),
            EngineEvent::MetadataComplete { .. } => println!("magnet metadata arrived"),
            EngineEvent::MetadataFailed { .. } => println!("magnet metadata failed"),
            EngineEvent::PeerConnected { addr, .. } => println!("peer {addr} connected"),
            EngineEvent::HashFailure { piece, .. } => println!("piece {piece} failed hash"),
            EngineEvent::PeerBanned { addr, reason, .. } => {
                println!("peer {addr} banned: {reason:?}")
            }
            EngineEvent::DhtNodeCount(n) => println!("DHT nodes: {n}"),
            EngineEvent::Error { code, detail } => {
                println!("engine degraded: {detail} (code {code})")
            }
            _ => {}
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
}
# Ok::<(), typebit::Error>(())
```

`Engine::new` with a proxy in `EngineConfig` automatically hardens the
engine: no inbound, no DHT, no UDP trackers, no port mapping, advertised
listen port `0`.

## 4. Selective download & rate limits

```rust
use typebit::session::FilePriority;

// Per-file priorities (index = file index): Skip / Normal / High.
engine.set_file_priorities(&hash, &[
    FilePriority::Skip,   // file 0: don't download
    FilePriority::High,   // file 1: download first
])?;
engine.set_file_priority(&hash, 2, FilePriority::Normal)?;

// Hold data (queue only, verify nothing) until priorities are committed:
engine.set_hold_data(&hash, true)?;
engine.set_file_priorities(&hash, &[FilePriority::Normal, FilePriority::Skip])?;
engine.set_hold_data(&hash, false)?; // commit: releases the hold

// Rate limits (bytes/s; 0 = unlimited):
engine.set_global_limits(2 * 1024 * 1024, 512 * 1024);   // global
engine.set_session_limits(&hash, 1 * 1024 * 1024, 256 * 1024)?; // per-task
```

## 5. Observe and persist

```rust
println!("progress: {:.1}%", engine.progress(&hash) * 100.0);
println!("downloaded: {} bytes", engine.downloaded(&hash));
println!("uploaded: {} bytes", engine.uploaded(&hash));
println!("complete: {}", engine.is_complete(&hash));

// Stats dialog data (qBittorrent-style):
let stats = engine.stats();
println!("connected peers: {}", stats.connected_peers);
println!("cache dirty entries: {}", stats.cache_dirty_entries);

// Peer snapshot for a peer list UI:
for p in engine.peer_snapshot(&hash) {
    println!("{} phase={:?} seed={} down={}B/s", p.addr, p.phase, p.is_seed, p.down_rate);
}

// Save and restore everything (verified pieces, priorities, limits,
// reputation, DHT nodes):
let state = engine.save_state();
let mut engine2 = Engine::new(StdHost::new(), EngineConfig::default());
engine2.load_state(&state, 0);
```

## 6. Add trackers at runtime

```rust
engine.add_tracker(&hash, "udp://tracker.opentrackr.org:1337/announce")?;
engine.remove_tracker(&hash, "udp://tracker.opentrackr.org:1337/announce")?;
for url in engine.trackers(&hash).unwrap_or_default() {
    println!("active tracker: {url}");
}
```

## 7. The full example programs

```sh
cargo run --example parse_links              # every link format, live
cargo run --example minimal_host             # in-memory Host driving a real engine
cargo run --example ffi_demo --features ffi  # C ABI end-to-end
```

`minimal_host.rs` is the canonical reference for implementing `Host` on a
platform that `StdHost` does not cover (see
[Implementing a Host](Implementing-a-Host)).
