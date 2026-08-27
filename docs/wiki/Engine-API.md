# Engine API Reference

`typebit::Engine<H: Host>` is the whole surface you drive. The `std` feature
ships [`StdHost`](https://docs.rs/typebit/latest/typebit/host_std/struct.StdHost.html);
for anything else implement [`Host`](https://docs.rs/typebit/latest/typebit/trait.Host.html)
(see [Implementing a Host](Implementing-a-Host)).

## Construction

| Signature | Notes |
|---|---|
| `Engine::new(host, cfg) -> Engine<H>` | `cfg.proxy.is_some()` hardens the engine (no inbound/DHT/UDP/portmap, port 0). |
| `EngineConfig::default()` | listen 6881, DHT on, cache 256 MiB, 512 max conns, 8 per IP, 30 s connect timeout. |

`EngineConfig` fields: `listen_port`, `cache_bytes`, `dht_enabled`,
`global_upload_limit_bps`, `global_download_limit_bps`,
`global_max_connections`, `max_connections_per_ip`, `port_mapping`,
`verify_workers` (`0` = auto under `std`, inline under `no_std`), `proxy`,
`connect_timeout_ms`, `session` (`SessionConfig` per-torrent defaults).

## Adding content

| Signature | Notes |
|---|---|
| `add_torrent(data: &[u8], save_dir: &str) -> Result<InfoHash>` | parse + add a `.torrent` blob |
| `add_torrent_obj(torrent: Torrent, save_dir: &str) -> Result<InfoHash>` | add a pre-parsed `Torrent` |
| `add_magnet(uri: &str, save_dir: &str) -> Result<InfoHash>` | magnet; metadata fetched from peers |
| `add_torrents_batch(&[(&[u8], &str)]) -> Vec<Result<InfoHash>>` | one failure never aborts the batch |
| `add_magnets_batch(&[(&str, &str)]) -> Vec<Result<InfoHash>>` | same, for magnets |
| `restore_torrent(hash, &TorrentState) -> Result<()>` | re-apply persisted state after re-adding |
| `install_metadata(hash, info_raw: &[u8]) -> Result<()>` | persist pre-fetched info dict (magnet never re-fetches) |
| `remove_torrent(hash) -> Result<()>` | stop + drop the session |

## Lifecycle

| Signature | Notes |
|---|---|
| `start(hash) -> Result<()>` | begin announcing / connecting |
| `pause(hash)` | pause the session |
| `resume(hash)` | resume it |
| `tick() -> Result<()>` | drive everything; call on a ~100–500 ms timer |
| `stop_port_mapping()` | best-effort removal of the NAT mapping |

## Observability

| Signature | Notes |
|---|---|
| `progress(hash) -> f64` | 0.0 – 1.0, computed over *selected* pieces |
| `downloaded(hash) -> u64` / `uploaded(hash) -> u64` | payload bytes |
| `is_complete(hash) -> bool` | all selected pieces verified |
| `peer_snapshot(hash) -> Vec<PeerSnapshot>` | per-peer phase/rates/flags |
| `metainfo(hash) -> Option<&Torrent>` | parsed metainfo once known |
| `stats() -> EngineStats` | cache + connection counters |
| `active_trackers() -> usize` | live trackers across sessions |
| `torrent_count() -> usize` | loaded sessions |
| `peer_id() -> &[u8; 20]` | our peer id |
| `dht() -> Option<&Dht>` | DHT handle (table stats, etc.) |
| `dht_external() -> Option<([u8; 16], u16)>` | BEP-42 confirmed external address |
| `take_events() -> Vec<EngineEvent>` | drain events (see below) |
| `flush_cache()` | force the disk cache to disk |

## Control

| Signature | Notes |
|---|---|
| `add_tracker(hash, url) -> Result<bool>` / `remove_tracker(hash, url) -> Result<bool>` | runtime tracker management |
| `trackers(hash) -> Option<Vec<String>>` | current tracker list |
| `set_file_priority(hash, file, FilePriority) -> Result<()>` | one file |
| `set_file_priorities(hash, &[FilePriority]) -> Result<()>` | many at once |
| `file_priority(hash, file) -> Option<FilePriority>` | current value |
| `file_priorities(hash) -> Option<Vec<FilePriority>>` | all files |
| `set_hold_data(hash, hold) -> Result<()>` | queue-only mode (nothing requested) |
| `holding_data(hash) -> Option<bool>` | hold state |
| `set_global_limits(down_bps, up_bps)` | engine-wide token buckets |
| `set_session_limits(hash, down_bps, up_bps) -> Result<()>` | per-torrent |

`FilePriority` is `Skip | Normal | High` (`typebit::session::FilePriority`).

## Persistence

| Signature | Notes |
|---|---|
| `save_state() -> SessionState` | verified pieces, partial blocks, priorities, limits, reputation, DHT nodes |
| `load_state(&SessionState, now: u64)` | restore a previous session |

Restore pattern:

```rust
let state = engine.save_state();
// later, after re-adding the same torrents:
engine.load_state(&state, 0);
for t in &state.torrents {
    if let Some(hash) = /* your lookup */ {
        engine.restore_torrent(&hash, t)?;
    }
}
```

## Inbound connections

The host hands completed inbound TCP connections to the engine:

```rust
engine.on_inbound_connection(conn, addr); // conn: ConnId from Host::tcp_connect
```

The engine owns the socket from then on. Proxy mode rejects inbound
immediately.

## EngineEvent

`#[non_exhaustive]` — always match with a wildcard arm:

- `PeerConnected { info_hash, addr, peer_id }`
- `PieceVerified { info_hash, piece }`
- `HashFailure { info_hash, piece }`
- `TorrentComplete { info_hash }`
- `MetadataComplete { info_hash }` / `MetadataFailed { info_hash }`
- `TrackerAnnounced { info_hash, peers }`
- `PeerBanned { info_hash, addr, reason }`
- `PortMapping { phase, external_port }`
- `DhtNodeCount(usize)`
- `Error { code, detail }` — non-fatal degradation (`0` = UDP open failed, `1` = no DHT router resolvable)

## InfoHash

`typebit::InfoHash` (re-exported from `metainfo`):

- `InfoHash::v1([u8; 20])` / `InfoHash::v2([u8; 32])`
- `to_hex() -> String` / `from_hex(&str) -> Result<InfoHash>`
- `as_bytes()`, `len()`, `is_v1()`, `is_v2()`, `full() -> [u8; 32]`
- `Ord`/`Eq`/`Hash` — usable as a map key
