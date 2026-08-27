# TypeBit

[![crates.io](https://img.shields.io/crates/v/typebit.svg)](https://crates.io/crates/typebit)
[![crates.io downloads](https://img.shields.io/crates/d/typebit.svg)](https://crates.io/crates/typebit)
[![docs.rs](https://img.shields.io/docsrs/typebit.svg)](https://docs.rs/typebit)
[![CI](https://img.shields.io/github/actions/workflow/status/blueokanna/TypeBit/ci.yml?branch=main)](https://github.com/blueokanna/TypeBit/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blueviolet)](https://github.com/blueokanna/TypeBit/blob/main/Cargo.toml)
[![no_std](https://img.shields.io/badge/no__std-%E2%9C%93-brightgreen)](#no_std-single-crate)
[![License](https://img.shields.io/badge/license-PolyForm%20Perimeter%201.0.0-orange)](LICENSE)

**One `no_std` engine core. Every link format it can parse, every byte
hash-verified, and on BitTorrent — actual research-grade swarm work.**

TypeBit is a download-engine **core** — a library, not a GUI. You bind it
into your Android (Kotlin), iOS (Swift), desktop, or embedded product and
implement one interface: [`Host`](https://docs.rs/typebit/latest/typebit/trait.Host.html).
Everything else (piece picking, DHT, receipts, rate limiting, anti-leech)
lives behind that seam.

- `no_std + alloc`, zero `unsafe` outside the optional FFI bridge
- dependency tree is **exactly four crates deep** — all of them ours
- one crate, no workspace ritual
- `#![warn(missing_docs)]`, full docs.rs coverage, CI-gated `-D warnings`

---

## Protocol matrix

| Protocol | Spec | Status |
|---|---|---|
| Metainfo v1 / v2 / hybrid | BEP-3 / BEP-52 | ✅ piece-verified (SHA-1 / SHA-256) |
| Peer wire + Fast extension | BEP-6 | ✅ |
| DHT (Kademlia) | BEP-5 | ✅ routing table, KRPC, lookups, peer store |
| PEX | BEP-11 | ✅ |
| Metadata exchange | BEP-9 | ✅ magnet → full metainfo |
| Web seeds | BEP-19 | ✅ range-fenced, SOCKS-aware |
| LSD (local discovery) | BEP-14 | ✅ multicast, IPv4 + IPv6 |
| uTP | BEP-29 | ✅ LEDBAT congestion control |
| UDP trackers | BEP-15 | ✅ |
| Magnet / `btmh` | BEP-9 / BEP-53 | ✅ |
| SOCKS5 proxy | RFC 1928/1929 | ✅ Tor/I2P, zero DNS leaks |
| NAT-PMP / UPnP IGD | RFC 6886 / UPnP | ✅ |

Plus a unified link parser ([`links::parse_link`](https://docs.rs/typebit/latest/typebit/links/fn.parse_link.html)):
`magnet:`, `ed2k://`, `thunder://`, `qqdl://`, `flashget://`, `ipfs://`,
`ipns://`, `kad://`, plain HTTP(S)/FTP, and Baidu/Xunlei Netdisk shares.

## The parts that are actually hard

- **Utility scheduler** — piece priority is a function of *content
  semantics*, not rarity. A video schedules head/tail pieces first so you
  can start watching while the middle still downloads.
- **Anti-leech engine** — reciprocity-based unchoke (tit-for-tat), corrupt
  block accountability (blame weighted by who supplied the bad blocks),
  peer-id fingerprinting, per-subnet connection quotas, and a persistent
  reputation store that remembers a leecher across sessions.
- **Provable download receipts** — after a verified download, produce an
  Ed25519-signed receipt binding
  `content_root · range · epoch · node_id · bytes`. A third party can verify
  that a node actually obtained *and held* data. Not claimed. Held.
- **Multi-core verification** — a piece-hash pool spreads SHA across cores,
  with a zero-thread inline fallback for `no_std`. One code path, two
  execution strategies.
- **uTP transport** — BEP-29 with LEDBAT: yields bandwidth under
  congestion, fills the pipe when idle.
- **Rate limiting** — global and per-session token buckets, enforced at the
  wire.
- **Disk cache** — coalesced write-back with a read-through LRU, so a
  session doesn't grind your SSD to death.
- **Swarm monitoring** — recovery estimation and poison/availability
  observability. It can tell you a swarm is dying before it does.

All cryptography is in-tree and `no_std`: SHA-1/256/512, Ed25519
(RFC 8032), ChaCha20 (RFC 8439), MD4, Base58/32/64, CSPRNG. No `ring`, no
`openssl`, no `sha2`.

---

## Quick start — parse a link

```rust,no_run
use typebit::links::parse_link;

let link = parse_link(
    "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=hello",
)?;
match link {
    typebit::links::DownloadLink::BitTorrent(m) => {
        println!("torrent: {}", m.name.as_deref().unwrap_or("<unnamed>"));
    }
    _ => unreachable!(),
}
# Ok::<(), typebit::Error>(())
```

## Quick start — run an engine

The engine is generic over [`Host`](https://docs.rs/typebit/latest/typebit/trait.Host.html).
With the `std` feature you get a complete OS-backed host out of the box:

```toml
[dependencies]
typebit = { version = "0.1", features = ["std"] }
```

```rust,no_run
use typebit::{Engine, EngineConfig};

let mut engine = Engine::new(typebit::host_std::StdHost::new(), EngineConfig::default());
let hash = engine.add_magnet(
    "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567",
    "/path/to/downloads",
)?;
engine.start(&hash)?;

// Drive it from a timer — on your thread, never blocking for long.
loop {
    engine.tick()?;
    for ev in engine.take_events() {
        println!("event: {ev:?}");
    }
    println!("progress: {:.1}%", engine.progress(&hash) * 100.0);
    std::thread::sleep(std::time::Duration::from_millis(500));
}
# Ok::<(), typebit::Error>(())
```

For embedded / mobile targets implement the ~18 methods of `Host` yourself —
the engine drives everything else. See
[`examples/minimal_host.rs`](examples/minimal_host.rs) for a complete
in-memory implementation, and the
[Wiki](https://github.com/blueokanna/TypeBit/wiki) for the full walkthrough.

## Features

| Feature | What you get |
|---|---|
| *(default)* | bare `no_std` core |
| `std` | OS-backed `StdHost`: sockets, files, clock, DNS |
| `ffi` | `extern "C"` ABI for Kotlin / Swift / C# / Go |

## Examples

```sh
cargo run --example parse_links              # parse all 10 link formats
cargo run --example minimal_host             # full in-memory Host + engine lifecycle
cargo run --example ffi_demo --features ffi  # drive the engine via the C ABI
```

---

## Engine lifecycle

```
add_torrent / add_magnet  →  start(hash)  →  tick() × N  →  save_state()
                                                 │
        on_inbound_connection / take_events ◄───┘
```

- `add_torrent(&[u8], save_dir)` / `add_magnet(&str, save_dir)` return an
  [`InfoHash`](https://docs.rs/typebit/latest/typebit/metainfo/struct.InfoHash.html).
- `start(hash)` begins announcing; `pause` / `resume` / `remove_torrent`
  control the session.
- `tick()` drives every session, DHT, UDP socket, port mapper, web seed,
  uTP socket and the verify pool. Call it on a timer (~100–500 ms).
- `take_events()` drains `EngineEvent`s — add this to your event loop.
- `save_state()` / `load_state()` persist verified pieces, file priorities,
  speed limits and reputation across restarts.

## Trackers & DHT

- Sessions merge the torrent's announce list, `SessionConfig::trackers`
  and — when the torrent carries none — the built-in
  [`trackerlist::DEFAULT_TRACKERS`](https://docs.rs/typebit/latest/typebit/trackerlist/constant.DEFAULT_TRACKERS.html).
  Refresh the community list at runtime from `consts::TRACKERS_LIST_URL`
  via `tracker::parse_tracker_list` into `SessionConfig::trackers`.
- Announcements round-robin with a failure penalty (3 consecutive failures
  park a tracker until one succeeds).
- DHT boots from the well-known permanent routers, keeps a real peer store,
  re-announces on a timer, and degrades gracefully if UDP dies.

---

## Honest limitations (read this)

- **Baidu / Xunlei Netdisk** are authenticated services. TypeBit parses and
  models the share links, but will *not* magically download them — your host
  has to inject a session (cookies) and drive the vendor API.
- **eD2k** needs the eMule network to actually download. TypeBit gives you
  the file identity (MD4/AICH) and a verified-download pipeline; the
  Kademlia transport is a roadmap item.
- **IPFS** content is fetched through an HTTP gateway (`ipfs.io`, your
  node, …); bitswap is not implemented yet.
- This is a *core*. No UI, no tracker database, no torrent search, no
  coffee.

---

## Design

```
src/
  crypto/      SHA-1/256/512, Ed25519, ChaCha20, MD4, base58/32/64, PRNG
  bencode.rs   dependency-free bencode codec with depth/size limits
  metainfo.rs  v1/v2/hybrid torrent parsing + per-piece layout/verification
  magnet.rs    magnet URI (BEP-9/53)
  links.rs     unified parser: magnet/ed2k/thunder/qqdl/flashget/ipfs/kad/http
  wire.rs      peer-wire codec (BEP-6/9/10/11) with frame limits
  dht.rs       Kademlia routing table + KRPC + lookups + peer store
  tracker.rs   HTTP + UDP (BEP-15) tracker clients
  trackerlist.rs built-in tracker list
  lsd.rs       local peer discovery (BEP-14)
  pex.rs       peer exchange (BEP-11)
  utp.rs       uTP transport (BEP-29, LEDBAT)
  leech.rs     anti-leech: reciprocity scoring + corrupt-block accountability
  ratelimit.rs token-bucket rate limiting
  scheduler.rs utility-driven piece scheduling (video head/tail first)
  disk_cache.rs coalesced write-back cache + read-through LRU
  verify.rs    multi-core piece verification (inline fallback for no_std)
  receipt.rs   provable-download receipts (Ed25519-signed)
  socks.rs     SOCKS5 (RFC 1928/1929) proxy plumbing
  portmap.rs   NAT-PMP (RFC 6886) + UPnP IGD
  state.rs     session state (save / resume)
  session.rs   per-torrent session state machine
  engine.rs    top-level engine: host + sessions + DHT + cache + uTP
  platform.rs  the `Host` seam (the only thing you implement)
```

## Versioning & releases

- CI enforces `-D warnings` across a feature × OS matrix, rustdoc + doc
  tests, three bare-metal `no_std` targets, MSRV 1.95, `cargo-audit` and
  `cargo package` verification before anything merges.
- Tag `v0.x.y` on `main` and the [`publish` workflow](.github/workflows/publish.yml)
  ships it to crates.io (configure the `CARGO_REGISTRY_TOKEN` secret).

## License

[PolyForm Perimeter License 1.0.0](https://polyformproject.org/licenses/perimeter/1.0.0)
