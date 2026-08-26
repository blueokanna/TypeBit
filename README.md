# TypeBit

[![crates.io](https://img.shields.io/crates/v/typebit.svg)](https://crates.io/crates/typebit)
[![crates.io downloads](https://img.shields.io/crates/d/typebit.svg)](https://crates.io/crates/typebit)
[![docs.rs](https://img.shields.io/docsrs/typebit.svg)](https://docs.rs/typebit)
[![CI](https://img.shields.io/github/actions/workflow/status/blueokanna/TypeBit/ci.yml?branch=main)](https://github.com/blueokanna/TypeBit/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blueviolet)](https://github.com/blueokanna/TypeBit/blob/main/Cargo.toml)
[![no_std](https://img.shields.io/badge/no__std-%E2%9C%93-brightgreen)](#no_std-single-crate)
[![License](https://img.shields.io/badge/license-PolyForm%20Perimeter%201.0.0-orange)](LICENSE)

A `no_std` download engine core that speaks more protocols than your average
download manager has even heard of — from one codebase.

The origin story is embarrassingly ordinary: I kept hopping between
qBittorrent, aMule and whatever Chinese downloader my friends were evangelizing
that week. Every single one was great at exactly one thing and hopeless at
everything else. So I did the only reasonable thing an engineer can do — I
wrote my own. A core that parses **every** link format it can get its hands
on, verifies every byte against the hash the link promises, and — when you're
on BitTorrent — does actual research-grade swarm work instead of being the
47th `libtorrent` wrapper on crates.io.

It's a **library**, not a GUI. The GUI is your problem: Android (Kotlin),
iOS (Swift), desktop, embedded, that toaster you keep meaning to flash.
TypeBit is the `core` you bind to.

---

## What it does

### One `parse_link` to rule them all

Feed it a string. It figures out the rest.

| Format | Example | Notes |
|---|---|---|
| BitTorrent magnet | `magnet:?xt=urn:btih:...` | BEP-9, BEP-53 (`btmh` v2), `urn:sha1` |
| eD2k / eMule | `ed2k://|file|name|size|md4|/` | MD4 hash, AICH, server list |
| Xunlei | `thunder://QUF...` | Base64 `AA…ZZ` unwrap |
| QQ Xuanfeng | `qqdl://...` | Base64-encoded URL |
| FlashGet | `flashget://[FLASHGET]...[/FLASHGET]` | Tagged Base64 |
| IPFS / IPNS | `ipfs://bafy...` · `ipns://docs.ipfs.tech` | CIDv0/CIDv1, HTTP-gateway resolvable |
| Kad node | `kad://<id>[@host:port]` | eMule Kademlia node link |
| HTTP(S) / FTP | any direct link | optionally content-addressed |
| Baidu Netdisk | `https://pan.baidu.com/s/...` | **needs your cookies** — see below |
| Xunlei Netdisk | `https://pan.xunlei.com/s/...` | **needs your cookies** — see below |

### The BitTorrent engine (where the real work lives)

Protocol matrix, because nerds love tables:

| Protocol | Spec | Status |
|---|---|---|
| Metainfo v1 / v2 / hybrid | BEP-3, BEP-52 | ✅ piece-verified (SHA-1 / SHA-256) |
| Peer wire + Fast extension | BEP-6 | ✅ |
| DHT (Kademlia) | BEP-5 | ✅ routing table, KRPC, lookups, peer store |
| PEX | BEP-11 | ✅ |
| Metadata exchange | BEP-9 | ✅ magnet → full metainfo |
| Web seeds | BEP-19 | ✅ range-fenced, SOCKS-aware |
| LSD (local discovery) | BEP-14 | ✅ multicast, IPv4 + IPv6 |
| UDP trackers | BEP-15 | ✅ |
| Magnet / `btmh` | BEP-9, BEP-53 | ✅ |
| SOCKS5 proxy | RFC 1928/1929 | ✅ Tor/I2P, zero DNS leaks |
| NAT-PMP / UPnP IGD | RFC 6886 / UPnP | ✅ |

And the parts that are actually hard:

- **Utility scheduler** — piece priority is a function of *content semantics*,
  not rarity. Downloading a video? The head/tail pieces get scheduled first so
  you can start watching while the middle still downloads.
- **Anti-leech engine** — meaner than your private tracker's ratio police.
  Reciprocity-based unchoke, corrupt-block accountability (blame is weighted
  by who actually supplied the bad blocks), peer-id fingerprinting,
  per-subnet connection quotas, and a persistent reputation store that
  remembers a leecher across sessions.
- **Rate limiting** — global and per-session token buckets, enforced at the
  wire, not in your dreams.
- **Disk cache** — coalesced write-back with an LRU-ish budget, so a torrent
  session doesn't grind your SSD to death (the ancient "BT kills my disk"
  problem).
- **Multi-core verification** — a piece-verification pool that spreads SHA
  hashing across your cores, with a zero-thread inline fallback for `no_std`.
  One code path, two execution strategies.
- **SOCKS5 plumbing** — route the whole engine through a proxy (Tor, I2P,
  whatever you trust). The engine treats the proxy as the wire and never emits
  a plaintext DNS query it doesn't have to.
- **Port mapping** — NAT-PMP + UPnP IGD, so peers can reach you without a
  degree in router administration.
- **Provable download receipts** — after a verified download you can produce
  an Ed25519-signed receipt binding
  `content_root · range · epoch · node_id · bytes`, so a third party can
  verify that a node actually obtained and held data. Not claimed. Held.
- **Selective downloads** — per-file `Skip / Normal / High`, persisted across
  resumes.
- **Smart resume** — save and restore session state (verified pieces, file
  priorities, speed limits). Re-add a torrent and it picks up where it died.
- **Swarm monitoring** — recovery estimation, poison/availability
  observability. Yes, it can tell you a swarm is dying before it does.

All cryptography is in-tree and `no_std`: SHA-1/256/512, Ed25519 (RFC 8032),
ChaCha20 (RFC 8439), MD4 (eMule compatibility), Base58/32/64, PRNG. No
`ring`, no `openssl`, no `sha2` — the `no_std` dependency tree is exactly four
crates deep, and they're all ours: `courierust`, `nextjson`, `tzcraft` and
`rustbinary`.

### `no_std`, single crate

The whole engine compiles with `#![no_std]` + `alloc` for embedded/mobile
targets, and ships as **one crate** — no workspace splitting, no
fourteen-crate monorepo ritual.

```toml
[dependencies]
typebit = { version = "0.1", default-features = false }
```

| Feature | What you get |
|---|---|
| *(default)* | bare `no_std` core |
| `std` | OS-backed `StdHost`: sockets, files, clock, DNS |
| `ffi` | `extern "C"` ABI for Kotlin / Swift / C# / Go |

---

## Quick start

```rust
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
```

For a real download you implement the ~18 methods of `typebit::Host` (sockets,
files, clock, randomness, one optional DNS hook) — the engine drives
everything else. See [`examples/`](examples) and the
[Wiki](https://github.com/blueokanna/TypeBit/wiki).

## Examples

```sh
cargo run --example parse_links             # parse all 10 link formats
cargo run --example minimal_host            # full in-memory Host + engine lifecycle
cargo run --example ffi_demo --features ffi # drive the engine via the C ABI
```

## Trackers & DHT

- Sessions merge the torrent's announce list, `SessionConfig::trackers` and —
  when the torrent carries none — the built-in `trackerlist::DEFAULT_TRACKERS`
  (qBittorrent/BitComet-compatible public list). Refresh the full community
  list at runtime from `consts::TRACKERS_LIST_URL` and feed it through
  `tracker::parse_tracker_list` into `SessionConfig::trackers`.
- Announcements round-robin across trackers with a failure penalty (3
  consecutive failures park a tracker until one succeeds).
- DHT boots from the well-known permanent routers: `router.bittorrent.com`,
  `router.utorrent.com`, `router.transmissionbt.com`, `dht.bitcomet.com`,
  `dht.libtorrent.org` (port 6881; libtorrent on 25401), keeps a real peer
  store, re-announces on a timer, and degrades gracefully if UDP dies.

---

## Honest limitations (read this)

- **Baidu / Xunlei Netdisk** are authenticated services. TypeBit parses and
  models the share links, but it will *not* magically download them — your
  host has to inject a session (cookies) and drive the vendor API. Anyone
  claiming otherwise is lying to you.
- **eD2k** needs the eMule network to actually download. TypeBit gives you
  the file identity (MD4/AICH) and a verified-download pipeline; the Kademlia
  transport is a roadmap item.
- **IPFS** content is fetched through an HTTP gateway (`ipfs.io`, your node,
  …); the bitswap protocol itself is not implemented yet.
- This is a *core*. It has no UI, no tracker database, no torrent search, and
  it will not make you coffee.

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
  lsd.rs       local peer discovery (BEP-14)
  pex.rs       peer exchange (BEP-11)
  leech.rs     anti-leech: reciprocity scoring + corrupt-block accountability
  ratelimit.rs token-bucket rate limiting
  scheduler.rs utility-driven piece scheduling (video head/tail first)
  disk_cache.rs coalesced write-back cache
  verify.rs    multi-core piece verification (inline fallback for no_std)
  receipt.rs   provable-download receipts (Ed25519-signed)
  socks.rs     SOCKS5 (RFC 1928/1929) proxy plumbing
  portmap.rs   NAT-PMP (RFC 6886) + UPnP IGD
  state.rs     session state (save / resume)
  session.rs   per-torrent session state machine
  engine.rs    top-level engine: host + sessions + DHT + cache
  platform.rs  the `Host` seam (the only thing you implement)
```

## License

[PolyForm Perimeter License 1.0.0](https://polyformproject.org/licenses/perimeter/1.0.0)
