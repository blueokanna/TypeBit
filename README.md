# TypeBit

A `no_std` download engine core that speaks many protocols from one codebase.

TypeBit is the piece of software I wished existed when I kept switching between
qBittorrent, aMule and whatever Chinese downloader my friends insisted on. All
of them are good at one thing and useless at the others. So I wrote a core that
parses **every** link format I could find, verifies downloads against the right
hash, and — when you're on BitTorrent — does actual research-grade swarm
work instead of being another `libtorrent` wrapper.

It is a **library**, not a GUI. The GUI is yours: Android (Kotlin), iOS
(Swift), desktop, embedded — TypeBit is the `core` you bind to.

---

## What it does

### Supported link formats (one `parse_link` to rule them all)

| Format | Example | Notes |
|---|---|---|
| BitTorrent magnet | `magnet:?xt=urn:btih:...` | BEP-9, BEP-53 (`btmh` v2), `urn:sha1` |
| eD2k / eMule | `ed2k://|file|name|size|md4|/` | MD4 hash, AICH, server list |
| Xunlei | `thunder://QUF...` | Base64 `AA…ZZ` unwrap |
| QQ Xuanfeng | `qqdl://...` | Base64 URL |
| FlashGet | `flashget://[FLASHGET]...[/FLASHGET]` | tagged Base64 |
| IPFS / IPNS | `ipfs://bafy...` · `ipns://docs.ipfs.tech` | CIDv0/CIDv1, HTTP-gateway resolvable |
| Kad node | `kad://<id>[@host:port]` | eMule Kademlia node link |
| HTTP(S) / FTP | any direct link | optionally content-addressed |
| Baidu Netdisk | `https://pan.baidu.com/s/...` | **needs your cookies** — see below |
| Xunlei Netdisk | `https://pan.xunlei.com/s/...` | **needs your cookies** — see below |

### BitTorrent engine (the real work)

- v1 / v2 / hybrid metainfo (BEP-3, BEP-52), piece verification by SHA-1/SHA-256
- Peer wire protocol with Fast (BEP-6), DHT (BEP-5), PEX (BEP-11), metadata
  exchange (BEP-9), web seeds
- **Utility scheduler** — piece priority is a function of content semantics,
  not just rarity. Downloading a video? The head/tail pieces get scheduled
  first so you can start playing while the middle still downloads.
- **Disk cache** — coalesced write-back with an LRU-ish budget, so a torrent
  session doesn't grind your SSD to death (the old "BT kills my disk" problem).
- **Provable download receipts** — after a verified download you can produce a
  signed receipt binding `content_root · range · epoch · node_id · bytes`,
  so a third party can verify that a node actually obtained and held data.
- **Swarm monitoring** — recovery estimation, poison/availability observability.

All cryptography is in-tree and `no_std`: SHA-1/256/512, Ed25519 (RFC 8032),
ChaCha20 (RFC 8439), MD4 (eMule compatibility), Base58/32/64, PRNG. No
`ring`, no `openssl`, no `sha2` — the four crates we depend on are
`courierust`, `nextjson`, `tzcraft` and `rustbinary`.

### no_std, single crate

The whole engine compiles with `#![no_std]` + `alloc` for embedded/mobile
targets, and ships as **one crate** — no workspace splitting.

```toml
[dependencies]
typebit = { version = "0.1", default-features = false }
```

Add `features = ["std"]` on desktop/server for the OS-backed host, or
`features = ["ffi"]` for the C ABI (Kotlin/Swift/C#/Go).

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
files, clock, randomness) — the engine drives everything else. See
[`examples/`](examples) and the [Wiki](https://github.com/blueokanna/TypeBit/wiki).

## Examples

```sh
cargo run --example parse_links            # parse all 10 link formats
cargo run --example minimal_host           # full in-memory Host + engine lifecycle
cargo run --example ffi_demo --features ffi # drive the engine via the C ABI
```

## Trackers & DHT

- Sessions merge the torrent's announce list, `SessionConfig::trackers` and —
  when the torrent carries none — the built-in `consts::DEFAULT_TRACKERS`
  (qBittorrent/BitComet compatible public list). Refresh the full community
  list at runtime from `consts::TRACKERS_LIST_URL` and feed it through
  `tracker::parse_tracker_list` into `SessionConfig::trackers`.
- Announcements round-robin across trackers with a failure penalty (3
  consecutive failures pause a tracker until one succeeds).
- DHT boots from the well-known permanent routers: `router.bittorrent.com`,
  `router.utorrent.com`, `router.transmissionbt.com`, `dht.bitcomet.com`,
  `dht.libtorrent.org` (port 6881, libtorrent on 25401).

---

## Honest limitations (read this)

- **Baidu / Xunlei Netdisk** are authenticated services. TypeBit parses and
  models the share links, but it will *not* magically download them — your host
  has to inject a session (cookies) and drive the vendor API. Anyone claiming
  otherwise is lying to you.
- **eD2k** needs the eMule network to actually download. TypeBit gives you the
  file identity (MD4/AICH) and a verified-download pipeline; the Kademlia
  transport is a roadmap item.
- **IPFS** content is fetched through an HTTP gateway (`ipfs.io`, your node,
  …); the bitswap protocol itself is not implemented yet.
- This is a *core*. It has no UI, no tracker database, no torrent search.

---

## Design

```
src/
  crypto/     SHA-1/256/512, Ed25519, ChaCha20, MD4, base58/32/64, PRNG
  bencode.rs  dependency-free bencode codec with depth/size limits
  metainfo.rs v1/v2/hybrid torrent parsing + per-piece layout/verification
  magnet.rs   magnet URI (BEP-9/53)
  links.rs    unified parser: magnet/ed2k/thunder/qqdl/flashget/ipfs/kad/http
  wire.rs     peer-wire codec (BEP-6/9/10/11) with frame limits
  dht.rs      Kademlia routing table + KRPC + lookups
  tracker.rs  HTTP + UDP (BEP-15) tracker clients
  scheduler.rs utility-driven piece scheduling (video head/tail first)
  disk_cache.rs coalesced write-back cache
  receipt.rs  provable-download receipts (Ed25519-signed)
  session.rs  per-torrent session state machine
  engine.rs   top-level engine: host + sessions + DHT + cache
  platform.rs the `Host` seam (the only thing you implement)
```

## License

AGPL-3.0-or-later. If you run a modified TypeBit as a network service, you
must make your modified source available to that network's users — that's the
point of the license.
