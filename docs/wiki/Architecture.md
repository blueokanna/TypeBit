# Architecture

TypeBit is one `no_std` crate with a single dependency direction: **the
engine asks [`Host`](https://docs.rs/typebit/latest/typebit/trait.Host.html)
for every OS primitive, and nothing reaches back.**

## Layering

```
┌──────────────────────────────────────────────────────────┐
│  your app (UI, Kotlin/Swift/C#/Go, embedded RTOS)         │
└───────────────────────────┬──────────────────────────────┘
                            │ tick() / take_events() / add_*()
┌───────────────────────────▼──────────────────────────────┐
│  typebit::Engine                                          │
│   ├─ TorrentSession × N   (per-torrent state machine)     │
│   ├─ Dht                  (Kademlia: table, KRPC, lookups)│
│   ├─ DiskCache            (write-back + read-through LRU) │
│   ├─ UtpManager           (BEP-29 transport)              │
│   ├─ PortMapManager       (NAT-PMP / UPnP IGD)            │
│   ├─ LsdScheduler         (BEP-14 multicast announce)     │
│   └─ VerifyPool           (multi-core piece hashing)      │
└───────────────────────────┬──────────────────────────────┘
                            │ every primitive, non-blocking
┌───────────────────────────▼──────────────────────────────┐
│  typebit::Host  ◄── YOU IMPLEMENT THIS (or StdHost)      │
│   sockets · files · clock · RNG · DNS · HTTP              │
└──────────────────────────────────────────────────────────┘
```

The engine never touches the OS. `Host` supplies ~18 primitives; the engine
drives hundreds of peers from one thread, so the methods **must not block**
(`tcp_recv`/`udp_recv` return `Err(Error::WouldBlock)` when idle).

## Module map

```
src/
  platform.rs   the Host trait + NetAddr/ConnId/DiskId — the only seam
  engine.rs     Engine: owns sessions, DHT, cache, uTP, portmap, LSD, pool
  session.rs    TorrentSession: one torrent's state machine (peers, pieces,
                trackers, web seeds, metadata fetch, choke passes)
  wire.rs       peer-wire codec (BEP-6/9/10/11), bounded frames
  metainfo.rs   v1/v2/hybrid torrent parsing + piece layout/verification
  dht.rs        Kademlia routing table + KRPC + lookups + peer store
  tracker.rs    HTTP + UDP (BEP-15) tracker clients
  trackerlist.rs built-in tracker list + community-list parsing
  lsd.rs        BEP-14 local peer discovery
  pex.rs        BEP-11 peer exchange
  utp.rs        BEP-29 uTP with LEDBAT
  leech.rs      anti-leech: reciprocity scoring, corrupt accountability,
                reputation store, bans. Depends ONLY on platform.
  ratelimit.rs  token-bucket rate limiting
  scheduler.rs  utility-driven piece scheduling
  picker.rs     stateless piece/block selection over scheduler utilities
  piece.rs      per-piece block tracker (in-flight/partial/have)
  disk_cache.rs coalesced write-back cache + read-through LRU
  verify.rs     pure verify_piece + optional worker pool
  receipt.rs    Ed25519 provable-download receipts
  socks.rs      SOCKS5 (RFC 1928/1929) client + proxied HTTP
  portmap.rs    NAT-PMP (RFC 6886) + UPnP IGD
  state.rs      session persistence codecs (binary + JSON)
  monitoring.rs swarm recoverability estimation
  links.rs      unified link parser (magnet/ed2k/thunder/qqdl/flashget/ipfs/kad/http)
  magnet.rs     magnet URI (BEP-9/53)
  bencode.rs    dependency-free bencode codec with depth/size limits
  crypto/       SHA-1/256/512, Ed25519, ChaCha20, MD4, base58/32/64, CSPRNG
  host_std.rs   [std] OS-backed Host implementation
  ffi.rs        [ffi] extern "C" bridge
```

## The tick pipeline

Every `Engine::tick()` does, in order:

1. **Timers** — flush the disk cache (bounded per tick), refresh DHT
   buckets, re-bootstrap if the table is tiny, re-announce on cadence.
2. **TCP pump** — advance non-blocking connects (`tcp_connect_done`),
   complete SOCKS5 handshakes, feed peer sockets, drain outgoing buffers
   through the global + per-session token buckets.
3. **UDP pump** — one datagram budget per tick: route DHT KRPC, UDP
   tracker responses, LSD announces, NAT-PMP/SSDP, uTP packets.
4. **Sessions** — announce to trackers (HTTP sync / UDP async), drive
   metadata fetches, run choke/unchoke passes, issue piece requests,
   drain web-seed block fetches.
5. **Verify** — hand assembled pieces to the pool (or verify inline),
   drain results, complete or punish pieces.
6. **Events** — append to the `events` queue for `take_events()`.

Everything is bounded per tick (datagram budget, cache flush budget,
request pipeline), so one slow peer or a hostile LAN can never freeze the
loop.

## Key design decisions

- **One code path, two execution strategies** — piece verification is a pure
  function; `VerifyPool` (threads under `std`) and inline (`no_std`) share it,
  so results are bit-identical.
- **Token buckets at the choke points** — the global rate is enforced where
  bytes actually flow (peer send loop, request issuance), not in a separate
  accounting pass.
- **UDP is optional, never fatal** — if `udp_open` fails, `start()` still
  succeeds; DHT/UDP-trackers degrade and the engine emits
  `EngineEvent::Error { code: 0 }`.
- **Anti-leech is behavior-first** — client fingerprinting is a *soft*
  signal; bans and disconnects come only from measured misbehavior.
  `leech` depends only on `platform`, so it is unit-testable in isolation.
- **The picker is stateless** — everything it needs is passed in
  (scheduler utilities, availability, peer bitfield, priorities, endgame
  flag), so scheduling logic is trivially testable.
