# TypeBit Wiki

Welcome. This wiki is the operator's manual for the TypeBit download-engine
core. The README tells you *what* it is; this tells you *how to drive it*.

## Pages

- **[Getting Started](Getting-Started)** — add the crate, parse links, run an engine
- **[Implementing a Host](Implementing-a-Host)** — the one interface you must write
- **[Supported Formats](Supported-Formats)** — every link format and its caveats
- **[Architecture](Architecture)** — module map and data flow
- **[中文首页](Home-zh-CN)** — 中文入口

## The 30-second mental model

```
your app (UI, Kotlin/Swift/...)
        │  calls
        ▼
┌─────────────────────────────────────────────┐
│  typebit::Engine  (session + DHT + cache)   │
│  └─ typebit::session::TorrentSession        │
│  └─ typebit::dht::Dht                       │
│  └─ typebit::disk_cache::DiskCache          │
└─────────────────────────────────────────────┘
        │  calls (every tick, on your thread)
        ▼
typebit::Host  ◄── YOU IMPLEMENT THIS
   (sockets, files, clock, RNG)
```

The engine never touches the OS. It asks `Host` for everything: connect a
socket, read a file, give me the time, fill this buffer with entropy. Your
job is a boring, well-tested implementation of `Host`. Everything clever
(piece picking, DHT, receipts, disk cache) lives in the engine.

Run `cargo run --example minimal_host` for a complete working `Host`
implementation (in-memory) driving a real engine.

## License reminder

TypeBit is AGPL-3.0. If you run a modified version as a network service, the
AGPL requires you to offer its source to that network's users. See LICENSE.
