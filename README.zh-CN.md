# TypeBit

[![crates.io](https://img.shields.io/crates/v/typebit.svg)](https://crates.io/crates/typebit)
[![crates.io downloads](https://img.shields.io/crates/d/typebit.svg)](https://crates.io/crates/typebit)
[![docs.rs](https://img.shields.io/docsrs/typebit.svg)](https://docs.rs/typebit)
[![CI](https://img.shields.io/github/actions/workflow/status/blueokanna/TypeBit/ci.yml?branch=main)](https://github.com/blueokanna/TypeBit/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blueviolet)](https://github.com/blueokanna/TypeBit/blob/main/Cargo.toml)
[![no_std](https://img.shields.io/badge/no__std-%E2%9C%93-brightgreen)](#no_std单一-crate)
[![License](https://img.shields.io/badge/license-PolyForm%20Perimeter%201.0.0-orange)](LICENSE)

**一个 `no_std` 下载引擎核心。能解析的链接格式全解析，每个字节都按哈希
校验；到了 BitTorrent 这块，做的是真正的研究级 swarm 调度。**

TypeBit 是一个下载引擎**核心**——是库，不是 GUI。你把它绑进你的 Android
（Kotlin）、iOS（Swift）、桌面或嵌入式产品，然后只实现一个接口：
[`Host`](https://docs.rs/typebit/latest/typebit/trait.Host.html)。其余一切
（选片、DHT、receipt、限速、反吸血）都在那层缝后面。

- `no_std + alloc`，除可选的 FFI 桥外**零 `unsafe`**
- 依赖树**只有四个 crate 深**——还全是自家的
- 单一 crate，不搞 workspace 仪式
- `#![warn(missing_docs)]`、完整 docs.rs 覆盖、CI 门禁 `-D warnings`

---

## 协议矩阵

| 协议 | 规范 | 状态 |
|---|---|---|
| v1 / v2 / hybrid 元信息 | BEP-3 / BEP-52 | ✅ 逐片校验（SHA-1 / SHA-256） |
| Peer wire + Fast 扩展 | BEP-6 | ✅ |
| DHT（Kademlia） | BEP-5 | ✅ 路由表、KRPC、查找、peer 存储 |
| PEX | BEP-11 | ✅ |
| 元数据交换 | BEP-9 | ✅ 磁力 → 完整元信息 |
| Web seed | BEP-19 | ✅ 窗口校验，走 SOCKS 也不漏 |
| LSD 本地发现 | BEP-14 | ✅ 组播，IPv4 + IPv6 |
| uTP | BEP-29 | ✅ LEDBAT 拥塞控制 |
| UDP tracker | BEP-15 | ✅ |
| 磁力 / `btmh` | BEP-9 / BEP-53 | ✅ |
| SOCKS5 代理 | RFC 1928/1929 | ✅ Tor/I2P，零 DNS 泄漏 |
| NAT-PMP / UPnP IGD | RFC 6886 / UPnP | ✅ |

外加统一链接解析器
（[`links::parse_link`](https://docs.rs/typebit/latest/typebit/links/fn.parse_link.html)）：
`magnet:`、`ed2k://`、`thunder://`、`qqdl://`、`flashget://`、`ipfs://`、
`ipns://`、`kad://`、普通 HTTP(S)/FTP，以及百度/迅雷网盘分享链接。

## 真正难啃的部分

- **语义驱动调度器**——片优先级是内容语义的函数，不只是稀有度。下视频
  时头尾片先调度，边下边播，中间还在传。
- **反吸血引擎**——基于互惠的 unchoke（tit-for-tat）、坏块问责（按实际
  供块者加权定罪）、peer-id 指纹、按子网限连接数、跨会话持久化声誉库
  （重进 swarm 也记得你是谁）。
- **可验证下载证明**——校验完成后可产出一张 Ed25519 签名的 receipt，
  绑定 `content_root · range · epoch · node_id · bytes`。第三方可以验证
  某个节点确实获取**并持有**过这份数据。不是"声称"，是"持有"。
- **多核校验**——片哈希池把 SHA 摊到所有核上，`no_std` 下自动退回零线程
  内联实现。一条代码路径，两种执行策略。
- **uTP 传输**——BEP-29 + LEDBAT：拥塞时让出带宽，空闲时灌满管道。
- **限速**——全局 + 单会话令牌桶，在线上强制执行。
- **磁盘缓存**——合并写回 + 读穿 LRU，不会把 SSD 磨死。
- **Swarm 监控**——可恢复性估计、污染/可用性观测。没错，它能比你先知道
  这个 swarm 要死。

所有密码学都在仓库内、`no_std`：SHA-1/256/512、Ed25519（RFC 8032）、
ChaCha20（RFC 8439）、MD4、Base58/32/64、CSPRNG。不依赖 `ring`、`openssl`、
`sha2`。

---

## 快速开始——解析链接

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

## 快速开始——跑引擎

引擎以
[`Host`](https://docs.rs/typebit/latest/typebit/trait.Host.html) 为泛型。
开 `std` feature 就有开箱即用的完整 OS 后端：

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

// 用定时器驱动——在你的线程上，绝不长时间阻塞。
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

嵌入式 / 移动端请自行实现 `Host` 的约 18 个方法——引擎驱动其余一切。
完整的内存版实现见 [`examples/minimal_host.rs`](examples/minimal_host.rs)，
完整教学见 [Wiki](https://github.com/blueokanna/TypeBit/wiki)。

## Features

| Feature | 给你什么 |
|---|---|
| （默认） | 裸 `no_std` 核心 |
| `std` | OS 后端 `StdHost`：socket、文件、时钟、DNS |
| `ffi` | `extern "C"` ABI，对接 Kotlin / Swift / C# / Go |

## 示例

```sh
cargo run --example parse_links              # 解析全部 10 种链接格式
cargo run --example minimal_host             # 完整的内存 Host + 引擎生命周期
cargo run --example ffi_demo --features ffi  # 通过 C ABI 驱动引擎
```

---

## 引擎生命周期

```
add_torrent / add_magnet  →  start(hash)  →  tick() × N  →  save_state()
                                                 │
        on_inbound_connection / take_events ◄───┘
```

- `add_torrent(&[u8], save_dir)` / `add_magnet(&str, save_dir)` 返回
  [`InfoHash`](https://docs.rs/typebit/latest/typebit/metainfo/struct.InfoHash.html)。
- `start(hash)` 开始 announce；`pause` / `resume` / `remove_torrent` 控制
  会话。
- `tick()` 驱动所有会话、DHT、UDP socket、端口映射、web seed、uTP socket
  和校验池。用定时器调用（约 100–500 ms）。
- `take_events()` 排空 `EngineEvent`——接进你的事件循环。
- `save_state()` / `load_state()` 跨重启持久化已验证片、文件优先级、限速
  和声誉。

## Tracker 与 DHT

- 会话会合并：torrent 自带 announce、`SessionConfig::trackers`、以及
  torrent 没带 announce 时的内置
  [`trackerlist::DEFAULT_TRACKERS`](https://docs.rs/typebit/latest/typebit/trackerlist/constant.DEFAULT_TRACKERS.html)。
  运行时从 `consts::TRACKERS_LIST_URL` 拉取社区完整列表，用
  `tracker::parse_tracker_list` 解析后注入 `SessionConfig::trackers`。
- announce 在多个 tracker 间轮询，带失败惩罚（连续 3 次失败就把该
  tracker 停掉，直到某次成功）。
- DHT 从主流常驻路由引导，有真正的 peer 存储、定时重新 announce，
  UDP 挂了还能优雅降级。

---

## 诚实说明（请先读）

- **百度网盘 / 迅雷网盘**是登录制服务。TypeBit 能解析并建模分享链接，但
  **不会凭空下载**——需要宿主注入会话（Cookie）并调用厂商 API。
- **eD2k** 真正下载要走 eMule 网络。TypeBit 给你文件身份（MD4/AICH）和
  可校验的下载管线；Kademlia 传输层还在路上。
- **IPFS** 内容目前通过 HTTP 网关（`ipfs.io`、你自己的节点……）拉取；
  bitswap 协议本身还没实现。
- 这是**核心库**。没有界面、没有 tracker 数据库、没有磁力搜索，也不会给
  你冲咖啡。

---

## 设计

```
src/
  crypto/      SHA-1/256/512、Ed25519、ChaCha20、MD4、base58/32/64、PRNG
  bencode.rs   无依赖的 bencode 编解码，带深度/大小限制
  metainfo.rs  v1/v2/hybrid torrent 解析 + 逐片布局/校验
  magnet.rs    磁力链接（BEP-9/53）
  links.rs     统一解析：magnet/ed2k/thunder/qqdl/flashget/ipfs/kad/http
  wire.rs      peer-wire 编解码（BEP-6/9/10/11），带帧长限制
  dht.rs       Kademlia 路由表 + KRPC + 查找 + peer 存储
  tracker.rs   HTTP + UDP（BEP-15）tracker 客户端
  trackerlist.rs 内置 tracker 列表
  lsd.rs       本地 peer 发现（BEP-14）
  pex.rs       peer 交换（BEP-11）
  utp.rs       uTP 传输（BEP-29、LEDBAT）
  leech.rs     反吸血：互惠评分 + 坏块问责
  ratelimit.rs 令牌桶限速
  scheduler.rs 效用驱动的片调度（视频头尾优先）
  disk_cache.rs 合并写回缓存 + 读穿 LRU
  verify.rs    多核片校验（no_std 下内联兜底）
  receipt.rs   可验证下载证明（Ed25519 签名）
  socks.rs     SOCKS5（RFC 1928/1929）代理管线
  portmap.rs   NAT-PMP（RFC 6886）+ UPnP IGD
  state.rs     会话状态（保存/恢复）
  session.rs   单 torrent 会话状态机
  engine.rs    顶层引擎：host + 会话 + DHT + 缓存 + uTP
  platform.rs  `Host` 缝（你唯一要实现的东西）
```

## 版本与发布

- CI 在 feature × OS 矩阵上强制 `-D warnings`，外加 rustdoc + doc test、
  三个裸机 `no_std` 目标、MSRV 1.95、`cargo-audit` 和 `cargo package`
  验证，全部通过才允许合并。
- 在 `main` 打 `v0.x.y` 标签，[`publish` 工作流](.github/workflows/publish.yml)
  就会把它发到 crates.io（需配置 `CARGO_REGISTRY_TOKEN` secret）。

## 许可

[PolyForm Perimeter License 1.0.0](https://polyformproject.org/licenses/perimeter/1.0.0)
