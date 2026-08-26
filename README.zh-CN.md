# TypeBit

[![crates.io](https://img.shields.io/crates/v/typebit.svg)](https://crates.io/crates/typebit)
[![crates.io downloads](https://img.shields.io/crates/d/typebit.svg)](https://crates.io/crates/typebit)
[![docs.rs](https://img.shields.io/docsrs/typebit.svg)](https://docs.rs/typebit)
[![CI](https://img.shields.io/github/actions/workflow/status/blueokanna/TypeBit/ci.yml?branch=main)](https://github.com/blueokanna/TypeBit/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blueviolet)](https://github.com/blueokanna/TypeBit/blob/main/Cargo.toml)
[![no_std](https://img.shields.io/badge/no__std-%E2%9C%93-brightgreen)](#no_std单一-crate)
[![License](https://img.shields.io/badge/license-PolyForm%20Perimeter%201.0.0-orange)](LICENSE)

一个 `no_std` 的下载引擎核心，用同一套代码，说比一般下载器听说过的还多的协议。

起因很朴素，甚至有点丢人：我一直在 qBittorrent、aMule 和朋友们那周狂推的
各种国产下载器之间反复横跳。每一个都只擅长一件事，其他全是一坨。所以我就
干了工程师唯一会干的事——自己写一个。能解析我见过的所有链接格式，下载完成
后用正确的哈希逐字节校验，而到了 BitTorrent 这块，做的是真正的研究级 swarm
调度，而不是 crates.io 上第 47 个 `libtorrent` 套壳。

它是一个**库**，不是 GUI。界面是你的活：安卓用 Kotlin、iOS 用 Swift、桌面、
嵌入式、以及你一直想刷的那台面包机。TypeBit 就是你要对接的那个 `core`。

---

## 能干什么

### 一个 `parse_link` 通吃所有链接

给它一个字符串，剩下的它自己猜。

| 格式 | 示例 | 说明 |
|---|---|---|
| BT 磁力 | `magnet:?xt=urn:btih:...` | BEP-9、BEP-53（`btmh` v2）、`urn:sha1` |
| eD2k / eMule | `ed2k://|file|名字|大小|md4|/` | MD4 哈希、AICH、服务器列表 |
| 迅雷 | `thunder://QUF...` | Base64 `AA…ZZ` 解包 |
| QQ 旋风 | `qqdl://...` | Base64 编码的 URL |
| FlashGet | `flashget://[FLASHGET]...[/FLASHGET]` | 带标签的 Base64 |
| IPFS / IPNS | `ipfs://bafy...` · `ipns://docs.ipfs.tech` | CIDv0/CIDv1，可走 HTTP 网关 |
| Kad 节点 | `kad://<id>[@host:port]` | eMule Kademlia 节点链接 |
| HTTP(S) / FTP 直链 | 任意直链 | 可选内容寻址校验 |
| 百度网盘 | `https://pan.baidu.com/s/...` | **需要你的 Cookie**——见下方 |
| 迅雷网盘 | `https://pan.xunlei.com/s/...` | **需要你的 Cookie**——见下方 |

### BitTorrent 引擎（真正下功夫的部分）

协议矩阵，毕竟是极客，得来点表格：

| 协议 | 规范 | 状态 |
|---|---|---|
| v1 / v2 / hybrid 元信息 | BEP-3、BEP-52 | ✅ 逐片校验（SHA-1 / SHA-256） |
| Peer wire + Fast 扩展 | BEP-6 | ✅ |
| DHT（Kademlia） | BEP-5 | ✅ 路由表、KRPC、查找、peer 存储 |
| PEX | BEP-11 | ✅ |
| 元数据交换 | BEP-9 | ✅ 磁力 → 完整元信息 |
| Web seed | BEP-19 | ✅ 窗口校验，走 SOCKS 也不漏 |
| LSD 本地发现 | BEP-14 | ✅ 组播，IPv4 + IPv6 |
| UDP tracker | BEP-15 | ✅ |
| 磁力 / `btmh` | BEP-9、BEP-53 | ✅ |
| SOCKS5 代理 | RFC 1928/1929 | ✅ Tor/I2P，零 DNS 泄漏 |
| NAT-PMP / UPnP IGD | RFC 6886 / UPnP | ✅ |

然后才是真正难啃的部分：

- **语义驱动调度器**——片优先级是内容语义的函数，不只是稀有度。下视频时
  头尾片先调度，边下边播，中间还在传。调度器知道你在下什么，它不是拿稀有度
  掷骰子。
- **反吸血引擎**——比私有站点的分享率警察还狠。基于互惠的 unchoke、
  坏块问责（按实际供块者加权定罪）、peer-id 指纹识别、按子网限连接数、
  跨会话持久化的声誉库（重进 swarm 也记得你是谁）。
- **限速**——全局 + 单会话令牌桶，在线上强制执行，而不是在你梦里。
- **磁盘缓存**——合并写回 + 预算控制，不会把 SSD 磨死（远古的"BT 伤硬盘"
  问题）。
- **多核校验**——片校验池把 SHA 哈希摊到所有核上，`no_std` 下自动退回
  零线程内联实现。一条代码路径，两种执行策略。
- **SOCKS5 全链路代理**——把整个引擎塞进代理（Tor、I2P，随你信谁）。
  引擎把代理当线路，能不发的明文 DNS 一个都不发。
- **端口映射**——NAT-PMP + UPnP IGD，不用考路由配置资格证也能让对端连进来。
- **可验证下载证明**——校验完成后可以出一张 Ed25519 签名的 receipt，
  绑定 `content_root · range · epoch · node_id · bytes`，第三方可以验证
  某个节点确实获取并持有过这份数据。不是"声称"，是"持有"。
- **选择性下载**——每个文件 `Skip / Normal / High`，重启续传也不丢。
- **智能续传**——保存/恢复会话状态（已验证的片、文件优先级、限速）。
  重新加种，原地复活。
- **Swarm 监控**——可恢复性估计、污染/可用性观测。没错，它能比你先知道
  这个 swarm 要死。

所有密码学都是仓库内自研且 `no_std` 的：SHA-1/256/512、Ed25519（RFC 8032）、
ChaCha20（RFC 8439）、MD4（eMule 兼容）、Base58/32/64、PRNG。不依赖
`ring`、`openssl`、`sha2`——`no_std` 依赖树只有四个 crate，而且全是我们
自己的：`courierust`、`nextjson`、`tzcraft`、`rustbinary`。

### `no_std`，单一 crate

整个引擎以 `#![no_std]` + `alloc` 编译，适配嵌入式/移动端，并且**只发一个
crate**——不拆 workspace，不搞十四 crate 的仪式感。

```toml
[dependencies]
typebit = { version = "0.1", default-features = false }
```

| Feature | 给你什么 |
|---|---|
| （默认） | 裸 `no_std` 核心 |
| `std` | OS 后端 `StdHost`：socket、文件、时钟、DNS |
| `ffi` | `extern "C"` ABI，对接 Kotlin / Swift / C# / Go |

---

## 快速开始

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

要真正下载，你实现 `typebit::Host` 的约 18 个方法（socket、文件、时钟、
随机数、一个可选 DNS 钩子），其余全部由引擎驱动。见
[`examples/`](examples) 和 [Wiki](https://github.com/blueokanna/TypeBit/wiki)。

## 示例

```sh
cargo run --example parse_links              # 解析全部 10 种链接格式
cargo run --example minimal_host             # 完整的内存 Host + 引擎生命周期
cargo run --example ffi_demo --features ffi  # 通过 C ABI 驱动引擎
```

## Tracker 与 DHT

- 会话会合并：torrent 自带 announce、`SessionConfig::trackers`、以及
  torrent 没带 announce 时的内置 `trackerlist::DEFAULT_TRACKERS`（兼容
  qBittorrent/BitComet 的公共列表）。运行时从 `consts::TRACKERS_LIST_URL`
  拉取社区完整列表，用 `tracker::parse_tracker_list` 解析后注入
  `SessionConfig::trackers`。
- announce 在多个 tracker 间轮询，带失败惩罚（连续 3 次失败就把该
  tracker 停掉，直到某次成功）。
- DHT 从主流常驻路由引导：`router.bittorrent.com`、`router.utorrent.com`、
  `router.transmissionbt.com`、`dht.bitcomet.com`、`dht.libtorrent.org`
  （端口 6881；libtorrent 为 25401）。有真正的 peer 存储、定时重新
  announce，UDP 挂了还能优雅降级。

---

## 诚实说明（请先读）

- **百度网盘 / 迅雷网盘**是登录制服务。TypeBit 能解析并建模分享链接，但
  **不会凭空下载**——需要宿主注入会话（Cookie）并调用厂商 API。谁跟你说
  能白嫖，谁就是在骗你。
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
  lsd.rs       本地 peer 发现（BEP-14）
  pex.rs       peer 交换（BEP-11）
  leech.rs     反吸血：互惠评分 + 坏块问责
  ratelimit.rs 令牌桶限速
  scheduler.rs 效用驱动的片调度（视频头尾优先）
  disk_cache.rs 合并写回缓存
  verify.rs    多核片校验（no_std 下内联兜底）
  receipt.rs   可验证下载证明（Ed25519 签名）
  socks.rs     SOCKS5（RFC 1928/1929）代理管线
  portmap.rs   NAT-PMP（RFC 6886）+ UPnP IGD
  state.rs     会话状态（保存/恢复）
  session.rs   单 torrent 会话状态机
  engine.rs    顶层引擎：host + 会话 + DHT + 缓存
  platform.rs  `Host` 缝（你唯一要实现的东西）
```

## 许可

[PolyForm Perimeter License 1.0.0](https://polyformproject.org/licenses/perimeter/1.0.0)
