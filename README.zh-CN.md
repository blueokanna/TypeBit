# TypeBit

一个 `no_std` 的下载引擎核心，用同一套代码说多种协议。

做这个东西的起因很朴素：我一直在 qBittorrent、aMule 和朋友们强推的各种国产下载器之间来回切换。每个都只擅长一件事，别的一塌糊涂。所以我自己写了一个核心：**能解析我见过的所有下载链接**，下载完成后用正确的哈希校验，而在 BitTorrent 这一块，做的是真正的研究级 swarm 调度，而不是又一个 `libtorrent` 的套壳。

它是一个**库**，不是 GUI。界面是你的活：安卓用 Kotlin、iOS 用 Swift、桌面、嵌入式——TypeBit 就是那个你要对接的 `core`。

---

## 能干什么

### 支持的链接格式（一个 `parse_link` 通吃）

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

- v1 / v2 / hybrid 元信息（BEP-3、BEP-52），按 SHA-1/SHA-256 逐片校验
- Peer wire 完整协议：Fast（BEP-6）、DHT（BEP-5）、PEX（BEP-11）、元数据交换（BEP-9）、web seed
- **语义驱动调度器**——片优先级是内容语义的函数，不只是稀有度。下载视频时优先调度头尾片，边下边放，中间还在传
- **磁盘缓存**——合并写回 + 预算控制，不会像老式 BT 软件那样把 SSD 磨死
- **可验证下载证明**——校验完成后可以出一张 Ed25519 签名的 receipt，绑定 `content_root · range · epoch · node_id · bytes`，第三方可以验证某个节点确实获取并持有过这份数据
- **Swarm 监控**——可恢复性估计、污染/可用性观测

所有密码学都是仓库内自研且 `no_std` 的：SHA-1/256/512、Ed25519（RFC 8032）、ChaCha20（RFC 8439）、MD4（eMule 兼容）、Base58/32/64、PRNG。不依赖 `ring`、`openssl`、`sha2`——我们只依赖四个 crate：`courierust`、`nextjson`、`tzcraft`、`rustbinary`。

### no_std，单一 crate

整个引擎以 `#![no_std]` + `alloc` 编译，适配嵌入式/移动端，并且**只发一个 crate**，不拆 workspace。

```toml
[dependencies]
typebit = { version = "0.1", default-features = false }
```

桌面/服务器加 `features = ["std"]` 启用 OS 后端；加 `features = ["ffi"]` 启用 C ABI（Kotlin/Swift/C#/Go 对接）。

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

要真正下载，你实现 `typebit::Host` 的约 18 个方法（socket、文件、时钟、随机数），其余全部由引擎驱动。见 [`examples/`](examples) 和 [Wiki](https://github.com/blueokanna/TypeBit/wiki)。

## 示例

```sh
cargo run --example parse_links              # 解析全部 10 种链接格式
cargo run --example minimal_host             # 完整的内存 Host + 引擎生命周期
cargo run --example ffi_demo --features ffi  # 通过 C ABI 驱动引擎
```

## Tracker 与 DHT

- 会话会合并：torrent 自带 announce 列表、`SessionConfig::trackers`、以及
  torrent 没有 announce 时内置的 `consts::DEFAULT_TRACKERS`（兼容
  qBittorrent/BitComet 的公共列表）。运行时从 `consts::TRACKERS_LIST_URL`
  刷新社区完整列表，用 `tracker::parse_tracker_list` 解析后注入
  `SessionConfig::trackers`。
- announce 在多个 tracker 间轮询，带失败惩罚（连续 3 次失败暂停该
  tracker，直到某次成功）。
- DHT 从主流常驻路由引导：`router.bittorrent.com`、`router.utorrent.com`、
  `router.transmissionbt.com`、`dht.bitcomet.com`、`dht.libtorrent.org`
  （端口 6881，libtorrent 为 25401）。

---

## 诚实说明（请先读）

- **百度网盘 / 迅雷网盘**是登录制服务。TypeBit 能解析并建模分享链接，但**不会凭空下载**——需要宿主注入会话（Cookie）并调用厂商 API。谁跟你说能白嫖，谁就是在骗你。
- **eD2k** 真正下载要走 eMule 网络。TypeBit 给你文件身份（MD4/AICH）和可校验的下载管线；Kademlia 传输层在路上。
- **IPFS** 内容目前通过 HTTP 网关（`ipfs.io`、你自己的节点……）拉取；bitswap 协议本身还没实现。
- 这是**核心库**。没有界面、没有 tracker 数据库、没有磁力搜索。

---

## 设计

```
src/
  crypto/     SHA-1/256/512、Ed25519、ChaCha20、MD4、base58/32/64、PRNG
  bencode.rs  无依赖的 bencode 编解码，带深度/大小限制
  metainfo.rs v1/v2/hybrid torrent 解析 + 逐片布局/校验
  magnet.rs   磁力链接（BEP-9/53）
  links.rs    统一解析：magnet/ed2k/thunder/qqdl/flashget/ipfs/kad/http
  wire.rs     peer-wire 编解码（BEP-6/9/10/11），带帧长限制
  dht.rs      Kademlia 路由表 + KRPC + 查找
  tracker.rs  HTTP + UDP（BEP-15）tracker 客户端
  scheduler.rs 效用驱动的片调度（视频头尾优先）
  disk_cache.rs 合并写回缓存
  receipt.rs  可验证下载证明（Ed25519 签名）
  session.rs  单 torrent 会话状态机
  engine.rs   顶层引擎：host + 会话 + DHT + 缓存
  platform.rs `Host` 缝（你唯一要实现的东西）
```

## 许可

PolyForm Perimeter License 1.0.0
