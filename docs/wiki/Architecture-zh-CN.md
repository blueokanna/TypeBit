# 架构

TypeBit 是**单一 `no_std` crate**,依赖方向只有一条:**引擎向
[`Host`](https://docs.rs/typebit/latest/typebit/trait.Host.html) 要一切 OS
原语,没有任何东西回头依赖引擎**。

## 分层

```
┌──────────────────────────────────────────────────────────┐
│  你的应用（UI / Kotlin / Swift / C# / Go / RTOS）         │
└───────────────────────────┬──────────────────────────────┘
                            │ tick() / take_events() / add_*()
┌───────────────────────────▼──────────────────────────────┐
│  typebit::Engine                                          │
│   ├─ TorrentSession × N   （单 torrent 状态机）           │
│   ├─ Dht                  （Kademlia：表、KRPC、查找）     │
│   ├─ DiskCache            （写回 + 读穿 LRU）             │
│   ├─ UtpManager           （BEP-29 传输）                 │
│   ├─ PortMapManager       （NAT-PMP / UPnP IGD）          │
│   ├─ LsdScheduler         （BEP-14 组播公告）             │
│   └─ VerifyPool           （多核片哈希）                   │
└───────────────────────────┬──────────────────────────────┘
                            │ 每个原语，非阻塞
┌───────────────────────────▼──────────────────────────────┐
│  typebit::Host  ◄── 你来实现这一层（或直接用 StdHost）    │
│   socket · 文件 · 时钟 · 随机数 · DNS · HTTP              │
└──────────────────────────────────────────────────────────┘
```

引擎从不碰操作系统。`Host` 提供约 18 个原语；引擎在**单线程**里驱动几百
个 peer,所以这些方法**绝不能阻塞**(`tcp_recv`/`udp_recv` 空闲时返回
`Err(Error::WouldBlock)`)。

## 模块地图

```
src/
  platform.rs   Host trait + NetAddr/ConnId/DiskId —— 唯一的缝
  engine.rs     Engine：拥有会话、DHT、缓存、uTP、端口映射、LSD、池
  session.rs    TorrentSession：单 torrent 状态机（peer/片/tracker/
                web seed/元数据抓取/unchoke 轮）
  wire.rs       peer-wire 编解码（BEP-6/9/10/11），有界帧
  metainfo.rs   v1/v2/hybrid torrent 解析 + 逐片布局/校验
  dht.rs        Kademlia 路由表 + KRPC + 查找 + peer 存储
  tracker.rs    HTTP + UDP（BEP-15）tracker 客户端
  trackerlist.rs 内置 tracker 列表 + 社区列表解析
  lsd.rs        BEP-14 本地 peer 发现
  pex.rs        BEP-11 peer 交换
  utp.rs        BEP-29 uTP（LEDBAT）
  leech.rs      反吸血：互惠评分、坏块问责、声誉库、封禁。只依赖 platform
  ratelimit.rs  令牌桶限速
  scheduler.rs  效用驱动片调度
  picker.rs     无状态片/块选择（消费 scheduler 效用）
  piece.rs      单片块追踪（in-flight/partial/have）
  disk_cache.rs 合并写回缓存 + 读穿 LRU
  verify.rs     纯 verify_piece + 可选线程池
  receipt.rs    Ed25519 可验证下载证明
  socks.rs      SOCKS5（RFC 1928/1929）客户端 + 代理 HTTP
  portmap.rs    NAT-PMP（RFC 6886）+ UPnP IGD
  state.rs      会话持久化编解码（二进制 + JSON）
  monitoring.rs swarm 可恢复性估计
  links.rs      统一链接解析（magnet/ed2k/thunder/qqdl/flashget/ipfs/kad/http）
  magnet.rs     磁力 URI（BEP-9/53）
  bencode.rs    无依赖 bencode 编解码，带深度/大小限制
  crypto/       SHA-1/256/512、Ed25519、ChaCha20、MD4、base58/32/64、CSPRNG
  host_std.rs   [std] OS 后端 Host
  ffi.rs        [ffi] extern "C" 桥
```

## tick 流水线

每次 `Engine::tick()` 按顺序执行：

1. **定时器**——有界刷缓存、刷新 DHT 桶、表太小则重引导、按节奏重公告。
2. **TCP 泵**——推进非阻塞 connect（`tcp_connect_done`）、完成 SOCKS5 握手、
   喂 peer socket、经全局 + 单会话令牌桶排空发送缓冲。
3. **UDP 泵**——每 tick 一个数据报预算：路由 DHT KRPC、UDP tracker 响应、
   LSD 公告、NAT-PMP/SSDP、uTP 包。
4. **会话**——向 tracker 公告（HTTP 同步 / UDP 异步）、驱动元数据抓取、
   跑 unchoke 轮、下发片请求、排空 web seed 块抓取。
5. **校验**——把组好的片交给线程池（或内联校验）、排空结果、完成或追责。
6. **事件**——追加到 `events` 队列供 `take_events()`。

每 tick 处处有界（数据报预算、刷缓存预算、请求管线），所以一个慢 peer
或一个恶意 LAN 永远冻结不了事件循环。

## 关键设计决策

- **一条代码路径，两种执行策略**——片校验是纯函数；`VerifyPool`（std 下
  线程）与内联（no_std）共用它，结果逐位一致。
- **令牌桶卡在咽喉点**——全局限速在字节真正流动的地方强制执行（peer
  发送循环、请求下发），不是单独的记账通道。
- **UDP 可选、绝不致命**——`udp_open` 失败 `start()` 照样成功；DHT/UDP
  tracker 降级并发出 `EngineEvent::Error { code: 0 }`。
- **反吸血行为优先**——客户端指纹只是*软*信号；封禁和断开只来自实测
  恶行。`leech` 只依赖 `platform`，可独立单测。
- **picker 无状态**——所需一切全部传入（scheduler 效用、可用性、peer
  位域、优先级、endgame 标志），调度逻辑极易测试。
