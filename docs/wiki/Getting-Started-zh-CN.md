# 快速开始

从空项目到一个正在下载的引擎：解析、启动、校验、重启续传。以下全部是
**真实可编译**的 TypeBit API，没有简化。

## 1. 添加依赖

```toml
[dependencies]
typebit = { version = "0.1", features = ["std"] }
```

| Feature | 什么时候用 |
|---|---|
| （默认） | 嵌入式 / `no_std` 目标；你自己实现 `Host` |
| `std` | 桌面 / 服务器；直接用内置 `StdHost` |
| `ffi` | 对接 Kotlin / Swift / C# / Go |

## 2. 解析链接与 torrent 文件

链接解析零依赖，任何 feature 组合下都可用：

```rust
use typebit::links::parse_link;

let link = parse_link(
    "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=hello",
)?;
match link {
    typebit::links::DownloadLink::BitTorrent(m) => {
        println!("torrent: {}", m.name.as_deref().unwrap_or("<unnamed>"));
        for tr in &m.announce_list {
            println!("tracker: {tr}");
        }
    }
    other => println!("不是磁力链接: {other:?}"),
}
# Ok::<(), typebit::Error>(())
```

`.torrent` 字节可以脱离引擎独立解析：

```rust
use typebit::metainfo::Torrent;

let t = Torrent::from_bytes(&torrent_bytes)?;
println!(
    "{}: {} 片 × {} KiB，共 {} 字节，类型={:?}",
    t.name,
    t.piece_count(),
    t.piece_length / 1024,
    t.total_size,
    t.kind, // TorrentKind::V1 | V2 | Hybrid
);
// 校验已有的一片：
t.verify_piece(0, &piece_data)?; // Ok(()) 或 Err(Error::HashMismatch)
# Ok::<(), typebit::Error>(())
```

## 3. 用 std host 跑引擎

`StdHost` 提供 socket、文件、时钟、DNS、随机数——完整传输层。建引擎、
加种、启动、用定时器泵：

```rust,no_run
use typebit::host_std::StdHost;
use typebit::{Engine, EngineConfig, EngineEvent};

let mut engine = Engine::new(StdHost::new(), EngineConfig::default());

// 加 .torrent 字节或磁力：
let hash = engine.add_torrent(&torrent_bytes, "/path/to/downloads")?;
// let hash = engine.add_magnet("magnet:?...", "/path/to/downloads")?;

engine.start(&hash)?;

// 事件循环——定时调 tick()（约 100–500 ms），绝不长时间阻塞：
loop {
    engine.tick()?; // 驱动会话、DHT、UDP、端口映射、web seed、uTP
    for ev in engine.take_events() {
        match ev {
            EngineEvent::PieceVerified { piece, .. } => println!("片 {piece} 校验通过"),
            EngineEvent::TorrentComplete { .. } => println!("下载完成！"),
            EngineEvent::MetadataComplete { .. } => println!("磁力元数据到达"),
            EngineEvent::MetadataFailed { .. } => println!("磁力元数据获取失败"),
            EngineEvent::PeerConnected { addr, .. } => println!("peer {addr} 已连接"),
            EngineEvent::HashFailure { piece, .. } => println!("片 {piece} 哈希校验失败"),
            EngineEvent::PeerBanned { addr, reason, .. } => {
                println!("peer {addr} 被封禁: {reason:?}")
            }
            EngineEvent::DhtNodeCount(n) => println!("DHT 节点数: {n}"),
            EngineEvent::Error { code, detail } => {
                println!("引擎降级: {detail} (code {code})")
            }
            _ => {}
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
}
# Ok::<(), typebit::Error>(())
```

`EngineConfig` 里带上 `proxy`，`Engine::new` 会自动硬化引擎：无入站、无
DHT、无 UDP tracker、无端口映射、公告端口为 `0`。

## 4. 选择性下载与限速

```rust
use typebit::session::FilePriority;

// 每文件优先级（下标 = 文件下标）：Skip / Normal / High。
engine.set_file_priorities(&hash, &[
    FilePriority::Skip,   // 文件 0：不下载
    FilePriority::High,   // 文件 1：优先下载
])?;
engine.set_file_priority(&hash, 2, FilePriority::Normal)?;

// 挂起模式（只排队、不请求），等优先级提交后再释放：
engine.set_hold_data(&hash, true)?;
engine.set_file_priorities(&hash, &[FilePriority::Normal, FilePriority::Skip])?;
engine.set_hold_data(&hash, false)?; // 提交：释放挂起

// 限速（字节/秒；0 = 不限）：
engine.set_global_limits(2 * 1024 * 1024, 512 * 1024);        // 全局
engine.set_session_limits(&hash, 1 * 1024 * 1024, 256 * 1024)?; // 单任务
```

## 5. 观测与持久化

```rust
println!("进度: {:.1}%", engine.progress(&hash) * 100.0);
println!("已下载: {} 字节", engine.downloaded(&hash));
println!("已上传: {} 字节", engine.uploaded(&hash));
println!("完成: {}", engine.is_complete(&hash));

// 统计面板数据（qBittorrent 风格）：
let stats = engine.stats();
println!("连接中的 peer: {}", stats.connected_peers);
println!("缓存脏条目: {}", stats.cache_dirty_entries);

// peer 列表 UI：
for p in engine.peer_snapshot(&hash) {
    println!("{} phase={:?} seed={} down={}B/s", p.addr, p.phase, p.is_seed, p.down_rate);
}

// 保存并恢复一切（已验证片、优先级、限速、声誉、DHT 节点）：
let state = engine.save_state();
let mut engine2 = Engine::new(StdHost::new(), EngineConfig::default());
engine2.load_state(&state, 0);
```

## 6. 运行时增删 tracker

```rust
engine.add_tracker(&hash, "udp://tracker.opentrackr.org:1337/announce")?;
engine.remove_tracker(&hash, "udp://tracker.opentrackr.org:1337/announce")?;
for url in engine.trackers(&hash).unwrap_or_default() {
    println!("当前 tracker: {url}");
}
```

## 7. 完整示例程序

```sh
cargo run --example parse_links              # 每种链接格式，现场演示
cargo run --example minimal_host             # 内存 Host 驱动真实引擎
cargo run --example ffi_demo --features ffi  # C ABI 端到端
```

`minimal_host.rs` 是 `StdHost` 覆盖不到的平台上实现 `Host` 的规范参考
（见 [实现 Host](Implementing-a-Host-zh-CN)）。
