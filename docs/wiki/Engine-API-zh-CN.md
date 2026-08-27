# Engine API 参考

`typebit::Engine<H: Host>` 就是你要驱动的全部表面。`std` feature 自带
[`StdHost`](https://docs.rs/typebit/latest/typebit/host_std/struct.StdHost.html)；
其他平台实现
[`Host`](https://docs.rs/typebit/latest/typebit/trait.Host.html)
（见 [实现 Host](Implementing-a-Host-zh-CN)）。

## 构造

| 签名 | 说明 |
|---|---|
| `Engine::new(host, cfg) -> Engine<H>` | `cfg.proxy.is_some()` 会硬化引擎（无入站/DHT/UDP/端口映射，端口 0）。 |
| `EngineConfig::default()` | 监听 6881、DHT 开、缓存 256 MiB、512 连接上限、每 IP 8 个、30 s 连接超时。 |

`EngineConfig` 字段：`listen_port`、`cache_bytes`、`dht_enabled`、
`global_upload_limit_bps`、`global_download_limit_bps`、
`global_max_connections`、`max_connections_per_ip`、`port_mapping`、
`verify_workers`（`0` = std 下自动、no_std 下内联）、`proxy`、
`connect_timeout_ms`、`session`（`SessionConfig` 单任务默认）。

## 添加内容

| 签名 | 说明 |
|---|---|
| `add_torrent(data: &[u8], save_dir: &str) -> Result<InfoHash>` | 解析并添加 `.torrent` 字节 |
| `add_torrent_obj(torrent: Torrent, save_dir: &str) -> Result<InfoHash>` | 添加已解析的 `Torrent` |
| `add_magnet(uri: &str, save_dir: &str) -> Result<InfoHash>` | 磁力；元数据从 peer 抓取 |
| `add_torrents_batch(&[(&[u8], &str)]) -> Vec<Result<InfoHash>>` | 单个失败不中断整批 |
| `add_magnets_batch(&[(&str, &str)]) -> Vec<Result<InfoHash>>` | 同上，磁力版 |
| `restore_torrent(hash, &TorrentState) -> Result<()>` | 重新加种后回放持久化状态 |
| `install_metadata(hash, info_raw: &[u8]) -> Result<()>` | 持久化预取 info dict（磁力不再重抓） |
| `remove_torrent(hash) -> Result<()>` | 停止并丢弃会话 |

## 生命周期

| 签名 | 说明 |
|---|---|
| `start(hash) -> Result<()>` | 开始公告 / 连接 |
| `pause(hash)` | 暂停会话 |
| `resume(hash)` | 恢复 |
| `tick() -> Result<()>` | 驱动一切；用 ~100–500 ms 定时器调用 |
| `stop_port_mapping()` | 尽力移除 NAT 映射 |

## 观测

| 签名 | 说明 |
|---|---|
| `progress(hash) -> f64` | 0.0 – 1.0，按*已选*片计算 |
| `downloaded(hash) -> u64` / `uploaded(hash) -> u64` | 载荷字节 |
| `is_complete(hash) -> bool` | 所有已选片校验完毕 |
| `peer_snapshot(hash) -> Vec<PeerSnapshot>` | 每 peer 的 phase/速率/标志 |
| `metainfo(hash) -> Option<&Torrent>` | 已知后的解析元信息 |
| `stats() -> EngineStats` | 缓存 + 连接计数器 |
| `active_trackers() -> usize` | 各会话活跃 tracker 数 |
| `torrent_count() -> usize` | 已加载会话数 |
| `peer_id() -> &[u8; 20]` | 我们的 peer id |
| `dht() -> Option<&Dht>` | DHT 句柄（表统计等） |
| `dht_external() -> Option<([u8; 16], u16)>` | BEP-42 确认的外部地址 |
| `take_events() -> Vec<EngineEvent>` | 排空事件（见下） |
| `flush_cache()` | 强制刷盘 |

## 控制

| 签名 | 说明 |
|---|---|
| `add_tracker(hash, url) -> Result<bool>` / `remove_tracker(hash, url) -> Result<bool>` | 运行时 tracker 管理 |
| `trackers(hash) -> Option<Vec<String>>` | 当前 tracker 列表 |
| `set_file_priority(hash, file, FilePriority) -> Result<()>` | 单文件 |
| `set_file_priorities(hash, &[FilePriority]) -> Result<()>` | 批量 |
| `file_priority(hash, file) -> Option<FilePriority>` | 当前值 |
| `file_priorities(hash) -> Option<Vec<FilePriority>>` | 全部文件 |
| `set_hold_data(hash, hold) -> Result<()>` | 仅排队模式（不请求任何东西） |
| `holding_data(hash) -> Option<bool>` | 挂起状态 |
| `set_global_limits(down_bps, up_bps)` | 引擎级令牌桶 |
| `set_session_limits(hash, down_bps, up_bps) -> Result<()>` | 单任务 |

`FilePriority` 是 `Skip | Normal | High`（`typebit::session::FilePriority`）。

## 持久化

| 签名 | 说明 |
|---|---|
| `save_state() -> SessionState` | 已验证片、部分块、优先级、限速、声誉、DHT 节点 |
| `load_state(&SessionState, now: u64)` | 恢复之前的会话 |

恢复模式：

```rust
let state = engine.save_state();
// 之后，重新添加相同 torrent：
engine.load_state(&state, 0);
for t in &state.torrents {
    if let Some(hash) = /* 你的查询 */ {
        engine.restore_torrent(&hash, t)?;
    }
}
```

## 入站连接

宿主把完成的入站 TCP 连接交给引擎：

```rust
engine.on_inbound_connection(conn, addr); // conn: Host::tcp_connect 返回的 ConnId
```

从此 socket 归引擎管。代理模式立即拒绝入站。

## EngineEvent

`#[non_exhaustive]`——匹配时务必带通配分支：

- `PeerConnected { info_hash, addr, peer_id }`
- `PieceVerified { info_hash, piece }`
- `HashFailure { info_hash, piece }`
- `TorrentComplete { info_hash }`
- `MetadataComplete { info_hash }` / `MetadataFailed { info_hash }`
- `TrackerAnnounced { info_hash, peers }`
- `PeerBanned { info_hash, addr, reason }`
- `PortMapping { phase, external_port }`
- `DhtNodeCount(usize)`
- `Error { code, detail }` —— 非致命降级（`0` = UDP 打开失败，`1` = 无
  DHT 路由可解析）

## InfoHash

`typebit::InfoHash`（从 `metainfo` 再导出）：

- `InfoHash::v1([u8; 20])` / `InfoHash::v2([u8; 32])`
- `to_hex() -> String` / `from_hex(&str) -> Result<InfoHash>`
- `as_bytes()`、`len()`、`is_v1()`、`is_v2()`、`full() -> [u8; 32]`
- `Ord`/`Eq`/`Hash` —— 可直接做 map 键
