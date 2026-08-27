# 实现 Host

`typebit::Host` 是你唯一需要实现的接口。约 18 个方法，全部 `no_std`
友好。引擎在 `tick()` 里、**你的线程**上调用它们，所以绝不能长时间阻塞
（用非阻塞 socket）。

## 这个 trait

```rust
pub trait Host {
    fn now_ms(&self) -> u64;                        // 时钟（毫秒）
    fn fill_random(&mut self, buf: &mut [u8]);      // CSPRNG
    fn log(&mut self, level: LogLevel, msg: &str);

    // HTTP(S) GET → 把响应体追加到 `out`（tracker、web seed、IPFS 网关）
    fn http_get(&mut self, url: &str, timeout_ms: u64, out: &mut Vec<u8>)
        -> Result<()>;

    // DNS：为 DHT 引导路由解析主机名（BEP-5）。
    // 可选——返回 None 就禁用 DHT 引导（HTTP/UDP tracker 仍可用）。
    // FFI 的 HostCbs.resolve_host 是它的 C 孪生。
    fn resolve_host(&self, host: &str, port: u16) -> Option<NetAddr>;

    // TCP（非阻塞）
    fn tcp_connect(&mut self, addr: &NetAddr) -> Result<ConnId>;
    fn tcp_connect_done(&mut self, id: ConnId) -> Result<()>;  // Ok=已建立
    fn tcp_send(&mut self, id: ConnId, data: &[u8]) -> Result<usize>;
    fn tcp_recv(&mut self, id: ConnId, buf: &mut [u8]) -> Result<usize>;
    fn tcp_close(&mut self, id: ConnId);

    // UDP（DHT、UDP tracker、uTP、LSD、端口映射）
    fn udp_open(&mut self, port: u16) -> Result<()>;
    fn udp_send(&mut self, addr: &NetAddr, data: &[u8]) -> Result<()>;
    fn udp_recv(&mut self, buf: &mut [u8]) -> Result<(NetAddr, usize)>;

    // 文件（片数据）
    fn disk_open(&mut self, path: &str) -> Result<DiskId>;
    fn disk_read(&mut self, id: DiskId, offset: u64, buf: &mut [u8]) -> Result<usize>;
    fn disk_write(&mut self, id: DiskId, offset: u64, data: &[u8]) -> Result<()>;
    fn disk_prealloc(&mut self, id: DiskId, size: u64) -> Result<()>;
    fn disk_flush(&mut self, id: DiskId) -> Result<()>;
    fn disk_close(&mut self, id: DiskId);
}
```

## 引擎依赖的约定

- `tcp_recv` / `udp_recv` 在当下无数据时返回 `Err(Error::WouldBlock)`。
  **绝不要在这些方法里阻塞。**
- `tcp_connect` 立即返回句柄（非阻塞 connect）；引擎用 `tcp_connect_done`
  轮询。
- `http_get` 最多阻塞 `timeout_ms`；引擎用它做 tracker 和 web seed。
- 磁盘偏移是单文件内的绝对偏移（按文件句柄）。
- **UDP 可选、绝不致命。** 引擎惰性打开 UDP socket，且只在确实需要时
  （DHT 开、有 UDP tracker、或端口映射）。`udp_open` 失败时 `start()`
  照样成功：DHT 和 UDP tracker 被禁用、发出 `EngineEvent::Error { code: 0 }`、
  HTTP tracker 和 peer 传输继续工作。想要真正用上 DHT，实现
  `resolve_host` 和真实的 `udp_open`/`udp_send`/`udp_recv`。

## 额外可选能力（带默认实现）

| 方法 | 默认 | 需要时 |
|---|---|---|
| `resolve_host(host, port) -> Option<NetAddr>` | `None` | DHT 引导 |
| `resolve_host_all(host, port) -> Vec<NetAddr>` | 只回 `resolve_host` | UDP tracker 多 A/AAAA 记录回退 |
| `resolve_host_async(host, port) -> bool` + `take_resolved_hosts()` | `false` / 空 | 非阻塞 DHT 引导 DNS |
| `http_post(url, body, timeout, out)` | `Err(NotSupported)` | UPnP IGD SOAP |
| `http_get_range(url, start, end, timeout, out)` | `Err(NotSupported)` | Web seed（BEP-19） |
| `http_get_async(url, timeout) -> u64` + `http_take_done()` | `0` / 空 | 非阻塞 tracker / web seed |
| `udp_multicast_send` / `udp_join_multicast` | 走 `udp_send` / no-op | LSD（BEP-14）、SSDP |
| `default_gateway() -> Option<NetAddr>` | `None` | NAT-PMP |
| `local_ip() -> Option<NetAddr>` | `None` | UPnP IGD `NewInternalClient` |
| `tcp_recv_buf_size() -> usize` | 64 KiB | 接收缓冲大小提示 |

> **注意**：所有 HTTP 回调的 `out` 都要**有界**。引擎按 `MAX_HTTP_BODY`
> 或请求窗口做上限校验，但宿主实现也应对恶意响应体做长度防护。

## 一份真实（std）宿主，约 60 行

完整可运行的内存版见 `examples/minimal_host.rs`（那是规范的参考实现）。
`std` 下的完整 OS 实现直接看 `src/host_std.rs`——那是开箱即用的
`StdHost`，桌面/服务器直接用它即可，不用自己写。

## 常见坑

- **非阻塞 connect 判定**：`tcp_connect` 只建 socket 并设非阻塞，不裁定
  连接结果；`tcp_connect_done` 先查 `take_error()`（SO_ERROR 是跨平台权威
  的失败来源），再零字节写探测（`Ok` = 已连，`WouldBlock` = SYN 仍在途）。
- **Windows UDP 的 `ConnectionReset`**：已连接 UDP 收到 ICMP 错误后，
  `recv` 会返回 ConnectionReset——这是瞬态，当 `WouldBlock` 处理即可。
- **IPv4-mapped IPv6**：双栈 socket 收到 `::ffff:a.b.c.d` 要归一化成
  `NetAddr::V4`，否则地址族逻辑、子网键、紧凑编码全错。
