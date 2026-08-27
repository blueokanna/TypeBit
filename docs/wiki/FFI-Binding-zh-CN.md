# FFI 绑定（C ABI）

开 `ffi` feature，crate 就导出一套稳定的 `extern "C"` 表面，Kotlin (JNI)、
Swift、C#、Go 或纯 C 都能调。同一个引擎——同一套代码、同一套语义——
只是隔了一层 C 桥。

```toml
[dependencies]
typebit = { version = "0.1", features = ["ffi"] }
```

```sh
cargo run --example ffi_demo --features ffi
```

## 回调表：`HostCbs`

`typebit_engine_new` 接收一个 `#[repr(C)]` 回调表的指针。每个字段都是 C
函数指针；**18 个必需回调必须非空**，否则构造函数返回 `NULL`（首次使用
前会校验整张表）。`resolve_host` 可选（可为 `NULL`——DHT 保持休眠；HTTP/
UDP tracker 不受影响）。

```c
typedef struct {
    void *ctx;                                    // 你的上下文，原样传回
    uint64_t (*now_ms)(void *);
    void (*fill_random)(void *, uint8_t *, size_t);
    void (*log)(void *, int level, const char *msg);
    int  (*http_get)(void *, const char *url, uint64_t timeout_ms,
                     uint8_t *out, size_t cap, size_t *written);
    int  (*tcp_connect)(void *, const uint8_t *ip4, uint16_t port, uint32_t *out_id);
    int  (*tcp_connect_done)(void *, uint32_t id);
    int  (*tcp_send)(void *, uint32_t id, const uint8_t *data, size_t len, size_t *sent);
    int  (*tcp_recv)(void *, uint32_t id, uint8_t *buf, size_t cap, size_t *got);
    void (*tcp_close)(void *, uint32_t id);
    int  (*udp_open)(void *, uint16_t port);
    int  (*udp_send)(void *, const uint8_t *ip4, uint16_t port, const uint8_t *data, size_t len);
    int  (*udp_recv)(void *, uint8_t *buf, size_t cap, uint8_t *ip4, uint16_t *port, size_t *got);
    int  (*disk_open)(void *, const char *path);
    int  (*disk_read)(void *, uint32_t id, uint64_t off, uint8_t *buf, size_t cap, size_t *got);
    int  (*disk_write)(void *, uint32_t id, uint64_t off, const uint8_t *data, size_t len);
    int  (*disk_prealloc)(void *, uint32_t id, uint64_t size);
    int  (*disk_flush)(void *, uint32_t id);
    void (*disk_close)(void *, uint32_t id);
    int  (*resolve_host)(void *, const char *host, uint16_t port, uint8_t *out_ip4, uint16_t *out_port); /* 可选 */
} HostCbs;
```

返回码：`FFI_OK = 0`、`FFI_ERR = -1`、`FFI_WOULD_BLOCK = -2`、
`FFI_NOT_FOUND = -3`、`FFI_INVALID = -4`。引擎把 `tcp_recv`/`udp_recv`
返回的 `FFI_WOULD_BLOCK` 当作 `Err(Error::WouldBlock)` 处理——**回调里
绝不能阻塞**。

## 引擎函数

| C 函数 | 说明 |
|---|---|
| `typebit_engine_new(cbs, listen_port, cache_bytes, dht_enabled) -> TypeBitEngine*` | 表非法返回 `NULL`。`dht_enabled` 为 `0`/`1`。 |
| `typebit_engine_free(e)` | 销毁句柄 |
| `typebit_engine_add_torrent(e, data, len, save_dir, out_hash, out_hash_len) -> int` | 写出 20/32 字节 infohash |
| `typebit_engine_add_magnet(e, uri, save_dir, out_hash, out_hash_len) -> int` | 同上 |
| `typebit_engine_start(e, hash, hash_len) -> int` | `hash_len` 20（v1）或 32（v2） |
| `typebit_engine_pause(e, hash, hash_len) -> int` | |
| `typebit_engine_resume(e, hash, hash_len) -> int` | |
| `typebit_engine_remove(e, hash, hash_len) -> int` | |
| `typebit_engine_progress(e, hash, hash_len, double *out) -> int` | 0.0..=1.0 |
| `typebit_engine_tick(e) -> int` | 用 ~100 ms 定时器调用 |
| `typebit_engine_take_event(e, out, out_cap) -> int` | 1 = 写入一个事件，0 = 无 |

`typebit_engine_take_event` 每次只返回**一个**事件；循环调用直到返回 0。
引擎内部有缓冲，事件永不丢失。

## 事件线格式

`[kind:u8]` 后接各类型载荷（整数全大端）：

| kind | 事件 | 载荷 |
|---|---|---|
| 1 | `PeerConnected` | 32 字节 infohash + 4 字节 IPv4 + 2 字节端口 |
| 2 | `PieceVerified` | infohash + 4 字节 piece |
| 3 | `HashFailure` | infohash + 4 字节 piece |
| 4 | `TorrentComplete` | infohash |
| 5 | `MetadataComplete` | infohash |
| 6 | `MetadataFailed` | infohash |
| 7 | `TrackerAnnounced` | infohash + 4 字节 peer 数 |
| 8 | `DhtNodeCount` | 4 字节计数 |
| 9 | `PeerBanned` | infohash + 4 字节 IPv4 + 2 字节端口 + 原因码 |
| 10 | `PortMapping` | phase 字节 + 2 字节外部端口（0 = 未知） |
| 11 | `Error` | code 字节 + NUL 结尾的详情串 |

## 极简 C 示例

```c
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* 声明你的回调；18 个必需回调全部要实现 */
uint64_t my_now_ms(void *ctx) { /* ... */ return 0; }
/* ... fill_random、log、http_get、tcp_*、udp_*、disk_* ... */

int main(void) {
    HostCbs cbs = {0};
    cbs.ctx = NULL;
    cbs.now_ms = my_now_ms;
    /* ... 逐个赋值所有必需回调 ... */

    TypeBitEngine *e = typebit_engine_new(&cbs, 6881, 256 * 1024 * 1024, 1);
    if (!e) { fprintf(stderr, "回调表不完整\n"); return 1; }

    uint8_t hash[32]; size_t hash_len = 0;
    if (typebit_engine_add_magnet(e,
        "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567",
        "/tmp/dl", hash, &hash_len) != 0) { /* ... */ }
    typebit_engine_start(e, hash, hash_len);

    for (;;) {
        typebit_engine_tick(e);
        uint8_t ev[64];
        while (typebit_engine_take_event(e, ev, sizeof(ev)) == 1) {
            printf("event kind=%d\n", ev[0]);
        }
        /* 睡 ~100 ms */
    }
    typebit_engine_free(e);
    return 0;
}
```

完整自测的 C ABI 脚手架见 `examples/ffi_demo.rs`。
