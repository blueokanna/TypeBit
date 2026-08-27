# FFI Binding (C ABI)

Enable the `ffi` feature and the crate exports a stable `extern "C"` surface
you can call from Kotlin (JNI), Swift, C#, Go, or plain C. It is the same
engine — same code, same semantics — behind a C bridge.

```toml
[dependencies]
typebit = { version = "0.1", features = ["ffi"] }
```

```sh
cargo run --example ffi_demo --features ffi
```

## The callback table: `HostCbs`

`typebit_engine_new` takes a pointer to a `#[repr(C)]` callback table. Every
field is a C function pointer; the **18 required callbacks must be
non-null** or the engine constructor returns `NULL` (it validates the whole
table before first use). `resolve_host` is optional (may be `NULL` — the
DHT then stays dormant; HTTP/UDP trackers are unaffected).

```c
typedef struct {
    void *ctx;                                    // your context, passed back
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
    int  (*resolve_host)(void *, const char *host, uint16_t port, uint8_t *out_ip4, uint16_t *out_port); /* optional */
} HostCbs;
```

Return codes: `FFI_OK = 0`, `FFI_ERR = -1`, `FFI_WOULD_BLOCK = -2`,
`FFI_NOT_FOUND = -3`, `FFI_INVALID = -4`. The engine treats `FFI_WOULD_BLOCK`
from `tcp_recv`/`udp_recv` exactly like `Err(Error::WouldBlock)` — do **not**
block in the callbacks.

## Engine functions

| C function | Notes |
|---|---|
| `typebit_engine_new(cbs, listen_port, cache_bytes, dht_enabled) -> TypeBitEngine*` | `NULL` on bad table. `dht_enabled` is `0`/`1`. |
| `typebit_engine_free(e)` | destroy the handle |
| `typebit_engine_add_torrent(e, data, len, save_dir, out_hash, out_hash_len) -> int` | writes 20/32-byte infohash |
| `typebit_engine_add_magnet(e, uri, save_dir, out_hash, out_hash_len) -> int` | same |
| `typebit_engine_start(e, hash, hash_len) -> int` | `hash_len` 20 (v1) or 32 (v2) |
| `typebit_engine_pause(e, hash, hash_len) -> int` | |
| `typebit_engine_resume(e, hash, hash_len) -> int` | |
| `typebit_engine_remove(e, hash, hash_len) -> int` | |
| `typebit_engine_progress(e, hash, hash_len, double *out) -> int` | 0.0..=1.0 |
| `typebit_engine_tick(e) -> int` | call on a ~100 ms timer |
| `typebit_engine_take_event(e, out, out_cap) -> int` | 1 = event written, 0 = none |

`typebit_engine_take_event` returns **one event per call**; call it in a
loop until it returns 0. The engine buffers internally, so events are never
dropped.

## Event wire format

`[kind:u8]` followed by per-kind payload (all integers big-endian):

| kind | event | payload |
|---|---|---|
| 1 | `PeerConnected` | 32-byte infohash + 4-byte IPv4 + 2-byte port |
| 2 | `PieceVerified` | infohash + 4-byte piece |
| 3 | `HashFailure` | infohash + 4-byte piece |
| 4 | `TorrentComplete` | infohash |
| 5 | `MetadataComplete` | infohash |
| 6 | `MetadataFailed` | infohash |
| 7 | `TrackerAnnounced` | infohash + 4-byte peer count |
| 8 | `DhtNodeCount` | 4-byte count |
| 9 | `PeerBanned` | infohash + 4-byte IPv4 + 2-byte port + reason code |
| 10 | `PortMapping` | phase byte + 2-byte external port (0 = unknown) |
| 11 | `Error` | code byte + NUL-terminated detail string |

## Minimal C example

```c
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* forward declarations of your callbacks; all 18 required ones */
uint64_t my_now_ms(void *ctx) { /* ... */ return 0; }
/* ... fill_random, log, http_get, tcp_*, udp_*, disk_* ... */

int main(void) {
    HostCbs cbs = {0};
    cbs.ctx = NULL;
    cbs.now_ms = my_now_ms;
    /* ... assign every required callback ... */

    TypeBitEngine *e = typebit_engine_new(&cbs, 6881, 256 * 1024 * 1024, 1);
    if (!e) { fprintf(stderr, "bad callback table\n"); return 1; }

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
        /* sleep ~100 ms */
    }
    typebit_engine_free(e);
    return 0;
}
```

See `examples/ffi_demo.rs` for a complete self-testing C ABI harness.
