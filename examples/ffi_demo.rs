//! TypeBit FFI demo — drive the engine through the C ABI the way Kotlin
//! (JNI), Swift (CInterop), C# or Go would.
//!
//! Build & run:
//! ```sh
//! cargo run --example ffi_demo --features ffi
//! ```
//!
//! This example re-declares the C surface (`extern "C"` + `#[repr(C)]`) and
//! supplies real host callbacks, exactly like a foreign-language host would.
//! The engine itself lives in `src/ffi.rs` behind `--features ffi`.

use std::ffi::{c_char, c_int, c_void, CString};

// ---------------------------------------------------------------------------
// 1. The C callback table — must match `typebit::ffi::HostCbs` exactly.
// ---------------------------------------------------------------------------

#[repr(C)]
struct HostCbs {
    ctx: *mut c_void,
    now_ms: extern "C" fn(*mut c_void) -> u64,
    fill_random: extern "C" fn(*mut c_void, *mut u8, usize),
    log: extern "C" fn(*mut c_void, c_int, *const c_char),
    http_get: extern "C" fn(*mut c_void, *const c_char, u64, *mut u8, usize, *mut usize) -> c_int,
    tcp_connect: extern "C" fn(*mut c_void, *const u8, u16, *mut u32) -> c_int,
    tcp_connect_done: extern "C" fn(*mut c_void, u32) -> c_int,
    tcp_send: extern "C" fn(*mut c_void, u32, *const u8, usize, *mut usize) -> c_int,
    tcp_recv: extern "C" fn(*mut c_void, u32, *mut u8, usize, *mut usize) -> c_int,
    tcp_close: extern "C" fn(*mut c_void, u32),
    udp_open: extern "C" fn(*mut c_void, u16) -> c_int,
    udp_send: extern "C" fn(*mut c_void, *const u8, u16, *const u8, usize) -> c_int,
    udp_recv: extern "C" fn(*mut c_void, *mut u8, usize, *mut u8, *mut u16, *mut usize) -> c_int,
    disk_open: extern "C" fn(*mut c_void, *const c_char) -> c_int,
    disk_read: extern "C" fn(*mut c_void, u32, u64, *mut u8, usize, *mut usize) -> c_int,
    disk_write: extern "C" fn(*mut c_void, u32, u64, *const u8, usize) -> c_int,
    disk_prealloc: extern "C" fn(*mut c_void, u32, u64) -> c_int,
    disk_flush: extern "C" fn(*mut c_void, u32) -> c_int,
    disk_close: extern "C" fn(*mut c_void, u32),
}

const FFI_OK: c_int = 0;
const FFI_ERR: c_int = -1;
const FFI_WOULD_BLOCK: c_int = -2;

// ---------------------------------------------------------------------------
// 2. The C entry points (re-declared so a foreign host knows the shape).
// ---------------------------------------------------------------------------

extern "C" {
    fn typebit_engine_new(
        cbs: *const HostCbs,
        listen_port: u16,
        cache_bytes: u64,
        dht_enabled: c_int,
    ) -> *mut c_void;
    fn typebit_engine_free(e: *mut c_void);
    fn typebit_engine_add_torrent(
        e: *mut c_void,
        data: *const u8,
        len: usize,
        save_dir: *const c_char,
        out_hash: *mut u8,
        out_hash_len: *mut usize,
    ) -> c_int;
    fn typebit_engine_start(e: *mut c_void, hash: *const u8, hash_len: usize) -> c_int;
    fn typebit_engine_tick(e: *mut c_void) -> c_int;
    fn typebit_engine_take_event(e: *mut c_void, out: *mut u8, out_cap: usize) -> c_int;
    fn typebit_engine_progress(
        e: *mut c_void,
        hash: *const u8,
        hash_len: usize,
        out: *mut f64,
    ) -> c_int;
}

// ---------------------------------------------------------------------------
// 3. Host-side state + callbacks. In a real C/Kotlin/Swift app these are
//    your socket/file/clock wrappers.
// ---------------------------------------------------------------------------

struct HostState {
    now: u64,
}

extern "C" fn cb_now_ms(ctx: *mut c_void) -> u64 {
    unsafe { (*(ctx as *mut HostState)).now }
}

extern "C" fn cb_fill_random(_ctx: *mut c_void, buf: *mut u8, len: usize) {
    unsafe {
        for i in 0..len {
            *buf.add(i) = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
    }
}

extern "C" fn cb_log(_ctx: *mut c_void, _level: c_int, msg: *const c_char) {
    unsafe {
        if !msg.is_null() {
            let s = std::ffi::CStr::from_ptr(msg).to_string_lossy();
            println!("[host-log] {s}");
        }
    }
}

extern "C" fn cb_http_get(
    _ctx: *mut c_void,
    _url: *const c_char,
    _timeout_ms: u64,
    _out: *mut u8,
    _cap: usize,
    _n: *mut usize,
) -> c_int {
    FFI_ERR // no network in this demo
}

extern "C" fn cb_tcp_connect(
    _ctx: *mut c_void,
    _ip: *const u8,
    _port: u16,
    out_id: *mut u32,
) -> c_int {
    unsafe {
        *out_id = 1; // "peer" accepts immediately
    }
    FFI_OK
}

extern "C" fn cb_tcp_connect_done(_ctx: *mut c_void, _id: u32) -> c_int {
    FFI_OK
}

extern "C" fn cb_tcp_send(
    _ctx: *mut c_void,
    _id: u32,
    _data: *const u8,
    len: usize,
    out_n: *mut usize,
) -> c_int {
    unsafe {
        *out_n = len;
    }
    FFI_OK
}

extern "C" fn cb_tcp_recv(
    _ctx: *mut c_void,
    _id: u32,
    _buf: *mut u8,
    _len: usize,
    _out_n: *mut usize,
) -> c_int {
    FFI_WOULD_BLOCK
}

extern "C" fn cb_tcp_close(_ctx: *mut c_void, _id: u32) {}

extern "C" fn cb_udp_open(_ctx: *mut c_void, _port: u16) -> c_int {
    FFI_ERR
}

extern "C" fn cb_udp_send(
    _ctx: *mut c_void,
    _ip: *const u8,
    _port: u16,
    _data: *const u8,
    _len: usize,
) -> c_int {
    FFI_ERR
}

extern "C" fn cb_udp_recv(
    _ctx: *mut c_void,
    _buf: *mut u8,
    _len: usize,
    _ip: *mut u8,
    _port: *mut u16,
    _n: *mut usize,
) -> c_int {
    FFI_WOULD_BLOCK
}

extern "C" fn cb_disk_open(_ctx: *mut c_void, _path: *const c_char) -> c_int {
    FFI_ERR
}

extern "C" fn cb_disk_read(
    _ctx: *mut c_void,
    _id: u32,
    _off: u64,
    _buf: *mut u8,
    _len: usize,
    _n: *mut usize,
) -> c_int {
    FFI_ERR
}

extern "C" fn cb_disk_write(
    _ctx: *mut c_void,
    _id: u32,
    _off: u64,
    _d: *const u8,
    _len: usize,
) -> c_int {
    FFI_ERR
}

extern "C" fn cb_disk_prealloc(_ctx: *mut c_void, _id: u32, _size: u64) -> c_int {
    FFI_ERR
}

extern "C" fn cb_disk_flush(_ctx: *mut c_void, _id: u32) -> c_int {
    FFI_ERR
}

extern "C" fn cb_disk_close(_ctx: *mut c_void, _id: u32) {}

// ---------------------------------------------------------------------------
// 4. Demo driver.
// ---------------------------------------------------------------------------

fn main() {
    // Host state the callbacks read (the `ctx` pointer).
    let mut state = HostState {
        now: 1_700_000_000_000,
    };
    let state_ptr = &mut state as *mut HostState as *mut c_void;

    let cbs = HostCbs {
        ctx: state_ptr,
        now_ms: cb_now_ms,
        fill_random: cb_fill_random,
        log: cb_log,
        http_get: cb_http_get,
        tcp_connect: cb_tcp_connect,
        tcp_connect_done: cb_tcp_connect_done,
        tcp_send: cb_tcp_send,
        tcp_recv: cb_tcp_recv,
        tcp_close: cb_tcp_close,
        udp_open: cb_udp_open,
        udp_send: cb_udp_send,
        udp_recv: cb_udp_recv,
        disk_open: cb_disk_open,
        disk_read: cb_disk_read,
        disk_write: cb_disk_write,
        disk_prealloc: cb_disk_prealloc,
        disk_flush: cb_disk_flush,
        disk_close: cb_disk_close,
    };

    // --- create engine -------------------------------------------------
    let engine = unsafe { typebit_engine_new(&cbs, 6881, 64 * 1024 * 1024, 0) };
    assert!(!engine.is_null(), "engine_new failed");

    // --- add a torrent (built in memory) -------------------------------
    let torrent = make_torrent_bytes();
    let mut hash = [0u8; 32];
    let mut hash_len = 0usize;
    let dir = CString::new("/tmp/ffi-demo").unwrap();
    let rc = unsafe {
        typebit_engine_add_torrent(
            engine,
            torrent.as_ptr(),
            torrent.len(),
            dir.as_ptr(),
            hash.as_mut_ptr(),
            &mut hash_len,
        )
    };
    assert_eq!(rc, FFI_OK, "add_torrent failed rc={rc}");
    println!(
        "added torrent: {} ({} hash bytes)",
        hex(&hash[..hash_len]),
        hash_len
    );

    // --- start ---------------------------------------------------------
    let rc = unsafe { typebit_engine_start(engine, hash.as_ptr(), hash_len) };
    println!("start rc = {rc}");

    // --- pump events ---------------------------------------------------
    let mut evbuf = [0u8; 128];
    for round in 0..10 {
        state.now = state.now.wrapping_add(100);
        let _ = state.now; // visible read (callbacks read it via ctx)
        unsafe { typebit_engine_tick(engine) };
        loop {
            let n = unsafe { typebit_engine_take_event(engine, evbuf.as_mut_ptr(), evbuf.len()) };
            if n <= 0 {
                break;
            }
            describe_event(&evbuf[..n as usize]);
        }
        let mut prog = 0.0f64;
        unsafe { typebit_engine_progress(engine, hash.as_ptr(), hash_len, &mut prog) };
        println!("round {round}: progress = {:.2}%", prog * 100.0);
    }

    // --- teardown ------------------------------------------------------
    unsafe { typebit_engine_free(engine) };
    println!("engine freed");
}

fn describe_event(b: &[u8]) {
    let kind = b[0];
    let hash_hex = if b.len() >= 4 {
        hex(&b[1..4])
    } else {
        String::new()
    };
    match kind {
        1 => println!("event: peer connected  (hash prefix {hash_hex})"),
        2 => {
            let piece = if b.len() >= 36 {
                u32::from_be_bytes([b[32], b[33], b[34], b[35]])
            } else {
                0
            };
            println!("event: piece verified  piece={piece}");
        }
        4 => println!("event: torrent complete"),
        5 => println!("event: metadata complete"),
        6 => println!("event: metadata failed"),
        7 => {
            let peers = if b.len() >= 36 {
                u32::from_be_bytes([b[32], b[33], b[34], b[35]])
            } else {
                0
            };
            println!("event: tracker announced peers={peers}");
        }
        8 => println!("event: dht node count"),
        other => println!("event: unknown kind={other}"),
    }
}

fn make_torrent_bytes() -> Vec<u8> {
    // One file, one 16 KiB piece — same as the minimal_host example.
    use typebit::bencode::{bytes, dict, int};
    let piece: Vec<u8> = (0..16 * 1024u32).map(|i| (i % 251) as u8).collect();
    let sha1 = typebit::crypto::Sha1::digest(&piece);
    let info = dict(vec![
        (b"name", bytes("hello.bin")),
        (b"piece length", int(16 * 1024)),
        (b"length", int(piece.len() as i64)),
        (b"pieces", bytes(sha1.to_vec())),
    ]);
    typebit::bencode::encode_to_vec(&dict(vec![(b"info", info)]))
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
