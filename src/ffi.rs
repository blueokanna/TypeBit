//! C ABI for the TypeBit engine — the language bridge.
//!
//! Exposes a minimal, allocation-clean C surface that Kotlin (JNI/Swift
//! Interop), Swift (CInterop), C#, Go or any FFI-capable language can call:
//!
//! ```c
//! typebit_engine_t* e = typebit_engine_new(&host_cbs, &host_ctx);
//! typebit_engine_add_torrent(e, bytes, len, save_dir);
//! typebit_engine_start(e, hash, hash_len);
//! // ... pump on a timer:
//! typebit_engine_tick(e);
//! // drain events:
//! typebit_engine_take_event(e, &out, out_cap);
//! ```

#![allow(clippy::missing_safety_doc)]
#![allow(missing_docs)]

// This module used to live in its own crate named `typebit_core`; the
// merged single-crate layout keeps those paths working via a crate alias.
use crate as typebit_core;

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::{c_char, c_int, c_void};
use typebit_core::error::Error as CoreError;
use typebit_core::platform::{ConnId, DiskId, Host, LogLevel, NetAddr};
use typebit_core::Engine as CoreEngine;
use typebit_core::EngineConfig;
use typebit_core::EngineEvent;

/// Opaque engine handle.
pub struct TypeBitEngine {
    engine: CoreEngine<HostBridge>,
    /// Engine events already drained from the core but not yet handed to the
    /// host. `typebit_engine_take_event` returns **one** event per call, so
    /// without this buffer every call would discard all events except the
    /// first. The queue keeps them until the host consumes each one.
    pending_events: VecDeque<EngineEvent>,
}

// ---------- host bridge ----------

#[repr(C)]
pub struct HostCbs {
    pub ctx: *mut c_void,
    pub now_ms: extern "C" fn(*mut c_void) -> u64,
    pub fill_random: extern "C" fn(*mut c_void, *mut u8, usize),
    pub log: extern "C" fn(*mut c_void, c_int, *const c_char),
    pub http_get:
        extern "C" fn(*mut c_void, *const c_char, u64, *mut u8, usize, *mut usize) -> c_int,
    pub tcp_connect: extern "C" fn(*mut c_void, *const u8, u16, *mut u32) -> c_int,
    pub tcp_connect_done: extern "C" fn(*mut c_void, u32) -> c_int,
    pub tcp_send: extern "C" fn(*mut c_void, u32, *const u8, usize, *mut usize) -> c_int,
    pub tcp_recv: extern "C" fn(*mut c_void, u32, *mut u8, usize, *mut usize) -> c_int,
    pub tcp_close: extern "C" fn(*mut c_void, u32),
    pub udp_open: extern "C" fn(*mut c_void, u16) -> c_int,
    pub udp_send: extern "C" fn(*mut c_void, *const u8, u16, *const u8, usize) -> c_int,
    pub udp_recv:
        extern "C" fn(*mut c_void, *mut u8, usize, *mut u8, *mut u16, *mut usize) -> c_int,
    pub disk_open: extern "C" fn(*mut c_void, *const c_char) -> c_int,
    pub disk_read: extern "C" fn(*mut c_void, u32, u64, *mut u8, usize, *mut usize) -> c_int,
    pub disk_write: extern "C" fn(*mut c_void, u32, u64, *const u8, usize) -> c_int,
    pub disk_prealloc: extern "C" fn(*mut c_void, u32, u64) -> c_int,
    pub disk_flush: extern "C" fn(*mut c_void, u32) -> c_int,
    pub disk_close: extern "C" fn(*mut c_void, u32),
    /// Resolve a hostname to an IPv4 endpoint (used for the DHT bootstrap
    /// routers, BEP-5). `host` is NUL-terminated. On success fill `out_ip`
    /// (4 bytes, network order) and `*out_port`, then return `FFI_OK`;
    /// return `FFI_NOT_FOUND` (or `FFI_ERR`) when the name cannot be
    /// resolved. May be a null function pointer — the engine then treats
    /// every hostname as unresolvable and the DHT stays dormant (HTTP and
    /// UDP trackers are unaffected).
    pub resolve_host: extern "C" fn(*mut c_void, *const c_char, u16, *mut u8, *mut u16) -> c_int,
}

/// Error codes returned across the FFI boundary.
pub const FFI_OK: c_int = 0;
pub const FFI_ERR: c_int = -1;
pub const FFI_WOULD_BLOCK: c_int = -2;
pub const FFI_NOT_FOUND: c_int = -3;
pub const FFI_INVALID: c_int = -4;

struct HostBridge {
    cbs: *const HostCbs,
}

impl Host for HostBridge {
    fn now_ms(&self) -> u64 {
        unsafe { (self.cbs.as_ref().unwrap().now_ms)(self.cbs.as_ref().unwrap().ctx) }
    }
    fn fill_random(&mut self, buf: &mut [u8]) {
        unsafe {
            (self.cbs.as_ref().unwrap().fill_random)(
                self.cbs.as_ref().unwrap().ctx,
                buf.as_mut_ptr(),
                buf.len(),
            )
        }
    }
    fn log(&mut self, level: LogLevel, msg: &str) {
        let lvl = match level {
            LogLevel::Trace => 0,
            LogLevel::Debug => 1,
            LogLevel::Info => 2,
            LogLevel::Warn => 3,
            LogLevel::Error => 4,
        };
        let mut buf = Vec::with_capacity(msg.len() + 1);
        buf.extend_from_slice(msg.as_bytes());
        buf.push(0);
        unsafe {
            (self.cbs.as_ref().unwrap().log)(
                self.cbs.as_ref().unwrap().ctx,
                lvl,
                buf.as_ptr() as *const c_char,
            )
        }
    }
    fn http_get(
        &mut self,
        url: &str,
        timeout_ms: u64,
        out: &mut Vec<u8>,
    ) -> typebit_core::Result<()> {
        let mut buf = Vec::with_capacity(url.len() + 1);
        buf.extend_from_slice(url.as_bytes());
        buf.push(0);
        let mut n = 0usize;
        let rc = unsafe {
            (self.cbs.as_ref().unwrap().http_get)(
                self.cbs.as_ref().unwrap().ctx,
                buf.as_ptr() as *const c_char,
                timeout_ms,
                out.as_mut_ptr(),
                out.capacity(),
                &mut n,
            )
        };
        if rc != FFI_OK {
            return Err(CoreError::Io);
        }
        unsafe { out.set_len(n) };
        Ok(())
    }
    fn tcp_connect(&mut self, addr: &NetAddr) -> typebit_core::Result<ConnId> {
        let (ip, port) = match addr {
            NetAddr::V4(ip, p) => (ip.to_vec(), *p),
            NetAddr::V6(_, _) => return Err(CoreError::NotSupported),
        };
        let mut id = 0u32;
        let rc = unsafe {
            (self.cbs.as_ref().unwrap().tcp_connect)(
                self.cbs.as_ref().unwrap().ctx,
                ip.as_ptr(),
                port,
                &mut id,
            )
        };
        if rc != FFI_OK {
            return Err(CoreError::Io);
        }
        Ok(id)
    }
    fn tcp_connect_done(&mut self, id: ConnId) -> typebit_core::Result<()> {
        let rc = unsafe {
            (self.cbs.as_ref().unwrap().tcp_connect_done)(self.cbs.as_ref().unwrap().ctx, id)
        };
        match rc {
            FFI_OK => Ok(()),
            FFI_WOULD_BLOCK => Err(CoreError::WouldBlock),
            _ => Err(CoreError::Io),
        }
    }
    fn tcp_send(&mut self, id: ConnId, data: &[u8]) -> typebit_core::Result<usize> {
        let mut n = 0usize;
        let rc = unsafe {
            (self.cbs.as_ref().unwrap().tcp_send)(
                self.cbs.as_ref().unwrap().ctx,
                id,
                data.as_ptr(),
                data.len(),
                &mut n,
            )
        };
        // The callback's return code is the authoritative error signal: a
        // failed send must not be reported as a success of 0 bytes (which
        // the engine would interpret as "connection closed").
        match rc {
            FFI_OK => Ok(n),
            FFI_WOULD_BLOCK => Err(CoreError::WouldBlock),
            _ => Err(CoreError::Io),
        }
    }
    fn tcp_recv(&mut self, id: ConnId, buf: &mut [u8]) -> typebit_core::Result<usize> {
        let mut n = 0usize;
        let rc = unsafe {
            (self.cbs.as_ref().unwrap().tcp_recv)(
                self.cbs.as_ref().unwrap().ctx,
                id,
                buf.as_mut_ptr(),
                buf.len(),
                &mut n,
            )
        };
        match rc {
            FFI_OK => Ok(n),
            FFI_WOULD_BLOCK => Err(CoreError::WouldBlock),
            _ => Err(CoreError::Io),
        }
    }
    fn tcp_close(&mut self, id: ConnId) {
        unsafe { (self.cbs.as_ref().unwrap().tcp_close)(self.cbs.as_ref().unwrap().ctx, id) }
    }
    fn udp_open(&mut self, port: u16) -> typebit_core::Result<()> {
        let rc =
            unsafe { (self.cbs.as_ref().unwrap().udp_open)(self.cbs.as_ref().unwrap().ctx, port) };
        if rc != FFI_OK {
            Err(CoreError::Io)
        } else {
            Ok(())
        }
    }
    fn resolve_host(&self, host: &str, port: u16) -> Option<NetAddr> {
        let cbs = unsafe { self.cbs.as_ref()? };
        let cb = cbs.resolve_host;
        // The resolver is an optional capability: a host that did not
        // install one (null pointer) simply cannot resolve any hostname.
        if (cb as usize) == 0 {
            return None;
        }
        let mut buf = Vec::with_capacity(host.len() + 1);
        buf.extend_from_slice(host.as_bytes());
        buf.push(0);
        let mut ip = [0u8; 4];
        let mut out_port = 0u16;
        // `cb` is a safe `extern "C" fn`; only the raw-pointer deref above
        // needs an unsafe block.
        let rc = cb(
            cbs.ctx,
            buf.as_ptr() as *const c_char,
            port,
            ip.as_mut_ptr(),
            &mut out_port,
        );
        if rc != FFI_OK {
            return None;
        }
        Some(NetAddr::V4(ip, out_port))
    }
    fn udp_send(&mut self, addr: &NetAddr, data: &[u8]) -> typebit_core::Result<()> {
        let (ip, port) = match addr {
            NetAddr::V4(ip, p) => (ip.to_vec(), *p),
            NetAddr::V6(_, _) => return Err(CoreError::NotSupported),
        };
        let rc = unsafe {
            (self.cbs.as_ref().unwrap().udp_send)(
                self.cbs.as_ref().unwrap().ctx,
                ip.as_ptr(),
                port,
                data.as_ptr(),
                data.len(),
            )
        };
        if rc != FFI_OK {
            Err(CoreError::Io)
        } else {
            Ok(())
        }
    }
    fn udp_recv(&mut self, buf: &mut [u8]) -> typebit_core::Result<(NetAddr, usize)> {
        let mut ip = [0u8; 16];
        let mut port = 0u16;
        let mut n = 0usize;
        let rc = unsafe {
            (self.cbs.as_ref().unwrap().udp_recv)(
                self.cbs.as_ref().unwrap().ctx,
                buf.as_mut_ptr(),
                buf.len(),
                ip.as_mut_ptr(),
                &mut port,
                &mut n,
            )
        };
        match rc {
            FFI_OK => Ok((NetAddr::V4([ip[0], ip[1], ip[2], ip[3]], port), n)),
            FFI_WOULD_BLOCK => Err(CoreError::WouldBlock),
            _ => Err(CoreError::Io),
        }
    }
    fn disk_open(&mut self, path: &str) -> typebit_core::Result<DiskId> {
        let mut buf = Vec::with_capacity(path.len() + 1);
        buf.extend_from_slice(path.as_bytes());
        buf.push(0);
        let rc = unsafe {
            (self.cbs.as_ref().unwrap().disk_open)(
                self.cbs.as_ref().unwrap().ctx,
                buf.as_ptr() as *const c_char,
            )
        };
        if rc < 0 {
            Err(CoreError::Io)
        } else {
            Ok(rc as DiskId)
        }
    }
    fn disk_read(
        &mut self,
        id: DiskId,
        offset: u64,
        buf: &mut [u8],
    ) -> typebit_core::Result<usize> {
        let mut n = 0usize;
        let rc = unsafe {
            (self.cbs.as_ref().unwrap().disk_read)(
                self.cbs.as_ref().unwrap().ctx,
                id,
                offset,
                buf.as_mut_ptr(),
                buf.len(),
                &mut n,
            )
        };
        match rc {
            FFI_OK => Ok(n),
            FFI_WOULD_BLOCK => Err(CoreError::WouldBlock),
            _ => Err(CoreError::Io),
        }
    }
    fn disk_write(&mut self, id: DiskId, offset: u64, data: &[u8]) -> typebit_core::Result<()> {
        let rc = unsafe {
            (self.cbs.as_ref().unwrap().disk_write)(
                self.cbs.as_ref().unwrap().ctx,
                id,
                offset,
                data.as_ptr(),
                data.len(),
            )
        };
        if rc != FFI_OK {
            Err(CoreError::Io)
        } else {
            Ok(())
        }
    }
    fn disk_prealloc(&mut self, id: DiskId, size: u64) -> typebit_core::Result<()> {
        let rc = unsafe {
            (self.cbs.as_ref().unwrap().disk_prealloc)(self.cbs.as_ref().unwrap().ctx, id, size)
        };
        if rc != FFI_OK {
            Err(CoreError::Io)
        } else {
            Ok(())
        }
    }
    fn disk_flush(&mut self, id: DiskId) -> typebit_core::Result<()> {
        let rc =
            unsafe { (self.cbs.as_ref().unwrap().disk_flush)(self.cbs.as_ref().unwrap().ctx, id) };
        if rc != FFI_OK {
            Err(CoreError::Io)
        } else {
            Ok(())
        }
    }
    fn disk_close(&mut self, id: DiskId) {
        unsafe { (self.cbs.as_ref().unwrap().disk_close)(self.cbs.as_ref().unwrap().ctx, id) }
    }
}

// ---------- C API ----------

/// Validate a callback table: every **required** entry must be non-null.
/// Dereferencing a null function pointer is UB; a half-initialized table is
/// a host bug that must be rejected cleanly at creation rather than crash
/// (or worse) on the first engine call. `resolve_host` is the one optional
/// entry (null = the host cannot resolve DNS; DHT stays dormant).
fn validate_cbs(cbs: &HostCbs) -> bool {
    let required: [usize; 18] = [
        cbs.now_ms as usize,
        cbs.fill_random as usize,
        cbs.log as usize,
        cbs.http_get as usize,
        cbs.tcp_connect as usize,
        cbs.tcp_connect_done as usize,
        cbs.tcp_send as usize,
        cbs.tcp_recv as usize,
        cbs.tcp_close as usize,
        cbs.udp_open as usize,
        cbs.udp_send as usize,
        cbs.udp_recv as usize,
        cbs.disk_open as usize,
        cbs.disk_read as usize,
        cbs.disk_write as usize,
        cbs.disk_prealloc as usize,
        cbs.disk_flush as usize,
        cbs.disk_close as usize,
    ];
    required.iter().all(|p| *p != 0)
}

/// Create an engine. Returns a heap handle (free with `typebit_engine_free`).
/// `cbs` must stay alive for the engine's lifetime.
#[no_mangle]
pub unsafe extern "C" fn typebit_engine_new(
    cbs: *const HostCbs,
    listen_port: u16,
    cache_bytes: u64,
    dht_enabled: c_int,
) -> *mut TypeBitEngine {
    if cbs.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the pointer was checked non-null above; this only reads the
    // table to validate it before any callback is invoked.
    if !validate_cbs(unsafe { &*cbs }) {
        return core::ptr::null_mut(); // host bug: incomplete callback table
    }
    let cfg = EngineConfig {
        listen_port,
        cache_bytes,
        dht_enabled: dht_enabled != 0,
        ..Default::default()
    };
    let bridge = HostBridge { cbs };
    let engine = CoreEngine::new(bridge, cfg);
    Box::into_raw(Box::new(TypeBitEngine {
        engine,
        pending_events: VecDeque::new(),
    }))
}

/// Destroy an engine.
#[no_mangle]
pub unsafe extern "C" fn typebit_engine_free(e: *mut TypeBitEngine) {
    if !e.is_null() {
        drop(Box::from_raw(e));
    }
}

/// Add a torrent from `.torrent` bytes.
#[no_mangle]
pub unsafe extern "C" fn typebit_engine_add_torrent(
    e: *mut TypeBitEngine,
    data: *const u8,
    len: usize,
    save_dir: *const c_char,
    out_hash: *mut u8,
    out_hash_len: *mut usize,
) -> c_int {
    if e.is_null() || data.is_null() {
        return FFI_INVALID;
    }
    let engine = &mut (*e).engine;
    let bytes = core::slice::from_raw_parts(data, len);
    let dir = cstr_to_string(save_dir);
    match engine.add_torrent(bytes, &dir) {
        Ok(hash) => {
            let b = hash.as_bytes();
            if !out_hash.is_null() {
                core::ptr::copy_nonoverlapping(b.as_ptr(), out_hash, b.len());
                *out_hash_len = b.len();
            }
            FFI_OK
        }
        Err(_) => FFI_INVALID,
    }
}

/// Add a torrent from a magnet URI.
#[no_mangle]
pub unsafe extern "C" fn typebit_engine_add_magnet(
    e: *mut TypeBitEngine,
    uri: *const c_char,
    save_dir: *const c_char,
    out_hash: *mut u8,
    out_hash_len: *mut usize,
) -> c_int {
    if e.is_null() {
        return FFI_INVALID;
    }
    let engine = &mut (*e).engine;
    let uri = cstr_to_string(uri);
    let dir = cstr_to_string(save_dir);
    match engine.add_magnet(&uri, &dir) {
        Ok(hash) => {
            let b = hash.as_bytes();
            if !out_hash.is_null() {
                core::ptr::copy_nonoverlapping(b.as_ptr(), out_hash, b.len());
                *out_hash_len = b.len();
            }
            FFI_OK
        }
        Err(_) => FFI_INVALID,
    }
}

/// Start a torrent.
#[no_mangle]
pub unsafe extern "C" fn typebit_engine_start(
    e: *mut TypeBitEngine,
    hash: *const u8,
    hash_len: usize,
) -> c_int {
    let engine = &mut (*e).engine;
    match bytes_to_hash(hash, hash_len) {
        Some(h) => match engine.start(&h) {
            Ok(()) => FFI_OK,
            Err(_) => FFI_ERR,
        },
        None => FFI_INVALID,
    }
}

/// Pause a torrent.
#[no_mangle]
pub unsafe extern "C" fn typebit_engine_pause(
    e: *mut TypeBitEngine,
    hash: *const u8,
    hash_len: usize,
) -> c_int {
    let engine = &mut (*e).engine;
    match bytes_to_hash(hash, hash_len) {
        Some(h) => {
            engine.pause(&h);
            FFI_OK
        }
        None => FFI_INVALID,
    }
}

/// Resume a torrent.
#[no_mangle]
pub unsafe extern "C" fn typebit_engine_resume(
    e: *mut TypeBitEngine,
    hash: *const u8,
    hash_len: usize,
) -> c_int {
    let engine = &mut (*e).engine;
    match bytes_to_hash(hash, hash_len) {
        Some(h) => {
            engine.resume(&h);
            FFI_OK
        }
        None => FFI_INVALID,
    }
}

/// Remove a torrent.
#[no_mangle]
pub unsafe extern "C" fn typebit_engine_remove(
    e: *mut TypeBitEngine,
    hash: *const u8,
    hash_len: usize,
) -> c_int {
    let engine = &mut (*e).engine;
    match bytes_to_hash(hash, hash_len) {
        Some(h) => match engine.remove_torrent(&h) {
            Ok(()) => FFI_OK,
            Err(_) => FFI_ERR,
        },
        None => FFI_INVALID,
    }
}

/// Progress of a torrent (0.0..=1.0, stored in *out).
#[no_mangle]
pub unsafe extern "C" fn typebit_engine_progress(
    e: *mut TypeBitEngine,
    hash: *const u8,
    hash_len: usize,
    out: *mut f64,
) -> c_int {
    let engine = &mut (*e).engine;
    match bytes_to_hash(hash, hash_len) {
        Some(h) => {
            *out = engine.progress(&h);
            FFI_OK
        }
        None => FFI_INVALID,
    }
}

/// Advance the engine (call on a timer, e.g. every 100 ms).
#[no_mangle]
pub unsafe extern "C" fn typebit_engine_tick(e: *mut TypeBitEngine) -> c_int {
    let engine = &mut (*e).engine;
    match engine.tick() {
        Ok(()) => FFI_OK,
        Err(_) => FFI_ERR,
    }
}

/// Drain one engine event. Returns 1 if an event was written, 0 if none.
/// Event layout: [u8 kind, 32-byte infohash, u32 piece, u32 peers].
#[no_mangle]
pub unsafe extern "C" fn typebit_engine_take_event(
    e: *mut TypeBitEngine,
    out: *mut u8,
    out_cap: usize,
) -> c_int {
    if e.is_null() || out.is_null() {
        return FFI_INVALID;
    }
    let wrapper = &mut *e;
    // Drain the core's event list into our pending queue only when it is
    // empty, then pop exactly one event. Events are never dropped: a caller
    // that drains one event per call sees every event, in order.
    if wrapper.pending_events.is_empty() {
        wrapper.pending_events.extend(wrapper.engine.take_events());
    }
    let ev = match wrapper.pending_events.pop_front() {
        Some(ev) => ev,
        None => return 0,
    };
    let mut buf: Vec<u8> = Vec::with_capacity(8 + 32 + 4 + 4);
    match ev {
        EngineEvent::PeerConnected {
            info_hash, addr, ..
        } => {
            buf.push(1);
            buf.extend_from_slice(&info_hash.full());
            let (ip, port) = match addr {
                NetAddr::V4(ip, p) => (ip, p),
                NetAddr::V6(_, p) => ([0; 4], p),
            };
            buf.extend_from_slice(&ip);
            buf.extend_from_slice(&port.to_be_bytes());
        }
        EngineEvent::PieceVerified { info_hash, piece } => {
            buf.push(2);
            buf.extend_from_slice(&info_hash.full());
            buf.extend_from_slice(&piece.to_be_bytes());
        }
        EngineEvent::HashFailure { info_hash, piece } => {
            buf.push(3);
            buf.extend_from_slice(&info_hash.full());
            buf.extend_from_slice(&piece.to_be_bytes());
        }
        EngineEvent::TorrentComplete { info_hash } => {
            buf.push(4);
            buf.extend_from_slice(&info_hash.full());
        }
        EngineEvent::MetadataComplete { info_hash } => {
            buf.push(5);
            buf.extend_from_slice(&info_hash.full());
        }
        EngineEvent::MetadataFailed { info_hash } => {
            buf.push(6);
            buf.extend_from_slice(&info_hash.full());
        }
        EngineEvent::TrackerAnnounced { info_hash, peers } => {
            buf.push(7);
            buf.extend_from_slice(&info_hash.full());
            buf.extend_from_slice(&(peers as u32).to_be_bytes());
        }
        EngineEvent::DhtNodeCount(n) => {
            buf.push(8);
            buf.extend_from_slice(&(n as u32).to_be_bytes());
        }
        EngineEvent::PeerBanned {
            info_hash,
            addr,
            reason,
        } => {
            buf.push(9);
            buf.extend_from_slice(&info_hash.full());
            let (ip, port) = match addr {
                NetAddr::V4(ip, p) => (ip, p),
                NetAddr::V6(_, p) => ([0; 4], p),
            };
            buf.extend_from_slice(&ip);
            buf.extend_from_slice(&port.to_be_bytes());
            let rc = match reason {
                crate::leech::BanReason::Corrupt => 1u8,
                crate::leech::BanReason::Protocol => 2u8,
                crate::leech::BanReason::FreeRide => 3u8,
            };
            buf.push(rc);
        }
        EngineEvent::PortMapping {
            phase,
            external_port,
        } => {
            buf.push(10);
            buf.push(phase.code());
            let ext = external_port.unwrap_or(0);
            buf.extend_from_slice(&ext.to_be_bytes());
        }
        EngineEvent::Error { code, detail } => {
            buf.push(11);
            buf.push(code);
            buf.extend_from_slice(detail.as_bytes());
            buf.push(0);
        }
    }
    let n = core::cmp::min(buf.len(), out_cap);
    core::ptr::copy_nonoverlapping(buf.as_ptr(), out, n);
    n as c_int
}

// ---------- helpers ----------

unsafe fn cstr_to_string(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *p.add(len) != 0 {
        len += 1;
    }
    let slice = core::slice::from_raw_parts(p as *const u8, len);
    String::from_utf8_lossy(slice).into_owned()
}

fn bytes_to_hash(p: *const u8, len: usize) -> Option<typebit_core::InfoHash> {
    if p.is_null() {
        return None;
    }
    let slice = unsafe { core::slice::from_raw_parts(p, len) };
    if len == 20 {
        let mut h = [0u8; 20];
        h.copy_from_slice(slice);
        Some(typebit_core::InfoHash::v1(h))
    } else if len == 32 {
        let mut h = [0u8; 32];
        h.copy_from_slice(slice);
        Some(typebit_core::InfoHash::v2(h))
    } else {
        None
    }
}

// Re-exports so bindgen/headers can find types.
pub use typebit_core::Engine;

#[cfg(test)]
mod tests {
    use super::*;

    struct Ctx {
        now: u64,
        resolved: Option<(String, u16)>,
    }

    extern "C" fn cb_now(ctx: *mut c_void) -> u64 {
        unsafe { (*(ctx as *mut Ctx)).now }
    }
    extern "C" fn cb_rand(_: *mut c_void, buf: *mut u8, len: usize) {
        unsafe {
            for i in 0..len {
                *buf.add(i) = (i as u8).wrapping_mul(13).wrapping_add(1);
            }
        }
    }
    extern "C" fn cb_log(_: *mut c_void, _l: c_int, _m: *const c_char) {}
    extern "C" fn cb_http(
        _: *mut c_void,
        _u: *const c_char,
        _t: u64,
        _o: *mut u8,
        _c: usize,
        _n: *mut usize,
    ) -> c_int {
        FFI_ERR
    }
    extern "C" fn cb_tcp_connect(_: *mut c_void, _ip: *const u8, _p: u16, _id: *mut u32) -> c_int {
        FFI_ERR
    }
    extern "C" fn cb_tcp_connect_done(_: *mut c_void, _id: u32) -> c_int {
        FFI_ERR
    }
    extern "C" fn cb_tcp_send(
        _: *mut c_void,
        _id: u32,
        _d: *const u8,
        _l: usize,
        _n: *mut usize,
    ) -> c_int {
        FFI_ERR
    }
    extern "C" fn cb_tcp_recv(
        _: *mut c_void,
        _id: u32,
        _b: *mut u8,
        _l: usize,
        _n: *mut usize,
    ) -> c_int {
        FFI_WOULD_BLOCK
    }
    extern "C" fn cb_tcp_close(_: *mut c_void, _id: u32) {}
    extern "C" fn cb_udp_open(_: *mut c_void, _p: u16) -> c_int {
        FFI_OK
    }
    extern "C" fn cb_udp_send(
        _: *mut c_void,
        _ip: *const u8,
        _p: u16,
        _d: *const u8,
        _l: usize,
    ) -> c_int {
        FFI_OK
    }
    extern "C" fn cb_udp_recv(
        _: *mut c_void,
        _b: *mut u8,
        _l: usize,
        _ip: *mut u8,
        _p: *mut u16,
        _n: *mut usize,
    ) -> c_int {
        FFI_WOULD_BLOCK
    }
    extern "C" fn cb_disk_open(_: *mut c_void, _p: *const c_char) -> c_int {
        FFI_ERR
    }
    extern "C" fn cb_disk_read(
        _: *mut c_void,
        _id: u32,
        _o: u64,
        _b: *mut u8,
        _l: usize,
        _n: *mut usize,
    ) -> c_int {
        FFI_ERR
    }
    extern "C" fn cb_disk_write(
        _: *mut c_void,
        _id: u32,
        _o: u64,
        _d: *const u8,
        _l: usize,
    ) -> c_int {
        FFI_ERR
    }
    extern "C" fn cb_disk_prealloc(_: *mut c_void, _id: u32, _s: u64) -> c_int {
        FFI_ERR
    }
    extern "C" fn cb_disk_flush(_: *mut c_void, _id: u32) -> c_int {
        FFI_ERR
    }
    extern "C" fn cb_disk_close(_: *mut c_void, _id: u32) {}
    extern "C" fn cb_resolve_host(
        ctx: *mut c_void,
        host: *const c_char,
        port: u16,
        out_ip: *mut u8,
        out_port: *mut u16,
    ) -> c_int {
        unsafe {
            let h = core::ffi::CStr::from_ptr(host)
                .to_string_lossy()
                .into_owned();
            let c = &mut *(ctx as *mut Ctx);
            c.resolved = Some((h, port));
            // "203.0.113.7"
            *out_ip.add(0) = 203;
            *out_ip.add(1) = 0;
            *out_ip.add(2) = 113;
            *out_ip.add(3) = 7;
            *out_port = port;
            FFI_OK
        }
    }

    fn make_cbs(ctx: *mut c_void) -> HostCbs {
        HostCbs {
            ctx,
            now_ms: cb_now,
            fill_random: cb_rand,
            log: cb_log,
            http_get: cb_http,
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
            resolve_host: cb_resolve_host,
        }
    }

    #[test]
    fn host_bridge_resolves_hostname() {
        let mut ctx = Ctx {
            now: 0,
            resolved: None,
        };
        let cbs = make_cbs(&mut ctx as *mut Ctx as *mut c_void);
        let bridge = HostBridge { cbs: &cbs };
        let got = bridge.resolve_host("router.bittorrent.com", 6881);
        assert_eq!(got, Some(NetAddr::V4([203, 0, 113, 7], 6881)));
        assert_eq!(
            ctx.resolved,
            Some((String::from("router.bittorrent.com"), 6881))
        );
    }

    #[test]
    #[allow(invalid_value, clippy::transmute_null_to_fn)] // intentionally building a null fn pointer
    fn host_bridge_resolve_host_null_returns_none() {
        let mut ctx = Ctx {
            now: 0,
            resolved: None,
        };
        let mut cbs = make_cbs(&mut ctx as *mut Ctx as *mut c_void);
        // A host that did not install a resolver (null fn pointer).
        type Resolve = extern "C" fn(*mut c_void, *const c_char, u16, *mut u8, *mut u16) -> c_int;
        cbs.resolve_host = unsafe { core::mem::transmute::<usize, Resolve>(0usize) };
        let bridge = HostBridge { cbs: &cbs };
        assert_eq!(bridge.resolve_host("router.bittorrent.com", 6881), None);
    }

    #[test]
    fn take_event_does_not_drop_events() {
        let mut ctx = Ctx {
            now: 1_000_000,
            resolved: None,
        };
        let cbs = make_cbs(&mut ctx as *mut Ctx as *mut c_void);
        let engine = unsafe { typebit_engine_new(&cbs, 6881, 1024 * 1024, 1) };
        assert!(!engine.is_null(), "engine_new failed");

        // Three ticks produce three queued DHT node-count events.
        for _ in 0..3 {
            unsafe {
                typebit_engine_tick(engine);
            }
        }

        let mut buf = [0u8; 128];
        // Regression: `take_events().into_iter().next()` used to drop every
        // event except the first, so the second and third calls returned 0.
        let n1 = unsafe { typebit_engine_take_event(engine, buf.as_mut_ptr(), buf.len()) };
        assert!(n1 > 0, "first event lost");
        assert_eq!(buf[0], 8, "first event must be DhtNodeCount");
        let n2 = unsafe { typebit_engine_take_event(engine, buf.as_mut_ptr(), buf.len()) };
        assert!(n2 > 0, "second event dropped by the queue bug");
        assert_eq!(buf[0], 8);
        let n3 = unsafe { typebit_engine_take_event(engine, buf.as_mut_ptr(), buf.len()) };
        assert!(n3 > 0, "third event dropped by the queue bug");
        assert_eq!(buf[0], 8);
        let n4 = unsafe { typebit_engine_take_event(engine, buf.as_mut_ptr(), buf.len()) };
        assert_eq!(n4, 0, "queue must be drained after all events");

        unsafe { typebit_engine_free(engine) };
    }

    #[test]
    #[allow(invalid_value, clippy::transmute_null_to_fn)] // null fn pointer on purpose
    fn engine_new_rejects_incomplete_callback_table() {
        let mut ctx = Ctx {
            now: 0,
            resolved: None,
        };
        let mut cbs = make_cbs(&mut ctx as *mut Ctx as *mut c_void);
        // A host bug: one required callback left null. Dereferencing it
        // later would be UB — creation must reject the table cleanly.
        type UdpOpen = extern "C" fn(*mut c_void, u16) -> c_int;
        cbs.udp_open = unsafe { core::mem::transmute::<usize, UdpOpen>(0usize) };
        let e = unsafe { typebit_engine_new(&cbs, 6881, 1 << 20, 0) };
        assert!(e.is_null(), "incomplete callback table must be rejected");
    }
}
