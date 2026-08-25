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
        let _ = rc;
        Ok(n)
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
        let _ = rc;
        Ok(n)
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
    let cfg = EngineConfig {
        listen_port,
        cache_bytes,
        dht_enabled: dht_enabled != 0,
        ..Default::default()
    };
    let bridge = HostBridge { cbs };
    let engine = CoreEngine::new(bridge, cfg);
    Box::into_raw(Box::new(TypeBitEngine { engine }))
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
    let engine = &mut (*e).engine;
    let ev = match engine.take_events().into_iter().next() {
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
