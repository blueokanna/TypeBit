//! The platform abstraction seam: the engine is written against [`Host`]; a
//! concrete implementation (std, Android/Kotlin, iOS/Swift, embedded) only
//! provides ~15 primitives. Transports are **non-blocking** ([`Host::tcp_recv`]
//! returns [`Error::WouldBlock`], `tcp_send` may take a partial prefix), so
//! one engine drives hundreds of peers from a single thread.

use crate::error::{Error, Result};

/// Opaque handle to an open TCP connection.
pub type ConnId = u32;

/// Opaque handle to an open file/backing store.
pub type DiskId = u32;

/// Log severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Trace noise.
    Trace,
    /// Debug.
    Debug,
    /// Informational.
    Info,
    /// Warning.
    Warn,
    /// Error.
    Error,
}

/// A network endpoint. Compact, `Copy`, comparable — suitable as map keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NetAddr {
    /// IPv4 address + port.
    V4([u8; 4], u16),
    /// IPv6 address + port.
    V6([u8; 16], u16),
}

impl NetAddr {
    /// IPv4 from parts.
    pub const fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> Self {
        NetAddr::V4([a, b, c, d], port)
    }
    /// Build from a compact 6-byte `IP:port` (IPv4) blob, as used by trackers,
    /// PEX and DHT peer lists.
    pub fn from_compact6(b: &[u8]) -> Option<Self> {
        if b.len() != 6 {
            return None;
        }
        let mut ip = [0u8; 4];
        ip.copy_from_slice(&b[..4]);
        Some(NetAddr::V4(ip, u16::from_be_bytes([b[4], b[5]])))
    }
    /// Build from a compact 18-byte `IP:port` (IPv6) blob.
    pub fn from_compact18(b: &[u8]) -> Option<Self> {
        if b.len() != 18 {
            return None;
        }
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&b[..16]);
        Some(NetAddr::V6(ip, u16::from_be_bytes([b[16], b[17]])))
    }
    /// Compact IPv4 `IP:port` (6 bytes) if this is an IPv4 address.
    pub fn to_compact6(&self) -> Option<[u8; 6]> {
        match *self {
            NetAddr::V4(ip, port) => {
                let mut out = [0u8; 6];
                out[..4].copy_from_slice(&ip);
                out[4..].copy_from_slice(&port.to_be_bytes());
                Some(out)
            }
            NetAddr::V6(_, _) => None,
        }
    }
    /// Compact IPv6 `IP:port` (18 bytes) if this is an IPv6 address.
    pub fn to_compact18(&self) -> Option<[u8; 18]> {
        match *self {
            NetAddr::V6(ip, port) => {
                let mut out = [0u8; 18];
                out[..16].copy_from_slice(&ip);
                out[16..].copy_from_slice(&port.to_be_bytes());
                Some(out)
            }
            NetAddr::V4(_, _) => None,
        }
    }
    /// The port, regardless of family.
    pub fn port(&self) -> u16 {
        match *self {
            NetAddr::V4(_, p) | NetAddr::V6(_, p) => p,
        }
    }
    /// Human-readable form into a caller buffer (allocator-free).
    ///
    /// IPv4 renders `a.b.c.d:port`, IPv6 renders `[a:b:c:...]:port`
    /// (RFC 5952 brackets + the conventional `ip:port` separator). The old
    /// code concatenated the port directly onto the address
    /// (`128.241.252.3449779`) which made peer rows and ban logs unreadable.
    pub fn write_to(&self, buf: &mut [u8]) -> Result<usize> {
        let mut w = 0usize;
        match *self {
            NetAddr::V4(ip, port) => {
                for (i, o) in ip.iter().enumerate() {
                    if i > 0 {
                        buf[w] = b'.';
                        w += 1;
                    }
                    let n = write_u32(buf.get_mut(w..).ok_or(Error::TooLarge)?, *o as u32);
                    w += n;
                }
                buf[w] = b':';
                w += 1;
                let n = write_u16(buf.get_mut(w..).ok_or(Error::TooLarge)?, port);
                w += n;
            }
            NetAddr::V6(ip, port) => {
                buf[w] = b'[';
                w += 1;
                for (i, g) in ip.chunks(2).enumerate() {
                    if i > 0 {
                        buf[w] = b':';
                        w += 1;
                    }
                    let v = u16::from_be_bytes([g[0], g[1]]);
                    let n = write_u16_hex(buf.get_mut(w..).ok_or(Error::TooLarge)?, v);
                    w += n;
                }
                buf[w] = b']';
                w += 1;
                buf[w] = b':';
                w += 1;
                let n = write_u16(buf.get_mut(w..).ok_or(Error::TooLarge)?, port);
                w += n;
            }
        }
        Ok(w)
    }
    /// Allocate a `String` representation (requires `alloc`).
    pub fn to_alloc_string(&self) -> alloc::string::String {
        let mut buf = [0u8; 64];
        let n = self.write_to(&mut buf).unwrap_or(0);
        alloc::string::String::from_utf8_lossy(&buf[..n]).into_owned()
    }
}

impl core::fmt::Display for NetAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [0u8; 64];
        let n = self.write_to(&mut buf).unwrap_or(0);
        f.write_str(core::str::from_utf8(&buf[..n]).unwrap_or("<addr>"))
    }
}

fn write_u32(buf: &mut [u8], mut v: u32) -> usize {
    let mut n = 0;
    if v == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut i = 0;
    while v > 0 {
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        buf[n] = tmp[i];
        n += 1;
    }
    n
}

fn write_u16(buf: &mut [u8], v: u16) -> usize {
    let mut n = 0;
    if v == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 5];
    let mut vv = v;
    let mut i = 0;
    while vv > 0 {
        tmp[i] = b'0' + (vv % 10) as u8;
        vv /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        buf[n] = tmp[i];
        n += 1;
    }
    n
}

fn write_u16_hex(buf: &mut [u8], v: u16) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    buf[0] = HEX[((v >> 12) & 0xf) as usize];
    buf[1] = HEX[((v >> 8) & 0xf) as usize];
    buf[2] = HEX[((v >> 4) & 0xf) as usize];
    buf[3] = HEX[(v & 0xf) as usize];
    4
}

/// The platform seam. Implementations must be cheap and must not block
/// longer than necessary.
pub trait Host {
    /// Monotonic-ish milliseconds clock. Used for deadlines, retry back-off
    /// and rate windows. Does not need wall-clock precision.
    fn now_ms(&self) -> u64;

    /// Fill `buf` with cryptographically secure random bytes.
    fn fill_random(&mut self, buf: &mut [u8]);

    /// Log a message.
    fn log(&mut self, level: LogLevel, msg: &str);

    // ---------- HTTP (tracker announces, web seeds, webseeds) ----------

    /// Perform a blocking HTTP GET and append the response body to `out`.
    /// `timeout_ms` bounds the whole operation. Used by tracker and web-seed
    /// transports in the host. Returns `Err(Timeout)` on deadline.
    fn http_get(&mut self, url: &str, timeout_ms: u64, out: &mut alloc::vec::Vec<u8>)
        -> Result<()>;

    /// Perform a blocking HTTP POST with a request body. Used by UPnP IGD
    /// SOAP control (`AddPortMapping`/`DeletePortMapping`). A platform that
    /// cannot POST leaves the default: [`Error::NotSupported`] (the port
    /// mapper then falls back to NAT-PMP only).
    fn http_post(
        &mut self,
        _url: &str,
        _body: &[u8],
        _timeout_ms: u64,
        _out: &mut alloc::vec::Vec<u8>,
    ) -> Result<()> {
        Err(Error::NotSupported)
    }

    /// Perform a blocking HTTP GET with a `Range: bytes=start-end` header
    /// and append the response body to `out`. Used by web seeds (BEP-19)
    /// to fetch arbitrary byte ranges of a file. A host that cannot send
    /// request headers leaves the default: [`Error::NotSupported`] (web
    /// seeds are then disabled for that host). The body MUST be exactly
    /// `end - start + 1` bytes; anything else is rejected by the engine.
    fn http_get_range(
        &mut self,
        _url: &str,
        _range_start: u64,
        _range_end: u64,
        _timeout_ms: u64,
        _out: &mut alloc::vec::Vec<u8>,
    ) -> Result<()> {
        Err(Error::NotSupported)
    }

    // ---------- async HTTP (non-blocking tracker / web-seed transport) ----------

    /// Enqueue an async HTTP GET; returns a job id (>0) when accepted, 0
    /// when the host has no async worker (the caller then falls back to the
    /// blocking [`Self::http_get`]). Non-blocking: the request runs on a
    /// host thread and its result arrives via [`Self::http_take_done`];
    /// `timeout_ms` bounds the request on the worker.
    fn http_get_async(&mut self, _url: &str, _timeout_ms: u64) -> u64 {
        0
    }

    /// Enqueue an async HTTP GET with a `Range: bytes=start-end` header
    /// (web seeds, BEP-19); same contract as [`Self::http_get_async`].
    fn http_get_range_async(
        &mut self,
        _url: &str,
        _range_start: u64,
        _range_end: u64,
        _timeout_ms: u64,
    ) -> u64 {
        0
    }

    /// Drain completed async HTTP jobs as `(job id, result)` — the body on
    /// success, the error kind on failure/timeout. Jobs not returned here
    /// are still pending on the worker.
    fn http_take_done(&mut self) -> alloc::vec::Vec<(u64, Result<alloc::vec::Vec<u8>>)> {
        alloc::vec::Vec::new()
    }

    // ---------- network info (UPnP / NAT-PMP port mapping) ----------

    /// The default gateway address, when the platform can discover it.
    /// Needed to reach NAT-PMP (RFC 6886) and as a fallback for SSDP.
    fn default_gateway(&self) -> Option<NetAddr> {
        None
    }

    /// A LAN address of this host (any interface). Required by UPnP IGD
    /// `AddPortMapping` (`NewInternalClient`).
    fn local_ip(&self) -> Option<NetAddr> {
        None
    }

    /// Resolve a hostname to an IP endpoint (with `port`). Returns `None`
    /// when the platform cannot resolve (or the name does not exist). This
    /// is used to bootstrap the DHT from its well-known router hostnames
    /// (BEP-5) — tracker URLs are always resolved inside `http_get` and
    /// never go through this hook.
    fn resolve_host(&self, _host: &str, _port: u16) -> Option<NetAddr> {
        None
    }

    /// Resolve **all** address records for a hostname (with `port`), so a
    /// UDP tracker whose DNS has multiple A/AAAA records can fall back
    /// through each of them instead of pinning to the first. The default
    /// returns just [`Self::resolve_host`]; hosts that can enumerate every
    /// record override this.
    fn resolve_host_all(&self, host: &str, port: u16) -> alloc::vec::Vec<NetAddr> {
        match self.resolve_host(host, port) {
            Some(a) => alloc::vec![a],
            None => alloc::vec![],
        }
    }

    // ---------- async DNS (non-blocking DHT bootstrap) ----------

    /// Enqueue an asynchronous hostname resolution; returns `true` when the
    /// host accepts it (the result arrives via [`Self::take_resolved_hosts`]).
    /// The default is `false`, so callers fall back to the blocking
    /// [`Self::resolve_host`]. Used for DHT bootstrap seeds — the engine
    /// must never block its thread on DNS.
    fn resolve_host_async(&mut self, _host: &str, _port: u16) -> bool {
        false
    }

    /// Drain completed async resolutions as `(host, port, addr)`.
    fn take_resolved_hosts(&mut self) -> alloc::vec::Vec<(alloc::string::String, u16, NetAddr)> {
        alloc::vec::Vec::new()
    }

    // ---------- TCP peers ----------

    /// Begin a non-blocking connect to `addr`. Returns a handle immediately.
    fn tcp_connect(&mut self, addr: &NetAddr) -> Result<ConnId>;

    /// Poll a pending connect. `Ok(())` = established, `Err(WouldBlock)` =
    /// still in progress, any other error = connection failed.
    fn tcp_connect_done(&mut self, id: ConnId) -> Result<()>;

    /// Send up to `data.len()` bytes (non-blocking). Returns bytes accepted.
    fn tcp_send(&mut self, id: ConnId, data: &[u8]) -> Result<usize>;

    /// Receive into `buf` (non-blocking). `Err(WouldBlock)` = no data.
    fn tcp_recv(&mut self, id: ConnId, buf: &mut [u8]) -> Result<usize>;

    /// Close a connection and free the handle.
    fn tcp_close(&mut self, id: ConnId);

    /// Socket receive buffer size hint (bytes) so the engine can size its
    /// read buffers.
    fn tcp_recv_buf_size(&self) -> usize {
        64 * 1024
    }

    // ---------- UDP (DHT, UDP trackers) ----------

    /// Open the UDP socket for outgoing+incoming datagrams (DHT / UDP tracker).
    fn udp_open(&mut self, port: u16) -> Result<()>;

    /// Send one datagram.
    fn udp_send(&mut self, addr: &NetAddr, data: &[u8]) -> Result<()>;

    /// Send one datagram to a multicast group (used by SSDP discovery and
    /// LSD, BEP-14). The default routes through [`Self::udp_send`];
    /// platforms that need multicast options (TTL/interface) override this.
    fn udp_multicast_send(&mut self, addr: &NetAddr, data: &[u8]) -> Result<()> {
        self.udp_send(addr, data)
    }

    /// Join a multicast group on the UDP socket so datagrams sent to the
    /// group are delivered to [`Self::udp_recv`] (SSDP responses, LSD
    /// announces, BEP-14). Default is a no-op; hosts that support multicast
    /// membership override this. Best-effort: failure to join is not fatal.
    fn udp_join_multicast(&mut self, addr: NetAddr) -> Result<()> {
        let _ = addr;
        Ok(())
    }

    /// Send one datagram to a multicast group **from the dedicated LSD
    /// socket** (BEP-14). Sending from the port-6771 socket makes the
    /// announce/reply flow symmetric: a neighbour's unicast reply comes back
    /// to 6771 (the socket that is always drained for LSD), instead of
    /// depending on the shared BT-port socket. Falls back to the shared
    /// socket when no dedicated LSD socket exists.
    fn udp_multicast_send_lsd(&mut self, addr: &NetAddr, data: &[u8]) -> Result<()> {
        self.udp_multicast_send(addr, data)
    }

    /// Receive one datagram (non-blocking). `Err(WouldBlock)` = none pending.
    fn udp_recv(&mut self, buf: &mut [u8]) -> Result<(NetAddr, usize)>;

    // ---------- LSD (BEP-14) dedicated socket ----------

    /// Open a dedicated LSD (BEP-14) UDP socket bound to the fixed multicast
    /// port ([`crate::lsd::LSD_PORT`]). The shared [`Self::udp_open`] socket
    /// is bound to the BT listen port, so multicast datagrams addressed to
    /// `239.192.152.143:6771` are NEVER delivered to it — LSD must listen on
    /// port 6771 to receive LAN announces (the "local peer never appears"
    /// bug). Default: `NotSupported` (LSD receive disabled; outgoing
    /// announces and unicast replies still work via the shared socket).
    fn udp_open_lsd(&mut self, _port: u16) -> Result<()> {
        Err(Error::NotSupported)
    }

    /// Join the LSD multicast group on the dedicated LSD socket. Default
    /// no-op; hosts without a dedicated socket leave it a no-op.
    fn udp_join_multicast_lsd(&mut self, _addr: NetAddr) -> Result<()> {
        Ok(())
    }

    /// Receive one datagram on the dedicated LSD socket (non-blocking).
    /// Default: `WouldBlock` (no dedicated socket).
    fn udp_recv_lsd(&mut self, _buf: &mut [u8]) -> Result<(NetAddr, usize)> {
        Err(Error::WouldBlock)
    }

    /// Close the dedicated LSD socket. Default no-op.
    fn udp_close_lsd(&mut self) {}

    // ---------- Disk ----------

    /// Open (create if missing) a file by path. Returns a handle.
    fn disk_open(&mut self, path: &str) -> Result<DiskId>;

    /// Read up to `buf.len()` bytes at `offset`.
    fn disk_read(&mut self, id: DiskId, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Write `data` at `offset`.
    fn disk_write(&mut self, id: DiskId, offset: u64, data: &[u8]) -> Result<()>;

    /// Pre-allocate `size` bytes (sparse where supported) — avoids
    /// fragmentation and reduces per-piece allocation churn.
    fn disk_prealloc(&mut self, id: DiskId, size: u64) -> Result<()>;

    /// Record the allocation strategy for a freshly-opened file before
    /// [`Host::disk_prealloc`]: 0 = off, 1 = sparse, 2 = full. Hosts may
    /// ignore the hint (the default no-op keeps custom hosts
    /// source-compatible); the native Windows host uses it to mark sparse
    /// files so reserved extents do not consume real disk space.
    fn disk_set_alloc(&mut self, _id: DiskId, _mode: u8) -> Result<()> {
        Ok(())
    }

    /// Flush buffered writes for this file to stable storage.
    fn disk_flush(&mut self, id: DiskId) -> Result<()>;

    /// Close a file.
    fn disk_close(&mut self, id: DiskId);
}
