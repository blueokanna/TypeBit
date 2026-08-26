//! SOCKS5 (RFC 1928) + username/password auth (RFC 1929) transport — the
//! anonymity seam for **Tor** (SOCKS5h :9050) and **I2P** (SOCKS :4444).
//! `no_std`, depends only on [`crate::platform`] + [`crate::error`].
//!
//! Two entry points, one codec: [`Socks5Client`] — a non-blocking handshake
//! state machine for every outbound peer; [`socks_http_get`] — a blocking
//! HTTP GET through the proxy (domain resolved by the proxy) for trackers.
//!
//! When a proxy is configured the engine enforces: no inbound, no DHT, no
//! UDP trackers, no port mapping, listen port 0.

use crate::error::{Error, Result};
use crate::platform::{ConnId, Host, NetAddr};
use alloc::string::String;
use alloc::vec::Vec;

// RFC 1928 constants
const SOCKS5: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const METHOD_NOAUTH: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_NONE: u8 = 0xFF;
// RFC 1929
const AUTH_VER: u8 = 0x01;

/// Hard cap on a proxied HTTP response body (memory bound).
const MAX_HTTP_BODY: usize = 4 * 1024 * 1024;
/// Hard cap on the SOCKS reply bytes buffered at once. The largest legal
/// reply is a CONNECT reply carrying a 255-byte domain: 4 + 1 + 255 + 2 =
/// 262 bytes. Anything beyond that is a hostile or broken proxy and is
/// rejected instead of growing the buffer without bound.
const MAX_SOCKS_FRAME: usize = 1024;
/// Read budget per [`Socks5Client::pump`] call, so a proxy streaming bytes
/// can neither exhaust memory nor stall the engine tick indefinitely; the
/// engine re-invokes `pump` next tick.
const MAX_SOCKS_READ_PER_PUMP: usize = 8 * 1024;

/// Where a SOCKS5 CONNECT should reach.
///
/// Peers are always IP-addressed; tracker announces use [`SocksTarget::Domain`]
/// so the **proxy** performs the DNS lookup (SOCKS5h) and the client never
/// issues a cleartext DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksTarget {
    /// A numeric endpoint.
    Ip(NetAddr),
    /// A hostname (`.i2p`, `.onion`, or any DNS name) + port.
    Domain(Vec<u8>, u16),
}

/// SOCKS5 proxy configuration.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Proxy endpoint. Tor: `127.0.0.1:9050`; I2P SOCKS: `127.0.0.1:4444`.
    pub socks5: NetAddr,
    /// Optional RFC 1929 credentials (username/password auth).
    pub username: Option<String>,
    /// Optional RFC 1929 password.
    pub password: Option<String>,
    /// Deadline for the whole SOCKS handshake, in ms.
    pub handshake_timeout_ms: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            socks5: NetAddr::V4([127, 0, 0, 1], 9050),
            username: None,
            password: None,
            handshake_timeout_ms: 30_000,
        }
    }
}

/// Outcome of one [`Socks5Client::pump`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksStatus {
    /// Handshake still in progress (needs more ticks).
    InProgress,
    /// Handshake completed; the connection is a plain pipe to the target.
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocksPhase {
    SendGreeting,
    RecvMethod,
    SendAuth,
    RecvAuth,
    SendConnect,
    RecvReply,
    Done,
}

/// Non-blocking SOCKS5 handshake state machine.
///
/// The engine owns one of these per outbound connection while the TCP
/// socket is connected to the *proxy*. Call [`Socks5Client::pump`] every
/// tick (it sends whatever the socket accepts and consumes whatever reply
/// bytes have arrived). Partial frames and partial sends are handled
/// internally; the caller only checks the returned status and
/// [`Socks5Client::timed_out`].
#[derive(Debug)]
pub struct Socks5Client {
    target: SocksTarget,
    cfg: ProxyConfig,
    phase: SocksPhase,
    /// Bytes of the current outbound frame yet to send.
    out: Vec<u8>,
    /// Write cursor into `out`.
    out_off: usize,
    /// Bytes received for the current reply frame.
    rx: Vec<u8>,
    /// Absolute deadline (ms) for the whole handshake.
    deadline: u64,
}

impl Socks5Client {
    /// Start a handshake toward `target` through `cfg`. The greeting is
    /// pre-buffered; the first [`Socks5Client::pump`] sends it.
    pub fn new(target: &SocksTarget, cfg: &ProxyConfig, now: u64) -> Self {
        let mut methods: Vec<u8> = vec![METHOD_NOAUTH];
        if cfg.username.is_some() {
            methods.push(METHOD_USERPASS);
        }
        let mut out = vec![SOCKS5, methods.len() as u8];
        out.extend_from_slice(&methods);
        Socks5Client {
            target: target.clone(),
            cfg: cfg.clone(),
            phase: SocksPhase::SendGreeting,
            out,
            out_off: 0,
            rx: Vec::new(),
            deadline: now.saturating_add(cfg.handshake_timeout_ms),
        }
    }

    /// Whether the handshake finished successfully.
    pub fn done(&self) -> bool {
        self.phase == SocksPhase::Done
    }

    /// Whether the handshake deadline has passed.
    pub fn timed_out(&self, now: u64) -> bool {
        now > self.deadline
    }

    /// Drive the handshake: send what the socket accepts, consume what has
    /// arrived, and advance the state machine. Never blocks and never
    /// processes unbounded input in one call (a hostile proxy cannot stall
    /// the engine or exhaust memory).
    pub fn pump<H: Host>(&mut self, host: &mut H, conn: ConnId, now: u64) -> Result<SocksStatus> {
        if self.done() {
            return Ok(SocksStatus::Done);
        }
        if self.timed_out(now) {
            return Err(Error::Timeout);
        }
        loop {
            if self.timed_out(now) {
                return Err(Error::Timeout);
            }
            let phase_before = self.phase;
            let mut sent_any = false;
            while self.out_off < self.out.len() {
                match host.tcp_send(conn, &self.out[self.out_off..]) {
                    Ok(0) | Err(Error::WouldBlock) => break,
                    Ok(n) => {
                        self.out_off += n;
                        sent_any = true;
                    }
                    Err(e) => return Err(e),
                }
            }
            if !self.out.is_empty() && self.out_off >= self.out.len() {
                self.after_send();
                if self.consume_frame()? {
                    return Ok(SocksStatus::Done);
                }
            }
            let mut buf = [0u8; 512];
            let mut recv_any = false;
            let mut read_budget = MAX_SOCKS_READ_PER_PUMP;
            while read_budget > 0 {
                let want = core::cmp::min(buf.len(), read_budget);
                match host.tcp_recv(conn, &mut buf[..want]) {
                    Ok(0) => break,
                    Ok(n) => {
                        read_budget -= n;
                        recv_any = true;
                        if self.rx.len().saturating_add(n) > MAX_SOCKS_FRAME {
                            return Err(Error::Protocol);
                        }
                        self.rx.extend_from_slice(&buf[..n]);
                        if self.consume_frame()? {
                            return Ok(SocksStatus::Done);
                        }
                    }
                    Err(Error::WouldBlock) => break,
                    Err(e) => return Err(e),
                }
            }
            if !sent_any && !recv_any && self.phase == phase_before {
                return Ok(SocksStatus::InProgress);
            }
            if self.done() {
                return Ok(SocksStatus::Done);
            }
        }
    }

    /// The outbound frame was fully sent: move to the matching receive phase.
    fn after_send(&mut self) {
        match self.phase {
            SocksPhase::SendGreeting => self.phase = SocksPhase::RecvMethod,
            SocksPhase::SendAuth => self.phase = SocksPhase::RecvAuth,
            SocksPhase::SendConnect => self.phase = SocksPhase::RecvReply,
            _ => {}
        }
        self.out.clear();
        self.out_off = 0;
    }

    /// Process one (possibly partial) reply frame, consuming only the bytes
    /// of that frame (trailing bytes belong to a later frame). Returns
    /// `true` when the whole handshake is done.
    fn consume_frame(&mut self) -> Result<bool> {
        match self.phase {
            SocksPhase::RecvMethod => {
                if self.rx.len() < 2 {
                    return Ok(false);
                }
                if self.rx[0] != SOCKS5 {
                    return Err(Error::Protocol);
                }
                match self.rx[1] {
                    METHOD_NOAUTH => self.build_connect(),
                    METHOD_USERPASS if self.cfg.username.is_some() => self.build_auth(),
                    METHOD_NONE => return Err(Error::Handshake),
                    _ => return Err(Error::Handshake),
                }
                self.rx.drain(..2);
                Ok(false)
            }
            SocksPhase::RecvAuth => {
                if self.rx.len() < 2 {
                    return Ok(false);
                }
                if self.rx[0] != AUTH_VER || self.rx[1] != 0 {
                    return Err(Error::Handshake);
                }
                self.build_connect();
                self.rx.drain(..2);
                Ok(false)
            }
            SocksPhase::RecvReply => {
                if self.rx.len() < 4 {
                    return Ok(false);
                }
                if self.rx[0] != SOCKS5 {
                    return Err(Error::Protocol);
                }
                if self.rx[1] != 0 {
                    return Err(Error::Handshake);
                }
                let atyp = self.rx[3];
                let extra = match atyp {
                    ATYP_IPV4 => 6,
                    ATYP_IPV6 => 18,
                    ATYP_DOMAIN => {
                        if self.rx.len() < 5 {
                            return Ok(false);
                        }
                        1 + self.rx[4] as usize + 2
                    }
                    _ => return Err(Error::Protocol),
                };
                if self.rx.len() < 4 + extra {
                    return Ok(false);
                }
                self.rx.drain(..4 + extra);
                self.phase = SocksPhase::Done;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Queue the RFC 1929 auth frame.
    fn build_auth(&mut self) {
        let user = self.cfg.username.as_deref().unwrap_or("");
        let pass = self.cfg.password.as_deref().unwrap_or("");
        let ulen = user.len().min(255);
        let plen = pass.len().min(255);
        let mut out = Vec::with_capacity(3 + ulen + plen);
        out.push(AUTH_VER);
        out.push(ulen as u8);
        out.extend_from_slice(&user.as_bytes()[..ulen]);
        out.push(plen as u8);
        out.extend_from_slice(&pass.as_bytes()[..plen]);
        self.out = out;
        self.out_off = 0;
        self.phase = SocksPhase::SendAuth;
    }

    /// Queue the CONNECT frame for the target.
    fn build_connect(&mut self) {
        let mut out = vec![SOCKS5, CMD_CONNECT, 0];
        match &self.target {
            SocksTarget::Ip(NetAddr::V4(ip, port)) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(ip);
                out.extend_from_slice(&port.to_be_bytes());
            }
            SocksTarget::Ip(NetAddr::V6(ip, port)) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(ip);
                out.extend_from_slice(&port.to_be_bytes());
            }
            SocksTarget::Domain(host, port) => {
                let n = host.len().min(255);
                out.push(ATYP_DOMAIN);
                out.push(n as u8);
                out.extend_from_slice(&host[..n]);
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
        self.out = out;
        self.out_off = 0;
        self.phase = SocksPhase::SendConnect;
    }
}

// ---------------------------------------------------------------------------
// Blocking HTTP/1.1 GET through the proxy (tracker announces)
// ---------------------------------------------------------------------------

/// Perform a blocking HTTP GET to `url` *through* the SOCKS5 proxy.
///
/// The hostname is handed to the proxy (SOCKS5h), so the client never
/// performs a cleartext DNS lookup. `https://` is rejected: this crate has
/// no TLS stack, so routing HTTPS through the proxy would be a false sense
/// of security — the caller should use `http://` trackers while proxied.
///
/// Bounded by `timeout_ms` (whole operation) and a fixed body cap. On any
/// failure the connection is closed before returning.
pub fn socks_http_get<H: Host>(
    host: &mut H,
    cfg: &ProxyConfig,
    url: &str,
    timeout_ms: u64,
    out: &mut Vec<u8>,
) -> Result<()> {
    socks_http_get_impl(host, cfg, url, None, timeout_ms, out)
}

/// Perform a blocking HTTP GET with a `Range: bytes=start-end` header
/// *through* the SOCKS5 proxy. Used by web seeds (BEP-19) so piece data is
/// never fetched from the real IP in proxy mode. The response body must be
/// exactly `end - start + 1` bytes, otherwise `Err(Protocol)`.
pub fn socks_http_get_range<H: Host>(
    host: &mut H,
    cfg: &ProxyConfig,
    url: &str,
    range_start: u64,
    range_end: u64,
    timeout_ms: u64,
    out: &mut Vec<u8>,
) -> Result<()> {
    socks_http_get_impl(
        host,
        cfg,
        url,
        Some((range_start, range_end)),
        timeout_ms,
        out,
    )
}

fn socks_http_get_impl<H: Host>(
    host: &mut H,
    cfg: &ProxyConfig,
    url: &str,
    range: Option<(u64, u64)>,
    timeout_ms: u64,
    out: &mut Vec<u8>,
) -> Result<()> {
    let deadline = host.now_ms().saturating_add(timeout_ms);
    let parts = parse_http_url(url)?;
    let conn = host.tcp_connect(&cfg.socks5)?;
    let result = run_http_get(host, conn, cfg, &parts, range, deadline, out);
    host.tcp_close(conn);
    result
}

/// Parsed `http://` URL pieces for one proxied request.
#[derive(Debug)]
struct HttpUrl {
    target: SocksTarget,
    host: Vec<u8>,
    path: Vec<u8>,
}

fn run_http_get<H: Host>(
    host: &mut H,
    conn: ConnId,
    cfg: &ProxyConfig,
    url: &HttpUrl,
    range: Option<(u64, u64)>,
    deadline: u64,
    out: &mut Vec<u8>,
) -> Result<()> {
    let mut client = Socks5Client::new(&url.target, cfg, host.now_ms());
    loop {
        if host.now_ms() > deadline {
            return Err(Error::Timeout);
        }
        match host.tcp_connect_done(conn) {
            Ok(()) => break,
            Err(Error::WouldBlock) => {}
            Err(_) => return Err(Error::Io),
        }
        if host.now_ms() > deadline {
            return Err(Error::Timeout);
        }
        match client.pump(host, conn, host.now_ms()) {
            Ok(SocksStatus::Done) => return Err(Error::Internal),
            Ok(SocksStatus::InProgress) => {}
            Err(e) => return Err(e),
        }
    }
    while !client.done() {
        if host.now_ms() > deadline {
            return Err(Error::Timeout);
        }
        match client.pump(host, conn, host.now_ms()) {
            Ok(SocksStatus::Done) => break,
            Ok(SocksStatus::InProgress) => {}
            Err(e) => return Err(e),
        }
    }
    let req = build_http_get(&url.host, &url.path, range);
    let mut off = 0usize;
    while off < req.len() {
        if host.now_ms() > deadline {
            return Err(Error::Timeout);
        }
        match host.tcp_send(conn, &req[off..]) {
            Ok(0) | Err(Error::WouldBlock) => {}
            Ok(n) => off += n,
            Err(e) => return Err(e),
        }
    }
    let mut resp: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if host.now_ms() > deadline {
            return Err(Error::Timeout);
        }
        match host.tcp_recv(conn, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if resp.len().saturating_add(n) > MAX_HTTP_BODY {
                    return Err(Error::TooLarge);
                }
                resp.extend_from_slice(&buf[..n]);
            }
            Err(Error::WouldBlock) => {}
            Err(e) => return Err(e),
        }
    }
    parse_http_body(&resp, out)?;
    if let Some((start, end)) = range {
        // A web seed MUST honor the range; a mismatched body would corrupt
        // the piece, so refuse it instead of accepting wrong data.
        let want = end.saturating_sub(start).saturating_add(1) as usize;
        if out.len() != want {
            return Err(Error::Protocol);
        }
    }
    Ok(())
}

/// Split `http://host[:port]/path` into a parsed [`HttpUrl`].
/// Rejects `https://` (no TLS in-crate), userinfo, non-ASCII, and any CR/LF
/// (header-injection hardening).
fn parse_http_url(url: &str) -> Result<HttpUrl> {
    let rest = url.strip_prefix("http://").ok_or(Error::NotSupported)?; // https:// and anything else
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().map_err(|_| Error::InvalidInput)?;
            (h, port)
        }
        None => (authority, 80),
    };
    if host.is_empty()
        || host.len() > 255
        || host.contains('@')
        || !host.is_ascii()
        || path.as_bytes().iter().any(|&b| b == b'\r' || b == b'\n')
    {
        return Err(Error::InvalidInput);
    }
    let host_b = host.as_bytes().to_vec();
    let path_b = path.as_bytes().to_vec();
    Ok(HttpUrl {
        target: SocksTarget::Domain(host_b.clone(), port),
        host: host_b,
        path: path_b,
    })
}

fn build_http_get(host: &[u8], path: &[u8], range: Option<(u64, u64)>) -> Vec<u8> {
    let mut req = Vec::with_capacity(96 + host.len() + path.len());
    req.extend_from_slice(b"GET ");
    req.extend_from_slice(path);
    req.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    req.extend_from_slice(host);
    if let Some((start, end)) = range {
        req.extend_from_slice(b"\r\nRange: bytes=");
        push_u64(&mut req, start);
        req.push(b'-');
        push_u64(&mut req, end);
    }
    req.extend_from_slice(
        b"\r\nUser-Agent: TypeBit/0.1\r\nConnection: close\r\nAccept: */*\r\n\r\n",
    );
    req
}

/// Append a u64 in decimal (no allocation, no `core` formatting dependency).
fn push_u64(out: &mut Vec<u8>, mut v: u64) {
    if v == 0 {
        out.push(b'0');
        return;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0;
    while v > 0 {
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        out.push(tmp[i]);
    }
}

/// Parse an HTTP/1.x response: status check (2xx), Content-Length or
/// chunked body decoding. Appends the body to `out`.
fn parse_http_body(resp: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let head_end = find_subslice(resp, b"\r\n\r\n").ok_or(Error::Protocol)?;
    let head = &resp[..head_end];
    let body = &resp[head_end + 4..];
    let line_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let status = trim_cr(&head[..line_end]);
    if !status.starts_with(b"HTTP/") {
        return Err(Error::Protocol);
    }
    let code = parse_status_code(status)?;
    if !(200..300).contains(&code) {
        return Err(Error::Tracker);
    }
    let mut chunked = false;
    let mut content_len: Option<usize> = None;
    for line in head[line_end + 1..].split(|&b| b == b'\n') {
        let line = trim_cr(line);
        if let Some(v) = line.strip_prefix(b"Transfer-Encoding:") {
            if contains_ignore_case(v, b"chunked") {
                chunked = true;
            }
        } else if let Some(v) = line.strip_prefix(b"Content-Length:") {
            content_len = parse_usize(trim_spaces(v));
        }
    }
    if chunked {
        decode_chunked(body, out)
    } else if let Some(n) = content_len {
        if body.len() < n {
            return Err(Error::Protocol); // truncated body (connection closed early)
        }
        out.extend_from_slice(&body[..n]);
        Ok(())
    } else {
        out.extend_from_slice(body);
        Ok(())
    }
}

fn parse_status_code(status: &[u8]) -> Result<u32> {
    let mut it = status.split(|&b| b == b' ');
    let _ver = it.next().ok_or(Error::Protocol)?;
    let code_s = it.next().ok_or(Error::Protocol)?;
    let mut code = 0u32;
    if code_s.len() != 3 {
        return Err(Error::Protocol);
    }
    for &b in code_s {
        if !b.is_ascii_digit() {
            return Err(Error::Protocol);
        }
        code = code * 10 + (b - b'0') as u32;
    }
    Ok(code)
}

/// Minimal chunked transfer decoding (`1f;ext\r\n<data>\r\n0\r\n\r\n`).
fn decode_chunked(mut body: &[u8], out: &mut Vec<u8>) -> Result<()> {
    loop {
        let line_end = body
            .iter()
            .position(|&b| b == b'\n')
            .ok_or(Error::Protocol)?;
        let line = trim_cr(&body[..line_end]);
        let size_end = line.iter().position(|&b| b == b';').unwrap_or(line.len());
        let hex = core::str::from_utf8(&line[..size_end]).map_err(|_| Error::Protocol)?;
        let size = usize::from_str_radix(hex, 16).map_err(|_| Error::Protocol)?;
        body = &body[line_end + 1..];
        if size == 0 {
            return Ok(());
        }
        if body.len() < size {
            return Err(Error::Protocol);
        }
        if out.len().saturating_add(size) > MAX_HTTP_BODY {
            return Err(Error::TooLarge);
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size..];
        if body.len() < 2 {
            return Err(Error::Protocol); // chunk-data CRLF
        }
        body = &body[2..];
    }
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn trim_spaces(mut s: &[u8]) -> &[u8] {
    while let Some((f, rest)) = s.split_first() {
        if *f == b' ' || *f == b'\t' {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn contains_ignore_case(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

fn parse_usize(s: &[u8]) -> Option<usize> {
    let s = s.strip_prefix(b"+").unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    let mut v = 0usize;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    Some(v)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::LogLevel;

    /// A scripted non-blocking host: returns queued bytes, accepts all sends.
    struct ScriptHost {
        now: u64,
        recv_queue: Vec<Vec<u8>>,
        sent: Vec<u8>,
        connected: bool,
        send_fail: Option<Error>,
        recv_fail: Option<Error>,
    }

    impl ScriptHost {
        fn new() -> Self {
            ScriptHost {
                now: 0,
                recv_queue: Vec::new(),
                sent: Vec::new(),
                connected: true,
                send_fail: None,
                recv_fail: None,
            }
        }
    }

    impl Host for ScriptHost {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn fill_random(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = 0x5a;
            }
        }
        fn log(&mut self, _l: LogLevel, _m: &str) {}
        fn http_get(&mut self, _url: &str, _t: u64, _out: &mut Vec<u8>) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn tcp_connect(&mut self, _a: &NetAddr) -> Result<ConnId> {
            Ok(7)
        }
        fn tcp_connect_done(&mut self, _id: ConnId) -> Result<()> {
            if self.connected {
                Ok(())
            } else {
                Err(Error::WouldBlock)
            }
        }
        fn tcp_send(&mut self, _id: ConnId, data: &[u8]) -> Result<usize> {
            if let Some(e) = self.send_fail {
                return Err(e);
            }
            self.sent.extend_from_slice(data);
            Ok(data.len())
        }
        fn tcp_recv(&mut self, _id: ConnId, buf: &mut [u8]) -> Result<usize> {
            if let Some(e) = self.recv_fail {
                return Err(e);
            }
            if let Some(q) = self.recv_queue.first_mut() {
                let n = core::cmp::min(buf.len(), q.len());
                buf[..n].copy_from_slice(&q[..n]);
                if n == q.len() {
                    self.recv_queue.remove(0);
                } else {
                    q.drain(..n);
                }
                return Ok(n);
            }
            Err(Error::WouldBlock)
        }
        fn tcp_close(&mut self, _id: ConnId) {}
        fn udp_open(&mut self, _p: u16) -> Result<()> {
            Ok(())
        }
        fn udp_send(&mut self, _a: &NetAddr, _d: &[u8]) -> Result<()> {
            Ok(())
        }
        fn udp_recv(&mut self, _b: &mut [u8]) -> Result<(NetAddr, usize)> {
            Err(Error::WouldBlock)
        }
        fn disk_open(&mut self, _p: &str) -> Result<u32> {
            Ok(1)
        }
        fn disk_read(&mut self, _id: u32, _o: u64, _b: &mut [u8]) -> Result<usize> {
            Err(Error::NotSupported)
        }
        fn disk_write(&mut self, _id: u32, _o: u64, _d: &[u8]) -> Result<()> {
            Ok(())
        }
        fn disk_prealloc(&mut self, _id: u32, _s: u64) -> Result<()> {
            Ok(())
        }
        fn disk_flush(&mut self, _id: u32) -> Result<()> {
            Ok(())
        }
        fn disk_close(&mut self, _id: u32) {}
        fn tcp_recv_buf_size(&self) -> usize {
            4096
        }
    }

    fn target() -> SocksTarget {
        SocksTarget::Ip(NetAddr::V4([198, 51, 100, 7], 6881))
    }

    fn noauth_cfg() -> ProxyConfig {
        ProxyConfig {
            socks5: NetAddr::V4([127, 0, 0, 1], 9050),
            username: None,
            password: None,
            handshake_timeout_ms: 5000,
        }
    }

    #[test]
    fn greeting_then_connect_noauth() {
        let mut h = ScriptHost::new();
        // proxy replies: method=noauth, then CONNECT ok with ipv4 bind
        h.recv_queue = vec![
            vec![SOCKS5, METHOD_NOAUTH],
            vec![SOCKS5, 0, 0, ATYP_IPV4, 1, 2, 3, 4, 0x1f, 0x90],
        ];
        let mut c = Socks5Client::new(&target(), &noauth_cfg(), 0);
        let st = c.pump(&mut h, 7, 0).unwrap();
        assert_eq!(st, SocksStatus::Done);
        assert!(c.done());
        // greeting (3 bytes) + connect (4 + 4 + 2 = 10 bytes)
        assert_eq!(
            h.sent,
            vec![
                SOCKS5,
                1,
                METHOD_NOAUTH,
                SOCKS5,
                CMD_CONNECT,
                0,
                ATYP_IPV4,
                198,
                51,
                100,
                7,
                0x1a,
                0xe1
            ]
        );
    }

    #[test]
    fn partial_frames_resume_across_pumps() {
        let mut h = ScriptHost::new();
        let mut c = Socks5Client::new(&target(), &noauth_cfg(), 0);
        // pump 1: sends the greeting, nothing to receive yet
        assert_eq!(c.pump(&mut h, 7, 0).unwrap(), SocksStatus::InProgress);
        h.recv_queue.push(vec![SOCKS5]); // first byte of the method reply
        assert_eq!(c.pump(&mut h, 7, 0).unwrap(), SocksStatus::InProgress);
        h.recv_queue.push(vec![METHOD_NOAUTH]); // completes it → queues CONNECT
        assert_eq!(c.pump(&mut h, 7, 0).unwrap(), SocksStatus::InProgress);
        h.recv_queue.push(vec![SOCKS5, 0, 0, ATYP_IPV4, 1, 2, 3, 4]); // partial reply
        assert_eq!(c.pump(&mut h, 7, 0).unwrap(), SocksStatus::InProgress);
        h.recv_queue.push(vec![0x1f, 0x90]); // remaining port bytes
        assert_eq!(c.pump(&mut h, 7, 0).unwrap(), SocksStatus::Done);
        assert!(c.done());
    }

    #[test]
    fn userpass_auth_flow() {
        let mut cfg = noauth_cfg();
        cfg.username = Some(String::from("alice"));
        cfg.password = Some(String::from("s3cret"));
        let mut h = ScriptHost::new();
        h.recv_queue = vec![
            vec![SOCKS5, METHOD_USERPASS],
            vec![AUTH_VER, 0], // auth ok
            vec![SOCKS5, 0, 0, ATYP_IPV4, 0, 0, 0, 0, 1, 0xbb],
        ];
        let mut c = Socks5Client::new(&target(), &cfg, 0);
        assert_eq!(c.pump(&mut h, 7, 0).unwrap(), SocksStatus::Done);
        // greeting advertises both methods
        assert_eq!(
            &h.sent[..3],
            &[SOCKS5, 2, METHOD_NOAUTH, METHOD_USERPASS][..3]
        );
        assert!(h.sent.windows(7).any(|w| w == b"\x01\x05alice"));
        assert!(h.sent.windows(7).any(|w| w == b"\x06s3cret"));
    }

    #[test]
    fn proxy_refuses_connect() {
        let mut h = ScriptHost::new();
        h.recv_queue = vec![
            vec![SOCKS5, METHOD_NOAUTH],
            vec![SOCKS5, 1, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0],
        ];
        let mut c = Socks5Client::new(&target(), &noauth_cfg(), 0);
        assert_eq!(c.pump(&mut h, 7, 0).unwrap_err(), Error::Handshake);
    }

    #[test]
    fn no_acceptable_method() {
        let mut h = ScriptHost::new();
        h.recv_queue = vec![vec![SOCKS5, METHOD_NONE]];
        let mut c = Socks5Client::new(&target(), &noauth_cfg(), 0);
        assert_eq!(c.pump(&mut h, 7, 0).unwrap_err(), Error::Handshake);
    }

    #[test]
    fn domain_connect_frame() {
        let mut h = ScriptHost::new();
        h.recv_queue = vec![
            vec![SOCKS5, METHOD_NOAUTH],
            vec![
                SOCKS5,
                0,
                0,
                ATYP_DOMAIN,
                5,
                b'h',
                b'e',
                b'l',
                b'l',
                b'o',
                0x01,
                0xbb,
            ],
        ];
        let t = SocksTarget::Domain(b"hello".to_vec(), 443);
        let mut c = Socks5Client::new(&t, &noauth_cfg(), 0);
        assert_eq!(c.pump(&mut h, 7, 0).unwrap(), SocksStatus::Done);
        // connect frame: 5,1,0,3,5,'hello',0x01,0xbb
        let expect = vec![
            SOCKS5,
            CMD_CONNECT,
            0,
            ATYP_DOMAIN,
            5,
            b'h',
            b'e',
            b'l',
            b'l',
            b'o',
            0x01,
            0xbb,
        ];
        assert!(h.sent.ends_with(&expect));
    }

    #[test]
    fn timeout_detected() {
        let mut h = ScriptHost::new();
        h.recv_queue = vec![vec![SOCKS5, METHOD_NOAUTH]]; // reply stalls after method
        let mut c = Socks5Client::new(&target(), &noauth_cfg(), 0);
        let _ = c.pump(&mut h, 7, 0);
        h.now = 6000;
        // the CONNECT reply never arrives → deadline passed
        assert!(c.timed_out(h.now));
        let now = h.now;
        assert_eq!(c.pump(&mut h, 7, now).unwrap_err(), Error::Timeout);
    }

    #[test]
    fn hostile_proxy_stream_is_rejected() {
        let mut h = ScriptHost::new();
        // a malicious/broken proxy streams arbitrary bytes instead of a
        // well-formed reply — the buffer cap must reject it rather than
        // growing without bound.
        h.recv_queue.push(vec![SOCKS5, METHOD_NOAUTH]);
        h.recv_queue.push(vec![0xEE; 4096]);
        let mut c = Socks5Client::new(&target(), &noauth_cfg(), 0);
        let r = c.pump(&mut h, 7, 0);
        assert_eq!(r.unwrap_err(), Error::Protocol);
    }

    #[test]
    fn parse_url_and_injection_hardening() {
        let p = parse_http_url("http://tracker.example.com:8080/announce?x=1").unwrap();
        assert_eq!(p.host, b"tracker.example.com");
        assert_eq!(p.path, b"/announce?x=1");
        assert_eq!(
            p.target,
            SocksTarget::Domain(b"tracker.example.com".to_vec(), 8080)
        );
        // https is rejected (no TLS in-crate)
        assert_eq!(
            parse_http_url("https://tracker.example.com/announce").unwrap_err(),
            Error::NotSupported
        );
        // CRLF injection is rejected
        assert!(parse_http_url("http://a.example.com/\r\nX-Evil: 1").is_err());
        // non-ascii host rejected
        assert!(parse_http_url("http://\u{4e2d}.com/").is_err());
        // userinfo rejected
        assert!(parse_http_url("http://user@example.com/").is_err());
    }

    #[test]
    fn http_body_parsing() {
        let mut out = Vec::new();
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        parse_http_body(resp, &mut out).unwrap();
        assert_eq!(out, b"hello");

        out.clear();
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        parse_http_body(resp, &mut out).unwrap();
        assert_eq!(out, b"hello");

        // non-2xx rejected
        out.clear();
        let resp = b"HTTP/1.1 404 Not Found\r\n\r\nnope";
        assert_eq!(parse_http_body(resp, &mut out).unwrap_err(), Error::Tracker);

        // truncated content-length rejected
        out.clear();
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhi";
        assert_eq!(
            parse_http_body(resp, &mut out).unwrap_err(),
            Error::Protocol
        );
    }
}
