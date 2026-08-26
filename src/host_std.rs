//! OS-backed [`Host`] for desktop/server builds (feature `std`).
//!
//! Complete runnable host: HTTP via `courierust` (tracker, web seeds),
//! non-blocking TCP peers, a UDP socket (DHT + UDP trackers), file-backed
//! disk I/O. All sockets non-blocking so the engine thread never stalls;
//! `Err(WouldBlock)` maps to `io::ErrorKind::WouldBlock` (plus the
//! transient Windows UDP `ConnectionReset` quirk).

use crate::platform::{ConnId, DiskId};
use crate::{Error, Host, LogLevel, NetAddr};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, ToSocketAddrs, UdpSocket,
};

/// Hard cap on a full HTTP response body collected by [`Host::http_get`]
/// (tracker announces, tracker lists, UPnP device descriptions). A tracker
/// is an untrusted network peer; without this bound a hostile tracker (or
/// a MITM on plaintext HTTP) could stream an unbounded body and exhaust
/// memory (CWE-770). Real tracker responses with hundreds of peers are
/// a few KB; even the community tracker list is well under 1 MiB.
const MAX_HTTP_BODY: usize = 4 * 1024 * 1024;

/// Map an engine endpoint onto a std socket address.
fn to_socket_addr(a: &NetAddr) -> SocketAddr {
    match *a {
        NetAddr::V4(ip, port) => SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
            port,
        )),
        NetAddr::V6(ip, port) => SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(
                u16::from_be_bytes([ip[0], ip[1]]),
                u16::from_be_bytes([ip[2], ip[3]]),
                u16::from_be_bytes([ip[4], ip[5]]),
                u16::from_be_bytes([ip[6], ip[7]]),
                u16::from_be_bytes([ip[8], ip[9]]),
                u16::from_be_bytes([ip[10], ip[11]]),
                u16::from_be_bytes([ip[12], ip[13]]),
                u16::from_be_bytes([ip[14], ip[15]]),
            ),
            port,
            0,
            0,
        )),
    }
}

/// Map a std socket address back onto an engine endpoint. IPv4-mapped IPv6
/// addresses (`::ffff:a.b.c.d`, as reported by dual-stack sockets) are
/// normalized back to real IPv4 so the engine's address-family logic
/// (subnet keys, compact encodings, LSD peer ports) sees true endpoints.
fn from_socket_addr(sa: SocketAddr) -> NetAddr {
    match sa {
        SocketAddr::V4(v4) => NetAddr::V4(v4.ip().octets(), v4.port()),
        SocketAddr::V6(v6) => {
            let ip = v6.ip().octets();
            if ip[..10] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0] && ip[10] == 0xff && ip[11] == 0xff {
                NetAddr::V4([ip[12], ip[13], ip[14], ip[15]], v6.port())
            } else {
                NetAddr::V6(ip, v6.port())
            }
        }
    }
}

/// A complete std host: courierust HTTP + native non-blocking TCP/UDP + files.
pub struct StdHost {
    http: courierust::courierust_client::Client,
    /// Open peer connections (conn id → stream).
    tcp: HashMap<ConnId, TcpStream>,
    /// Next TCP conn id (1-based so 0 stays a "no handle" sentinel).
    next_tcp: ConnId,
    /// UDP socket for DHT / UDP trackers / LSD. Preferentially a dual-stack
    /// (IPv4+IPv6) socket so one socket serves both address families,
    /// including the BEP-14 v6 multicast group; falls back to IPv4-only on
    /// hosts without IPv6. Opened through `socket2` (for `set_only_v6` and
    /// the IPv6 multicast hop limit — neither is exposed by std) and then
    /// converted to `UdpSocket` so all runtime I/O stays unsafe-free.
    udp: Option<UdpSocket>,
    /// Whether the UDP socket is dual-stack (IPv4+IPv6). When true, IPv4
    /// destinations are sent as IPv4-mapped IPv6 addresses — Windows
    /// rejects native AF_INET sockaddrs on an AF_INET6 dual-stack socket.
    udp_dual_stack: bool,
    /// Open files (disk id → file).
    disk: HashMap<DiskId, File>,
    /// Next disk id (1-based).
    next_disk: DiskId,
}

impl StdHost {
    /// Create a host with a default `courierust` client.
    pub fn new() -> Self {
        StdHost {
            http: courierust::courierust_client::Client::new(),
            tcp: HashMap::new(),
            next_tcp: 1,
            udp: None,
            udp_dual_stack: false,
            disk: HashMap::new(),
            next_disk: 1,
        }
    }

    /// Open a dual-stack (IPv4+IPv6) non-blocking UDP socket bound to the
    /// IPv6 wildcard with V6ONLY disabled. The IPv6 multicast hop limit is
    /// set here once — it persists on the fd after conversion to
    /// `UdpSocket`.
    fn open_dual_stack(port: u16) -> crate::Result<UdpSocket> {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(|_| Error::Io)?;
        sock.set_only_v6(false).map_err(|_| Error::Io)?;
        let bind_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
        sock.bind(&bind_addr.into()).map_err(|_| Error::Io)?;
        sock.set_nonblocking(true).map_err(|_| Error::Io)?;
        // IPv6 multicast hop limit for LSD (BEP-14): org/site scope.
        let _ = sock.set_multicast_hops_v6(16);
        Ok(sock.into())
    }

    /// Fallback when dual-stack is unavailable (IPv6 disabled on the host):
    /// an IPv4-only non-blocking UDP socket bound to `0.0.0.0:port`.
    fn open_v4_only(port: u16) -> crate::Result<UdpSocket> {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(|_| Error::Io)?;
        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        sock.bind(&bind_addr.into()).map_err(|_| Error::Io)?;
        sock.set_nonblocking(true).map_err(|_| Error::Io)?;
        Ok(sock.into())
    }

    /// The destination `SocketAddr` to hand the UDP socket. On a dual-stack
    /// socket, Windows requires IPv4 destinations in IPv4-mapped form
    /// (`::ffff:a.b.c.d`), so V4 addresses are mapped when the socket is
    /// dual-stack (harmless on Unix, which accepts both forms).
    fn send_sock_addr(&self, a: &NetAddr) -> SocketAddr {
        match *a {
            NetAddr::V4(ip, port) if self.udp_dual_stack => SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(
                    0,
                    0,
                    0,
                    0,
                    0,
                    0xffff,
                    u16::from_be_bytes([ip[0], ip[1]]),
                    u16::from_be_bytes([ip[2], ip[3]]),
                ),
                port,
                0,
                0,
            )),
            _ => to_socket_addr(a),
        }
    }
}

impl Default for StdHost {
    fn default() -> Self {
        Self::new()
    }
}

impl Host for StdHost {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn fill_random(&mut self, buf: &mut [u8]) {
        #[cfg(unix)]
        {
            use std::io::Read;
            if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
                if f.read_exact(buf).is_ok() {
                    return;
                }
            }
        }
        let t = self.now_ms();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (t >> (i % 64)) as u8 ^ (i as u8).wrapping_mul(31);
        }
    }

    fn log(&mut self, _level: LogLevel, _msg: &str) {}

    fn http_get(
        &mut self,
        url: &str,
        _timeout_ms: u64,
        out: &mut alloc::vec::Vec<u8>,
    ) -> crate::Result<()> {
        let resp = self.http.get(url).map_err(|_| crate::Error::Io)?;
        if resp.status.as_u16() != 200 {
            return Err(crate::Error::Tracker);
        }
        // `collect_limited` enforces the cap before each allocation/copy,
        // so a hostile tracker cannot make us materialize a huge body.
        let body = resp
            .body
            .collect_limited(MAX_HTTP_BODY)
            .map_err(|_| crate::Error::Io)?;
        out.extend_from_slice(&body);
        Ok(())
    }

    fn http_get_range(
        &mut self,
        url: &str,
        range_start: u64,
        range_end: u64,
        _timeout_ms: u64,
        out: &mut alloc::vec::Vec<u8>,
    ) -> crate::Result<()> {
        use courierust::courierust_body::Body;
        use courierust::courierust_http::header::{HeaderName, HeaderValue};
        use courierust::courierust_http::method::Method;
        use courierust::courierust_http::request::Request;
        let mut req = Request::<Body>::new(Method::GET, "/");
        let value = format!("bytes={}-{}", range_start, range_end);
        req.headers.insert(
            HeaderName::from_lowercase("range"),
            HeaderValue::from_bytes(value.as_bytes()).map_err(|_| crate::Error::InvalidInput)?,
        );
        let resp = self.http.execute(url, req).map_err(|_| crate::Error::Io)?;
        let status = resp.status.as_u16();
        if status != 200 && status != 206 {
            return Err(crate::Error::Tracker);
        }
        // A web seed MUST honor the range (BEP-19): bound the body to the
        // requested window so a hostile seed cannot stream unbounded data.
        let window = range_end.saturating_sub(range_start) + 1;
        let body = resp
            .body
            .collect_limited(window as usize)
            .map_err(|_| crate::Error::Io)?;
        // Refuse anything that is not exactly the window (a mismatched
        // body would corrupt the piece).
        if body.len() as u64 != window {
            return Err(crate::Error::Protocol);
        }
        out.extend_from_slice(&body);
        Ok(())
    }

    fn resolve_host(&self, host: &str, port: u16) -> Option<NetAddr> {
        let mut addrs = (host, port).to_socket_addrs().ok()?;
        let a = addrs.next()?;
        Some(from_socket_addr(a))
    }

    fn resolve_host_all(&self, host: &str, port: u16) -> alloc::vec::Vec<NetAddr> {
        let mut out = alloc::vec::Vec::new();
        if let Ok(addrs) = (host, port).to_socket_addrs() {
            let mut seen = alloc::collections::BTreeSet::new();
            for a in addrs {
                let na = from_socket_addr(a);
                // dedupe (getaddrinfo may repeat the same address) — use a
                // uniform 16-byte key so IPv4 and IPv6 compare cleanly.
                let key: (u8, [u8; 16], u16) = match na {
                    NetAddr::V4(ip, p) => {
                        let mut b = [0u8; 16];
                        b[..4].copy_from_slice(&ip);
                        (0, b, p)
                    }
                    NetAddr::V6(ip, p) => (1, ip, p),
                };
                if seen.insert(key) {
                    out.push(na);
                }
            }
        }
        out
    }

    fn tcp_connect(&mut self, addr: &NetAddr) -> crate::Result<ConnId> {
        let sa = to_socket_addr(addr);
        let domain = if sa.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket =
            socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
                .map_err(|_| Error::Io)?;
        socket.set_nonblocking(true).map_err(|_| Error::Io)?;
        let _ = socket.connect(&sa.into());
        let stream: TcpStream = socket.into();
        let id = self.next_tcp;
        self.next_tcp = self.next_tcp.wrapping_add(1);
        self.tcp.insert(id, stream);
        Ok(id)
    }

    fn tcp_connect_done(&mut self, id: ConnId) -> crate::Result<()> {
        let stream = self.tcp.get_mut(&id).ok_or(Error::NotFound)?;
        if let Some(_e) = stream.take_error().map_err(|_| Error::Io)? {
            return Err(Error::Io);
        }
        match stream.write(&[]) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(Error::WouldBlock),
            Err(_) => Err(Error::Io),
        }
    }

    fn tcp_send(&mut self, id: ConnId, data: &[u8]) -> crate::Result<usize> {
        let stream = self.tcp.get_mut(&id).ok_or(Error::NotFound)?;
        match stream.write(data) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(Error::WouldBlock),
            Err(_) => Err(Error::Io),
        }
    }

    fn tcp_recv(&mut self, id: ConnId, buf: &mut [u8]) -> crate::Result<usize> {
        let stream = self.tcp.get_mut(&id).ok_or(Error::NotFound)?;
        match stream.read(buf) {
            Ok(0) => Ok(0),
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(Error::WouldBlock),
            Err(_) => Err(Error::Io),
        }
    }

    fn tcp_close(&mut self, id: ConnId) {
        // Dropping the stream closes the socket. Unknown ids are a no-op
        // (the engine sweeps stale handles).
        self.tcp.remove(&id);
    }

    fn udp_open(&mut self, port: u16) -> crate::Result<()> {
        if self.udp.is_some() {
            return Ok(());
        }
        // Prefer a dual-stack socket (`[::]:port`, V6ONLY off): one socket
        // then serves DHT, UDP trackers and LSD (BEP-14) on both IPv4 and
        // IPv6 — including the v6 LSD multicast group `ff15::efc0:988f`.
        // On hosts without IPv6 support (socket creation/bind fails) we
        // fall back to an IPv4-only socket so nothing regresses.
        let (udp, dual_stack) = match Self::open_dual_stack(port) {
            Ok(s) => (s, true),
            Err(_) => (Self::open_v4_only(port)?, false),
        };
        self.udp_dual_stack = dual_stack;
        self.udp = Some(udp);
        Ok(())
    }

    fn udp_send(&mut self, addr: &NetAddr, data: &[u8]) -> crate::Result<()> {
        let sock = self.udp.as_ref().ok_or(Error::NotFound)?;
        let sa = self.send_sock_addr(addr);
        sock.send_to(data, sa).map_err(|_| Error::Io)?;
        Ok(())
    }

    fn udp_multicast_send(&mut self, addr: &NetAddr, data: &[u8]) -> crate::Result<()> {
        let sock = self.udp.as_ref().ok_or(Error::NotFound)?;
        // Per-family multicast options on the (possibly dual-stack) socket:
        // TTL/hops 16 keeps announces within the org/site scope the LSD
        // groups are defined for, loop on so our own datagrams reach us
        // for cookie-based echo filtering.
        match *addr {
            NetAddr::V4(..) => {
                let _ = sock.set_multicast_ttl_v4(16);
                let _ = sock.set_multicast_loop_v4(true);
            }
            NetAddr::V6(..) => {
                // The v6 hop limit was set at open (it persists on the fd);
                // ensure loop so our own datagrams reach us for cookie-
                // based echo filtering.
                let _ = sock.set_multicast_loop_v6(true);
            }
        }
        let sa = self.send_sock_addr(addr);
        sock.send_to(data, sa).map_err(|_| Error::Io)?;
        Ok(())
    }

    fn udp_join_multicast(&mut self, addr: NetAddr) -> crate::Result<()> {
        let sock = self.udp.as_ref().ok_or(Error::NotFound)?;
        match addr {
            NetAddr::V4(ip, _) => {
                let group = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
                sock.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)
                    .map_err(|_| Error::Io)
            }
            NetAddr::V6(ip, _) => {
                let group = Ipv6Addr::from(ip);
                sock.join_multicast_v6(&group, 0).map_err(|_| Error::Io)
            }
        }
    }

    fn udp_recv(&mut self, buf: &mut [u8]) -> crate::Result<(NetAddr, usize)> {
        let sock = self.udp.as_ref().ok_or(Error::NotFound)?;
        match sock.recv_from(buf) {
            Ok((n, sa)) => {
                // `from_socket_addr` normalizes IPv4-mapped sources
                // (`::ffff:a.b.c.d`, reported by dual-stack sockets) back
                // to real IPv4.
                Ok((from_socket_addr(sa), n))
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                Err(Error::WouldBlock)
            }
            Err(_) => Err(Error::Io),
        }
    }

    fn disk_open(&mut self, path: &str) -> crate::Result<DiskId> {
        let f = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|_| Error::Io)?;
        let id = self.next_disk;
        self.next_disk = self.next_disk.wrapping_add(1);
        self.disk.insert(id, f);
        Ok(id)
    }

    fn disk_read(&mut self, id: DiskId, offset: u64, buf: &mut [u8]) -> crate::Result<usize> {
        let f = self.disk.get_mut(&id).ok_or(Error::NotFound)?;
        f.seek(SeekFrom::Start(offset)).map_err(|_| Error::Io)?;
        f.read(buf).map_err(|_| Error::Io)
    }

    fn disk_write(&mut self, id: DiskId, offset: u64, data: &[u8]) -> crate::Result<()> {
        let f = self.disk.get_mut(&id).ok_or(Error::NotFound)?;
        f.seek(SeekFrom::Start(offset)).map_err(|_| Error::Io)?;
        f.write_all(data).map_err(|_| Error::Io)?;
        Ok(())
    }

    fn disk_prealloc(&mut self, id: DiskId, size: u64) -> crate::Result<()> {
        let f = self.disk.get_mut(&id).ok_or(Error::NotFound)?;
        f.set_len(size).map_err(|_| Error::Io)?;
        Ok(())
    }

    fn disk_flush(&mut self, id: DiskId) -> crate::Result<()> {
        let f = self.disk.get_mut(&id).ok_or(Error::NotFound)?;
        f.sync_all().map_err(|_| Error::Io)?;
        Ok(())
    }

    fn disk_close(&mut self, id: DiskId) {
        self.disk.remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};
    use std::time::Duration;

    #[test]
    fn tcp_connect_send_recv_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        let ip = match addr {
            SocketAddr::V4(v4) => v4.ip().octets(),
            SocketAddr::V6(v6) => {
                let o = v6.ip().octets();
                [o[12], o[13], o[14], o[15]] // mapped v4
            }
        };
        let mut host = StdHost::new();
        let id = host
            .tcp_connect(&NetAddr::V4(ip, addr.port()))
            .expect("connect");
        let (mut server, _) = listener.accept().expect("accept");
        let mut done = false;
        for _ in 0..100 {
            if host.tcp_connect_done(id).is_ok() {
                done = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(done, "connect never completed");
        host.tcp_send(id, b"ping").expect("send");
        let mut got = [0u8; 4];
        server.read_exact(&mut got).expect("server read");
        assert_eq!(&got, b"ping");
        server.write_all(b"pong").expect("server write");
        let mut buf = [0u8; 4];
        let n = loop {
            match host.tcp_recv(id, &mut buf) {
                Ok(n) => break n,
                Err(Error::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("recv: {e:?}"),
            }
        };
        assert_eq!(n, 4);
        assert_eq!(&buf, b"pong");
        drop(server);
        let mut scratch = [0u8; 64];
        let eof = loop {
            match host.tcp_recv(id, &mut scratch) {
                Ok(0) => break true,
                Ok(_) => continue,
                Err(Error::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break false,
            }
        };
        assert!(eof, "expected EOF after peer close");
        host.tcp_close(id);
    }

    #[test]
    fn connect_to_refused_port_is_reported_by_probe() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        drop(listener); // port is now closed
        let ip = match addr {
            SocketAddr::V4(v4) => v4.ip().octets(),
            SocketAddr::V6(v6) => {
                let o = v6.ip().octets();
                [o[12], o[13], o[14], o[15]] // mapped v4
            }
        };
        let mut host = StdHost::new();
        let id = host
            .tcp_connect(&NetAddr::V4(ip, addr.port()))
            .expect("tcp_connect must start even when the peer refuses");
        // The probe must eventually report the refusal.
        let mut failed = false;
        for _ in 0..100 {
            match host.tcp_connect_done(id) {
                Ok(()) => {
                    // Defensive: on loopback a refusal surfaces fast; if a
                    // platform ever reported Ok first, keep polling.
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(Error::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        assert!(failed, "connect probe never reported the refusal");
        host.tcp_close(id);
    }

    #[test]
    fn udp_roundtrip() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let peer_addr = sock.local_addr().unwrap();
        let mut host = StdHost::new();
        host.udp_open(0).expect("open");
        let dst = NetAddr::V4([127, 0, 0, 1], peer_addr.port());
        host.udp_send(&dst, b"hello").expect("send");
        let mut got = [0u8; 8];
        let (n, from) = sock.recv_from(&mut got).expect("recv");
        assert_eq!(&got[..n], b"hello");
        sock.send_to(b"world", from).expect("send back");
        let mut buf = [0u8; 8];
        let (_, n) = loop {
            match host.udp_recv(&mut buf) {
                Ok(x) => break x,
                Err(Error::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("udp_recv: {e:?}"),
            }
        };
        assert_eq!(&buf[..n], b"world");
    }

    #[test]
    fn udp_dual_stack_normalizes_v4_mapped_sources() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        let peer_addr = sock.local_addr().unwrap();
        let mut host = StdHost::new();
        host.udp_open(0).expect("open");

        let dst = NetAddr::V4([127, 0, 0, 1], peer_addr.port());
        host.udp_send(&dst, b"ping").expect("send");
        let mut got = [0u8; 8];
        let (n, from) = sock.recv_from(&mut got).expect("peer recv");
        assert_eq!(&got[..n], b"ping");
        sock.send_to(b"pong", from).expect("peer reply");

        // A dual-stack socket reports IPv4 sources as `::ffff:127.0.0.1`;
        // the host must hand the engine a real IPv4 endpoint so family
        // logic (subnet keys, compact encodings, LSD peer ports) is sane.
        let mut buf = [0u8; 8];
        let (src, n) = loop {
            match host.udp_recv(&mut buf) {
                Ok(x) => break x,
                Err(Error::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("udp_recv: {e:?}"),
            }
        };
        assert_eq!(&buf[..n], b"pong");
        assert_eq!(
            src,
            NetAddr::V4([127, 0, 0, 1], peer_addr.port()),
            "v4 source must be normalized, not ::ffff-mapped v6"
        );
    }

    #[test]
    fn udp_v6_roundtrip_when_available() {
        // Skip silently on hosts without IPv6 loopback.
        let peer = match UdpSocket::bind("[::1]:0") {
            Ok(s) => s,
            Err(_) => return,
        };
        let peer_addr = peer.local_addr().unwrap();
        let mut host = StdHost::new();
        if host.udp_open(0).is_err() {
            return; // host fell back to v4-only (no IPv6) — nothing to test
        }
        let mut ip = [0u8; 16];
        ip[15] = 1; // ::1
        let dst = NetAddr::V6(ip, peer_addr.port());
        if host.udp_send(&dst, b"v6ping").is_err() {
            return; // v4-only fallback socket
        }
        let mut got = [0u8; 16];
        let (n, from) = peer.recv_from(&mut got).expect("peer v6 recv");
        assert_eq!(&got[..n], b"v6ping");
        peer.send_to(b"v6pong", from).expect("peer v6 reply");
        let mut buf = [0u8; 16];
        let (src, n) = loop {
            match host.udp_recv(&mut buf) {
                Ok(x) => break x,
                Err(Error::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("udp_recv: {e:?}"),
            }
        };
        assert_eq!(&buf[..n], b"v6pong");
        assert_eq!(src, NetAddr::V6(ip, peer_addr.port()));
    }

    #[test]
    fn from_socket_addr_normalizes_v4_mapped_v6() {
        let mapped = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1]),
            6881,
            0,
            0,
        ));
        assert_eq!(from_socket_addr(mapped), NetAddr::V4([192, 0, 2, 1], 6881));
        let real6 = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            6881,
            0,
            0,
        ));
        assert_eq!(
            from_socket_addr(real6),
            NetAddr::V6([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 6881)
        );
    }

    #[test]
    fn disk_write_read_prealloc_flush() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("typebit-hoststd-test-{}.bin", std::process::id()));
        let path = path.to_str().unwrap().to_string();
        let mut host = StdHost::new();
        let id = host.disk_open(&path).expect("open");
        host.disk_prealloc(id, 1024).expect("prealloc");
        host.disk_write(id, 0, b"abcd").expect("write");
        host.disk_flush(id).expect("flush");
        let mut buf = [0u8; 4];
        let n = host.disk_read(id, 0, &mut buf).expect("read");
        assert_eq!(n, 4);
        assert_eq!(&buf, b"abcd");
        host.disk_close(id);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolve_host_returns_a_socket() {
        let host = StdHost::new();
        // "localhost" should resolve without touching the public network.
        let r = host.resolve_host("localhost", 6881);
        assert!(r.is_some(), "localhost should resolve");
        let a = r.unwrap();
        match a {
            NetAddr::V4(_, p) | NetAddr::V6(_, p) => assert_eq!(p, 6881),
        }
    }
}
