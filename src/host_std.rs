//! OS-backed [`Host`] for desktop/server builds (feature `std`).
//!
//! This is a **complete, runnable** host for a standalone client: HTTP via
//! `courierust` (tracker announces, web seeds), **non-blocking TCP** peer
//! connections (the engine drives hundreds from one thread), a **UDP**
//! socket (DHT + UDP trackers) and **file-backed disk** I/O. Every socket
//! is put in non-blocking mode so the single engine thread never stalls;
//! the engine's `Err(WouldBlock)` contract maps onto
//! `io::ErrorKind::WouldBlock` (plus the Windows `ConnectionReset` quirk on
//! UDP, which is transient).

use crate::platform::{ConnId, DiskId};
use crate::{Error, Host, LogLevel, NetAddr};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, ToSocketAddrs, UdpSocket,
};

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

/// Map a std socket address back onto an engine endpoint.
fn from_socket_addr(sa: SocketAddr) -> NetAddr {
    match sa {
        SocketAddr::V4(v4) => NetAddr::V4(v4.ip().octets(), v4.port()),
        SocketAddr::V6(v6) => NetAddr::V6(v6.ip().octets(), v6.port()),
    }
}

/// A complete std host: courierust HTTP + native non-blocking TCP/UDP + files.
pub struct StdHost {
    http: courierust::courierust_client::Client,
    /// Open peer connections (conn id → stream).
    tcp: HashMap<ConnId, TcpStream>,
    /// Next TCP conn id (1-based so 0 stays a "no handle" sentinel).
    next_tcp: ConnId,
    /// UDP socket for DHT / UDP trackers (one per host).
    udp: Option<UdpSocket>,
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
            disk: HashMap::new(),
            next_disk: 1,
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
        let body = resp.body.collect().map_err(|_| crate::Error::Io)?;
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
        let body = resp.body.collect().map_err(|_| crate::Error::Io)?;
        if body.len() as u64 != range_end.saturating_sub(range_start) + 1 {
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
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).map_err(|_| Error::Io)?;
        sock.set_nonblocking(true).map_err(|_| Error::Io)?;
        self.udp = Some(sock);
        Ok(())
    }

    fn udp_send(&mut self, addr: &NetAddr, data: &[u8]) -> crate::Result<()> {
        let sock = self.udp.as_ref().ok_or(Error::NotFound)?;
        let sa = to_socket_addr(addr);
        sock.send_to(data, sa).map_err(|_| Error::Io)?;
        Ok(())
    }

    fn udp_multicast_send(&mut self, addr: &NetAddr, data: &[u8]) -> crate::Result<()> {
        let sock = self.udp.as_ref().ok_or(Error::NotFound)?;
        if matches!(*addr, NetAddr::V4(..)) {
            let _ = sock.set_multicast_ttl_v4(16);
            let _ = sock.set_multicast_loop_v4(true);
        }
        let sa = to_socket_addr(addr);
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
            Ok((n, sa)) => Ok((from_socket_addr(sa), n)),
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
    use std::net::TcpListener;
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
