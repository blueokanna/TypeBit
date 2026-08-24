# Implementing a Host

`typebit::Host` is the only interface you implement. It has ~18 methods, all
`no_std`-friendly. The engine calls them from `tick()` on **your** thread, so
they must not block for long (use non-blocking sockets).

## The trait

```rust
pub trait Host {
    fn now_ms(&self) -> u64;                        // clock (ms)
    fn fill_random(&mut self, buf: &mut [u8]);      // CSPRNG
    fn log(&mut self, level: LogLevel, msg: &str);

    // HTTP(S) GET → append body to `out` (trackers, web seeds, IPFS gateways)
    fn http_get(&mut self, url: &str, timeout_ms: u64, out: &mut Vec<u8>)
        -> Result<()>;

    // TCP (non-blocking)
    fn tcp_connect(&mut self, addr: &NetAddr) -> Result<ConnId>;
    fn tcp_connect_done(&mut self, id: ConnId) -> Result<()>;  // Ok=established
    fn tcp_send(&mut self, id: ConnId, data: &[u8]) -> Result<usize>;
    fn tcp_recv(&mut self, id: ConnId, buf: &mut [u8]) -> Result<usize>;
    fn tcp_close(&mut self, id: ConnId);

    // UDP (DHT, UDP trackers)
    fn udp_open(&mut self, port: u16) -> Result<()>;
    fn udp_send(&mut self, addr: &NetAddr, data: &[u8]) -> Result<()>;
    fn udp_recv(&mut self, buf: &mut [u8]) -> Result<(NetAddr, usize)>;

    // Files (piece data)
    fn disk_open(&mut self, path: &str) -> Result<DiskId>;
    fn disk_read(&mut self, id: DiskId, offset: u64, buf: &mut [u8]) -> Result<usize>;
    fn disk_write(&mut self, id: DiskId, offset: u64, data: &[u8]) -> Result<()>;
    fn disk_prealloc(&mut self, id: DiskId, size: u64) -> Result<()>;
    fn disk_flush(&mut self, id: DiskId) -> Result<()>;
    fn disk_close(&mut self, id: DiskId);
}
```

## Conventions the engine relies on

- `tcp_recv` / `udp_recv` return `Err(Error::WouldBlock)` when there is no
  data right now. Do **not** block in these.
- `tcp_connect` returns a handle immediately (non-blocking connect); the
  engine polls with `tcp_connect_done`.
- `http_get` may block up to `timeout_ms`; the engine uses it for trackers
  and web seeds.
- Disk offsets are absolute within one file (per-file handles).

## A real (std) host in ~60 lines

```rust
use std::net::TcpStream;
use typebit::platform::{ConnId, DiskId, Host, LogLevel, NetAddr};
use typebit::{Error, Result};

pub struct StdHost {
    tcp: HashMap<ConnId, TcpStream>,
    disks: HashMap<DiskId, std::fs::File>,
    next_id: u32,
}

impl Host for StdHost {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
    fn fill_random(&mut self, buf: &mut [u8]) {
        // os random (e.g. getrandom or /dev/urandom)
    }
    fn tcp_connect(&mut self, addr: &NetAddr) -> Result<ConnId> {
        let (ip, port) = match addr {
            NetAddr::V4(ip, p) => (std::net::Ipv4Addr::from(*ip), *p),
            NetAddr::V6(ip, p) => (std::net::Ipv6Addr::from(*ip), *p),
        };
        let stream = TcpStream::connect((ip, port)).map_err(|_| Error::Io)?;
        stream.set_nonblocking(true).map_err(|_| Error::Io)?;
        let id = self.next_id;
        self.next_id += 1;
        self.tcp.insert(id, stream);
        Ok(id)
    }
    fn tcp_recv(&mut self, id: ConnId, buf: &mut [u8]) -> Result<usize> {
        use std::io::Read;
        match self.tcp.get_mut(&id).unwrap().read(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(Error::WouldBlock),
            Err(_) => Err(Error::Io),
        }
    }
    // ... and the rest. See examples/minimal_host.rs for a complete mock.
}
```

## Integration checklist

1. `Engine::new(host, config)` — one per app
2. `add_torrent(&bytes, save_dir)` or `add_magnet(uri, save_dir)` → infohash
3. `start(&hash)`
4. on a timer: `tick()`, then `take_events()` and forward events to your UI
5. inbound sockets: `on_inbound_connection(conn, addr)`
6. persistence: `save_state()` / `load_state(&state, now)`

That's the whole integration surface. Everything else is internal.
