//! OS-backed [`Host`] for desktop/server builds (feature `std`).
//!
//! HTTP is served by `courierust` (HTTP/1.1 · HTTP/2 client); sockets and
//! files remain application-owned — this type wires the engine to a real
//! `courierust` client and leaves transports to the embedding app.

use crate::platform::{ConnId, DiskId};
use crate::{Host, LogLevel, NetAddr};

/// A minimal std host with a real `courierust` HTTP client.
pub struct StdHost {
    http: courierust::courierust_client::Client,
}

impl StdHost {
    /// Create a host with a default `courierust` client.
    pub fn new() -> Self {
        StdHost {
            http: courierust::courierust_client::Client::new(),
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
        // Fallback (not CSPRNG-grade): derived from the clock. Embedders
        // that need real entropy should override this method.
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
        // Web seeds (BEP-19): fetch one byte window via Range.
        let mut req = Request::<Body>::new(Method::GET, "/");
        let value = format!("bytes={}-{}", range_start, range_end);
        req.headers.insert(
            HeaderName::from_lowercase("range"),
            HeaderValue::from_bytes(value.as_bytes()).map_err(|_| crate::Error::InvalidInput)?,
        );
        let resp = self.http.execute(url, req).map_err(|_| crate::Error::Io)?;
        // 206 Partial Content for a fulfilled range; 200 if the server
        // ignored the Range header (we still require the exact window).
        let status = resp.status.as_u16();
        if status != 200 && status != 206 {
            return Err(crate::Error::Tracker);
        }
        let body = resp.body.collect().map_err(|_| crate::Error::Io)?;
        // A web seed MUST honor the range (BEP-19). A body that does not
        // match the requested window would corrupt the piece — refuse it.
        if body.len() as u64 != range_end.saturating_sub(range_start) + 1 {
            return Err(crate::Error::Protocol);
        }
        out.extend_from_slice(&body);
        Ok(())
    }

    fn tcp_connect(&mut self, _addr: &NetAddr) -> crate::Result<ConnId> {
        Err(crate::Error::NotSupported)
    }
    fn tcp_connect_done(&mut self, _id: ConnId) -> crate::Result<()> {
        Err(crate::Error::NotSupported)
    }
    fn tcp_send(&mut self, _id: ConnId, _data: &[u8]) -> crate::Result<usize> {
        Err(crate::Error::NotSupported)
    }
    fn tcp_recv(&mut self, _id: ConnId, _buf: &mut [u8]) -> crate::Result<usize> {
        Err(crate::Error::NotSupported)
    }
    fn tcp_close(&mut self, _id: ConnId) {}
    fn udp_open(&mut self, _port: u16) -> crate::Result<()> {
        Err(crate::Error::NotSupported)
    }
    fn udp_send(&mut self, _addr: &NetAddr, _data: &[u8]) -> crate::Result<()> {
        Err(crate::Error::NotSupported)
    }
    fn udp_recv(&mut self, _buf: &mut [u8]) -> crate::Result<(NetAddr, usize)> {
        Err(crate::Error::NotSupported)
    }
    fn disk_open(&mut self, _path: &str) -> crate::Result<DiskId> {
        Err(crate::Error::NotSupported)
    }
    fn disk_read(&mut self, _id: DiskId, _offset: u64, _buf: &mut [u8]) -> crate::Result<usize> {
        Err(crate::Error::NotSupported)
    }
    fn disk_write(&mut self, _id: DiskId, _offset: u64, _data: &[u8]) -> crate::Result<()> {
        Err(crate::Error::NotSupported)
    }
    fn disk_prealloc(&mut self, _id: DiskId, _size: u64) -> crate::Result<()> {
        Err(crate::Error::NotSupported)
    }
    fn disk_flush(&mut self, _id: DiskId) -> crate::Result<()> {
        Err(crate::Error::NotSupported)
    }
    fn disk_close(&mut self, _id: DiskId) {}
}
