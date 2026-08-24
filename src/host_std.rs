//! OS-backed [`Host`] for desktop/server builds (feature `std`).
//!
//! Implements non-blocking TCP/UDP, file I/O, wall clock and HTTP via
//! `courierust`. The skeleton below keeps `feature = "std"` compiling with a
//! default host type; applications typically implement [`Host`] directly or
//! route through the FFI bridge.

use crate::platform::{ConnId, DiskId};
use crate::{Host, LogLevel, NetAddr};

/// A std host placeholder.
///
/// Real implementations should fill in [`Host`] using `std::net`,
/// `std::fs` and `std::time`. The type exists so `feature = "std"`
/// compiles with a default host type available.
pub struct StdHost;

impl Host for StdHost {
    fn now_ms(&self) -> u64 {
        0
    }
    fn fill_random(&mut self, _buf: &mut [u8]) {}
    fn log(&mut self, _level: LogLevel, _msg: &str) {}
    fn http_get(
        &mut self,
        _url: &str,
        _timeout_ms: u64,
        _out: &mut alloc::vec::Vec<u8>,
    ) -> crate::Result<()> {
        Err(crate::Error::NotSupported)
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
