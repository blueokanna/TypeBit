//! Write-back disk cache: blocks are buffered and flushed in large,
//! offset-ordered coalesced batches (fewer writes/seeks); a piece hits
//! stable storage before it is verified. Read-through serves seeding reads.
//!
//! `no_std + alloc`, zero `unsafe`.

use crate::error::{Error, Result};
use crate::platform::{DiskId, Host};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Coalescing statistics (surfaced to the UI/monitoring).
#[derive(Debug, Clone, Copy, Default)]
pub struct CacheStats {
    /// Number of disk writes issued.
    pub write_ops: u64,
    /// Bytes actually written to disk.
    pub write_bytes: u64,
    /// Bytes that were merged into larger writes (never hit disk alone).
    pub bytes_coalesced: u64,
    /// Number of writes saved by coalescing (ops avoided).
    pub ops_saved: u64,
    /// Disk reads issued.
    pub read_ops: u64,
    /// Bytes read from disk.
    pub read_bytes: u64,
    /// Bytes served from the cache instead of the disk.
    pub read_hits: u64,
    /// Full-cache flushes triggered.
    pub evictions: u64,
}

/// A write-back cache keyed by (disk handle, absolute offset).
#[derive(Debug)]
pub struct DiskCache {
    budget: u64,
    used: u64,
    dirty: BTreeMap<(DiskId, u64), Vec<u8>>,
    /// Stats.
    pub stats: CacheStats,
}

impl DiskCache {
    /// Create with a byte budget.
    pub fn new(budget: u64) -> Self {
        DiskCache {
            budget: budget.max(1 << 20),
            used: 0,
            dirty: BTreeMap::new(),
            stats: CacheStats::default(),
        }
    }

    /// Buffered bytes.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Cache budget.
    pub fn budget(&self) -> u64 {
        self.budget
    }

    /// Buffered bytes for one file.
    pub fn dirty_bytes(&self, disk: DiskId) -> u64 {
        self.dirty
            .range((disk, 0)..=(disk, u64::MAX))
            .map(|(_, v)| v.len() as u64)
            .sum()
    }

    /// Buffer a write. Flushes oldest data first when over budget.
    pub fn write<H: Host>(
        &mut self,
        host: &mut H,
        disk: DiskId,
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        // if a single write exceeds the whole budget, bypass cache
        if data.len() as u64 > self.budget {
            self.flush(host)?;
            host.disk_write(disk, offset, data)?;
            self.stats.write_ops += 1;
            self.stats.write_bytes += data.len() as u64;
            return Ok(());
        }
        // make room
        while self.used + data.len() as u64 > self.budget && !self.dirty.is_empty() {
            let freed = self.flush_oldest(host, data.len() as u64)?;
            self.stats.evictions += 1;
            if freed == 0 {
                break;
            }
        }
        self.insert_coalesced(disk, offset, data);
        Ok(())
    }

    /// Coalesce `data` at `offset` into the dirty map, merging with
    /// adjacent entries.
    fn insert_coalesced(&mut self, disk: DiskId, offset: u64, data: &[u8]) {
        // exact same start → replace (fresher data wins)
        if let Some(existing) = self.dirty.get_mut(&(disk, offset)) {
            let old_len = existing.len();
            self.used -= old_len as u64;
            existing.clear();
            existing.extend_from_slice(data);
            self.used += data.len() as u64;
            return;
        }
        // predecessor ending exactly at `offset`
        let mut mergeable_pred: Option<(DiskId, u64)> = None;
        if let Some((&k, v)) = self.dirty.range(..(disk, offset)).next_back() {
            if k.0 == disk && k.1 + v.len() as u64 == offset {
                mergeable_pred = Some(k);
            }
        }
        if let Some(k) = mergeable_pred {
            let end = k.1 + self.dirty.get(&k).map(|v| v.len() as u64).unwrap_or(0);
            // merge with a successor starting exactly at the extended end
            let succ_data = self.dirty.get(&(disk, end)).cloned();
            let has_succ = succ_data.is_some();
            if has_succ {
                let sd = succ_data.clone().unwrap();
                self.dirty.remove(&(disk, end));
                self.used -= sd.len() as u64;
            }
            let v = self.dirty.get_mut(&k).unwrap();
            v.extend_from_slice(data);
            self.used += data.len() as u64;
            self.stats.bytes_coalesced += data.len() as u64;
            self.stats.ops_saved += 1;
            if let Some(succ_data) = succ_data {
                v.extend_from_slice(&succ_data);
                self.used += succ_data.len() as u64;
            }
            return;
        }
        // successor starting exactly at `offset + len`
        if let Some(succ) = self.dirty.get(&(disk, offset + data.len() as u64)) {
            let mut merged = Vec::with_capacity(data.len() + succ.len());
            merged.extend_from_slice(data);
            merged.extend_from_slice(succ);
            let succ_len = succ.len();
            self.dirty.remove(&(disk, offset + data.len() as u64));
            self.used -= succ_len as u64;
            self.dirty.insert((disk, offset), merged);
            self.used += data.len() as u64;
            self.stats.bytes_coalesced += data.len() as u64;
            self.stats.ops_saved += 1;
            return;
        }
        self.dirty.insert((disk, offset), data.to_vec());
        self.used += data.len() as u64;
    }

    /// Read-through: serve from dirty pages where possible, else disk.
    pub fn read<H: Host>(
        &mut self,
        host: &mut H,
        disk: DiskId,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        let mut got = 0usize;
        let mut pos = offset;
        while got < buf.len() {
            let len = (buf.len() - got) as u64;
            // dirty page covering `pos`?
            let hit = self
                .dirty
                .range(..=(disk, pos))
                .next_back()
                .filter(|((d, o), v)| *d == disk && *o <= pos && pos < *o + v.len() as u64)
                .map(|((_, o), v)| (o, v.clone()));
            if let Some((page_off, page)) = hit {
                let in_page = (pos - page_off) as usize;
                let take = core::cmp::min(len as usize, page.len() - in_page);
                buf[got..got + take].copy_from_slice(&page[in_page..in_page + take]);
                got += take;
                pos += take as u64;
                self.stats.read_hits += take as u64;
            } else {
                // read from disk
                let n = host.disk_read(disk, pos, &mut buf[got..])?;
                if n == 0 {
                    break;
                }
                got += n;
                pos += n as u64;
                self.stats.read_ops += 1;
                self.stats.read_bytes += n as u64;
            }
        }
        Ok(got)
    }

    /// Flush everything (sorted, coalesced).
    pub fn flush<H: Host>(&mut self, host: &mut H) -> Result<()> {
        self.flush_oldest(host, u64::MAX)?;
        debug_assert!(self.dirty.is_empty());
        Ok(())
    }

    /// Flush all dirty data for one file.
    pub fn flush_disk<H: Host>(&mut self, host: &mut H, disk: DiskId) -> Result<()> {
        let keys: alloc::vec::Vec<(DiskId, u64)> = self
            .dirty
            .range((disk, 0)..=(disk, u64::MAX))
            .map(|(k, _)| *k)
            .collect();
        for k in keys {
            let data = self.dirty.remove(&k).ok_or(Error::Internal)?;
            self.used -= data.len() as u64;
            host.disk_write(k.0, k.1, &data)?;
            self.stats.write_ops += 1;
            self.stats.write_bytes += data.len() as u64;
        }
        Ok(())
    }

    /// Flush oldest entries until at least `min_freed` bytes are freed
    /// (or the cache is empty). Writes are merged across contiguous runs.
    fn flush_oldest<H: Host>(&mut self, host: &mut H, min_freed: u64) -> Result<u64> {
        let mut freed = 0u64;
        // build a batch of contiguous runs from the oldest entries
        let mut batch: Vec<(DiskId, u64, Vec<u8>)> = Vec::new();
        let keys: alloc::vec::Vec<(DiskId, u64)> = self.dirty.keys().copied().collect();
        for k in keys {
            if freed >= min_freed {
                break;
            }
            if let Some(data) = self.dirty.remove(&k) {
                self.used -= data.len() as u64;
                freed += data.len() as u64;
                // merge with a previous contiguous run?
                if let Some(last) = batch.last_mut() {
                    if last.0 == k.0 && last.1 + last.2.len() as u64 == k.1 {
                        last.2.extend_from_slice(&data);
                        self.stats.ops_saved += 1;
                        continue;
                    }
                }
                batch.push((k.0, k.1, data));
            }
        }
        for (d, o, data) in batch {
            host.disk_write(d, o, &data)?;
            self.stats.write_ops += 1;
            self.stats.write_bytes += data.len() as u64;
        }
        Ok(freed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error as E;
    use crate::platform::{ConnId, LogLevel, NetAddr};
    use alloc::collections::BTreeMap;

    /// In-memory host for tests.
    struct MemHost {
        files: BTreeMap<DiskId, Vec<u8>>,
        next_disk: DiskId,
    }

    impl MemHost {
        fn new() -> Self {
            MemHost {
                files: BTreeMap::new(),
                next_disk: 1,
            }
        }
        fn data(&self, id: DiskId) -> &[u8] {
            self.files.get(&id).map(|v| v.as_slice()).unwrap_or(&[])
        }
    }

    impl Host for MemHost {
        fn now_ms(&self) -> u64 {
            0
        }
        fn fill_random(&mut self, _buf: &mut [u8]) {}
        fn log(&mut self, _l: LogLevel, _m: &str) {}
        fn http_get(&mut self, _u: &str, _t: u64, _o: &mut alloc::vec::Vec<u8>) -> Result<()> {
            Ok(())
        }
        fn tcp_connect(&mut self, _a: &NetAddr) -> Result<ConnId> {
            Err(E::NotSupported)
        }
        fn tcp_connect_done(&mut self, _id: ConnId) -> Result<()> {
            Err(E::NotSupported)
        }
        fn tcp_send(&mut self, _id: ConnId, _d: &[u8]) -> Result<usize> {
            Err(E::NotSupported)
        }
        fn tcp_recv(&mut self, _id: ConnId, _b: &mut [u8]) -> Result<usize> {
            Err(E::NotSupported)
        }
        fn tcp_close(&mut self, _id: ConnId) {}
        fn udp_open(&mut self, _p: u16) -> Result<()> {
            Ok(())
        }
        fn udp_send(&mut self, _a: &NetAddr, _d: &[u8]) -> Result<()> {
            Ok(())
        }
        fn udp_recv(&mut self, _b: &mut [u8]) -> Result<(NetAddr, usize)> {
            Err(E::WouldBlock)
        }
        fn disk_open(&mut self, _p: &str) -> Result<DiskId> {
            let id = self.next_disk;
            self.next_disk += 1;
            self.files.insert(id, Vec::new());
            Ok(id)
        }
        fn disk_read(&mut self, id: DiskId, offset: u64, buf: &mut [u8]) -> Result<usize> {
            let f = self.files.get(&id).ok_or(E::NotFound)?;
            let start = offset as usize;
            if start >= f.len() {
                return Ok(0);
            }
            let n = core::cmp::min(buf.len(), f.len() - start);
            buf[..n].copy_from_slice(&f[start..start + n]);
            Ok(n)
        }
        fn disk_write(&mut self, id: DiskId, offset: u64, data: &[u8]) -> Result<()> {
            let f = self.files.get_mut(&id).ok_or(E::NotFound)?;
            let start = offset as usize;
            if start + data.len() > f.len() {
                f.resize(start + data.len(), 0);
            }
            f[start..start + data.len()].copy_from_slice(data);
            Ok(())
        }
        fn disk_prealloc(&mut self, id: DiskId, size: u64) -> Result<()> {
            let f = self.files.get_mut(&id).ok_or(E::NotFound)?;
            f.resize(size as usize, 0);
            Ok(())
        }
        fn disk_flush(&mut self, _id: DiskId) -> Result<()> {
            Ok(())
        }
        fn disk_close(&mut self, _id: DiskId) {}
    }

    fn file_of(host: &MemHost, id: DiskId) -> Vec<u8> {
        host.data(id).to_vec()
    }

    #[test]
    fn coalesces_contiguous_writes() {
        let mut host = MemHost::new();
        let d = host.disk_open("f").unwrap();
        let mut cache = DiskCache::new(1 << 20);
        // write blocks 0..4 of a 16 KiB block stream, one at a time
        for i in 0..4u64 {
            let data = vec![i as u8; 16384];
            cache.write(&mut host, d, i * 16384, &data).unwrap();
        }
        assert_eq!(cache.used(), 4 * 16384);
        assert_eq!(cache.dirty.len(), 1); // merged into one run
        cache.flush(&mut host).unwrap();
        assert_eq!(cache.stats.write_ops, 1); // single disk write!
        let f = file_of(&host, d);
        assert_eq!(f.len(), 4 * 16384);
        for i in 0..4u64 {
            let start = (i * 16384) as usize;
            assert_eq!(f[start], i as u8);
        }
    }

    #[test]
    fn read_serves_from_cache() {
        let mut host = MemHost::new();
        let d = host.disk_open("f").unwrap();
        let mut cache = DiskCache::new(1 << 20);
        cache.write(&mut host, d, 0, &[9u8; 100]).unwrap();
        // nothing on disk yet
        assert_eq!(host.data(d).len(), 0);
        let mut buf = [0u8; 50];
        let n = cache.read(&mut host, d, 25, &mut buf).unwrap();
        assert_eq!(n, 50);
        assert!(buf.iter().all(|&b| b == 9));
        // no disk read happened for the cached portion
        assert_eq!(cache.stats.read_ops, 0);
    }

    #[test]
    fn flushes_under_pressure() {
        let mut host = MemHost::new();
        let d = host.disk_open("f").unwrap();
        // minimum budget is 1 MiB (clamped in `new`); use that as the cap
        let budget = 1 << 20;
        let mut cache = DiskCache::new(budget);
        // write 8 MiB in 16 KiB blocks
        for i in 0..512u64 {
            cache
                .write(&mut host, d, i * 16384, &vec![(i % 251) as u8; 16384])
                .unwrap();
        }
        // cache stayed bounded
        assert!(
            cache.used() <= budget,
            "used={} budget={} dirty_entries={}",
            cache.used(),
            budget,
            cache.dirty.len()
        );
        // everything eventually on disk
        cache.flush(&mut host).unwrap();
        let f = file_of(&host, d);
        assert_eq!(f.len(), 8 << 20);
        assert_eq!(f[0], 0);
        // last block is index 511 => value = 511 % 251 = 9
        assert_eq!(f[(8 << 20) - 1], 9);
    }

    #[test]
    fn flush_disk_only_one_file() {
        let mut host = MemHost::new();
        let a = host.disk_open("a").unwrap();
        let b = host.disk_open("b").unwrap();
        let mut cache = DiskCache::new(1 << 20);
        cache.write(&mut host, a, 0, &[1u8; 10]).unwrap();
        cache.write(&mut host, b, 0, &[2u8; 10]).unwrap();
        cache.flush_disk(&mut host, a).unwrap();
        assert_eq!(host.data(a).len(), 10);
        assert_eq!(host.data(b).len(), 0);
        cache.flush(&mut host).unwrap();
        assert_eq!(host.data(b).len(), 10);
    }
}
