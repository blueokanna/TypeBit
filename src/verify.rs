//! Piece hash verification, optionally offloaded to a `std` worker pool so
//! the engine loop keeps pumping I/O while SHA-1 / SHA-256 runs on other
//! cores. Under `no_std`, [`VerifyPool`] is a no-op handle (inline
//! verification). Both paths share the pure [`verify_piece`] function, so
//! pooled and inline results are guaranteed identical.

use crate::metainfo::{InfoHash, TorrentKind};
use alloc::vec::Vec;

/// Which hash to check a piece against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    /// v1: SHA-1 of the whole piece.
    Sha1,
    /// v2: Merkle root of the 16 KiB block SHA-256s (BEP-52).
    Sha256Merkle,
}

impl From<TorrentKind> for HashKind {
    fn from(k: TorrentKind) -> Self {
        match k {
            TorrentKind::V1 => HashKind::Sha1,
            TorrentKind::V2 | TorrentKind::Hybrid => HashKind::Sha256Merkle,
        }
    }
}

/// A verification task (all data owned, so it can cross threads freely).
pub struct VerifyJob {
    /// Owning torrent (routes the result back to its session).
    pub torrent: InfoHash,
    /// Piece index.
    pub piece: u32,
    /// Expected piece length.
    pub len: u32,
    /// Hash kind.
    pub kind: HashKind,
    /// Expected hash bytes (20 for v1, 32 for v2).
    pub expect: Vec<u8>,
    /// Assembled piece bytes.
    pub data: Vec<u8>,
}

/// Outcome of a verification task. `data` travels back so the engine can
/// write the verified piece to disk.
pub struct VerifyResult {
    /// Owning torrent.
    pub torrent: InfoHash,
    /// Piece index.
    pub piece: u32,
    /// Whether the hash matched.
    pub ok: bool,
    /// The piece bytes.
    pub data: Vec<u8>,
}

/// Verify piece bytes against the expected hash. Pure and thread-safe;
/// shared by the inline path and the worker pool.
pub fn verify_piece(kind: HashKind, len: u32, data: &[u8], expect: &[u8]) -> bool {
    if data.len() != len as usize {
        return false;
    }
    match kind {
        HashKind::Sha1 => expect.len() == 20 && crate::crypto::Sha1::digest(data) == expect[..20],
        HashKind::Sha256Merkle => {
            if expect.len() != 32 {
                return false;
            }
            let blocks: Vec<[u8; 32]> = data
                .chunks(crate::consts::BLOCK_LEN as usize)
                .map(crate::crypto::Sha256::digest)
                .collect();
            crate::metainfo::merkle_root(&blocks) == expect[..32]
        }
    }
}

// ---------------------------------------------------------------------------
// Worker pool (real threads under `std`)
// ---------------------------------------------------------------------------

#[cfg(feature = "std")]
mod pool {
    use super::{VerifyJob, VerifyResult};
    use alloc::vec::Vec;
    use std::sync::mpsc;

    pub(crate) struct VerifyPoolInner {
        txs: Vec<mpsc::Sender<VerifyJob>>,
        rxs: Vec<mpsc::Receiver<VerifyResult>>,
        workers: Vec<std::thread::JoinHandle<()>>,
    }

    impl VerifyPoolInner {
        pub(crate) fn spawn(workers: usize) -> Self {
            let n = workers.max(1);
            let mut txs = Vec::with_capacity(n);
            let mut rxs = Vec::with_capacity(n);
            let mut handles = Vec::with_capacity(n);
            for _ in 0..n {
                let (job_tx, job_rx) = mpsc::channel::<VerifyJob>();
                let (res_tx, res_rx) = mpsc::channel::<VerifyResult>();
                txs.push(job_tx);
                rxs.push(res_rx);
                handles.push(std::thread::spawn(move || {
                    while let Ok(job) = job_rx.recv() {
                        let ok = super::verify_piece(job.kind, job.len, &job.data, &job.expect);
                        if res_tx
                            .send(VerifyResult {
                                torrent: job.torrent,
                                piece: job.piece,
                                ok,
                                data: job.data,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                }));
            }
            VerifyPoolInner {
                txs,
                rxs,
                workers: handles,
            }
        }

        pub(crate) fn submit(&self, job: VerifyJob) {
            let idx = (job.piece as usize) % self.txs.len();
            let _ = self.txs[idx].send(job);
        }

        pub(crate) fn poll(&self) -> Option<VerifyResult> {
            for rx in &self.rxs {
                if let Ok(res) = rx.try_recv() {
                    return Some(res);
                }
            }
            None
        }
    }

    impl Drop for VerifyPoolInner {
        fn drop(&mut self) {
            // closing the senders lets the workers drain their queue and exit
            self.txs.clear();
            for w in self.workers.drain(..) {
                let _ = w.join();
            }
        }
    }
}

/// Worker pool. Under `std` this spawns real threads; under `no_std` it is
/// a no-op handle and verification stays inline.
pub struct VerifyPool {
    #[cfg(feature = "std")]
    inner: pool::VerifyPoolInner,
}

impl VerifyPool {
    /// Spawn `workers` verification threads (no-op handle under `no_std`).
    pub fn spawn(workers: usize) -> Self {
        #[cfg(feature = "std")]
        {
            VerifyPool {
                inner: pool::VerifyPoolInner::spawn(workers),
            }
        }
        #[cfg(not(feature = "std"))]
        {
            let _ = workers;
            VerifyPool {}
        }
    }

    /// Queue a verification task.
    pub fn submit(&self, job: VerifyJob) {
        #[cfg(feature = "std")]
        self.inner.submit(job);
        #[cfg(not(feature = "std"))]
        {
            let _ = job;
        }
    }

    /// Non-blocking poll for a completed result.
    pub fn poll(&self) -> Option<VerifyResult> {
        #[cfg(feature = "std")]
        {
            self.inner.poll()
        }
        #[cfg(not(feature = "std"))]
        {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_verify_matches_and_rejects() {
        let data = b"the quick brown fox".to_vec();
        let mut expect = crate::crypto::Sha1::digest(&data).to_vec();
        assert!(verify_piece(
            HashKind::Sha1,
            data.len() as u32,
            &data,
            &expect
        ));
        expect[0] ^= 0xff;
        assert!(!verify_piece(
            HashKind::Sha1,
            data.len() as u32,
            &data,
            &expect
        ));
    }

    #[test]
    fn v2_merkle_verify_matches_reference() {
        let data: Vec<u8> = (0..(48 * 1024) as u32).map(|i| (i % 251) as u8).collect();
        let blocks: Vec<[u8; 32]> = data
            .chunks(crate::consts::BLOCK_LEN as usize)
            .map(crate::crypto::Sha256::digest)
            .collect();
        let root = crate::metainfo::merkle_root(&blocks);
        assert!(verify_piece(
            HashKind::Sha256Merkle,
            data.len() as u32,
            &data,
            &root
        ));
        assert!(!verify_piece(
            HashKind::Sha256Merkle,
            (data.len() - 1) as u32,
            &data,
            &root
        ));
        let mut bad = root;
        bad[0] ^= 1;
        assert!(!verify_piece(
            HashKind::Sha256Merkle,
            data.len() as u32,
            &data,
            &bad
        ));
    }

    #[test]
    fn hash_kind_maps_torrent_kind() {
        assert_eq!(HashKind::from(TorrentKind::V1), HashKind::Sha1);
        assert_eq!(HashKind::from(TorrentKind::V2), HashKind::Sha256Merkle);
        assert_eq!(HashKind::from(TorrentKind::Hybrid), HashKind::Sha256Merkle);
    }

    #[cfg(feature = "std")]
    #[test]
    fn pool_verifies_across_workers() {
        let pool = VerifyPool::spawn(2);
        let torrent = InfoHash::v1([1u8; 20]);
        let data: Vec<u8> = (0..(16 * 1024) as u32).map(|i| (i % 251) as u8).collect();
        let expect = crate::crypto::Sha1::digest(&data).to_vec();
        for p in 0..4u32 {
            pool.submit(VerifyJob {
                torrent,
                piece: p,
                len: data.len() as u32,
                kind: HashKind::Sha1,
                expect: expect.clone(),
                data: data.clone(),
            });
        }
        let mut got = 0;
        let mut attempts = 0u32;
        while got < 4 && attempts < 100_000 {
            if let Some(res) = pool.poll() {
                assert!(res.ok, "piece {} should verify", res.piece);
                assert_eq!(res.torrent, torrent);
                assert_eq!(res.data, data);
                got += 1;
            } else {
                std::thread::yield_now();
                attempts += 1;
            }
        }
        assert_eq!(got, 4, "all four jobs must complete");
    }
}
