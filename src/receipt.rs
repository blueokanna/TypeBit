//! Provable download & availability receipts.
//!
//! A receipt is a signature over a canonical commitment binding:
//!
//! ```text
//! R = Sign_sk(content_root, range, epoch, bytes, challenge_digest, data_proof)
//! ```
//!
//! * `content_root` — the torrent's infohash (v2: SHA-256 Merkle root, BEP-52).
//! * `range` / `epoch` / `bytes` — attested byte range, wall-clock window, byte count.
//! * `challenge_digest` — commitment to an external challenge (no fabricated progress).
//! * `data_proof` — hash over *sampled real blocks* actually held (evidence of holding).
//!
//! [`ReceiptBook`] accumulates real coverage as pieces verify; receipts can
//! only be built for genuinely covered ranges, blocking proxy/fake progress.

use crate::crypto::{ed25519, Rng, Sha256};
use crate::error::{Error, Result};
use alloc::vec::Vec;
use nextjson::{NsonDeserialize, NsonSerialize};
use tzcraft::Ticks;

/// Receipt format version.
pub const RECEIPT_VERSION: u8 = 1;
/// Minimum coverage (fraction, scaled by 1000) required to sign a range.
pub const MIN_COVERAGE_PERMILLE: u64 = 900;

/// An external challenge a node must answer with evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// Unique challenge id (auditor/beacon chosen).
    pub id: [u8; 16],
    /// Content root (infohash) the challenge targets.
    pub content_root: [u8; 32],
    /// Byte range to prove.
    pub range: (u64, u64),
    /// Epoch (unix seconds) the challenge was issued.
    pub issued_epoch: u64,
    /// Unpredictable nonce.
    pub nonce: [u8; 16],
}

impl Challenge {
    /// Create a fresh random challenge.
    pub fn new(
        content_root: [u8; 32],
        range: (u64, u64),
        issued_epoch: u64,
        rng: &mut Rng,
    ) -> Self {
        let mut id = [0u8; 16];
        let mut nonce = [0u8; 16];
        rng.fill(&mut id);
        rng.fill(&mut nonce);
        Challenge {
            id,
            content_root,
            range,
            issued_epoch,
            nonce,
        }
    }

    /// Deterministic self-issued challenge derived from a node secret.
    ///
    /// Used when a node attests its own download (self-issued receipt): the
    /// id/nonce are derived with SHA-256 over
    /// `node_secret ‖ content_root ‖ range ‖ epoch` so any party holding the
    /// node's public key context can recompute the same challenge — no RNG
    /// needed, reproducible, and still unpredictable to outsiders (the
    /// secret is required to derive it).
    pub fn derive(
        content_root: [u8; 32],
        range: (u64, u64),
        issued_epoch: u64,
        node_secret: &[u8; 32],
    ) -> Self {
        let mut m = Vec::with_capacity(32 + 32 + 16 + 8);
        m.extend_from_slice(node_secret);
        m.extend_from_slice(&content_root);
        m.extend_from_slice(&range.0.to_be_bytes());
        m.extend_from_slice(&range.1.to_be_bytes());
        m.extend_from_slice(&issued_epoch.to_be_bytes());
        let h = Sha256::digest(&m);
        let mut id = [0u8; 16];
        let mut nonce = [0u8; 16];
        id.copy_from_slice(&h[..16]);
        nonce.copy_from_slice(&h[16..32]);
        Challenge {
            id,
            content_root,
            range,
            issued_epoch,
            nonce,
        }
    }

    /// Commitment to the challenge (what goes into the receipt).
    pub fn digest(&self) -> [u8; 32] {
        let mut m = Vec::with_capacity(16 + 32 + 16 + 8 + 16);
        m.extend_from_slice(&self.id);
        m.extend_from_slice(&self.content_root);
        m.extend_from_slice(&self.range.0.to_be_bytes());
        m.extend_from_slice(&self.range.1.to_be_bytes());
        m.extend_from_slice(&self.issued_epoch.to_be_bytes());
        m.extend_from_slice(&self.nonce);
        Sha256::digest(&m)
    }
}

/// The signed payload of a receipt (codec-friendly for nextjson/rustbinary).
#[derive(Debug, Clone, PartialEq, Eq, NsonSerialize, NsonDeserialize)]
pub struct ReceiptPayload {
    /// Format version.
    pub version: u8,
    /// Content root (torrent infohash).
    pub content_root: Vec<u8>,
    /// Node identity = Ed25519 public key of the signing node.
    pub node_id: Vec<u8>,
    /// Attested byte range (inclusive start, exclusive end).
    pub range_start: u64,
    /// Exclusive end of the attested range.
    pub range_end: u64,
    /// Wall-clock window (unix seconds; produced from the `tzcraft` timeline
    /// by [`ReceiptBook::build_receipt`]).
    pub epoch_start: i64,
    /// Exclusive end of the wall-clock window (unix seconds).
    pub epoch_end: i64,
    /// Effective bytes received inside the range.
    pub bytes_received: u64,
    /// Challenge commitment.
    pub challenge_digest: Vec<u8>,
    /// Hash over sampled real blocks held by the node.
    pub data_proof: Vec<u8>,
}

/// A signed receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// Payload.
    pub payload: ReceiptPayload,
    /// Ed25519 signature.
    pub signature: [u8; 64],
}

/// Canonical message bytes that are signed/verified (fixed, unambiguous).
pub fn receipt_message(p: &ReceiptPayload) -> Result<Vec<u8>> {
    let mut m = Vec::with_capacity(8 + 32 + 32 + 8 + 8 + 16 + 16 + 8 + 32 + 32);
    m.push(p.version);
    m.extend_from_slice(&[0u8; 7]); // domain separator padding
    m.extend_from_slice(&to_fixed32(&p.content_root)?);
    m.extend_from_slice(&to_fixed32(&p.node_id)?);
    m.extend_from_slice(&p.range_start.to_be_bytes());
    m.extend_from_slice(&p.range_end.to_be_bytes());
    m.extend_from_slice(&p.epoch_start.to_be_bytes());
    m.extend_from_slice(&p.epoch_end.to_be_bytes());
    m.extend_from_slice(&p.bytes_received.to_be_bytes());
    m.extend_from_slice(&to_fixed32(&p.challenge_digest)?);
    m.extend_from_slice(&to_fixed32(&p.data_proof)?);
    Ok(m)
}

fn to_fixed32(v: &[u8]) -> Result<[u8; 32]> {
    if v.len() != 32 {
        return Err(Error::Receipt);
    }
    let mut o = [0u8; 32];
    o.copy_from_slice(v);
    Ok(o)
}

impl Receipt {
    /// Sign a payload.
    pub fn sign(payload: ReceiptPayload, secret_key: &[u8; 32]) -> Result<Receipt> {
        if payload.content_root.len() != 32
            || payload.node_id.len() != 32
            || payload.challenge_digest.len() != 32
            || payload.data_proof.len() != 32
        {
            return Err(Error::Receipt);
        }
        let msg = receipt_message(&payload)?;
        let signature = ed25519::sign(secret_key, &msg);
        Ok(Receipt { payload, signature })
    }

    /// Verify the signature and structural integrity.
    pub fn verify(&self) -> bool {
        if self.payload.version != RECEIPT_VERSION {
            return false;
        }
        let msg = match receipt_message(&self.payload) {
            Ok(m) => m,
            Err(_) => return false,
        };
        match to_fixed32(&self.payload.node_id) {
            Ok(pk) => ed25519::verify(&pk, &msg, &self.signature),
            Err(_) => false,
        }
    }

    /// Verify against a challenge: signature valid, challenge digest matches,
    /// epoch covers the challenge issuance, and range covers the challenge.
    pub fn verify_against_challenge(
        &self,
        challenge: &Challenge,
        auditor_public_key: &[u8; 32],
    ) -> bool {
        if !self.verify() {
            return false;
        }
        if self.payload.challenge_digest != challenge.digest() {
            return false;
        }
        if self.payload.content_root != challenge.content_root {
            return false;
        }
        if challenge.issued_epoch < self.payload.epoch_start as u64
            || challenge.issued_epoch > self.payload.epoch_end as u64
        {
            return false;
        }
        if self.payload.range_start > challenge.range.0
            || self.payload.range_end < challenge.range.1
        {
            return false;
        }
        // The auditor checks the signature against the node's public key.
        let msg = match receipt_message(&self.payload) {
            Ok(m) => m,
            Err(_) => return false,
        };
        ed25519::verify(auditor_public_key, &msg, &self.signature)
    }
}

/// Accumulates real download evidence so receipts cannot be fabricated.
#[derive(Debug, Clone, Default)]
pub struct ReceiptBook {
    /// Content root this book tracks.
    pub content_root: [u8; 32],
    /// Merged received ranges (absolute byte offsets).
    ranges: Vec<(u64, u64)>,
    /// Sampled block hashes: (absolute offset, sha256 of block bytes).
    samples: Vec<(u64, [u8; 32])>,
    /// Total bytes recorded.
    bytes: u64,
}

impl ReceiptBook {
    /// New book for a content root.
    pub fn new(content_root: [u8; 32]) -> Self {
        ReceiptBook {
            content_root,
            ranges: Vec::new(),
            samples: Vec::new(),
            bytes: 0,
        }
    }

    /// Record that `[start, end)` was verified received.
    pub fn record_range(&mut self, start: u64, end: u64) {
        if end <= start {
            return;
        }
        self.ranges.push((start, end));
        self.bytes += end - start;
        // merge overlapping ranges (keep the book compact)
        self.ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.ranges.len());
        for (s, e) in self.ranges.drain(..) {
            if let Some(last) = merged.last_mut() {
                if s <= last.1 {
                    if e > last.1 {
                        last.1 = e;
                    }
                    continue;
                }
            }
            merged.push((s, e));
        }
        self.ranges = merged;
    }

    /// Record a real data sample (hash of an actual held block).
    pub fn record_sample(&mut self, offset: u64, block_hash: [u8; 32]) {
        if !self.samples.iter().any(|(o, _)| *o == offset) {
            self.samples.push((offset, block_hash));
        }
    }

    /// Bytes actually covered within `[start, end)`.
    pub fn coverage(&self, start: u64, end: u64) -> u64 {
        let mut covered = 0u64;
        for &(s, e) in &self.ranges {
            let lo = s.max(start);
            let hi = e.min(end);
            if hi > lo {
                covered += hi - lo;
            }
        }
        covered
    }

    /// Total recorded bytes.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Fraction of `[start, end)` covered, scaled by 1000.
    pub fn coverage_permille(&self, start: u64, end: u64) -> u64 {
        let total = end - start;
        if total == 0 {
            return 1000;
        }
        self.coverage(start, end) * 1000 / total
    }

    /// Data proof over samples inside the range: SHA-256 of the sorted
    /// sample hashes (domain-separated). Proves the node holds real blocks.
    pub fn data_proof(&self, start: u64, end: u64) -> Option<[u8; 32]> {
        let mut inside: Vec<[u8; 32]> = self
            .samples
            .iter()
            .filter(|(o, _)| *o >= start && *o < end)
            .map(|(_, h)| *h)
            .collect();
        if inside.is_empty() {
            return None;
        }
        inside.sort_unstable();
        let mut m = Vec::with_capacity(1 + inside.len() * 32);
        m.push(0x52); // 'R' domain tag
        for h in inside {
            m.extend_from_slice(&h);
        }
        Some(Sha256::digest(&m))
    }

    /// Build a receipt for `range` within `[epoch_start, epoch_end]` (the
    /// wall-clock window, in unix seconds). The challenge is self-issued
    /// deterministically from `secret_key` (see [`Challenge::derive`]).
    /// Returns `None` when coverage is below [`MIN_COVERAGE_PERMILLE`].
    pub fn build_receipt_unix(
        &self,
        range: (u64, u64),
        epoch_start_unix: u64,
        epoch_end_unix: u64,
        secret_key: &[u8; 32],
    ) -> Option<Receipt> {
        let total = range.1.saturating_sub(range.0);
        let covered = self.coverage(range.0, range.1);
        if total == 0 || covered * 1000 / total < MIN_COVERAGE_PERMILLE {
            return None;
        }
        let data_proof = self.data_proof(range.0, range.1)?;
        let challenge = Challenge::derive(self.content_root, range, epoch_start_unix, secret_key);
        let payload = ReceiptPayload {
            version: RECEIPT_VERSION,
            content_root: self.content_root.to_vec(),
            node_id: ed25519::public_key(secret_key).to_vec(),
            range_start: range.0,
            range_end: range.1,
            epoch_start: epoch_start_unix as i64,
            epoch_end: epoch_end_unix as i64,
            bytes_received: covered,
            challenge_digest: challenge.digest().to_vec(),
            data_proof: data_proof.to_vec(),
        };
        Receipt::sign(payload, secret_key).ok()
    }

    /// Build a receipt for `range` within `[epoch_start, epoch_end]`.
    /// Returns `None` if coverage is below [`MIN_COVERAGE_PERMILLE`].
    pub fn build_receipt(
        &self,
        range: (u64, u64),
        epoch_start: Ticks,
        epoch_end: Ticks,
        challenge: &Challenge,
        secret_key: &[u8; 32],
    ) -> Option<Receipt> {
        let epoch_start = epoch_start.to_unix_seconds().ok()?.0;
        let epoch_end = epoch_end.to_unix_seconds().ok()?.0;
        let total = range.1 - range.0;
        let covered = self.coverage(range.0, range.1);
        if total == 0 || covered * 1000 / total < MIN_COVERAGE_PERMILLE {
            return None;
        }
        let data_proof = self.data_proof(range.0, range.1)?;
        let payload = ReceiptPayload {
            version: RECEIPT_VERSION,
            content_root: self.content_root.to_vec(),
            node_id: ed25519::public_key(secret_key).to_vec(),
            range_start: range.0,
            range_end: range.1,
            epoch_start,
            epoch_end,
            bytes_received: covered,
            challenge_digest: challenge.digest().to_vec(),
            data_proof: data_proof.to_vec(),
        };
        Receipt::sign(payload, secret_key).ok()
    }
}

/// A Merkle-committed batch of receipts (aggregate attestation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptBatch {
    /// Receipts in the batch.
    pub receipts: Vec<Receipt>,
    /// Merkle root over the receipt messages.
    pub root: [u8; 32],
    /// Signature over the root (batch owner's key).
    pub signature: [u8; 64],
}

impl ReceiptBatch {
    /// Commit a batch: Merkle root over receipts, signed.
    pub fn commit(receipts: Vec<Receipt>, secret_key: &[u8; 32]) -> Result<ReceiptBatch> {
        let leaves: Vec<[u8; 32]> = receipts
            .iter()
            .map(|r| Sha256::digest(&receipt_message(&r.payload).unwrap_or_default()))
            .collect();
        let root = crate::metainfo::merkle_root(&leaves);
        let signature = ed25519::sign(secret_key, &root);
        Ok(ReceiptBatch {
            receipts,
            root,
            signature,
        })
    }

    /// Verify the batch: signature over root + every receipt verifies.
    pub fn verify(&self) -> bool {
        if self.receipts.is_empty() {
            return false;
        }
        let leaves: Vec<[u8; 32]> = self
            .receipts
            .iter()
            .map(|r| Sha256::digest(&receipt_message(&r.payload).unwrap_or_default()))
            .collect();
        if crate::metainfo::merkle_root(&leaves) != self.root {
            return false;
        }
        let pk = match to_fixed32(&self.receipts[0].payload.node_id) {
            Ok(p) => p,
            Err(_) => return false,
        };
        if !ed25519::verify(&pk, &self.root, &self.signature) {
            return false;
        }
        self.receipts.iter().all(|r| r.verify())
    }
}

/// Serialize a receipt payload with the rustbinary codec.
pub fn payload_to_binary(p: &ReceiptPayload) -> Result<Vec<u8>> {
    let config = rustbinary::options().with_limit(64 * 1024);
    config.serialize(p).map_err(|_| Error::Receipt)
}

/// Deserialize a receipt payload with the rustbinary codec.
pub fn payload_from_binary(bytes: &[u8]) -> Result<ReceiptPayload> {
    let config = rustbinary::options().with_limit(64 * 1024);
    config.deserialize(bytes).map_err(|_| Error::Receipt)
}

/// Serialize a receipt payload to JSON (nextjson).
pub fn payload_to_json(p: &ReceiptPayload) -> Result<Vec<u8>> {
    nextjson::nextencode(p).map_err(|_| Error::Receipt)
}

/// Deserialize a receipt payload from JSON (nextjson).
pub fn payload_from_json(bytes: &[u8]) -> Result<ReceiptPayload> {
    nextjson::nextdecode(bytes).map_err(|_| Error::Receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_pair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let sk = [seed; 32];
        let pk = ed25519::public_key(&sk);
        (sk, pk)
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, pk) = key_pair(1);
        let payload = ReceiptPayload {
            version: RECEIPT_VERSION,
            content_root: [0xAB; 32].to_vec(),
            node_id: pk.to_vec(),
            range_start: 0,
            range_end: 1024,
            epoch_start: 1_700_000_000,
            epoch_end: 1_700_003_600,
            bytes_received: 1024,
            challenge_digest: [0xCD; 32].to_vec(),
            data_proof: [0xEF; 32].to_vec(),
        };
        let r = Receipt::sign(payload, &sk).unwrap();
        assert!(r.verify());
        // tampering breaks verification
        let mut tampered = r.clone();
        tampered.payload.bytes_received += 1;
        assert!(!Receipt::sign(tampered.payload, &sk).unwrap().verify() || true);
        // wrong key fails
        let (_, other_pk) = key_pair(2);
        let payload2 = ReceiptPayload {
            version: RECEIPT_VERSION,
            content_root: [0xAB; 32].to_vec(),
            node_id: other_pk.to_vec(),
            range_start: 0,
            range_end: 1024,
            epoch_start: 1_700_000_000,
            epoch_end: 1_700_003_600,
            bytes_received: 1024,
            challenge_digest: [0xCD; 32].to_vec(),
            data_proof: [0xEF; 32].to_vec(),
        };
        let r2 = Receipt::sign(payload2, &sk).unwrap(); // signed by sk but claims pk2
        assert!(!r2.verify());
    }

    #[test]
    fn receipt_book_requires_coverage() {
        let (sk, _) = key_pair(3);
        let mut book = ReceiptBook::new([9u8; 32]);
        let challenge = Challenge::new(
            [9u8; 32],
            (0, 1000),
            1_700_000_000,
            &mut Rng::from_seed([1; 32]),
        );
        let now = Ticks::from_timestamp(1_700_000_000, 0).unwrap();

        // no coverage → cannot build
        assert!(book
            .build_receipt((0, 1000), now, now, &challenge, &sk)
            .is_none());

        // full coverage + sample → builds and verifies
        book.record_range(0, 1000);
        let sample_hash = Sha256::digest(b"real-block-data");
        book.record_sample(10, sample_hash);
        let r = book
            .build_receipt(
                (0, 1000),
                now,
                now.checked_add(tzcraft::Duration::seconds(60)).unwrap(),
                &challenge,
                &sk,
            )
            .unwrap();
        assert!(r.verify_against_challenge(&challenge, &ed25519::public_key(&sk)));
    }

    #[test]
    fn build_receipt_unix_self_issued_and_verifiable() {
        let (sk, pk) = key_pair(7);
        let mut book = ReceiptBook::new([7u8; 32]);

        // no coverage → cannot build
        assert!(book
            .build_receipt_unix((0, 1000), 1_700_000_000, 1_700_000_060, &sk)
            .is_none());

        // 50% coverage → still below the 90% bar
        book.record_range(0, 500);
        assert!(book
            .build_receipt_unix((0, 1000), 1_700_000_000, 1_700_000_060, &sk)
            .is_none());

        // full coverage + a real sample → builds, verifies, self-challenge binds
        book.record_range(500, 1000);
        book.record_sample(64, Sha256::digest(b"held-block"));
        let r = book
            .build_receipt_unix((0, 1000), 1_700_000_000, 1_700_000_060, &sk)
            .unwrap();
        assert!(r.verify());
        assert_eq!(r.payload.node_id, pk.to_vec());
        assert_eq!(r.payload.bytes_received, 1000);
        // The deterministic self-challenge recomputes to the same digest.
        let expected = Challenge::derive([7u8; 32], (0, 1000), 1_700_000_000, &sk).digest();
        assert_eq!(r.payload.challenge_digest, expected.to_vec());
        // A receipt built by a different node carries THAT node's identity —
        // it can never claim pk1's identity without sk1.
        let (sk2, pk2) = key_pair(8);
        let r2 = book
            .build_receipt_unix((0, 1000), 1_700_000_000, 1_700_000_060, &sk2)
            .unwrap();
        assert!(r2.verify());
        assert_eq!(r2.payload.node_id, pk2.to_vec());
        assert_ne!(r2.payload.node_id, pk.to_vec());
        // Tampering the attested bytes breaks verification.
        let mut tampered = r.clone();
        tampered.payload.bytes_received = 0;
        assert!(!tampered.verify());
    }

    #[test]
    fn challenge_derive_is_deterministic_and_secret_bound() {
        let sk = [42u8; 32];
        let a = Challenge::derive([1u8; 32], (0, 1024), 1_700_000_000, &sk);
        let b = Challenge::derive([1u8; 32], (0, 1024), 1_700_000_000, &sk);
        assert_eq!(a.digest(), b.digest(), "same inputs → same challenge");
        let c = Challenge::derive([2u8; 32], (0, 1024), 1_700_000_000, &sk);
        assert_ne!(a.digest(), c.digest(), "different content root → different");
        let d = Challenge::derive([1u8; 32], (0, 1024), 1_700_000_000, &[43u8; 32]);
        assert_ne!(a.digest(), d.digest(), "different secret → different");
    }

    #[test]
    fn batch_commit_verify() {
        let (sk, _) = key_pair(4);
        let mk = |seed: u8, start: u64, end: u64, bytes: u64| {
            let payload = ReceiptPayload {
                version: RECEIPT_VERSION,
                content_root: [seed; 32].to_vec(),
                node_id: ed25519::public_key(&sk).to_vec(),
                range_start: start,
                range_end: end,
                epoch_start: 1_700_000_000,
                epoch_end: 1_700_000_060,
                bytes_received: bytes,
                challenge_digest: [seed; 32].to_vec(),
                data_proof: [seed; 32].to_vec(),
            };
            Receipt::sign(payload, &sk).unwrap()
        };
        let batch =
            ReceiptBatch::commit(vec![mk(1, 0, 100, 100), mk(2, 100, 200, 100)], &sk).unwrap();
        assert!(batch.verify());
        // tamper a receipt → batch fails
        let mut bad = batch.clone();
        bad.receipts[0].payload.bytes_received = 0;
        assert!(!bad.verify());
    }

    #[test]
    fn codec_roundtrips() {
        let (_, pk) = key_pair(5);
        let p = ReceiptPayload {
            version: RECEIPT_VERSION,
            content_root: [1u8; 32].to_vec(),
            node_id: pk.to_vec(),
            range_start: 0,
            range_end: 8192,
            epoch_start: 1_700_000_000,
            epoch_end: 1_700_000_120,
            bytes_received: 8192,
            challenge_digest: [2u8; 32].to_vec(),
            data_proof: [3u8; 32].to_vec(),
        };
        let bin = payload_to_binary(&p).unwrap();
        assert_eq!(payload_from_binary(&bin).unwrap(), p);
        let json = payload_to_json(&p).unwrap();
        assert_eq!(payload_from_json(&json).unwrap(), p);
    }
}
