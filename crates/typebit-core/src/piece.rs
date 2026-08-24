//! Per-torrent piece/block state tracking.
//!
//! A torrent is split into pieces (`piece_length` bytes each, last one
//! possibly shorter); every piece is split into 16 KiB blocks. This module
//! tracks which pieces are verified-complete, which are partially received,
//! and which blocks have arrived for the in-flight pieces.

use crate::bitfield::Bitfield;
use crate::consts::BLOCK_LEN;
use crate::error::Result;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// State of a single piece.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PieceState {
    /// Nothing received.
    Missing,
    /// Some blocks received, not yet verified.
    Partial,
    /// Fully received and hash-verified.
    Have,
}

/// Tracks pieces and their blocks for one torrent.
#[derive(Debug, Clone)]
pub struct PieceTracker {
    piece_count: u32,
    piece_length: u32,
    /// Verified-complete pieces.
    have: Bitfield,
    /// Pieces with at least one block requested or received (in-flight).
    in_flight: Bitfield,
    /// Received blocks per partial piece (bitmap).
    partial: BTreeMap<u32, Bitfield>,
    /// Blocks requested from peers but not yet received (in-flight).
    requested: BTreeMap<u32, Bitfield>,
    /// Total blocks received (for stats).
    blocks_received_total: u64,
}

impl PieceTracker {
    /// Create with `piece_count` pieces of `piece_length` bytes.
    pub fn new(piece_count: u32, piece_length: u32) -> Self {
        PieceTracker {
            piece_count,
            piece_length,
            have: Bitfield::new(piece_count),
            in_flight: Bitfield::new(piece_count),
            partial: BTreeMap::new(),
            requested: BTreeMap::new(),
            blocks_received_total: 0,
        }
    }

    /// Number of pieces.
    pub fn piece_count(&self) -> u32 {
        self.piece_count
    }

    /// Piece length (bytes).
    pub fn piece_length(&self) -> u32 {
        self.piece_length
    }

    /// Number of blocks in a given piece (last piece may be shorter).
    pub fn block_count(&self, piece: u32) -> u16 {
        if piece >= self.piece_count {
            return 0;
        }
        let len = if piece + 1 == self.piece_count && self.piece_length > 0 {
            // caller must know the true last-piece size; we use piece_length
            // as an upper bound — engines override via `set_last_piece_len`.
            self.piece_length
        } else {
            self.piece_length
        };
        (len as u64).div_ceil(BLOCK_LEN as u64) as u16
    }

    /// Whether a piece is fully verified.
    pub fn is_have(&self, piece: u32) -> bool {
        self.have.get(piece)
    }

    /// Whether a piece is in-flight (blocks requested).
    pub fn is_in_flight(&self, piece: u32) -> bool {
        self.in_flight.get(piece)
    }

    /// Set in-flight flag.
    pub fn set_in_flight(&mut self, piece: u32, on: bool) {
        if on {
            self.in_flight.set(piece);
        } else {
            self.in_flight.clear(piece);
        }
    }

    /// Per-piece state.
    pub fn state(&self, piece: u32) -> PieceState {
        if self.have.get(piece) {
            PieceState::Have
        } else if self.partial.contains_key(&piece) {
            PieceState::Partial
        } else {
            PieceState::Missing
        }
    }

    /// Number of received blocks in a piece.
    pub fn blocks_received(&self, piece: u32) -> u16 {
        self.partial
            .get(&piece)
            .map(|b| b.count() as u16)
            .unwrap_or(0)
    }

    /// Whether a block has been received.
    pub fn block_received(&self, piece: u32, block: u16) -> bool {
        self.partial
            .get(&piece)
            .map(|b| b.get(block as u32))
            .unwrap_or(false)
    }

    /// Whether a block is currently requested (in-flight).
    pub fn block_requested(&self, piece: u32, block: u16) -> bool {
        self.requested
            .get(&piece)
            .map(|b| b.get(block as u32))
            .unwrap_or(false)
    }

    /// Mark a block as requested (in-flight).
    pub fn mark_block_requested(&mut self, piece: u32, block: u16, total_blocks: u16) {
        if piece >= self.piece_count || block >= total_blocks {
            return;
        }
        let entry = self
            .requested
            .entry(piece)
            .or_insert_with(|| Bitfield::new(total_blocks as u32));
        entry.set(block as u32);
        self.in_flight.set(piece);
    }

    /// Clear a block's in-flight flag (block arrived, was cancelled, or the
    /// request failed).
    pub fn clear_block_requested(&mut self, piece: u32, block: u16, total_blocks: u16) {
        if piece >= self.piece_count || block >= total_blocks {
            return;
        }
        if let Some(entry) = self.requested.get_mut(&piece) {
            entry.clear(block as u32);
            if entry.count() == 0 {
                self.requested.remove(&piece);
                self.in_flight.clear(piece);
            }
        }
    }

    /// Clear all in-flight flags for a piece (e.g. peer disconnected).
    pub fn clear_piece_requests(&mut self, piece: u32) {
        self.requested.remove(&piece);
        self.in_flight.clear(piece);
    }

    /// Mark a block as received. Returns true if it was newly received.
    pub fn mark_block_received(&mut self, piece: u32, block: u16, total_blocks: u16) -> bool {
        if piece >= self.piece_count || block >= total_blocks {
            return false;
        }
        let entry = self
            .partial
            .entry(piece)
            .or_insert_with(|| Bitfield::new(total_blocks as u32));
        if entry.get(block as u32) {
            return false;
        }
        entry.set(block as u32);
        self.blocks_received_total += 1;
        true
    }

    /// Whether all blocks of a piece have arrived (not yet hash-verified).
    pub fn piece_data_complete(&self, piece: u32, total_blocks: u16) -> bool {
        self.partial
            .get(&piece)
            .map(|b| b.count() == total_blocks as u32)
            .unwrap_or(false)
    }

    /// Mark a piece as verified-complete; clears partial bookkeeping.
    pub fn mark_piece_have(&mut self, piece: u32) {
        self.have.set(piece);
        self.in_flight.clear(piece);
        self.partial.remove(&piece);
        self.requested.remove(&piece);
    }

    /// Mark a piece as missing (e.g. after a hash failure reset).
    pub fn reset_piece(&mut self, piece: u32) {
        self.in_flight.clear(piece);
        self.partial.remove(&piece);
        self.requested.remove(&piece);
    }

    /// Count of verified pieces.
    pub fn have_count(&self) -> u32 {
        self.have.count()
    }

    /// Verified piece bitfield (network bytes).
    pub fn have_bitfield(&self) -> &Bitfield {
        &self.have
    }

    /// Total bytes downloaded (blocks received × block len).
    pub fn downloaded_bytes(&self) -> u64 {
        self.blocks_received_total * BLOCK_LEN as u64
    }

    /// Number of pieces that still need blocks (missing or partial).
    pub fn outstanding_pieces(&self) -> u32 {
        self.piece_count - self.have.count()
    }

    /// Restore `have` from network bytes.
    pub fn set_have_from_bytes(&mut self, bytes: &[u8], count: u32) -> Result<()> {
        let mut b = Bitfield::new(0);
        b.from_bytes(bytes, count)?;
        self.have = b;
        Ok(())
    }

    /// Iterate pieces that are neither have nor in-flight (candidates).
    pub fn candidates(&self) -> CandidateIter<'_> {
        CandidateIter {
            inner: self,
            next: 0,
        }
    }

    /// Serialize `have` + partial state for persistence.
    pub fn snapshot(&self) -> (Vec<u8>, Vec<(u32, Vec<u8>)>) {
        let have = self.have.to_bytes();
        let partial = self
            .partial
            .iter()
            .map(|(p, b)| (*p, b.to_bytes()))
            .collect();
        (have, partial)
    }

    /// Restore from a snapshot.
    pub fn restore(&mut self, have: &[u8], partial: &[(u32, Vec<u8>)]) -> Result<()> {
        self.have.from_bytes(have, self.piece_count)?;
        self.partial.clear();
        for (p, bytes) in partial {
            if *p >= self.piece_count {
                continue;
            }
            let total = self.block_count(*p);
            let mut b = Bitfield::new(0);
            b.from_bytes(bytes, total as u32)?;
            self.partial.insert(*p, b);
        }
        self.blocks_received_total =
            self.partial.values().map(|b| b.count() as u64).sum::<u64>() * BLOCK_LEN as u64;
        Ok(())
    }
}

/// Iterator over pieces that need downloading.
pub struct CandidateIter<'a> {
    inner: &'a PieceTracker,
    next: u32,
}

impl<'a> Iterator for CandidateIter<'a> {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        while self.next < self.inner.piece_count {
            let i = self.next;
            self.next += 1;
            if !self.inner.have.get(i) && !self.inner.in_flight.get(i) {
                return Some(i);
            }
        }
        None
    }
}

/// Compute the number of 16 KiB blocks in a piece of `piece_len` bytes.
pub fn block_count_for(piece_len: u32) -> u16 {
    (piece_len as u64).div_ceil(BLOCK_LEN as u64) as u16
}

/// Given a piece length and its data size, the block index containing
/// `offset` and its length.
pub fn block_at(piece_len: u32, offset: u32, block_len: u32) -> (u16, u32) {
    let idx = offset / block_len;
    let start = idx * block_len;
    let len = core::cmp::min(block_len, piece_len - start);
    (idx as u16, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_accounting() {
        let mut t = PieceTracker::new(4, 32 * 1024);
        assert_eq!(t.block_count(0), 2);
        assert!(t.mark_block_received(0, 0, 2)); // first time → new
        assert!(!t.mark_block_received(0, 0, 2)); // duplicate
        assert!(t.mark_block_received(0, 1, 2));
        assert!(t.piece_data_complete(0, 2));
        assert!(!t.piece_data_complete(1, 2));
        t.mark_piece_have(0);
        assert!(t.is_have(0));
        assert_eq!(t.state(1), PieceState::Missing);
        assert_eq!(t.have_count(), 1);
        assert_eq!(t.outstanding_pieces(), 3);
    }

    #[test]
    fn snapshot_roundtrip() {
        let mut t = PieceTracker::new(8, 16 * 1024);
        t.mark_block_received(2, 0, 1);
        t.mark_piece_have(5);
        let (have, partial) = t.snapshot();
        let mut t2 = PieceTracker::new(8, 16 * 1024);
        t2.restore(&have, &partial).unwrap();
        assert_eq!(t.have_bitfield(), t2.have_bitfield());
        assert_eq!(t.blocks_received(2), t2.blocks_received(2));
    }

    #[test]
    fn candidate_iteration() {
        let mut t = PieceTracker::new(5, 16 * 1024);
        t.mark_piece_have(0);
        t.set_in_flight(1, true);
        let cands: Vec<u32> = t.candidates().collect();
        assert_eq!(cands, vec![2, 3, 4]);
    }
}
