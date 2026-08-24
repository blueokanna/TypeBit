//! Piece/block picker.
//!
//! Consumes the scheduler's per-piece utility vector plus per-piece rarity,
//! and selects (a) which piece to request from a peer and (b) which block
//! of that piece to request next. Supports the **endgame** mode that
//! prevents the classic 99% stall: once few pieces remain, duplicate
//! requests are allowed and cancelled as blocks arrive.

use crate::bitfield::Bitfield;
use crate::piece::PieceTracker;

/// Options for piece picking.
#[derive(Debug, Clone, Copy)]
pub struct PickOptions {
    /// Enable endgame (allow re-requesting in-flight pieces).
    pub endgame: bool,
}

impl Default for PickOptions {
    fn default() -> Self {
        PickOptions { endgame: false }
    }
}

/// The picker is stateless: everything it needs is passed in.
#[derive(Debug, Clone, Copy)]
pub struct Picker;

impl Picker {
    /// Pick the best piece to request from `peer_have`.
    ///
    /// `utilities` comes from the scheduler; `availability` is the per-piece
    /// peer count (used for rare-first tie-breaking). Pieces we already have
    /// or (unless endgame) already have in flight are skipped.
    pub fn pick_piece(
        tracker: &PieceTracker,
        utilities: &[i64],
        availability: &[u32],
        peer_have: &Bitfield,
        opts: PickOptions,
    ) -> Option<u32> {
        let n = tracker.piece_count();
        let max_avail = availability.iter().copied().max().unwrap_or(0);
        let mut best: Option<(i64, i64, u32)> = None; // (score, rarity, piece)
        for p in 0..n {
            if tracker.is_have(p) {
                continue;
            }
            if !opts.endgame && tracker.is_in_flight(p) {
                continue;
            }
            if !peer_have.get(p) {
                continue;
            }
            let util = utilities.get(p as usize).copied().unwrap_or(0);
            let rarity =
                (max_avail as i64) - (availability.get(p as usize).copied().unwrap_or(0) as i64);
            let score = util.saturating_mul(1024).saturating_add(rarity);
            if let Some((bs, br, _)) = best {
                if score > bs || (score == bs && rarity > br) {
                    best = Some((score, rarity, p));
                }
            } else {
                best = Some((score, rarity, p));
            }
        }
        best.map(|(_, _, p)| p)
    }

    /// Pick the next block of `piece` that is neither received nor already
    /// requested. Returns the block index.
    pub fn pick_block(
        tracker: &PieceTracker,
        piece: u32,
        total_blocks: u16,
        prefer_contiguous: bool,
    ) -> Option<u16> {
        if tracker.is_have(piece) {
            return None;
        }
        // contiguous: start scanning from the first missing position for
        // locality; otherwise from a pseudo-random-ish offset derived from
        // the piece index to spread load.
        let start = if prefer_contiguous {
            0u16
        } else {
            (piece % 97) as u16 % total_blocks.max(1)
        };
        for i in 0..total_blocks {
            let b = (start + i) % total_blocks;
            if !tracker.block_received(piece, b) && !tracker.block_requested(piece, b) {
                return Some(b);
            }
        }
        None
    }

    /// Whether endgame should activate: the number of not-yet-have pieces
    /// is below the threshold.
    pub fn should_endgame(tracker: &PieceTracker, threshold: u32) -> bool {
        tracker.outstanding_pieces() <= threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::piece::PieceTracker;

    #[test]
    fn picks_utility_winner() {
        let t = PieceTracker::new(8, 16 * 1024);
        let mut peer = Bitfield::new(8);
        peer.set(3);
        peer.set(5);
        let util = [0i64, 0, 0, 100, 0, 90, 0, 0];
        let avail = [0u32; 8];
        let p = Picker::pick_piece(&t, &util, &avail, &peer, PickOptions::default()).unwrap();
        assert_eq!(p, 3);
    }

    #[test]
    fn respects_have_and_peer() {
        let mut t = PieceTracker::new(4, 16 * 1024);
        t.mark_piece_have(0);
        let mut peer = Bitfield::new(4);
        peer.set(0);
        peer.set(1);
        let util = [0i64; 4];
        let avail = [0u32; 4];
        let p = Picker::pick_piece(&t, &util, &avail, &peer, PickOptions::default()).unwrap();
        assert_eq!(p, 1);
    }

    #[test]
    fn block_selection_skips_requested() {
        let mut t = PieceTracker::new(4, 32 * 1024);
        t.mark_block_received(0, 0, 2);
        t.mark_block_requested(0, 1, 2);
        assert_eq!(Picker::pick_block(&t, 0, 2, true), None);
        // free it up
        t.clear_block_requested(0, 1, 2);
        assert_eq!(Picker::pick_block(&t, 0, 2, true), Some(1));
    }
}
