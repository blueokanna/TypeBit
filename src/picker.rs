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
#[derive(Debug, Clone, Copy, Default)]
pub struct PickOptions {
    /// Enable endgame (allow re-requesting in-flight pieces).
    pub endgame: bool,
    /// Streaming-sequential mode (边下载边播放): download the piece HEAD
    /// first, then the body strictly in file order, and only then the tail
    /// (e.g. a `moov` atom at the end of an MP4). Rarity never overrides
    /// order, so the bytes a media player needs are on disk contiguously —
    /// the player can start after the head and stream the rest as it lands.
    pub sequential: bool,
}

/// The picker is stateless: everything it needs is passed in.
#[derive(Debug, Clone, Copy)]
pub struct Picker;

impl Picker {
    /// Pick the best piece to request from a peer.
    ///
    /// `availability` (peer count) breaks rarity ties; `peer_has_all`
    /// (BEP-6) means the seed owns every piece while its bitfield is empty,
    /// so `peer_have` MUST NOT be consulted for it. `priorities` are
    /// per-piece multipliers (0 = skipped). Pieces we have, or (unless
    /// endgame) have in flight, are skipped.
    ///
    /// In [`PickOptions::sequential`] mode the score is banded by the
    /// scheduler's streaming task utility (head → body → tail) and, within
    /// a band, by piece index — so the download is contiguous and
    /// playback-ready.
    pub fn pick_piece(
        tracker: &PieceTracker,
        utilities: &[i64],
        availability: &[u32],
        peer_have: &Bitfield,
        peer_has_all: bool,
        priorities: &[i64],
        opts: PickOptions,
    ) -> Option<u32> {
        let n = tracker.piece_count();
        if opts.sequential {
            // Banded in-order pick: smallest (band, index) wins.
            //   band 0 = head (task ≥ 2500)        — playable prefix first
            //   band 1 = body (task < 2500, ≠ 2000) — strict file order
            //   band 2 = tail (task == 2000)       — moov/mux tail last
            let mut best: Option<(u8, i64, u32)> = None; // (band, index, piece)
            for p in 0..n {
                if tracker.is_have(p) {
                    continue;
                }
                if !opts.endgame && tracker.is_in_flight(p) {
                    continue;
                }
                if !peer_has_all && !peer_have.get(p) {
                    continue;
                }
                let prio = priorities.get(p as usize).copied().unwrap_or(1);
                if prio <= 0 {
                    continue;
                }
                let task = utilities.get(p as usize).copied().unwrap_or(0);
                let band = if task >= 2500 {
                    0
                } else if task == 2000 {
                    2
                } else {
                    1
                };
                // Smallest (band, index) wins: head first, then body in
                // strict file order, tail (moov) last.
                let key = (band, p as i64);
                if best.map(|(b, i, _)| (b, i) > key).unwrap_or(true) {
                    best = Some((band, p as i64, p));
                }
            }
            return best.map(|(_, _, p)| p);
        }
        let max_avail = availability.iter().copied().max().unwrap_or(0);
        let mut best: Option<(i64, i64, u32)> = None; // (score, rarity, piece)
        for p in 0..n {
            if tracker.is_have(p) {
                continue;
            }
            if !opts.endgame && tracker.is_in_flight(p) {
                continue;
            }
            if !peer_has_all && !peer_have.get(p) {
                continue;
            }
            let prio = priorities.get(p as usize).copied().unwrap_or(1);
            if prio <= 0 {
                continue; // piece belongs only to skipped files
            }
            let util = utilities.get(p as usize).copied().unwrap_or(0);
            let rarity =
                (max_avail as i64) - (availability.get(p as usize).copied().unwrap_or(0) as i64);
            let score = util
                .saturating_mul(prio)
                .saturating_mul(1024)
                .saturating_add(rarity);
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
        let prio = [1i64; 8];
        let p = Picker::pick_piece(
            &t,
            &util,
            &avail,
            &peer,
            false,
            &prio,
            PickOptions::default(),
        )
        .unwrap();
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
        let prio = [1i64; 4];
        let p = Picker::pick_piece(
            &t,
            &util,
            &avail,
            &peer,
            false,
            &prio,
            PickOptions::default(),
        )
        .unwrap();
        assert_eq!(p, 1);
    }

    #[test]
    fn skips_disabled_pieces() {
        let t = PieceTracker::new(4, 16 * 1024);
        let mut peer = Bitfield::new(4);
        peer.set_all();
        let util = [0i64; 4];
        let avail = [0u32; 4];
        // piece 2 belongs to a skipped file
        let prio = [1i64, 1, 0, 1];
        let p = Picker::pick_piece(
            &t,
            &util,
            &avail,
            &peer,
            false,
            &prio,
            PickOptions::default(),
        )
        .unwrap();
        assert_ne!(p, 2);
        // all skipped → nothing to pick (even for a have_all seed)
        let prio = [0i64; 4];
        assert!(Picker::pick_piece(
            &t,
            &util,
            &avail,
            &peer,
            true,
            &prio,
            PickOptions::default()
        )
        .is_none());
    }

    #[test]
    fn high_priority_wins_tie() {
        let t = PieceTracker::new(4, 16 * 1024);
        let mut peer = Bitfield::new(4);
        peer.set_all();
        let util = [10i64, 10, 10, 10];
        let avail = [0u32; 4];
        // high-priority piece 1 beats equal-utility normal pieces
        let prio = [1i64, 4, 1, 1];
        let p = Picker::pick_piece(
            &t,
            &util,
            &avail,
            &peer,
            false,
            &prio,
            PickOptions::default(),
        )
        .unwrap();
        assert_eq!(p, 1);
    }

    #[test]
    fn have_all_seed_is_pickable_with_empty_bitfield() {
        // A fast-extension seed declares have_all but keeps its bitfield
        // empty. The picker must treat it as owning every piece — otherwise
        // no request is ever issued and the download stalls at 0%.
        let t = PieceTracker::new(8, 16 * 1024);
        let empty = Bitfield::new(8); // have_all: bitfield stays empty
        let util = [0i64; 8];
        let avail = [1u32; 8];
        let prio = [1i64; 8];
        let p = Picker::pick_piece(
            &t,
            &util,
            &avail,
            &empty,
            true,
            &prio,
            PickOptions::default(),
        )
        .expect("have_all seed must be pickable");
        assert!(p < 8);
        // without the have_all flag the same empty bitfield is unpickable
        assert!(Picker::pick_piece(
            &t,
            &util,
            &avail,
            &empty,
            false,
            &prio,
            PickOptions::default()
        )
        .is_none());
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

    #[test]
    fn sequential_mode_downloads_head_then_body_then_tail() {
        // Simulate a streaming scheduler's task utilities:
        //   pieces 0..2 head (3000), pieces 5..7 tail (2000), 3..4 body.
        let mut t = PieceTracker::new(8, 16 * 1024);
        let mut peer = Bitfield::new(8);
        peer.set_all();
        let util = [3000i64, 3000, 3000, 500, 490, 2000, 2000, 2000];
        let avail = [0u32; 8];
        let prio = [1i64; 8];
        let opts = PickOptions {
            endgame: false,
            sequential: true,
        };
        // 1) Head pieces first (in index order).
        assert_eq!(
            Picker::pick_piece(&t, &util, &avail, &peer, false, &prio, opts),
            Some(0)
        );
        let mut t2 = PieceTracker::new(8, 16 * 1024);
        t2.set_in_flight(0, true);
        assert_eq!(
            Picker::pick_piece(&t2, &util, &avail, &peer, false, &prio, opts),
            Some(1)
        );
        // 2) Head done → body in strict file order, rarity cannot override.
        for p in 0..3 {
            t.set_in_flight(p, true);
        }
        let mut avail_rare = [0u32; 8];
        avail_rare[4] = 1; // piece 4 rarer than piece 3
        assert_eq!(
            Picker::pick_piece(&t, &util, &avail_rare, &peer, false, &prio, opts),
            Some(3),
            "body downloads in file order regardless of rarity"
        );
        // 3) Tail downloads only after the whole body.
        t.set_in_flight(3, true);
        assert_eq!(
            Picker::pick_piece(&t, &util, &avail, &peer, false, &prio, opts),
            Some(4)
        );
        t.set_in_flight(4, true);
        assert_eq!(
            Picker::pick_piece(&t, &util, &avail, &peer, false, &prio, opts),
            Some(5),
            "tail (moov) is last so the body streams contiguously"
        );
        // 4) Sequential mode respects priorities (skipped files stay skipped).
        let prio_skip = [1i64, 1, 1, 0, 0, 1, 1, 1];
        assert_eq!(
            Picker::pick_piece(&t, &util, &avail, &peer, false, &prio_skip, opts),
            Some(5),
            "skipped body pieces are never picked"
        );
    }
}
