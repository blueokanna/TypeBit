//! Semantic, utility-driven piece scheduler:
//!
//! ```text
//! p* = argmax_p [ α·U_task(p) + β·U_availability(p) − γ·C_network(p) − δ·R_integrity(p) ]
//! ```
//!
//! `U_task` is content-aware (video: head+tail; archives: tail then head;
//! weights: head), `U_availability` rewards rarity (rarest-first),
//! `C_network` penalizes pieces far from the frontier, `R_integrity` pieces
//! touched by suspicious peers. Produces a per-piece integer utility vector
//! consumed by [`crate::picker::Picker`].

use crate::metainfo::Torrent;
use alloc::vec::Vec;

/// What the user primarily wants from the content (drives `U_task`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentGoal {
    /// Playback-first: head + tail, then sequential (video).
    Streaming,
    /// Extract/verify-first: tail (central dir) then head (archives).
    Extract,
    /// Verify/load-first: head metadata then sequential (model weights).
    Load,
    /// Just get the bytes (rarest-first).
    Generic,
}

/// Scheduler weights (integer, so the core stays allocation-free of floats).
#[derive(Debug, Clone, Copy)]
pub struct SchedulerConfig {
    /// Weight of task utility.
    pub alpha: i64,
    /// Weight of availability (rarity) utility.
    pub beta: i64,
    /// Weight of network cost.
    pub gamma: i64,
    /// Weight of integrity risk.
    pub delta: i64,
    /// Bytes reserved for the "edge" (head/tail) of streaming content.
    pub edge_bytes: u64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        SchedulerConfig {
            alpha: 8,
            beta: 2,
            gamma: 1,
            delta: 64,
            edge_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Detects the content goal from file names.
pub fn detect_goal(torrent: &Torrent) -> ContentGoal {
    let mut video = false;
    let mut archive = false;
    let mut model = false;
    for f in &torrent.files {
        let name = f.display_path().to_ascii_lowercase();
        for ext in [
            ".mp4", ".mkv", ".avi", ".webm", ".mov", ".m4v", ".ts", ".flv", ".wmv", ".mpg", ".mpeg",
        ] {
            if name.ends_with(ext) {
                video = true;
            }
        }
        for ext in [
            ".zip", ".tar", ".gz", ".7z", ".rar", ".xz", ".zst", ".bz2", ".tgz",
        ] {
            if name.ends_with(ext) {
                archive = true;
            }
        }
        for ext in [
            ".safetensors",
            ".pt",
            ".pth",
            ".onnx",
            ".gguf",
            ".ckpt",
            ".bin",
            ".pb",
            ".tflite",
            ".npy",
            ".npz",
            ".parquet",
            ".sqlite",
            ".sqlite3",
            ".zarr",
        ] {
            if name.ends_with(ext) {
                model = true;
            }
        }
    }
    if video {
        ContentGoal::Streaming
    } else if archive {
        ContentGoal::Extract
    } else if model {
        ContentGoal::Load
    } else {
        ContentGoal::Generic
    }
}

/// The scheduler: owns per-piece utility terms and combines them.
#[derive(Debug, Clone)]
pub struct Scheduler {
    piece_count: u32,
    cfg: SchedulerConfig,
    goal: ContentGoal,
    /// U_task per piece.
    task: Vec<i64>,
    /// U_availability per piece (rarity score).
    availability: Vec<i64>,
    /// C_network per piece (locality cost).
    cost: Vec<i64>,
    /// R_integrity per piece (risk).
    risk: Vec<i64>,
    /// Combined utility per piece.
    utility: Vec<i64>,
    /// Download frontier (last piece index touched) for locality.
    frontier: i64,
}

impl Scheduler {
    /// Build a scheduler for a torrent, detecting the content goal.
    pub fn new(torrent: &Torrent, cfg: SchedulerConfig) -> Self {
        let n = torrent.piece_count() as usize;
        let goal = detect_goal(torrent);
        let mut s = Scheduler {
            piece_count: torrent.piece_count(),
            cfg,
            goal,
            task: vec![0; n],
            availability: vec![0; n],
            cost: vec![0; n],
            risk: vec![0; n],
            utility: vec![0; n],
            frontier: -1,
        };
        s.compute_task(torrent);
        s.recompute();
        s
    }

    /// Build with a forced goal.
    pub fn with_goal(torrent: &Torrent, goal: ContentGoal, cfg: SchedulerConfig) -> Self {
        let mut s = Scheduler::new(torrent, cfg);
        s.goal = goal;
        s.compute_task(torrent);
        s.recompute();
        s
    }

    /// Current goal.
    pub fn goal(&self) -> ContentGoal {
        self.goal
    }

    fn compute_task(&mut self, torrent: &Torrent) {
        let n = self.task.len();
        if n == 0 {
            return;
        }
        let pl = torrent.piece_length as u64;
        let total = torrent.total_size.max(1);
        let edge = self.cfg.edge_bytes.min(total / 10).max(pl);
        let head_pieces = (edge / pl).max(1) as usize;
        let tail_pieces = (edge / pl).max(1) as usize;
        match self.goal {
            ContentGoal::Streaming => {
                // head pieces: absolute top; tail pieces: high; middle:
                // sequential from head (later middle = lower).
                for p in 0..n {
                    let idx = p as i64;
                    if (p as u64) < head_pieces as u64 {
                        self.task[p] = 3000;
                    } else if p >= n.saturating_sub(tail_pieces) {
                        self.task[p] = 2000;
                    } else {
                        // sequential preference for smooth playback
                        self.task[p] = 1000 - idx;
                    }
                }
            }
            ContentGoal::Extract => {
                for p in 0..n {
                    if p >= n.saturating_sub(tail_pieces) {
                        self.task[p] = 2000; // central directory at the end
                    } else if (p as u64) < head_pieces as u64 {
                        self.task[p] = 1500; // local file headers
                    } else {
                        self.task[p] = 0;
                    }
                }
            }
            ContentGoal::Load => {
                for p in 0..n {
                    if (p as u64) < head_pieces as u64 {
                        self.task[p] = 1500; // metadata / manifest / shards index
                    } else {
                        self.task[p] = 0;
                    }
                }
            }
            ContentGoal::Generic => {
                self.task.iter_mut().for_each(|t| *t = 0);
            }
        }
        let _ = total;
    }

    /// Update per-piece availability counts (number of peers holding the
    /// piece). Rarity utility = (max − avail).
    pub fn update_availability(&mut self, availability: &[u32]) {
        let n = self.availability.len().min(availability.len());
        let max_avail = availability.iter().copied().max().unwrap_or(0);
        for i in 0..n {
            let a = availability[i];
            self.availability[i] = (max_avail as i64) - (a as i64);
        }
        self.recompute();
    }

    /// Mark a piece as touched by a suspicious peer (raises risk).
    pub fn mark_suspicious(&mut self, piece: u32) {
        if let Some(r) = self.risk.get_mut(piece as usize) {
            *r = 1;
            self.recompute();
        }
    }

    /// Clear all risk flags.
    pub fn clear_risk(&mut self) {
        self.risk.iter_mut().for_each(|r| *r = 0);
        self.recompute();
    }

    /// Set the download frontier (used for locality cost).
    pub fn set_frontier(&mut self, piece: i64) {
        self.frontier = piece;
        self.recompute();
    }

    fn recompute(&mut self) {
        let n = self.task.len();
        for p in 0..n {
            // locality: distance from frontier (only meaningful for streaming)
            let mut cost = 0i64;
            if self.goal == ContentGoal::Streaming && self.frontier >= 0 {
                cost = (self.frontier - p as i64).abs().min(4096);
            }
            self.cost[p] = cost;
            self.utility[p] = self.cfg.alpha * self.task[p] + self.cfg.beta * self.availability[p]
                - self.cfg.gamma * cost
                - self.cfg.delta * self.risk[p];
        }
    }

    /// Combined utility of a piece.
    pub fn utility(&self, piece: u32) -> i64 {
        self.utility
            .get(piece as usize)
            .copied()
            .unwrap_or(i64::MIN)
    }

    /// Whole utility vector.
    pub fn utilities(&self) -> &[i64] {
        &self.utility
    }

    /// Piece count.
    pub fn piece_count(&self) -> u32 {
        self.piece_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bencode::{bytes, dict, int};
    use crate::metainfo::Torrent;

    fn make_torrent(name: &str, size: u64, piece: u32, n_pieces: usize) -> Torrent {
        // build a synthetic v1 torrent; hashes don't matter for scheduling
        let info = dict(vec![
            (b"name", bytes(name)),
            (b"piece length", int(piece as i64)),
            (b"pieces", bytes(vec![0u8; n_pieces * 20])),
            (b"length", int(size as i64)),
        ]);
        let t = dict(vec![(b"announce", bytes("http://t")), (b"info", info)]);
        let mut data = Vec::new();
        t.encode(&mut data);
        Torrent::from_bytes(&data).unwrap()
    }

    #[test]
    fn video_head_tail_priority() {
        let t = make_torrent("movie.mp4", 64 * 1024 * 1024, 256 * 1024, 256);
        let s = Scheduler::new(&t, SchedulerConfig::default());
        assert_eq!(s.goal(), ContentGoal::Streaming);
        // head pieces dominate
        assert!(s.utility(0) > s.utility(128));
        // tail pieces high too
        assert!(s.utility(255) > s.utility(128));
    }

    #[test]
    fn generic_uses_rarity() {
        let t = make_torrent("data.xyz", 16 * 1024 * 1024, 256 * 1024, 64);
        let mut s = Scheduler::new(&t, SchedulerConfig::default());
        let mut avail = vec![0u32; 64];
        // piece 10 is rare (1 peer), piece 0 is common (10 peers)
        avail[0] = 10;
        avail[10] = 1;
        s.update_availability(&avail);
        // rare piece should win (higher availability utility)
        assert!(s.utility(10) > s.utility(0));
    }

    #[test]
    fn risk_penalty() {
        let t = make_torrent("x.bin", 8 * 1024 * 1024, 256 * 1024, 32);
        let mut s = Scheduler::new(&t, SchedulerConfig::default());
        let avail = vec![1u32; 32];
        s.update_availability(&avail);
        let before = s.utility(5);
        s.mark_suspicious(5);
        assert!(s.utility(5) < before);
    }
}
