//! SHA-1 throughput on this machine: the backend the engine uses for a piece,
//! the portable reference, and the streaming (16 KiB block) path.
//!
//! `cargo bench --features std` — no external harness, so the numbers are
//! reproducible anywhere the crate builds (including on the NAS itself).
//!
//! Two scales matter for a BitTorrent client:
//!
//! * **piece scale** (256 KiB-4 MiB): verification, seeding and recheck;
//! * **block scale** (16 KiB, BEP-52): v2 torrents and incremental writes.
//!
//! Everything is reported in MiB/s, measured over whole buffers, taking the
//! best of several runs so a scheduling hiccup cannot flatter the result.

use std::hint::black_box;
use std::time::Instant;
use typebit::crypto::{sha1_backend_name, sha1_digest_scalar, Sha1};

fn fill(len: usize) -> Vec<u8> {
    let mut rng = 0x2545_F491_4F6C_DD1Du64;
    (0..len)
        .map(|_| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng as u8
        })
        .collect()
}

/// Best of `reps` timed runs, in MiB/s.
fn throughput<F: Fn(&[u8]) -> [u8; 20]>(data: &[u8], reps: u32, f: F) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..reps {
        let t = Instant::now();
        black_box(f(black_box(data)));
        let secs = t.elapsed().as_secs_f64();
        best = best.min(secs);
    }
    (data.len() as f64 / (1024.0 * 1024.0)) / best
}

fn report(label: &str, data: &[u8], reps: u32) {
    let hw = throughput(data, reps, Sha1::digest);
    let scalar = throughput(data, reps, sha1_digest_scalar);
    println!(
        "  {label:<26} engine {hw:>9.1} MiB/s   scalar {scalar:>9.1} MiB/s   speedup {:.2}x",
        hw / scalar
    );
}

fn main() {
    println!("SHA-1 backend: {} (this build)", sha1_backend_name());
    println!();

    println!("piece scale (verification / seeding / recheck)");
    for kib in [256usize, 1024, 4096] {
        report(&format!("{kib} KiB piece"), &fill(kib * 1024), 40);
    }

    println!();
    println!("BEP-52 block scale (v2 hashing, incremental writes)");
    report("16 KiB block", &fill(16 * 1024), 400);
    report("64 KiB block", &fill(64 * 1024), 200);

    println!();
    println!("multi-piece batch (how a recheck hashes a torrent)");
    let torrent = fill(64 * 1024 * 1024);
    let t = Instant::now();
    let mut acc = [0u8; 20];
    for piece in torrent.chunks(256 * 1024) {
        acc[0] ^= Sha1::digest(piece)[0];
    }
    let secs = t.elapsed().as_secs_f64();
    black_box(acc);
    println!(
        "  64 MiB as 256 KiB pieces      {:>9.1} MiB/s",
        (torrent.len() as f64 / (1024.0 * 1024.0)) / secs
    );
}
