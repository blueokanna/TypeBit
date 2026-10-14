# Performance

Numbers are only worth reading next to the command that produced them, so this
page records both.

```bash
cargo bench --features std      # prints backend + MiB/s for every scale
cargo test  --features std      # includes the SHA-NI vs scalar differential test
```

## SHA-1 (piece hashing: verification, seeding, recheck)

Measured on one machine — 16-core x86_64 with the Intel SHA extensions
(`sha_ni`), WSL2, `--release`, best of 40 runs. The spread is load, not noise in
the code: an idle machine reaches the upper end, a busy one the lower.

| Buffer | before (`HEAD`) | portable path now | engine path now (`sha-ni`) | speed-up |
| --- | --- | --- | --- | --- |
| 16 KiB block (BEP-52) | 288 MiB/s | 305-426 MiB/s | 1200-1621 MiB/s | **4.2-5.6×** |
| 256 KiB piece | 320 MiB/s | 335-410 MiB/s | 1296-1506 MiB/s | **4.1-4.7×** |
| 1 MiB piece | 328 MiB/s | 337-406 MiB/s | 1279-1654 MiB/s | **3.9-5.0×** |
| 4 MiB piece | 300 MiB/s | 334-402 MiB/s | 1418-1507 MiB/s | **4.7-5.0×** |
| 64 MiB as 256 KiB pieces | 270 MiB/s | — | 856-1240 MiB/s | **3.2-4.6×** |

Two independent changes:

* **portable path** — the message schedule now lives in a rolling 16-word
  window instead of an 80-word array rebuilt per block, full blocks are
  compressed straight out of the caller's buffer (no 64-byte copy per block),
  the four 20-round phases are separate loops so the `f` function and the
  constant stay out of the inner loop, and finalisation compresses the padded
  block once instead of calling `update` byte by byte. ~1.3× on every
  architecture, including the ARM boards a NAS package ships to.
* **SHA-NI path** (`simd` feature, on by default) — four SHA-1 rounds per
  instruction plus the `sha1msg1`/`sha1msg2` schedule pipeline. Selected at
  runtime from CPUID and cached; every CPU without the instructions runs the
  portable path, and the two are cross-checked against each other on the
  machine that will actually run them
  (`crypto::sha1::tests::accelerated_matches_scalar`).

`typebit::crypto::sha1_backend_name()` reports which path a process picked —
`"sha-ni"` or `"scalar"` — so a NAS build can show it in its statistics.

## Where this lands

A recheck of a 64 GiB torrent is ~262 144 piece hashes: ~4 minutes on the old
portable code, under a minute on the SHA-NI path — and the engine's verify
pool spreads that over every core, so on a NAS the disk becomes the limit
before the CPU does.

## Honest gaps (next)

* **aarch64** still runs the portable path: the ARMv8 SHA-1 instructions
  (`SHA1C`/`SHA1M`/`SHA1P` + the schedule pipeline) are not wired up yet.
* **SHA-256** (BitTorrent v2 / BEP-52 blocks, receipts) is still scalar; the
  same SHA-NI machinery covers it (`sha256rnds2`/`sha256msg1`/`sha256msg2`).
* Nothing here profiles the engine *outside* hashing — peer protocol, disk
  staging and the JNI boundary are unmeasured, so any claim about them would
  be a guess.
