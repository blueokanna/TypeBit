//! SHA-1 (FIPS 180-1) — required by BitTorrent v1 piece hashing.
//!
//! Two interchangeable block-compression backends, both producing identical
//! digests:
//!
//! * **hardware** (the default `simd` feature) — the Intel SHA extensions on
//!   x86_64 (`sha`, `ssse3`, `sse4.1`) and the ARMv8 crypto extension on
//!   aarch64 (`sha2`). Four rounds per instruction; measured ~4× the scalar
//!   path per core on x86 (see `benches/sha1.rs`).
//! * **scalar** — portable reference, byte-for-byte compatible with the FIPS
//!   180-1 vectors and the differential-test target for the accelerated path.
//!
//! The backend is chosen once per process from CPUID / HWCAP and cached in a
//! relaxed atomic, so no call pays for detection. aarch64 needs `std` for
//! `is_aarch64_feature_detected!`, so a `no_std` aarch64 build compiles the
//! portable path.
//!
//! The scalar path itself is written so the common case costs little: no
//! per-block copy, no 80-word schedule array (a rolling 16-word window keeps
//! everything in registers) and one compression per finalised block instead
//! of the previous byte-at-a-time padding loop.

/// Backend detection, cached in one atomic because a piece hash calls the
/// compressor for every 64 bytes: x86 SHA extensions via CPUID, ARMv8 crypto
/// via HWCAP (which needs `std`'s feature detection, so a `no_std` aarch64
/// build uses the portable path).
#[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "simd"))]
mod hw {
    use core::sync::atomic::{AtomicU8, Ordering};

    const UNKNOWN: u8 = 0;
    const SCALAR: u8 = 1;
    const HW: u8 = 2;

    static BACKEND: AtomicU8 = AtomicU8::new(UNKNOWN);

    /// True when this CPU has the needed instructions.
    #[inline]
    pub(super) fn available() -> bool {
        let cached = BACKEND.load(Ordering::Relaxed);
        if cached != UNKNOWN {
            return cached == HW;
        }
        let detected = if detect() { HW } else { SCALAR };
        BACKEND.store(detected, Ordering::Relaxed);
        detected == HW
    }

    #[cfg(target_arch = "x86_64")]
    fn detect() -> bool {
        // CPUID leaf 1: ECX bit 9 = SSSE3, bit 19 = SSE4.1;
        // leaf 7 sub-leaf 0: EBX bit 29 = SHA extensions.
        //
        // Reading CPUID directly (instead of `is_x86_feature_detected!`) keeps
        // detection working under `no_std`.
        let leaf1 = core::arch::x86_64::__cpuid(1);
        let leaf7 = core::arch::x86_64::__cpuid_count(7, 0);
        let ssse3 = leaf1.ecx & (1 << 9) != 0;
        let sse41 = leaf1.ecx & (1 << 19) != 0;
        let sha = leaf7.ebx & (1 << 29) != 0;
        ssse3 && sse41 && sha
    }

    #[cfg(all(target_arch = "aarch64", feature = "std"))]
    fn detect() -> bool {
        std::arch::is_aarch64_feature_detected!("sha2")
    }

    #[cfg(all(target_arch = "aarch64", not(feature = "std")))]
    fn detect() -> bool {
        false
    }
}

/// Compress one 64-byte block into `state`, via the best backend available.
#[inline(always)]
fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    #[cfg(all(target_arch = "x86_64", feature = "simd"))]
    {
        if hw::available() {
            // SAFETY: `hw::available` only reports `true` after CPUID confirmed
            // `sha` + `ssse3` + `sse4.1`, and `block` is a full 64-byte block.
            unsafe { sha1_shani(state, block) };
            return;
        }
    }
    #[cfg(all(target_arch = "aarch64", feature = "simd"))]
    {
        if hw::available() {
            // SAFETY: `hw::available` only reports `true` after HWCAP reported
            // the ARMv8 SHA-1 extension, and `block` is a full 64-byte block.
            unsafe { sha1_armv8(state, block) };
            return;
        }
    }
    sha1_scalar(state, block);
}

/// Incremental SHA-1 hasher.
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    len: u64,
    block: [u8; 64],
    n: usize,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// New hasher with the standard initial state.
    pub fn new() -> Self {
        Sha1 {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            len: 0,
            block: [0u8; 64],
            n: 0,
        }
    }

    /// Absorb `data`.
    pub fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        if self.n > 0 {
            let want = 64 - self.n;
            if data.len() < want {
                self.block[self.n..self.n + data.len()].copy_from_slice(data);
                self.n += data.len();
                return;
            }
            self.block[self.n..].copy_from_slice(&data[..want]);
            let block = self.block;
            compress(&mut self.state, &block);
            self.n = 0;
            data = &data[want..];
        }
        let mut chunks = data.chunks_exact(64);
        for chunk in &mut chunks {
            let block: &[u8; 64] = chunk.try_into().unwrap();
            compress(&mut self.state, block);
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            self.block[..rem.len()].copy_from_slice(rem);
            self.n = rem.len();
        }
    }

    /// Finalize, returning the 20-byte digest.
    pub fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.len.wrapping_mul(8);
        self.block[self.n] = 0x80;
        self.n += 1;
        if self.n > 56 {
            self.block[self.n..].fill(0);
            let block = self.block;
            compress(&mut self.state, &block);
            self.n = 0;
        }
        self.block[self.n..56].fill(0);
        self.block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.block;
        compress(&mut self.state, &block);
        let mut out = [0u8; 20];
        for (i, s) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&s.to_be_bytes());
        }
        out
    }

    /// One-shot SHA-1.
    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut h = Sha1::new();
        h.update(data);
        h.finalize()
    }
}

/// One-shot SHA-1 through the portable (non-SIMD) backend.
///
/// Exposed so the accelerated path can be differential-tested against the
/// reference implementation on the machine that will actually run it — the
/// scalar code is also the fallback every CPU without the instructions uses.
pub fn digest_scalar(data: &[u8]) -> [u8; 20] {
    let mut state = [
        0x67452301u32,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    ];
    let mut chunks = data.chunks_exact(64);
    for chunk in &mut chunks {
        let block: &[u8; 64] = chunk.try_into().unwrap();
        sha1_scalar(&mut state, block);
    }
    let rem = chunks.remainder();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut block = [0u8; 64];
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] = 0x80;
    if rem.len() >= 56 {
        sha1_scalar(&mut state, &block);
        block = [0u8; 64];
    }
    block[56..64].copy_from_slice(&bit_len.to_be_bytes());
    sha1_scalar(&mut state, &block);
    let mut out = [0u8; 20];
    for (i, s) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&s.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------- scalar path

/// Name of the block-compression backend this process picked — `"sha-ni"` on
/// x86_64 with the Intel SHA extensions, `"scalar"` everywhere else. Reported
/// in the engine statistics so a NAS user can see which path is running.
pub fn backend_name() -> &'static str {
    #[cfg(all(target_arch = "x86_64", feature = "simd"))]
    {
        if hw::available() {
            return "sha-ni";
        }
    }
    #[cfg(all(target_arch = "aarch64", feature = "simd"))]
    {
        if hw::available() {
            return "armv8-crypto";
        }
    }
    "scalar"
}

/// Portable compression function.
///
/// The message schedule lives in a 16-word rolling window (`& 15` wraps, so
/// words are overwritten exactly when they are no longer needed) and the four
/// 20-round phases are separate loops, which lets the compiler keep the `f`
/// function and the constant out of the inner loop — the previous version
/// rebuilt an 80-word array and re-ran a `match` for every round.
fn sha1_scalar(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 16];
    for (i, word) in w.iter_mut().enumerate() {
        *word = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    let (mut a, mut b, mut c, mut d, mut e) = (state[0], state[1], state[2], state[3], state[4]);

    macro_rules! round {
        ($f:expr, $k:expr, $wi:expr) => {{
            let t = a
                .rotate_left(5)
                .wrapping_add($f)
                .wrapping_add(e)
                .wrapping_add($k)
                .wrapping_add($wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }};
    }
    macro_rules! schedule {
        ($i:expr) => {{
            let v = (w[($i - 3) & 15] ^ w[($i - 8) & 15] ^ w[($i - 14) & 15] ^ w[$i & 15])
                .rotate_left(1);
            w[$i & 15] = v;
            v
        }};
    }

    // Rounds 0-19: f = choose, k = 0x5A827999.
    for &wi in &w {
        round!((b & c) | ((!b) & d), 0x5A827999u32, wi);
    }
    for i in 16..20 {
        round!((b & c) | ((!b) & d), 0x5A827999u32, schedule!(i));
    }
    // Rounds 20-39: f = parity, k = 0x6ED9EBA1.
    for i in 20..40 {
        round!(b ^ c ^ d, 0x6ED9EBA1u32, schedule!(i));
    }
    // Rounds 40-59: f = majority, k = 0x8F1BBCDC.
    for i in 40..60 {
        round!((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32, schedule!(i));
    }
    // Rounds 60-79: f = parity, k = 0xCA62C1D6.
    for i in 60..80 {
        round!(b ^ c ^ d, 0xCA62C1D6u32, schedule!(i));
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

// ------------------------------------------------------------- x86 SHA-NI

/// SHA-NI compression: 4 rounds per `sha1rnds4`, message schedule generated by
/// the `sha1msg1`/`sha1msg2` pipeline instructions.
///
/// The register dance is the one Intel's own sample uses: `E` travels in dword
/// 3 of the vectors (`sha1nexte` turns the previous state's A into the next
/// group's E and folds in the scheduled word), and `sha1rnds4` returns the
/// updated `(A, B, C, D)`.
#[cfg(all(target_arch = "x86_64", feature = "simd"))]
#[target_feature(enable = "sha,ssse3,sse4.1")]
unsafe fn sha1_shani(state: &mut [u32; 5], block: &[u8; 64]) {
    use core::arch::x86_64::*;

    // Big-endian message words, highest word first (the layout `sha1rnds4`
    // expects in its operand).
    let mask = _mm_set_epi64x(
        0x0001_0203_0405_0607u64 as i64,
        0x0809_0a0b_0c0d_0e0fu64 as i64,
    );

    let mut abcd = _mm_loadu_si128(state.as_ptr() as *const __m128i);
    abcd = _mm_shuffle_epi32(abcd, 0x1B);
    let abcd_save = abcd;
    let mut e0 = _mm_set_epi32(state[4] as i32, 0, 0, 0);
    let e0_save = e0;

    let mut m0 = _mm_shuffle_epi8(_mm_loadu_si128(block.as_ptr() as *const __m128i), mask);
    let mut m1 = _mm_shuffle_epi8(
        _mm_loadu_si128(block.as_ptr().add(16) as *const __m128i),
        mask,
    );
    let mut m2 = _mm_shuffle_epi8(
        _mm_loadu_si128(block.as_ptr().add(32) as *const __m128i),
        mask,
    );
    let mut m3 = _mm_shuffle_epi8(
        _mm_loadu_si128(block.as_ptr().add(48) as *const __m128i),
        mask,
    );

    let mut e1;

    // Rounds 0-3.
    e0 = _mm_add_epi32(e0, m0);
    e1 = abcd;
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);

    // Rounds 4-7.
    e1 = _mm_sha1nexte_epu32(e1, m1);
    e0 = abcd;
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 0);
    m0 = _mm_sha1msg1_epu32(m0, m1);

    // Rounds 8-11.
    e0 = _mm_sha1nexte_epu32(e0, m2);
    e1 = abcd;
    abcd = _mm_sha1rnds4_epu32(abcd, e0, 0);
    m1 = _mm_sha1msg1_epu32(m1, m2);
    m0 = _mm_xor_si128(m0, m2);

    // Rounds 12-15.
    e1 = _mm_sha1nexte_epu32(e1, m3);
    e0 = abcd;
    m0 = _mm_sha1msg2_epu32(m0, m3);
    abcd = _mm_sha1rnds4_epu32(abcd, e1, 0);
    m2 = _mm_sha1msg1_epu32(m2, m3);
    m1 = _mm_xor_si128(m1, m3);

    /// One 4-round group from round 16 on: fetch the next scheduled word into
    /// the E slot, save the state for the following group, advance the
    /// schedule by one step and run the rounds.
    macro_rules! group {
        ($abcd:ident, $rc:expr, $e_cur:ident, $e_save:ident, $m_cur:ident, $m_msg2:ident, $m_msg1:ident, $m_xor:ident) => {{
            $e_cur = _mm_sha1nexte_epu32($e_cur, $m_cur);
            $e_save = $abcd;
            $m_msg2 = _mm_sha1msg2_epu32($m_msg2, $m_cur);
            $abcd = _mm_sha1rnds4_epu32($abcd, $e_cur, $rc);
            $m_msg1 = _mm_sha1msg1_epu32($m_msg1, $m_cur);
            $m_xor = _mm_xor_si128($m_xor, $m_cur);
        }};
    }

    /// A group whose `msg1` output is only ever read by rounds past the end of
    /// the block: the `msg2`/`xor` steps still feed the remaining groups.
    macro_rules! group_no_msg1 {
        ($abcd:ident, $rc:expr, $e_cur:ident, $e_save:ident, $m_cur:ident, $m_msg2:ident, $m_xor:ident) => {{
            $e_cur = _mm_sha1nexte_epu32($e_cur, $m_cur);
            $e_save = $abcd;
            $m_msg2 = _mm_sha1msg2_epu32($m_msg2, $m_cur);
            $abcd = _mm_sha1rnds4_epu32($abcd, $e_cur, $rc);
            $m_xor = _mm_xor_si128($m_xor, $m_cur);
        }};
    }

    /// The closing group: nothing it schedules is ever read again (there is no
    /// round 80), so it only fetches the word its rounds need.
    macro_rules! group_final {
        ($abcd:ident, $rc:expr, $e_cur:ident, $e_save:ident, $m_cur:ident) => {{
            $e_cur = _mm_sha1nexte_epu32($e_cur, $m_cur);
            $e_save = $abcd;
            $abcd = _mm_sha1rnds4_epu32($abcd, $e_cur, $rc);
        }};
    }
    /// The next-to-last group: it still schedules the word the final group
    /// consumes, so it fetches that one but skips the two that would only be
    /// read by rounds that do not exist.
    macro_rules! group_tail {
        ($abcd:ident, $rc:expr, $e_cur:ident, $e_save:ident, $m_cur:ident, $m_msg2:ident) => {{
            $e_cur = _mm_sha1nexte_epu32($e_cur, $m_cur);
            $e_save = $abcd;
            $m_msg2 = _mm_sha1msg2_epu32($m_msg2, $m_cur);
            $abcd = _mm_sha1rnds4_epu32($abcd, $e_cur, $rc);
        }};
    }

    // Rounds 16-19.
    group!(abcd, 0, e0, e1, m0, m1, m3, m2);
    // Rounds 20-23, 24-27, 28-31, 32-35, 36-39 (k = 0x6ED9EBA1).
    group!(abcd, 1, e1, e0, m1, m2, m0, m3);
    group!(abcd, 1, e0, e1, m2, m3, m1, m0);
    group!(abcd, 1, e1, e0, m3, m0, m2, m1);
    group!(abcd, 1, e0, e1, m0, m1, m3, m2);
    group!(abcd, 1, e1, e0, m1, m2, m0, m3);
    // Rounds 40-59 (k = 0x8F1BBCDC).
    group!(abcd, 2, e0, e1, m2, m3, m1, m0);
    group!(abcd, 2, e1, e0, m3, m0, m2, m1);
    group!(abcd, 2, e0, e1, m0, m1, m3, m2);
    group!(abcd, 2, e1, e0, m1, m2, m0, m3);
    group!(abcd, 2, e0, e1, m2, m3, m1, m0);
    // Rounds 60-67 (k = 0xCA62C1D6).
    group!(abcd, 3, e1, e0, m3, m0, m2, m1);
    group!(abcd, 3, e0, e1, m0, m1, m3, m2);
    // Rounds 68-75: the tail of the schedule pipeline, where only the steps
    // that still feed a later group are worth doing.
    group_no_msg1!(abcd, 3, e1, e0, m1, m2, m3);
    group_tail!(abcd, 3, e0, e1, m2, m3);
    // Rounds 76-79.
    group_final!(abcd, 3, e1, e0, m3);

    abcd = _mm_add_epi32(abcd, abcd_save);
    e0 = _mm_sha1nexte_epu32(e0, e0_save);

    abcd = _mm_shuffle_epi32(abcd, 0x1B);
    _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, abcd);
    state[4] = _mm_extract_epi32(e0, 3) as u32;
}

// ------------------------------------------------------------- aarch64 path

/// ARMv8 crypto compression: four rounds per `SHA1C`/`SHA1P`/`SHA1M`, with the
/// message schedule produced by `SHA1SU0`/`SHA1SU1` four words at a time.
///
/// The schedule pair is used exactly as ARM documents it:
/// `su1(su0(W[i..i+4], W[i+4..i+8], W[i+8..i+12]), W[i+12..i+16])` yields
/// `W[i+16..i+20]` in lanes 0-3 — the "expected" column of the probe in
/// `docs/performance.md`'s companion test, not an assumption.
///
/// E for the next group is SHA-1's own bookkeeping — `ROL30(A)` of the state
/// going into the group — which `SHA1H` computes.
#[cfg(all(target_arch = "aarch64", feature = "simd"))]
#[target_feature(enable = "sha2")]
unsafe fn sha1_armv8(state: &mut [u32; 5], block: &[u8; 64]) {
    use core::arch::aarch64::*;

    /// Big-endian words with the first word in lane 0.
    macro_rules! words {
        ($off:expr) => {{
            let p = block.as_ptr().add($off);
            vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p)))
        }};
    }
    /// The next four schedule words.
    macro_rules! sched {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            vsha1su1q_u32(vsha1su0q_u32($a, $b, $c), $d)
        };
    }
    /// One group of four rounds (`$instr` picks the round function and hence
    /// the round constant bucket).
    macro_rules! rounds {
        ($abcd:ident, $e:ident, $k:expr, $msg:expr, $instr:ident) => {{
            let wk = vaddq_u32($msg, vdupq_n_u32($k));
            let next_e = vsha1h_u32(vgetq_lane_u32($abcd, 0));
            $abcd = $instr($abcd, $e, wk);
            $e = next_e;
        }};
    }

    const K0: u32 = 0x5A82_7999;
    const K1: u32 = 0x6ED9_EBA1;
    const K2: u32 = 0x8F1B_BCDC;
    const K3: u32 = 0xCA62_C1D6;

    let mut abcd = vld1q_u32(state.as_ptr());
    let abcd_save = abcd;
    let mut e = state[4];

    let v0 = words!(0);
    let v1 = words!(16);
    let v2 = words!(32);
    let v3 = words!(48);

    rounds!(abcd, e, K0, v0, vsha1cq_u32);
    rounds!(abcd, e, K0, v1, vsha1cq_u32);
    rounds!(abcd, e, K0, v2, vsha1cq_u32);
    rounds!(abcd, e, K0, v3, vsha1cq_u32);
    let v4 = sched!(v0, v1, v2, v3);
    rounds!(abcd, e, K0, v4, vsha1cq_u32);
    let v5 = sched!(v1, v2, v3, v4);
    rounds!(abcd, e, K1, v5, vsha1pq_u32);
    let v6 = sched!(v2, v3, v4, v5);
    rounds!(abcd, e, K1, v6, vsha1pq_u32);
    let v7 = sched!(v3, v4, v5, v6);
    rounds!(abcd, e, K1, v7, vsha1pq_u32);
    let v8 = sched!(v4, v5, v6, v7);
    rounds!(abcd, e, K1, v8, vsha1pq_u32);
    let v9 = sched!(v5, v6, v7, v8);
    rounds!(abcd, e, K1, v9, vsha1pq_u32);
    let v10 = sched!(v6, v7, v8, v9);
    rounds!(abcd, e, K2, v10, vsha1mq_u32);
    let v11 = sched!(v7, v8, v9, v10);
    rounds!(abcd, e, K2, v11, vsha1mq_u32);
    let v12 = sched!(v8, v9, v10, v11);
    rounds!(abcd, e, K2, v12, vsha1mq_u32);
    let v13 = sched!(v9, v10, v11, v12);
    rounds!(abcd, e, K2, v13, vsha1mq_u32);
    let v14 = sched!(v10, v11, v12, v13);
    rounds!(abcd, e, K2, v14, vsha1mq_u32);
    let v15 = sched!(v11, v12, v13, v14);
    rounds!(abcd, e, K3, v15, vsha1pq_u32);
    let v16 = sched!(v12, v13, v14, v15);
    rounds!(abcd, e, K3, v16, vsha1pq_u32);
    let v17 = sched!(v13, v14, v15, v16);
    rounds!(abcd, e, K3, v17, vsha1pq_u32);
    let v18 = sched!(v14, v15, v16, v17);
    rounds!(abcd, e, K3, v18, vsha1pq_u32);
    let v19 = sched!(v15, v16, v17, v18);
    rounds!(abcd, e, K3, v19, vsha1pq_u32);

    abcd = vaddq_u32(abcd, abcd_save);
    vst1q_u32(state.as_mut_ptr(), abcd);
    state[4] = state[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    fn hex(d: [u8; 20]) -> String {
        let mut s = String::new();
        for b in d {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    #[test]
    fn fips_vectors() {
        // FIPS 180-1 examples
        assert_eq!(
            hex(Sha1::digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(Sha1::digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            hex(Sha1::digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        // incremental == one-shot
        let mut h = Sha1::new();
        for chunk in b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".chunks(7) {
            h.update(chunk);
        }
        assert_eq!(
            hex(h.finalize()),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    /// One million 'a' — the second published FIPS vector, which also walks
    /// the multi-block path 15 625 times.
    #[test]
    fn fips_million_a() {
        let mut h = Sha1::new();
        let chunk = [b'a'; 4096];
        for _ in 0..244 {
            h.update(&chunk);
        }
        h.update(&[b'a'; 576]);
        assert_eq!(
            hex(h.finalize()),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    /// Every length around the padding boundaries, plus multi-block inputs:
    /// this is what catches a wrong round-constant bucket or a broken message
    /// schedule in the accelerated backends.
    #[test]
    fn accelerated_matches_scalar() {
        let mut rng = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let mut buf = [0u8; 1024];
        for len in (0..200).chain([255, 256, 511, 512, 513, 1023, 1024]) {
            for b in buf[..len].iter_mut() {
                *b = next() as u8;
            }
            let data = &buf[..len];
            assert_eq!(
                hex(Sha1::digest(data)),
                hex(digest_scalar(data)),
                "len {len}"
            );
        }
    }

    /// The one-shot reference must agree with the incremental hasher for
    /// chunked writes too (the torrent path feeds 16 KiB blocks).
    #[test]
    fn digest_scalar_matches_incremental() {
        let data: alloc::vec::Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        for chunk in [1usize, 63, 64, 65, 4096] {
            let mut h = Sha1::new();
            for part in data.chunks(chunk) {
                h.update(part);
            }
            assert_eq!(
                hex(h.finalize()),
                hex(digest_scalar(&data)),
                "chunk {chunk}"
            );
        }
    }
}
