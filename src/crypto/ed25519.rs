//! Ed25519 (RFC 8032) — pure `no_std`, zero `unsafe`, from scratch.
//!
//! This is the signature primitive behind TypeBit's *provable download /
//! availability receipts*. Field arithmetic is radix-2^51 with 5×u64 limbs
//! over GF(2^255 − 19); points are Edwards extended coordinates; scalars
//! are reduced modulo the group order L with a 512→256 bit binary
//! shift-subtract reduction. Correctness is pinned by the RFC 8032 §7.1
//! test vectors.

use super::sha512::Sha512;
use alloc::vec::Vec;

// ---------- field element ----------

const MASK51: u64 = (1 << 51) - 1;
/// p = 2^255 − 19 in radix 2^51.
const P: [u64; 5] = [
    0x7FFFFFFFFFFED,
    0x7FFFFFFFFFFFF,
    0x7FFFFFFFFFFFF,
    0x7FFFFFFFFFFFF,
    0x7FFFFFFFFFFFF,
];

/// Field element over GF(2^255 − 19); always carried (limbs < 2^51) and
/// reduced (< p) after every public operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fe([u64; 5]);

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    fn from_limbs(l: [u64; 5]) -> Fe {
        Fe(l)
    }

    /// Decode a 32-byte little-endian field element (top bit ignored).
    fn from_bytes(b: &[u8; 32]) -> Fe {
        let mut m = [0u8; 32];
        m.copy_from_slice(b);
        m[31] &= 0x7f;
        let a0 = load64(&m[0..8]);
        let a1 = load64(&m[6..14]);
        let a2 = load64(&m[12..20]);
        let a3 = load64(&m[19..27]);
        let a4 = load64_7(&m[25..32]);
        Fe([
            a0 & MASK51,
            (a1 >> 3) & MASK51,
            (a2 >> 6) & MASK51,
            (a3 >> 1) & MASK51,
            (a4 >> 4) & MASK51,
        ])
    }

    /// Encode as 32 little-endian bytes (bit 255 = 0).
    fn to_bytes(self) -> [u8; 32] {
        let [l0, l1, l2, l3, l4] = self.0;
        let mut o = [0u64; 4];
        o[0] = l0 | ((l1 & 0x1FFF) << 51);
        o[1] = (l1 >> 13) | ((l2 & 0x3FFFFFF) << 38);
        o[2] = (l2 >> 26) | ((l3 & 0x7FFFFFFFFF) << 25);
        o[3] = (l3 >> 39) | (l4 << 12);
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&o[i].to_le_bytes());
        }
        out
    }

    fn is_negative(&self) -> bool {
        self.0[0] & 1 == 1
    }

    fn add(a: Fe, b: Fe) -> Fe {
        let mut t = [0i128; 5];
        for i in 0..5 {
            t[i] = a.0[i] as i128 + b.0[i] as i128;
        }
        let mut r = normalize(t);
        cond_sub_p(&mut r);
        r
    }

    fn sub(a: Fe, b: Fe) -> Fe {
        let mut t = [0i128; 5];
        for i in 0..5 {
            t[i] = a.0[i] as i128 + P[i] as i128 - b.0[i] as i128;
        }
        let mut r = normalize(t);
        cond_sub_p(&mut r);
        r
    }

    fn neg(a: Fe) -> Fe {
        Fe::sub(Fe::ZERO, a)
    }

    fn mul(a: Fe, b: Fe) -> Fe {
        // schoolbook 5x5 → 10 limbs (each product < 2^102; sum < 2^105)
        let mut t = [0u128; 10];
        for i in 0..5 {
            for j in 0..5 {
                t[i + j] += a.0[i] as u128 * b.0[j] as u128;
            }
        }
        // fold high limbs into low with factor 19 (2^255 ≡ 19 mod p)
        for i in 0..5 {
            t[i] += 19u128 * t[i + 5];
        }
        // propagate carries (limbs now < 2^110 → carry < 2^59)
        let mut out = [0u64; 5];
        let mut carry = 0u128;
        for i in 0..5 {
            let cur = t[i] + carry;
            out[i] = (cur & MASK51 as u128) as u64;
            carry = cur >> 51;
        }
        // fold final carry (2^255 ≡ 19)
        let mut c = 19u128 * carry; // < 2^64
        let mut i = 0usize;
        while c > 0 {
            let cur = out[i] as u128 + c;
            out[i] = (cur & MASK51 as u128) as u64;
            c = cur >> 51;
            i += 1;
            if i == 5 && c > 0 {
                // residual c·2^255 ≡ 19·c — fold back into limb 0
                c *= 19u128;
                i = 0;
            }
        }
        let mut r = Fe(out);
        cond_sub_p(&mut r);
        r
    }

    fn square(a: Fe) -> Fe {
        Fe::mul(a, a)
    }

    fn pow(&self, e: [u8; 32]) -> Fe {
        // e is little-endian exponent; iterate MSB first.
        let mut result = Fe::ONE;
        for i in (0..256).rev() {
            result = Fe::square(result);
            if (e[i / 8] >> (i % 8)) & 1 == 1 {
                result = Fe::mul(result, *self);
            }
        }
        result
    }

    /// a^(p−2) = a^(2^255 − 21): LE bytes = 0xEB then 0xFF×30 then 0x7F.
    fn invert(&self) -> Fe {
        let mut e = [0xFFu8; 32];
        e[0] = 0xEB;
        e[31] = 0x7F;
        self.pow(e)
    }

    /// Square root: returns Some if `self` is a QR, with sqrt^2 == self.
    /// p ≡ 5 (mod 8), so candidate = a^((p+3)/8); fallback × sqrt(-1).
    fn sqrt(&self) -> Option<Fe> {
        // (p+3)/8 = (2^255 − 16)/8 = 2^252 − 2: LE bytes = 0xFE then 0xFF×30 then 0x0F.
        let mut e = [0xFFu8; 32];
        e[0] = 0xFE;
        e[31] = 0x0F;
        let r = self.pow(e);
        if Fe::square(r) == *self {
            return Some(r);
        }
        let r2 = Fe::mul(r, sqrt_m1());
        if Fe::square(r2) == *self {
            return Some(r2);
        }
        None
    }
}

/// sqrt(−1) mod p (RFC 7748, §5), decoded from its 32-byte encoding.
fn sqrt_m1() -> Fe {
    Fe::from_bytes(&[
        0xB0, 0xA0, 0x0E, 0x4A, 0x27, 0x1B, 0xEE, 0xC4, 0x78, 0xE4, 0x2F, 0xAD, 0x06, 0x18, 0x43,
        0x2F, 0xA7, 0xD7, 0xFB, 0x3D, 0x99, 0x00, 0x4D, 0x2B, 0x0B, 0xDF, 0xC1, 0x4F, 0x80, 0x24,
        0x83, 0x2B,
    ])
}

/// Normalize a 5-limb i128 array to carried limbs < 2^51 and fold the
/// 2^255 term (factor 19). Input limbs must be within ±2^52.
fn normalize(t: [i128; 5]) -> Fe {
    let mut carry: i128 = 0;
    let mut out = [0u64; 5];
    for i in 0..5 {
        let cur = t[i] + carry;
        let q = cur.div_euclid(MASK51 as i128 + 1);
        let r = cur.rem_euclid(MASK51 as i128 + 1);
        out[i] = r as u64;
        carry = q;
    }
    // carry represents carry * 2^255 ≡ 19 * carry (mod p)
    let extra = 19i128 * carry;
    // re-fold into limb0 and re-carry limb0 → limb1
    let cur = out[0] as i128 + extra;
    out[0] = cur.rem_euclid(MASK51 as i128 + 1) as u64;
    let c = cur.div_euclid(MASK51 as i128 + 1);
    let cur1 = out[1] as i128 + c;
    out[1] = cur1.rem_euclid(MASK51 as i128 + 1) as u64;
    let c2 = cur1.div_euclid(MASK51 as i128 + 1);
    if c2 != 0 {
        // value is huge only in pathological cases; fold via limb2
        let cur2 = out[2] as i128 + c2;
        out[2] = cur2.rem_euclid(MASK51 as i128 + 1) as u64;
        let c3 = cur2.div_euclid(MASK51 as i128 + 1);
        if c3 != 0 {
            let cur3 = out[3] as i128 + c3;
            out[3] = cur3.rem_euclid(MASK51 as i128 + 1) as u64;
            let c4 = cur3.div_euclid(MASK51 as i128 + 1);
            if c4 != 0 {
                let cur4 = out[4] as i128 + c4;
                out[4] = cur4.rem_euclid(MASK51 as i128 + 1) as u64;
                let c5 = cur4.div_euclid(MASK51 as i128 + 1);
                if c5 != 0 {
                    // fold c5*2^255 ≡ 19*c5
                    let cur0 = out[0] as i128 + 19 * c5;
                    out[0] = cur0.rem_euclid(MASK51 as i128 + 1) as u64;
                    let c6 = cur0.div_euclid(MASK51 as i128 + 1);
                    if c6 != 0 {
                        out[1] = (out[1] as i128 + c6).rem_euclid(MASK51 as i128 + 1) as u64;
                    }
                }
            }
        }
    }
    Fe(out)
}

/// If `a >= p`, subtract p once (requires a < 2p).
fn cond_sub_p(a: &mut Fe) {
    if ge_p(a) {
        let mut borrow = 0u64;
        for i in 0..5 {
            let (d, b) = a.0[i].overflowing_sub(P[i]);
            let (d2, b2) = d.overflowing_sub(borrow);
            a.0[i] = d2;
            borrow = (b || b2) as u64;
        }
    }
}

/// a >= p ?
fn ge_p(a: &Fe) -> bool {
    for i in (0..5).rev() {
        if a.0[i] > P[i] {
            return true;
        }
        if a.0[i] < P[i] {
            return false;
        }
    }
    true
}

fn load64(b: &[u8]) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(&b[..8]);
    u64::from_le_bytes(x)
}

fn load64_7(b: &[u8]) -> u64 {
    debug_assert!(b.len() == 7);
    let mut x = [0u8; 8];
    x[..7].copy_from_slice(&b[..7]);
    u64::from_le_bytes(x)
}

// ---------- point ----------

/// Extended Edwards coordinates (X:Y:Z:T), T = XY/Z.
#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// d = −121665/121666 mod p (computed, never hardcoded).
fn d_constant() -> Fe {
    let a = Fe::from_limbs([121665, 0, 0, 0, 0]);
    let b = Fe::from_limbs([121666, 0, 0, 0, 0]);
    Fe::neg(Fe::mul(a, b.invert()))
}

impl Point {
    fn identity() -> Point {
        Point {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
            t: Fe::ZERO,
        }
    }

    fn from_xy(x: Fe, y: Fe) -> Point {
        let t = Fe::mul(x, y);
        Point {
            x,
            y,
            z: Fe::ONE,
            t,
        }
    }

    /// Base point of the Ed25519 group: y = 4/5, x even.
    fn base() -> Point {
        let y = Fe::from_bytes(&[
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ]);
        // x = sqrt((y^2-1)/(d y^2+1)), even root
        let y2 = Fe::square(y);
        let d = d_constant();
        let u = Fe::sub(y2, Fe::ONE);
        let v = Fe::add(Fe::mul(d, y2), Fe::ONE);
        let x = Fe::mul(u, v.invert()).sqrt().expect("base point on curve");
        let x = if x.is_negative() { Fe::neg(x) } else { x };
        Point::from_xy(x, y)
    }

    /// Decompress a 32-byte point encoding; None if not on the curve.
    fn decompress(b: &[u8; 32]) -> Option<Point> {
        let mut m = [0u8; 32];
        m.copy_from_slice(b);
        let sign = m[31] >> 7;
        m[31] &= 0x7f;
        let y = Fe::from_bytes(&m);
        let y2 = Fe::square(y);
        let d = d_constant();
        let u = Fe::sub(y2, Fe::ONE);
        let v = Fe::add(Fe::mul(d, y2), Fe::ONE);
        let x = Fe::mul(u, v.invert()).sqrt()?;
        let x = if x.is_negative() != (sign == 1) {
            Fe::neg(x)
        } else {
            x
        };
        Some(Point::from_xy(x, y))
    }

    /// Compress to 32 bytes.
    fn compress(&self) -> [u8; 32] {
        let zi = self.z.invert();
        let x = Fe::mul(self.x, zi);
        let y = Fe::mul(self.y, zi);
        let mut out = y.to_bytes();
        if x.is_negative() {
            out[31] |= 0x80;
        }
        out
    }

    fn add(a: Point, b: Point) -> Point {
        let d2 = Fe::mul(d_constant(), Fe([2, 0, 0, 0, 0]));
        let a_x = a.x;
        let a_y = a.y;
        let a_z = a.z;
        let a_t = a.t;
        let b_x = b.x;
        let b_y = b.y;
        let b_z = b.z;
        let b_t = b.t;
        let a = Fe::sub(a_y, a_x);
        let b_ = Fe::sub(b_y, b_x);
        let c = Fe::mul(a, b_);
        let d_ = Fe::add(a_y, a_x);
        let e = Fe::add(b_y, b_x);
        let f = Fe::mul(d_, e);
        let g = Fe::mul(a_t, b_t);
        let g = Fe::mul(g, d2);
        let h = Fe::mul(a_z, b_z);
        let h = Fe::add(h, h);
        let i = Fe::sub(f, c);
        let j = Fe::sub(h, g);
        let k = Fe::add(h, g);
        let l = Fe::add(f, c);
        let x3 = Fe::mul(i, j);
        let y3 = Fe::mul(k, l);
        let t3 = Fe::mul(i, l);
        let z3 = Fe::mul(j, k);
        Point {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }

    fn double(a: Point) -> Point {
        let a_x = a.x;
        let a_y = a.y;
        let a_z = a.z;
        let a_ = Fe::square(a_x);
        let b_ = Fe::square(a_y);
        let c_ = Fe::square(a_z);
        let c_ = Fe::add(c_, c_);
        let d_ = Fe::neg(a_);
        let e = Fe::add(a_x, a_y);
        let e = Fe::sub(Fe::square(e), Fe::add(a_, b_));
        let g = Fe::add(d_, b_);
        let f = Fe::sub(g, c_);
        let h = Fe::sub(d_, b_);
        let x3 = Fe::mul(e, f);
        let y3 = Fe::mul(g, h);
        let t3 = Fe::mul(e, h);
        let z3 = Fe::mul(f, g);
        Point {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }

    /// Scalar multiplication with a 4-bit window table (fixed or variable base).
    fn scalar_mul(&self, scalar: &[u8; 32]) -> Point {
        // table[j] = j * self
        let mut table = [Point::identity(); 16];
        table[1] = *self;
        for j in 2..16 {
            table[j] = Point::add(table[j - 1], *self);
        }
        let mut result = Point::identity();
        // 32 bytes = 64 nibbles (little-endian nibble order), one per loop.
        for i in (0..64).rev() {
            for _ in 0..4 {
                result = Point::double(result);
            }
            let nib = ((scalar[i / 2] >> ((i % 2) * 4)) & 0x0f) as usize;
            result = Point::add(result, table[nib]);
        }
        result
    }
}

// ---------- scalar arithmetic mod L ----------

/// Group order L = 2^252 + 27742317777372353535851937790883648493.
const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

fn bytes_to_limbs(b: &[u8]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for i in 0..4 {
        let mut x = [0u8; 8];
        x.copy_from_slice(&b[i * 8..i * 8 + 8]);
        out[i] = u64::from_le_bytes(x);
    }
    out
}

fn limbs_to_bytes(l: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&l[i].to_le_bytes());
    }
    out
}

fn ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

/// Reduce a 512-bit little-endian number modulo L (binary shift-subtract).
fn mod_l(x: &[u64; 8]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for i in (0..512).rev() {
        let bit = (x[i / 64] >> (i % 64)) & 1;
        let mut carry = bit;
        for j in 0..4 {
            let next = r[j] >> 63;
            r[j] = (r[j] << 1) | carry;
            carry = next;
        }
        if ge(&r, &L) {
            let mut borrow = 0u64;
            for j in 0..4 {
                let (d, b1) = r[j].overflowing_sub(L[j]);
                let (d2, b2) = d.overflowing_sub(borrow);
                r[j] = d2;
                borrow = (b1 || b2) as u64;
            }
        }
    }
    r
}

/// Reduce a 64-byte digest (little-endian) to a 32-byte scalar mod L.
fn mod_l_digest(digest: &[u8; 64]) -> [u8; 32] {
    let mut x = [0u64; 8];
    for i in 0..8 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&digest[i * 8..i * 8 + 8]);
        x[i] = u64::from_le_bytes(b);
    }
    let r = mod_l(&x);
    limbs_to_bytes(&r)
}

/// 32-byte scalar already < L (allows passing raw clamped bytes).
fn scalar_from_bytes(b: &[u8; 32]) -> [u8; 32] {
    *b
}

/// Clamp a 32-byte scalar per RFC 8032.
fn clamp(mut a: [u8; 32]) -> [u8; 32] {
    a[0] &= 248;
    a[31] &= 63;
    a[31] |= 64;
    a
}

// ---------- public API ----------

/// A 64-byte Ed25519 signature (R || S).
pub type Signature = [u8; 64];

/// Sign `msg` with the 32-byte secret key, returning a 64-byte signature.
pub fn sign(secret_key: &[u8; 32], msg: &[u8]) -> Signature {
    let h = Sha512::digest(secret_key);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    let prefix = &h[32..];
    let a_clamped = clamp(a);

    let public = Point::base().scalar_mul(&scalar_from_bytes(&a_clamped));
    let a_enc = public.compress();

    // r = SHA512(prefix || msg) mod L
    let mut r_input = Vec::with_capacity(32 + msg.len());
    r_input.extend_from_slice(prefix);
    r_input.extend_from_slice(msg);
    let r = mod_l_digest(&Sha512::digest(&r_input));
    let r_point = Point::base().scalar_mul(&scalar_from_bytes(&r));
    let r_enc = r_point.compress();

    // h = SHA512(R || A || msg) mod L
    let mut h_input = Vec::with_capacity(64 + msg.len());
    h_input.extend_from_slice(&r_enc);
    h_input.extend_from_slice(&a_enc);
    h_input.extend_from_slice(msg);
    let h_scalar = mod_l_digest(&Sha512::digest(&h_input));

    // S = (r + h * a) mod L
    let a_limbs = bytes_to_limbs(&a_clamped);
    let h_limbs = bytes_to_limbs(&h_scalar);
    let r_limbs = bytes_to_limbs(&r);
    let mut prod = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let cur = prod[i + j] as u128 + h_limbs[i] as u128 * a_limbs[j] as u128 + carry;
            prod[i + j] = cur as u64;
            carry = cur >> 64;
        }
        prod[i + 4] = carry as u64;
    }
    let mut carry = 0u128;
    for i in 0..4 {
        let cur = prod[i] as u128 + r_limbs[i] as u128 + carry;
        prod[i] = cur as u64;
        carry = cur >> 64;
    }
    prod[4] = prod[4].wrapping_add(carry as u64);
    let s = mod_l(&prod);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_enc);
    sig[32..].copy_from_slice(&limbs_to_bytes(&s));
    sig
}

/// Derive the 32-byte public key from a secret key.
pub fn public_key(secret_key: &[u8; 32]) -> [u8; 32] {
    let h = Sha512::digest(secret_key);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    let a_clamped = clamp(a);
    Point::base()
        .scalar_mul(&scalar_from_bytes(&a_clamped))
        .compress()
}

/// Verify a signature. `None`-returning internals become `false`.
pub fn verify(public_key: &[u8; 32], msg: &[u8], signature: &Signature) -> bool {
    let a = match Point::decompress(public_key) {
        Some(p) => p,
        None => return false,
    };
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let r = match Point::decompress(&r_bytes) {
        Some(p) => p,
        None => return false,
    };
    // reject non-canonical S (S >= L)
    let s_limbs = bytes_to_limbs(&signature[32..]);
    if ge(&s_limbs, &L) {
        return false;
    }
    let s_bytes = limbs_to_bytes(&s_limbs);

    let mut h_input = Vec::with_capacity(64 + msg.len());
    h_input.extend_from_slice(&signature[..32]);
    h_input.extend_from_slice(public_key);
    h_input.extend_from_slice(msg);
    let h_scalar = mod_l_digest(&Sha512::digest(&h_input));

    let s_b = Point::base().scalar_mul(&s_bytes);
    let h_a = a.scalar_mul(&h_scalar);
    let rhs = Point::add(r, h_a);
    s_b.compress() == rhs.compress()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_arr32(v: &[u8]) -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(v);
        a
    }

    #[test]
    fn field_roundtrip() {
        // from_bytes / to_bytes roundtrip for random-ish values
        let mut v = [0u8; 32];
        for i in 0..32 {
            v[i] = (i * 37 + 11) as u8;
        }
        v[31] &= 0x7f; // field elements keep bit 255 clear
        let f = Fe::from_bytes(&v);
        assert_eq!(f.to_bytes(), v);
        // 1 + p - 1 == 0
        let one = Fe::ONE;
        assert_eq!(Fe::sub(one, one), Fe::ZERO);
        assert_eq!(Fe::add(one, Fe::ZERO), one);
        // 19 has inverse: 19 * 19^-1 = 1
        let nineteen = Fe::from_limbs([19, 0, 0, 0, 0]);
        let inv = nineteen.invert();
        assert_eq!(Fe::mul(nineteen, inv), Fe::ONE);
    }

    #[test]
    fn base_point_on_curve() {
        let b = Point::base();
        // 5 * y == 4
        let y5 = Fe::mul(Fe::from_limbs([5, 0, 0, 0, 0]), b.y);
        assert_eq!(
            y5,
            Fe::from_limbs([4, 0, 0, 0, 0]),
            "5*y = {:?}, y = {:?}",
            y5.0,
            b.y.0
        );
        let enc = b.compress();
        // RFC 8032 base point encoding: y = 4/5
        let mut expect = [0x66u8; 32];
        expect[0] = 0x58;
        assert_eq!(enc, expect, "base compress = {:02x?}", enc);
        // and it decompresses to the same point
        let d = Point::decompress(&enc).unwrap();
        assert_eq!(d.compress(), enc);
        // on-curve check (twisted Edwards): y^2 - x^2 = 1 + d·x^2·y^2
        let x = b.x;
        let y = b.y;
        let d = d_constant();
        let lhs = Fe::sub(Fe::square(y), Fe::square(x));
        let rhs = Fe::add(Fe::ONE, Fe::mul(d, Fe::mul(Fe::square(x), Fe::square(y))));
        assert_eq!(lhs, rhs);
        // scalar mult sanity: 2B via add == 2B via scalar_mul
        let mut two = [0u8; 32];
        two[0] = 2;
        let b2 = b.scalar_mul(&two);
        let bb = Point::add(b, b);
        assert_eq!(b2.compress(), bb.compress(), "2B via scalar vs add");
        let mut three = [0u8; 32];
        three[0] = 3;
        let b3 = b.scalar_mul(&three);
        let b3a = Point::add(bb, b);
        assert_eq!(b3.compress(), b3a.compress(), "3B via scalar vs add");
        // 2B should be on the curve and not the identity
        assert_ne!(b2.compress(), b.compress());
        assert_ne!(b2.compress(), Point::identity().compress());
    }

    #[test]
    fn sqrt_works() {
        for (i, a) in [
            Fe::ONE,
            Fe([2, 0, 0, 0, 0]),
            Fe::from_limbs([12345, 0, 0, 0, 0]),
        ]
        .iter()
        .enumerate()
        {
            let s = Fe::square(*a);
            let r = s
                .sqrt()
                .unwrap_or_else(|| panic!("sqrt({:?}) -> None at idx {}", s.0, i));
            assert_eq!(Fe::square(r), s);
        }
        // -1 is a QR
        let m1 = Fe::neg(Fe::ONE);
        let r = m1.sqrt().unwrap();
        assert_eq!(Fe::square(r), m1);
    }

    #[test]
    fn rfc8032_test1() {
        let sk = to_arr32(&unhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        let pk = to_arr32(&unhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ));
        let sig = unhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555\
             fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        assert_eq!(public_key(&sk), pk);
        assert_eq!(sign(&sk, b""), to_arr64(&sig));
        assert!(verify(&pk, b"", &to_arr64(&sig)));
    }

    #[test]
    fn rfc8032_test2() {
        let sk = to_arr32(&unhex(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        ));
        let pk = to_arr32(&unhex(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        ));
        let msg = unhex("72");
        let sig = unhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da0\
             85ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );
        assert_eq!(public_key(&sk), pk);
        let s = sign(&sk, &msg);
        assert_eq!(s, to_arr64(&sig));
        assert!(verify(&pk, &msg, &s));
        assert!(!verify(&pk, b"tampered", &s));
    }

    #[test]
    fn rfc8032_test3() {
        let sk = to_arr32(&unhex(
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        ));
        let pk = to_arr32(&unhex(
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        ));
        let msg = unhex("af82");
        let sig = unhex(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac1\
             8ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        );
        assert_eq!(public_key(&sk), pk);
        assert!(verify(&pk, &msg, &to_arr64(&sig)));
    }

    fn to_arr64(v: &[u8]) -> [u8; 64] {
        let mut a = [0u8; 64];
        a.copy_from_slice(v);
        a
    }
}
