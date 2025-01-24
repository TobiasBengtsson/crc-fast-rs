/*
 * Copyright (c) 2024 Tobias Bengtsson
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

use proc_macro::TokenStream;

// Adapted from https://stackoverflow.com/q/21171733
// t=exponent, n=crc bits, m=mask, q=quotient, r=remainder
fn calc_const(mut t: u32, mut poly: u64) -> (u64, u64) {
    let mut n = get_n(format!("{:#X}", poly).as_str());
    if t < n {
        return (0, poly);
    }

    let m = (1 << n) - 1;
    poly = poly & m;
    let mut r = poly;
    let mut q = 1;
    n = n - 1;
    t = t - 1;
    while t > n {
        let high = (r >> n) & 1;
        q = (q << 1) | high;  /* quotient bits may be lost off the top */
        r = r << 1;
        if high != 0 {
            r = r ^ poly;
        }

        t = t - 1
    }
    return (q, r & m);
}

/// Get the degree of the polynomial. Throws if unsupported.
/// WARNING: still UB for unsupported degrees (since the string can have the
/// same length as a supported one, and the function is currently rather naive)
fn get_n(poly_str: &str) -> u32 {
    let n = 4 * (poly_str.len() - 3);
    if !matches!(n, 8 | 16 | 24 | 32) {
        unimplemented!("{}-bit CRCs are not currently supported", n)
    }

    n as u32
}

fn get_table(n: u32, poly: u64) -> String {
    let mut table: Vec<u32> = vec![];
    // Table entries are just calculating the CRC of single bytes (0-255)
    // (without init, output XOR)
    for i in 0x0..=0xFF {
        let mut x = i << (n - 8);
        for _ in 0..8 {
            x = x << 1;
            if x & ((1 as u64) << n) != 0 {
                x = x ^ poly
            }
        }
        x = x & (((1 as u64) << n) - 1);
        table.push(x as u32);
    }

    // 64 rows * (4 spaces + 4(n/4) + hex chars + (2 * 4) 0x:s + 4 commas + 3 spaces + 1 newline)
    let mut table_str = String::with_capacity(64 * (n + 28) as usize);
    let rows = table.chunks(4);
    for row in rows {
        table_str.push_str("    ");
        table_str.push_str(row.iter().map(|entry| format!("{:#0width$X},", entry, width = (2 + n / 4) as usize)).collect::<Vec<String>>().join(" ").as_str());
        table_str.push_str("\n");
    }

    table_str
}

#[proc_macro]
pub fn crc(ts: TokenStream) -> TokenStream {
    let args_str = ts.to_string();
    let args: Vec<&str> = args_str.split(", ").collect();
    let poly_str = args.get(0).unwrap();
    let init_str = args.get(1).unwrap();
    let output_xor = args.get(2).unwrap();
    let lorem_expected_result = args.get(3).unwrap();
    let lorem_aligned_expected_result = args.get(4).unwrap();
    let check_expected_result = args.get(5).unwrap();
    let n = get_n(poly_str);

    let poly = u64::from_str_radix(poly_str.strip_prefix("0x").unwrap(), 16).unwrap();

    // Shifted to the left to 32-bits (i.e. with trailing zeroes).
    let poly_str_simd = format!("{:0<11}", poly_str);
    let init_str_simd = format!("{:0<10}", init_str);

    // Calculate constants used in SIMD
    let poly_simd = u64::from_str_radix(poly_str_simd.strip_prefix("0x").unwrap(), 16).unwrap();
    let (u, k6) = calc_const(64, poly_simd);
    let (_, k5) = calc_const(96, poly_simd);
    let (_, k4) = calc_const(128, poly_simd);
    let (_, k3) = calc_const(128 + 64, poly_simd);
    let (_, k2) = calc_const(128 * 4, poly_simd);
    let (_, k1) = calc_const(128 * 4 + 64, poly_simd);

    (r#"
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
"#.to_owned() +
        format!("const POLY: u64 = {};", poly_str).as_str() +
        format!("const INIT: u64 = {};", init_str).as_str() +
r#"

/// Calculate the CRC checksum of the octets using an SIMD implementation if
/// available. If not, a fallback algorithm is used. If the table-fallback
/// feature is enabled this will be a lookup table based algorithm, otherwise a
/// simple loop is used (slowest).
///
/// Currently, SIMD is implemented for x86-64 CPU:s with pclmulqdq and sse4.1
/// support.
pub fn hash(octets: &[u8]) -> u32 {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if core_detect::is_x86_feature_detected!("pclmulqdq")
        && core_detect::is_x86_feature_detected!("sse4.1")
    {
        unsafe {
            return hash_pclmulqdq(octets);
        }
    }

    #[cfg(all(target_arch = "aarch64", target_feature="aes"))]
    unsafe {
        return hash_pmull(octets);
    }
    #[cfg(all(target_arch = "aarch64", feature="std"))]
    if std::arch::is_aarch64_feature_detected!("aes")
    {
        unsafe {
            return hash_pmull(octets);
        }
    }

    hash_fallback(octets)
}

fn hash_fallback(octets: &[u8]) -> u32 {
    if cfg!(feature = "table-fallback") {
        hash_table(octets)
    } else {
        hash_simple(octets)
    }
}

/// Calculate the CRC checksum of the octets using a simple loop algorithm
/// (slow).
pub fn hash_simple(octets: &[u8]) -> u32 {
    let mut x: u64 = INIT;
    for octet in octets {
"# +
     format!("        x = x ^ ((*octet as u64) << {});", n - 8).as_str() +
r#"
        for _ in 0..8 {
            x = x << 1;
"# +
     format!("            if x & ({:#X} as u64) != 0 {{", (1 as u64) << n).as_str() +
r#"
                x = x ^ POLY;
            }
        }
    }

"# +
     format!("    ((x & {:#X}) ^ {}) as u32", ((1 as u64) << n) - 1, output_xor).as_str() +
r#"
}

#[cfg(feature = "table-fallback")]
const CRC_TABLE: [u64; 256] = [
"# +
     format!("{}", get_table(n, poly)).as_str() +
r#"
];

/// Calculate the CRC checksum of the octets using a table lookup algorithm.
#[cfg(feature = "table-fallback")]
pub fn hash_table(octets: &[u8]) -> u32 {
    let mut x = INIT;
    for octet in octets {
"# +
     format!("        let index = ((*octet as u64) ^ (x >> {})) & 0xFF;", n - 8).as_str() +
r#"
        x = (x << 8) ^ CRC_TABLE[index as usize];
    }
"# +
     format!("    ((x & {:#X}) ^ {}) as u32", ((1 as u64) << n) - 1, output_xor).as_str() +
r#"
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(overflowing_literals)]
#[target_feature(enable = "pclmulqdq")]
#[target_feature(enable = "sse4.1")]
unsafe fn hash_pclmulqdq(bin: &[u8]) -> u32 {
    let mut octets = bin;
"# +
     format!("    const Q_X: i64 = {};", poly_str_simd).as_str() +
     format!("    const U: i64 = {:#X};", u).as_str() +
     format!("    const K1: i64 = {:#X};", k1).as_str() +
     format!("    const K2: i64 = {:#X};", k2).as_str() +
     format!("    const K3: i64 = {:#X};", k3).as_str() +
     format!("    const K4: i64 = {:#X};", k4).as_str() +
     format!("    const K5: i64 = {:#X};", k5).as_str() +
     format!("    const K6: i64 = {:#X};", k6).as_str() +
r#"
    if octets.len() < 128 {
        return hash_fallback(octets);
    }

    let shuf_mask = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);

    let mut x3 = _mm_loadu_si128(octets.as_ptr() as *const __m128i);
    octets = &octets[16..];
    let mut x2 = _mm_loadu_si128(octets.as_ptr() as *const __m128i);
    octets = &octets[16..];
    let mut x1 = _mm_loadu_si128(octets.as_ptr() as *const __m128i);
    octets = &octets[16..];
    let mut x0 = _mm_loadu_si128(octets.as_ptr() as *const __m128i);
    octets = &octets[16..];

    x3 = _mm_shuffle_epi8(x3, shuf_mask);
    x2 = _mm_shuffle_epi8(x2, shuf_mask);
    x1 = _mm_shuffle_epi8(x1, shuf_mask);
    x0 = _mm_shuffle_epi8(x0, shuf_mask);
"# +
     format!("    x3 = _mm_xor_si128(x3, _mm_set_epi32({}i32, 0, 0, 0));", init_str_simd).as_str() +
r#"

    let k1k2 = _mm_set_epi64x(K2, K1);
    while octets.len() >= 128 {
        (x3, x2, x1, x0) = fold_by_4_128_x86(x3, x2, x1, x0, k1k2, shuf_mask, &mut octets);
    }

    let k3k4 = _mm_set_epi64x(K4, K3);
    let mut x = reduce128_x86(x3, x2, k3k4);
    x = reduce128_x86(x, x1, k3k4);
    x = reduce128_x86(x, x0, k3k4);

    while octets.len() >= 16 {
        let y = _mm_loadu_si128(octets.as_ptr() as *const __m128i);
        octets = &octets[16..];
        let y = _mm_shuffle_epi8(y, shuf_mask);
        x = reduce128_x86(x, y, k3k4);
    }

    if octets.len() > 0 {
        // Pad data with zero to 256 bits, apply final reduce
        let pad = 16 - octets.len() as i32;
        let pad_usize = pad as usize;
        let mut bfr: [u8; 32] = [0; 32];

        // TODO: the back-and forth shuffling of x shouldn't be necessary
        x = _mm_shuffle_epi8(x, shuf_mask);
        _mm_storeu_si128(bfr[pad_usize..].as_ptr() as *mut __m128i, x);
        bfr[16+pad_usize..].copy_from_slice(&octets);
        x = _mm_loadu_si128(bfr.as_ptr() as *const __m128i);
        x = _mm_shuffle_epi8(x, shuf_mask);
        let y = _mm_loadu_si128(bfr[16..].as_ptr() as *const __m128i);
        let y = _mm_shuffle_epi8(y, shuf_mask);
        x = reduce128_x86(x, y, k3k4);
    }

    let k5k6 = _mm_set_epi64x(K6, K5);
    // Apply 128 -> 64 bit reduce
    let k5mul = _mm_clmulepi64_si128(x, k5k6, 0x01);

    let x = _mm_and_si128(
        _mm_xor_si128(_mm_slli_si128::<4>(x), k5mul),
        _mm_set_epi32(0, !0, !0, !0),
    );

    let k6mul = _mm_clmulepi64_si128(x, k5k6, 0x11);
    let x = _mm_and_si128(_mm_xor_si128(x, k6mul), _mm_set_epi32(0, 0, !0, !0));

    let pu = _mm_set_epi64x(U, Q_X);
    let t1 = _mm_clmulepi64_si128(_mm_srli_si128::<4>(x), pu, 0x10);
    let t2 = _mm_clmulepi64_si128(_mm_srli_si128::<4>(t1), pu, 0x00);

    let x = _mm_xor_si128(x, t2);
    let mut c = _mm_extract_epi32(x, 0) as u32;

"# +
     format!("    c = c >> {};", 32 - n).as_str() +
     format!("    c ^ {}", output_xor).as_str() +
r#"
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "pclmulqdq")]
#[target_feature(enable = "sse4.1")]
unsafe fn fold_by_4_128_x86(
    x3: __m128i,
    x2: __m128i,
    x1: __m128i,
    x0: __m128i,
    k1k2: __m128i,
    shuf_mask: __m128i,
    octets: &mut &[u8],
) -> (__m128i, __m128i, __m128i, __m128i) {
    let y3 = _mm_loadu_si128(octets.as_ptr() as *const __m128i);
    *octets = &octets[16..];
    let y2 = _mm_loadu_si128(octets.as_ptr() as *const __m128i);
    *octets = &octets[16..];
    let y1 = _mm_loadu_si128(octets.as_ptr() as *const __m128i);
    *octets = &octets[16..];
    let y0 = _mm_loadu_si128(octets.as_ptr() as *const __m128i);
    *octets = &octets[16..];

    let y3 = _mm_shuffle_epi8(y3, shuf_mask);
    let y2 = _mm_shuffle_epi8(y2, shuf_mask);
    let y1 = _mm_shuffle_epi8(y1, shuf_mask);
    let y0 = _mm_shuffle_epi8(y0, shuf_mask);

    let x3 = reduce128_x86(x3, y3, k1k2);
    let x2 = reduce128_x86(x2, y2, k1k2);
    let x1 = reduce128_x86(x1, y1, k1k2);
    let x0 = reduce128_x86(x0, y0, k1k2);
    (x3, x2, x1, x0)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "pclmulqdq")]
#[target_feature(enable = "sse4.1")]
unsafe fn reduce128_x86(a: __m128i, b: __m128i, keys: __m128i) -> __m128i {
    let t1 = _mm_clmulepi64_si128(a, keys, 0x01);
    let t2 = _mm_clmulepi64_si128(a, keys, 0x10);
    _mm_xor_si128(_mm_xor_si128(b, t1), t2)
}

#[cfg(target_arch = "aarch64")]
#[allow(overflowing_literals)]
#[target_feature(enable = "aes")]
unsafe fn hash_pmull(bin: &[u8]) -> u32 {
    let mut octets = bin;
"# +
     format!("    const Q_X: i64 = {};", poly_str_simd).as_str() +
     format!("    const U: i64 = {:#X};", u).as_str() +
     format!("    const K1: i64 = {:#X};", k1).as_str() +
     format!("    const K2: i64 = {:#X};", k2).as_str() +
     format!("    const K3: i64 = {:#X};", k3).as_str() +
     format!("    const K4: i64 = {:#X};", k4).as_str() +
     format!("    const K5: i64 = {:#X};", k5).as_str() +
     format!("    const K6: i64 = {:#X};", k6).as_str() +
r#"
    if octets.len() < 128 {
        return hash_fallback(octets);
    }

    let shuf_mask = vld1q_u8([15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0].as_ptr());

    let mut x3 = vld1q_u8(octets.as_ptr());
    octets = &octets[16..];
    let mut x2 = vld1q_u8(octets.as_ptr());
    octets = &octets[16..];
    let mut x1 = vld1q_u8(octets.as_ptr());
    octets = &octets[16..];
    let mut x0 = vld1q_u8(octets.as_ptr());
    octets = &octets[16..];

    x3 = vqtbl1q_u8(x3, shuf_mask);
    x2 = vqtbl1q_u8(x2, shuf_mask);
    x1 = vqtbl1q_u8(x1, shuf_mask);
    x0 = vqtbl1q_u8(x0, shuf_mask);
"# +
     format!("    x3 = veorq_u8(x3, vreinterpretq_u8_s32(vld1q_s32([0, 0, 0, {}i32].as_ptr())));", init_str_simd).as_str() +
r#"

    let k1k2 = vreinterpretq_u8_s64(vld1q_s64([K1, K2].as_ptr()));
    while octets.len() >= 128 {
        (x3, x2, x1, x0) = fold_by_4_128_aarch64(x3, x2, x1, x0, k1k2, shuf_mask, &mut octets);
    }

    let k3k4 = vreinterpretq_u8_s64(vld1q_s64([K3, K4].as_ptr()));
    let mut x = reduce128_aarch64(x3, x2, k3k4);
    x = reduce128_aarch64(x, x1, k3k4);
    x = reduce128_aarch64(x, x0, k3k4);

    while octets.len() >= 16 {
        let y = vld1q_u8(octets.as_ptr());
        octets = &octets[16..];
        let y = vqtbl1q_u8(y, shuf_mask);
        x = reduce128_aarch64(x, y, k3k4);
    }

    if octets.len() > 0 {
        // Pad data with zero to 256 bits, apply final reduce
        let pad = 16 - octets.len() as i32;
        let pad_usize = pad as usize;
        let mut bfr: [u8; 32] = [0; 32];

        // TODO: the back-and forth shuffling of x shouldn't be necessary
        x = vqtbl1q_u8(x, shuf_mask);
        vst1q_u8(bfr[pad_usize..].as_ptr() as *mut u8, x);
        bfr[16+pad_usize..].copy_from_slice(&octets);
        x = vld1q_u8(bfr.as_ptr());
        x = vqtbl1q_u8(x, shuf_mask);
        let y = vld1q_u8(bfr[16..].as_ptr());
        let y = vqtbl1q_u8(y, shuf_mask);
        x = reduce128_aarch64(x, y, k3k4);
    }

    let k5k6 = vreinterpretq_u8_s64(vld1q_s64([K5, K6].as_ptr()));
    // Apply 128 -> 64 bit reduce
    let k5mul = core::mem::transmute(vmull_p64(vgetq_lane_p64(vreinterpretq_p64_u8(x), 1), vgetq_lane_p64(vreinterpretq_p64_u8(k5k6), 0)));

    // Left shift by 4 bytes using tbl lookup. Out-of index automatically zeroes the right bytes.
    let left_shift_4bytes_mask = vld1q_u8([255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11].as_ptr());
    let x = vandq_u8(
        veorq_u8(
            vqtbl1q_u8(x, left_shift_4bytes_mask),
            k5mul,
        ),
        vreinterpretq_u8_s32(vld1q_s32([!0, !0, !0, 0].as_ptr())),
    );

    let k6mul = core::mem::transmute(vmull_p64(vgetq_lane_p64(vreinterpretq_p64_u8(x), 1), vgetq_lane_p64(vreinterpretq_p64_u8(k5k6), 1)));
    let x = vandq_u8(veorq_u8(x, k6mul), vreinterpretq_u8_s32(vld1q_s32([!0, !0, 0, 0].as_ptr())));

    let right_shift_4bytes_mask = vld1q_u8([4,5,6,7,8,9,10,11,12,13,14,15,255,255,255,255].as_ptr());
    let pu = vreinterpretq_u8_s64(vld1q_s64([Q_X, U].as_ptr()));
    let t1 = core::mem::transmute(
        vmull_p64(
            vgetq_lane_p64(vreinterpretq_p64_u8(vqtbl1q_u8(x, right_shift_4bytes_mask)), 0),
            vgetq_lane_p64(vreinterpretq_p64_u8(pu), 1),
        ),
    );
    let t2 = core::mem::transmute(
        vmull_p64(
            vgetq_lane_p64(vreinterpretq_p64_u8(vqtbl1q_u8(t1, right_shift_4bytes_mask)), 0),
            vgetq_lane_p64(vreinterpretq_p64_u8(pu), 0),
        ),
    );

    let x = veorq_u8(x, t2);
    let mut c = vgetq_lane_u32(vreinterpretq_u32_u8(x), 0) as u32;

"# +
     format!("    c = c >> {};", 32 - n).as_str() +
     format!("    c ^ {}", output_xor).as_str() +
r#"
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes")]
unsafe fn fold_by_4_128_aarch64(
    x3: uint8x16_t,
    x2: uint8x16_t,
    x1: uint8x16_t,
    x0: uint8x16_t,
    k1k2: uint8x16_t,
    shuf_mask: uint8x16_t,
    octets: &mut &[u8],
) -> (uint8x16_t, uint8x16_t, uint8x16_t, uint8x16_t) {
    let y3 = vld1q_u8(octets.as_ptr());
    *octets = &octets[16..];
    let y2 = vld1q_u8(octets.as_ptr());
    *octets = &octets[16..];
    let y1 = vld1q_u8(octets.as_ptr());
    *octets = &octets[16..];
    let y0 = vld1q_u8(octets.as_ptr());
    *octets = &octets[16..];

    let y3 = vqtbl1q_u8(y3, shuf_mask);
    let y2 = vqtbl1q_u8(y2, shuf_mask);
    let y1 = vqtbl1q_u8(y1, shuf_mask);
    let y0 = vqtbl1q_u8(y0, shuf_mask);

    let x3 = reduce128_aarch64(x3, y3, k1k2);
    let x2 = reduce128_aarch64(x2, y2, k1k2);
    let x1 = reduce128_aarch64(x1, y1, k1k2);
    let x0 = reduce128_aarch64(x0, y0, k1k2);
    (x3, x2, x1, x0)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes")]
unsafe fn reduce128_aarch64(a: uint8x16_t, b: uint8x16_t, keys: uint8x16_t) -> uint8x16_t {
    let t1 = core::mem::transmute(vmull_p64(vgetq_lane_p64(vreinterpretq_p64_u8(a), 0), vgetq_lane_p64(vreinterpretq_p64_u8(keys), 1)));
    let t2 = core::mem::transmute(vmull_p64(vgetq_lane_p64(vreinterpretq_p64_u8(a), 1), vgetq_lane_p64(vreinterpretq_p64_u8(keys), 0)));
    veorq_u8(veorq_u8(b, t1), t2)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOREM: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Lorem ipsum dolor sit amet, consectetur adipiscing";

    // Lorem ipsum padded to 128-bit boundary
    const LOREM_ALIGNED: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Lorem ipsum dolor sit amet, consectetur adipiscing aaaaaaaaaaaaaaa";

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    pub fn test_lorem_pclmulqdq() {
        let result = unsafe {hash_pclmulqdq(LOREM) };
"# +
     format!("        assert_eq!(result, {});", lorem_expected_result).as_str() +
r#"
    }

    #[cfg(any(target_arch = "aarch64"))]
    #[test]
    pub fn test_lorem_pmull() {
        let result = unsafe {hash_pmull(LOREM) };
"# +
     format!("        assert_eq!(result, {});", lorem_expected_result).as_str() +
r#"
    }

    #[test]
    pub fn test_lorem_table() {
        let result = hash_table(LOREM);
"# +
     format!("        assert_eq!(result, {});", lorem_expected_result).as_str() +
r#"
    }

    #[test]
    pub fn test_lorem_simple() {
        let result = hash_simple(LOREM);
"# +
     format!("        assert_eq!(result, {});", lorem_expected_result).as_str() +
r#"
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    pub fn test_lorem_aligned_pclmulqdq() {
        let result = unsafe { hash_pclmulqdq(LOREM_ALIGNED) };
"# +
     format!("        assert_eq!(result, {});", lorem_aligned_expected_result).as_str() +
r#"
    }

    #[cfg(any(target_arch = "aarch64"))]
    #[test]
    pub fn test_lorem_aligned_pmull() {
        let result = unsafe { hash_pmull(LOREM_ALIGNED) };
"# +
     format!("        assert_eq!(result, {});", lorem_aligned_expected_result).as_str() +
r#"
    }

    #[test]
    pub fn test_lorem_aligned_table() {
        let result = hash_table(LOREM_ALIGNED);
"# +
     format!("        assert_eq!(result, {});", lorem_aligned_expected_result).as_str() +
r#"
    }

    #[test]
    pub fn test_lorem_aligned_simple() {
        let result = hash_simple(LOREM_ALIGNED);
"# +
     format!("        assert_eq!(result, {});", lorem_aligned_expected_result).as_str() +
r#"
    }

    #[test]
    pub fn test_check_simple() {
        let raw = *b"123456789";
"# +
     format!("        assert_eq!(hash_simple(&raw), {});", check_expected_result).as_str() +
r#"
    }

    #[test]
    pub fn test_check_table() {
        let raw = *b"123456789";
"# +
     format!("        assert_eq!(hash_table(&raw), {});", check_expected_result).as_str() +
r#"
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    pub fn test_120_bytes() {
        // Uses fallback
        let raw = b"12345678".repeat(15);
        let expected_result = hash_simple(&raw);
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let result = unsafe { hash_pclmulqdq(&raw) };
        #[cfg(any(target_arch = "aarch64"))]
        let result = unsafe { hash_pmull(&raw) };
        assert_eq!(result, expected_result);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    pub fn test_128_bytes() {
        let raw = b"12345678".repeat(16);
        let expected_result = hash_simple(&raw);
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let result = unsafe { hash_pclmulqdq(&raw) };
        #[cfg(any(target_arch = "aarch64"))]
        let result = unsafe { hash_pmull(&raw) };
        assert_eq!(result, expected_result);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    pub fn test_2187_bytes() {
        // Large enough to fold multiple times, will need padding
        let raw = b"abc123)(#".repeat(243);
        let expected_result = hash_simple(&raw);
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let result = unsafe { hash_pclmulqdq(&raw) };
        #[cfg(any(target_arch = "aarch64"))]
        let result = unsafe { hash_pmull(&raw) };
        assert_eq!(result, expected_result);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    pub fn test_80056_bytes() {
        // Random "larger" number
        let raw = b"1jn5?`=Z".repeat(10007);
        let expected_result = hash_simple(&raw);
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let result = unsafe { hash_pclmulqdq(&raw) };
        #[cfg(any(target_arch = "aarch64"))]
        let result = unsafe { hash_pmull(&raw) };
        assert_eq!(result, expected_result);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    pub fn test_zero_data() {
        let raw = [0; 10007];
        let expected_result = hash_simple(&raw);
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let result = unsafe { hash_pclmulqdq(&raw) };
        #[cfg(any(target_arch = "aarch64"))]
        let result = unsafe { hash_pmull(&raw) };
        assert_eq!(result, expected_result);
    }
}
    "#).parse().unwrap()
}
