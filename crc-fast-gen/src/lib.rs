use proc_macro::TokenStream;

#[proc_macro]
pub fn crc(ts: TokenStream) -> TokenStream {
    r#"
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[cfg(target_arch = "x86")]
use std::arch::x86::*;

fn hash(octets: &[u8]) -> u32 {
    if is_x86_feature_detected!("pclmulqdq")
        && is_x86_feature_detected!("sse4.1")
    {
        unsafe {
            return hash_pclmulqdq(octets);
        }
    }

    hash_simple(octets)
}

fn hash_simple(octets: &[u8]) -> u32 {
    let mut x: u32 = 0xB704CE;
    for octet in octets {
        x = x ^ ((*octet as u32) << 16);
        for _ in 0..8 {
            x = x << 1;
            if x & (0x1000000 as u32) != 0 {
                x = x ^ 0x1864CFB;
            }
        }
    }

    x & 0xFFFFFF
}

#[allow(overflowing_literals)]
#[target_feature(enable = "pclmulqdq")]
#[target_feature(enable = "sse4.1")]
unsafe fn hash_pclmulqdq(bin: &[u8]) -> u32 {
    let mut octets = bin;
    const Q_X: i64 = 0x1864CFB00; // P(x) * x^8
    const U: i64 = 0x1F845FE24;

    // see https://stackoverflow.com/questions/21171733/calculating-constants-for-crc32-using-pclmulqdq
    const K1: i64 = 0x1F428700; // T = 128 * 4 + 64
    const K2: i64 = 0x467D2400; // T = 128 * 4
    const K3: i64 = 0x2C8C9D00; // T = 128 + 64
    const K4: i64 = 0x64E4D700; // T = 128
    const K5: i64 = 0xFD7E0C00; // T = 96
    const K6: i64 = 0xD9FE8C00; // T = 64

    if octets.len() < 128 {
        return hash_simple(octets);
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

    x3 = _mm_xor_si128(x3, _mm_set_epi32(0xB704CE00i32, 0, 0, 0));

    let k1k2 = _mm_set_epi64x(K2, K1);
    while octets.len() >= 128 {
        (x3, x2, x1, x0) = fold_by_4_128(x3, x2, x1, x0, k1k2, shuf_mask, &mut octets);
    }

    let k3k4 = _mm_set_epi64x(K4, K3);
    let mut x = reduce128(x3, x2, k3k4);
    x = reduce128(x, x1, k3k4);
    x = reduce128(x, x0, k3k4);

    while octets.len() >= 16 {
        let y = _mm_loadu_si128(octets.as_ptr() as *const __m128i);
        octets = &octets[16..];
        let y = _mm_shuffle_epi8(y, shuf_mask);
        x = reduce128(x, y, k3k4);
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
        x = reduce128(x, y, k3k4);
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
    let c = _mm_extract_epi32(x, 0) as u32;

    c >> 8
}

#[target_feature(enable = "pclmulqdq")]
#[target_feature(enable = "sse4.1")]
unsafe fn fold_by_4_128(
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

    let x3 = reduce128(x3, y3, k1k2);
    let x2 = reduce128(x2, y2, k1k2);
    let x1 = reduce128(x1, y1, k1k2);
    let x0 = reduce128(x0, y0, k1k2);
    (x3, x2, x1, x0)
}

#[target_feature(enable = "pclmulqdq")]
#[target_feature(enable = "sse4.1")]
unsafe fn reduce128(a: __m128i, b: __m128i, keys: __m128i) -> __m128i {
    let t1 = _mm_clmulepi64_si128(a, keys, 0x01);
    let t2 = _mm_clmulepi64_si128(a, keys, 0x10);
    _mm_xor_si128(_mm_xor_si128(b, t1), t2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_lorem() {
        // Lorem ipsum
        let result = hash(b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Lorem ipsum dolor sit amet, consectetur adipiscing");
        assert_eq!(result, 0x470B16);
    }

    #[test]
    pub fn test_lorem_aligned() {
        // Lorem ipsum padded to 128-bits
        let result = hash(b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Lorem ipsum dolor sit amet, consectetur adipiscing aaaaaaaaaaaaaaa");
        assert_eq!(result, 0xE8DDBB);
    }

    #[test]
    pub fn test_120_bytes() {
        // Uses fallback
        let raw = b"12345678".repeat(15);
        let expected_result = hash_simple(&raw);
        let result = hash(&raw);
        assert_eq!(result, expected_result);
    }

    #[test]
    pub fn test_128_bytes() {
        let raw = b"12345678".repeat(16);
        let expected_result = hash_simple(&raw);
        let result = hash(&raw);
        assert_eq!(result, expected_result);
    }

    #[test]
    pub fn test_2187_bytes() {
        // Large enough to fold multiple times, will need padding
        let raw = b"abc123)(#".repeat(243);
        let expected_result = hash_simple(&raw);
        let result = hash(&raw);
        assert_eq!(result, expected_result);
    }

    #[test]
    pub fn test_80056_bytes() {
        // Random "larger" number
        let raw = b"1jn5?`=Z".repeat(10007);
        let expected_result = hash_simple(&raw);
        let result = hash(&raw);
        assert_eq!(result, expected_result);
    }

    #[test]
    pub fn test_zero_data() {
        let raw = [0; 10007];
        let expected_result = hash_simple(&raw);
        let result = hash(&raw);
        assert_eq!(result, expected_result);
    }
}
    "#.parse().unwrap()
}
