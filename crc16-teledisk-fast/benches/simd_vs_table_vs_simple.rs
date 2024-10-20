/*
 * Copyright (c) 2024 Tobias Bengtsson
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 * This file was automatically generated by https://github.com/TobiasBengtsson/crc-fast-rs
 */

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("crc16_teledisk_fast");
    for nbytes in [128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536].iter() {
        group.bench_with_input(
            BenchmarkId::new("SIMD", nbytes),
            nbytes,
            |b, nbytes| b.iter(|| crc16_teledisk_fast::hash(&(b"F".repeat(*nbytes)))),
        );
        group.bench_with_input(
            BenchmarkId::new("Table", nbytes),
            nbytes,
            |b, nbytes| b.iter(|| crc16_teledisk_fast::hash_table(&(b"F".repeat(*nbytes)))),
        );
        group.bench_with_input(
            BenchmarkId::new("Simple", nbytes),
            nbytes,
            |b, nbytes| b.iter(|| crc16_teledisk_fast::hash_simple(&(b"F".repeat(*nbytes)))),
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
