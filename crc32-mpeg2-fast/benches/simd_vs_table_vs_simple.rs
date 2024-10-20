use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("crc32_mpeg2_fast");
    for nbytes in [128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536].iter() {
        group.bench_with_input(
            BenchmarkId::new("SIMD", nbytes),
            nbytes,
            |b, nbytes| b.iter(|| crc32_mpeg2_fast::hash(&(b"F".repeat(*nbytes)))),
        );
        group.bench_with_input(
            BenchmarkId::new("Table", nbytes),
            nbytes,
            |b, nbytes| b.iter(|| crc32_mpeg2_fast::hash_table(&(b"F".repeat(*nbytes)))),
        );
        group.bench_with_input(
            BenchmarkId::new("Simple", nbytes),
            nbytes,
            |b, nbytes| b.iter(|| crc32_mpeg2_fast::hash_simple(&(b"F".repeat(*nbytes)))),
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
