use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("$PACKAGE_NAMESPACE");
    for nbytes in [128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536].iter() {
        group.bench_with_input(
            BenchmarkId::new("Fast", nbytes),
            nbytes,
            |b, nbytes| b.iter(|| $PACKAGE_NAMESPACE::hash(&(b"F".repeat(*nbytes)))),
        );
        group.bench_with_input(
            BenchmarkId::new("Fallback", nbytes),
            nbytes,
            |b, nbytes| b.iter(|| $PACKAGE_NAMESPACE::hash_simple(&(b"F".repeat(*nbytes)))),
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
