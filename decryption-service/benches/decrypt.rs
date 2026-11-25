use criterion::{black_box, criterion_group, criterion_main, Criterion};
use spr_tvc_decryption_service::timing::{MaxEnvelope, TransferBatch};
use spr_tvc_protocol::constants::NOTES_PER_SIGNATURE;

fn decrypt(c: &mut Criterion) {
    let one = TransferBatch::new(1);
    let page = TransferBatch::new(NOTES_PER_SIGNATURE);
    let envelope = MaxEnvelope::page();
    c.bench_function("open 1 transfer ciphertext", |b| {
        b.iter(|| black_box(one.open()))
    });
    c.bench_function("open one indexer page of transfer ciphertexts", |b| {
        b.iter(|| black_box(page.open()))
    });
    c.bench_function("decrypt one max-size quorum envelope", |b| {
        b.iter(|| black_box(envelope.open()))
    });
}

criterion_group!(benches, decrypt);
criterion_main!(benches);
