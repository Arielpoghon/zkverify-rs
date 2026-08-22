use criterion::{black_box, criterion_group, criterion_main, Criterion};
use zkverify_rs::{parser, verifier};

fn bench_parse_and_verify(c: &mut Criterion) {
    let vkey_json = std::fs::read_to_string("examples/vkey.json").unwrap();
    let proof_json = std::fs::read_to_string("examples/proof.json").unwrap();
    let public_json = std::fs::read_to_string("examples/public.json").unwrap();

    c.bench_function("full_verify_from_files", |b| {
        b.iter(|| {
            let vkey = parser::load_vkey("examples/vkey.json").unwrap();
            let proof = parser::load_proof("examples/proof.json").unwrap();
            let public = parser::load_public("examples/public.json").unwrap();
            verifier::verify_proof(black_box(&vkey), black_box(&proof), black_box(&public)).unwrap();
        })
    });

    c.bench_function("full_verify_from_str", |b| {
        b.iter(|| {
            zkverify_rs::verify_from_str(
                black_box(&vkey_json),
                black_box(&proof_json),
                black_box(&public_json),
            )
            .unwrap();
        })
    });

    c.bench_function("parse_proof_json", |b| {
        b.iter(|| {
            parser::parse_proof_json(black_box(&proof_json)).unwrap();
        })
    });

    c.bench_function("parse_vkey_json", |b| {
        b.iter(|| {
            parser::parse_vkey_json(black_box(&vkey_json)).unwrap();
        })
    });
}

criterion_group!(benches, bench_parse_and_verify);
criterion_main!(benches);
