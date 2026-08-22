.PHONY: build test bench lint fmt fmt-check clean generate verify

build:
	cargo build --release

test:
	cargo test

bench:
	cargo bench

generate:
	cargo run --bin generate_test_proof --release

verify:
	cargo run --bin zkverify-rs -- examples/vkey.json examples/proof.json examples/public.json

lint:
	cargo clippy -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

clean:
	cargo clean
