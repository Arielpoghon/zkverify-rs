# List available commands
default:
    @just --list

# Build the project
build:
    cargo build --release

# Run all tests
test:
    cargo test

# Run benchmarks
bench:
    cargo bench

# Generate fresh proof files
generate:
    cargo run --bin generate_test_proof --release

# Verify the example proof
verify:
    cargo run --bin zkverify-rs -- examples/vkey.json examples/proof.json examples/public.json

# Run clippy lints
lint:
    cargo clippy -- -D warnings

# Format code
fmt:
    cargo fmt

# Check formatting without modifying
fmt-check:
    cargo fmt -- --check

# Run security audit
audit:
    cargo install cargo-deny || true
    cargo deny check

# Clean build artifacts
clean:
    cargo clean
