# Contributing to zkverify-rs

Thank you for your interest in contributing to zkverify-rs!

## Development Setup

1. Install Rust via [rustup.rs](https://rustup.rs/)
2. Clone the repository
3. Run `cargo build` to verify the build works
4. Run `cargo test` to verify all tests pass

## Code Style

- Follow standard Rust formatting (`cargo fmt`)
- Ensure `cargo clippy` passes without warnings
- Add doc comments for all public items
- Write tests for new functionality

## Pull Requests

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes with clear, descriptive commits
4. Add or update tests as needed
5. Run `cargo test` and `cargo clippy` before submitting
6. Open a pull request with a clear description

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include steps to reproduce for bug reports
- Specify your Rust version and OS

## Cryptographic Code Guidelines

- Never implement cryptographic primitives from scratch
- Always use audited libraries (arkworks, etc.)
- Be cautious with unsafe code
- Document security assumptions
