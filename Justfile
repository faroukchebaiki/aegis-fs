set shell := ["bash", "-euxo", "pipefail", "-c"]

fmt:
    cargo fmt --all

lint:
    cargo clippy --workspace --all-targets --all-features -- -W clippy::pedantic -A dead_code -D warnings

build:
    cargo build --workspace --all-targets

test:
    cargo test --workspace --all-targets

run:
    cargo run --package aegis-cli --

ci:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features -- -W clippy::pedantic -A dead_code -D warnings
    cargo test --workspace --all-targets
