# Contributing

Thanks for your interest in improving aegis-fs. Phase 0 focuses on project scaffolding, so contributions should preserve the minimal placeholder logic while strengthening tooling and workflows.

## Style Rules
- Format all Rust code with `cargo fmt --all` (or `just fmt`).
- Keep the codebase lint-clean with `cargo clippy --workspace --all-targets --all-features -- -W clippy::pedantic -A dead_code -D warnings` (or `just lint`).
- Run the full Phase 0 pipeline with `just ci` before pushing changes.
- When changing the pack/unpack pipeline, run `cargo test --test integration -- --ignored` to exercise the large round-trip scenario.
- Avoid introducing `unsafe` blocks or network-dependent code in this phase.

## Development Workflow
1. Fork or branch from `main`.
2. Make focused commits with clear messages.
3. Ensure `cargo build` and `just ci` succeed locally.
4. Open a Pull Request describing the motivation, notable changes, and testing performed.
