# aegis-fs
Encrypted, redundant cloud filesystem that mounts like a disk; local encryption, Reed-Solomon sharding, multi-account storage. Phase 2 adds a pluggable remote backend (HTTP bucket prototype) with resumable uploads, downloads, and shard cataloguing.

## Quick Start
1. Install the workspace toolchain (`rustup toolchain install stable` if needed) and run `cargo build`.
2. Initialise a workspace: `cargo run --package aegis-cli -- init --password <pass> --confirm-password <pass>` (defaults to `~/.aegis-fs`).
3. Pack a file: `cargo run --package aegis-cli -- pack --password <pass> --id demo ./path/to/source.bin`.
4. List tracked objects: `cargo run --package aegis-cli -- list`.
5. Register a remote account (HTTP bucket backend shown):
   `cargo run --package aegis-cli -- account add --password <pass> --name primary --backend httpbucket --endpoint https://bucket.example/ --token <bearer>`.
6. Upload shards: `cargo run --package aegis-cli -- upload --password <pass> --id demo --account primary`.
7. Fetch + unpack from remote storage: `cargo run --package aegis-cli -- fetch --password <pass> --id demo --account primary --overwrite ./restore.bin`.
8. Clean up remote copies when done: `cargo run --package aegis-cli -- gc-remote --password <pass> --id demo --account primary`.

Set an alternate home with `--home /path/to/workdir` or `AEGIS_FS_HOME`.

## Storage Layout
- `vault.bin` – AES-256-GCM encrypted JSON containing defaults, cache settings, and per-file wrapped keys (master key derived with Argon2id, file keys wrapped via HKDF).
- `objects/<file_id>/shard_<n>.bin` – encrypted data + parity shards; `meta.json` + `journal.json` track metadata and progress for crash-safe resume.
- `state.db` – `sqlx`-managed SQLite catalog for files, shards, and settings.

## CLI Highlights
- `init` – prompts (or accepts flags) for master password, Reed–Solomon defaults, and cache size.
- `pack` – optional `--compress`, per-file overrides (`--k`, `--m`, `--name`), resumes via the journal.
- `unpack` – withstands loss of up to `m` shards, can pull shards from remote via `--from-remote`/`--account`.
- `account add/list` – register remote backends; credentials live in the encrypted vault, the DB stores only references.
- `upload` / `fetch` / `gc-remote` – move shards to and from the configured backend with resumable PUT/GET and explicit garbage collection.
- `set-cache`, `list`, `show`, `rm` cover core local operations.

Tracing is enabled through `RUST_LOG=aegis_core=info` by default.

## Testing
- Fast suite: `cargo test` (unit + CLI integration cover encryption, sharding, vault workflow, crash-resume, remote upload/fetch, corruption, and shard loss).
- Heavy integration: `cargo test --test integration -- --ignored` exercises ~1 GiB pack/unpack.
- CI-equivalent checks: `just ci` (`cargo fmt --check`, full clippy pedantic profile, and tests).

## Phase Roadmap
- P0 — Workspace scaffolding, tooling, and CI.
- P1 — Cryptographic key management, local vault, erasure pipeline, and CLI.
- P2 — Remote storage adapters (HTTP bucket prototype), resumable transfers, and CLI surface.
- P3 — Metadata catalog and persistence adapters.
- P4 — Reed-Solomon encoding pipeline and verifier harnesses.
- P5 — Multi-backend orchestration (e.g., MEGA), scheduling, and policy.
- P6 — End-to-end data flow with integrity checks and retries.
- P7 — Performance profiling, caching, and tuning.
- P8 — Security hardening, audits, and recovery drills.
- P9 — Release readiness, packaging, and user documentation.
