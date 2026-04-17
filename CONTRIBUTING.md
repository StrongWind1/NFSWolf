# Contributing to nfswolf

Thanks for your interest in improving nfswolf. This document is the short-form engineering guide.

## Ground rules

- nfswolf is an **authorized-use** security tool.
- Every protocol constant, flag, and wire value must be traceable to an RFC section or documented as a deliberate deviation.
- Pure Rust only — no new C dependencies. The primary distribution is a static musl binary.
- Keep the threat model in mind: nfswolf connects to potentially hostile NFS servers. Server-controlled data must be bounded and validated.

## Prerequisites

- Rust 1.94 or newer (the repo pins the channel via `rust-toolchain.toml`).
- `libfuse3-dev` + `pkg-config` (Linux, for the `fuse` feature).
- `musl-tools` (Linux, for `make dist`).
- GNU `make` and `grep` (the hygiene targets currently use `grep -P`).

## Setup

```sh
git clone https://github.com/StrongWind1/NFSWolf
cd nfswolf
make hooks          # install .githooks/pre-commit
make dev            # first debug build
```

## Full gate

Before pushing:

```sh
make check-all
```

That target runs, in order:

1. `cargo fmt -- --check`
2. `cargo clippy --all-targets --all-features` — zero warnings.
3. `cargo deny check` — licenses, advisories, sources. Requires network access on first run to fetch the advisory DB.
4. `cargo check --all-targets --all-features`
5. `test-matrix` — three feature combinations (`--all-features`, `--no-default-features`, `--features fuse`).
6. `cargo doc --all-features --no-deps` with `-D warnings`.
7. ASCII / LF hygiene over tracked `.rs` files.
8. `cargo machete` — unused dependency check.

If you need an offline gate that skips `cargo deny`, run the targets individually:

```sh
make fmt lint check test-matrix doc hygiene machete
```

## Tests

- Integration tests live in `tests/integration/` and each is registered as a `[[test]]` entry in `Cargo.toml`.
- Most tests stand up an in-process NFSv3 server from `nfs3_server::memfs::MemFs`. MemFs does not enforce auth, so tests that require credential-gated behavior belong in a custom mock (see `tests/common/` once it lands) or behind `#[ignore]` for live-server runs.
- Live-server tests are gated with `#[ignore]` and opted into via `cargo test -- --ignored` with `NFSWOLF_LIVE_HOST=10.0.0.1` in the environment. They are not part of `make check-all`.

## Coding style

- Follow the rules I am following:
  - Rust 2024 edition, `#![forbid(unsafe_code)]`.
  - `thiserror` for library-internal error enums, `anyhow` at the application boundary.
  - `tracing` for logging. Reserve `println!` for CLI output.
  - Every public item carries a doc comment (`missing_docs = "warn"`).

Run `cargo fmt` and `cargo clippy --fix` liberally; the repo uses `rustfmt.toml` and `clippy.toml` to pin the house style.

## Commit and PR

- Commit messages use imperative mood, first line ≤72 chars. Conventional-commit prefixes (`feat:`, `fix:`, `refactor:`, `ci:`, `docs:`, `chore:`) are welcome but not enforced.
- One logical change per PR. Keep refactors separate from behavior changes when practical.

## Releasing

Releases are cut by pushing a `v*` tag. `.github/workflows/release.yml` builds every platform artifact and uploads them to a GitHub Release. Update `CHANGELOG.md` before tagging.
