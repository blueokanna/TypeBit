# Publishing to crates.io

TypeBit ships as **one crate** (`typebit`). CI verifies the exact artifact
before anything merges; a tag triggers the publish workflow.

## Prerequisites (one-time)

1. Create a crates.io API token: <https://crates.io/settings/tokens>
   (scope `publish-new` / `publish-update`).
2. Add it as a repository secret **`CARGO_REGISTRY_TOKEN`**:
   Settings → Secrets and variables → Actions → New repository secret.

## Release flow

```sh
# 1. Bump the version in Cargo.toml (keep the changelog honest).
# 2. Commit, push to main (CI runs the full matrix).
# 3. Tag with a leading 'v' and push:
git tag v0.1.7
git push origin v0.1.7
```

The `publish` workflow (`.github/workflows/publish.yml`) then:

1. checks out the tag,
2. runs `cargo package` (the same artifact that gets published),
3. runs `cargo publish` with the token.

## What CI enforces before you even tag

- `cargo fmt --check`
- `clippy -D warnings` on: `no-default-features`, `std`, `std,ffi`,
  `--all-features` — on Linux, Windows **and** macOS
- `cargo test --all-features` and `cargo test --no-default-features`
  (real `no_std` code-path execution, not just a compile check)
- `cargo doc --all-features` (rustdoc must build) + doc tests
- bare-metal `no_std` targets: `aarch64-unknown-none`,
  `thumbv7em-none-eabihf`, `riscv32imac-unknown-none-elf`
- MSRV 1.95 (`cargo check` with Rust 1.95)
- `cargo-audit` against `Cargo.lock`
- `cargo package` + `cargo package --list`

## Package contents

`Cargo.toml` `include` ships `src/**`, `README.md`, `LICENSE`, `docs/**`
(the wiki lives in-repo and ships with the crate) and `examples/**`.

```sh
cargo package --list   # inspect the tarball contents
cargo package          # build + verify the exact artifact
```

## docs.rs

`[package.metadata.docs.rs]` in `Cargo.toml` builds docs with
`--all-features` and `--cfg docsrs`, so the FFI symbols, `StdHost` and the
feature-gated modules all render (with `doc(cfg)` badges). Every public item
has `///` docs (`#![warn(missing_docs)]`); the CI `doc` job fails the build
if any intra-doc link breaks.

## Keeping the GitHub Wiki in sync

The wiki pages live in-repo under `docs/wiki/` (they ship with the crate).
The GitHub Wiki is a **separate git repository** (`<owner>/<repo>.wiki.git`),
so the pages must be pushed to it explicitly — they are NOT updated by
pushing to the main repo.

Two ways to sync:

1. **CI (automatic)** — `.github/workflows/wiki-sync.yml` checks out the
   wiki via `actions/checkout` and mirrors `docs/wiki/` into it on every
   change to `docs/wiki/**`. It uses the automatic `GITHUB_TOKEN` (granted
   `contents: write`, which covers wiki pushes) with no extra setup. If your
   fork/org blocks that, set a fine-grained PAT with "Read and write" wiki
   access as the `GH_PAT` secret — the workflow falls back to it
   automatically.
2. **Local script (manual)** — `scripts/sync-wiki.ps1` or
   `scripts/sync-wiki.sh` (needs the `gh` CLI, authenticated).

```sh
./scripts/sync-wiki.sh
```

## Versioning policy

Semver. Pre-1.0: `0.x.y` — a breaking change bumps `x`, features/fixes bump
`y`. The FFI is explicitly **unstable until 1.0** (`#[doc(cfg)]`/docs call
this out).
