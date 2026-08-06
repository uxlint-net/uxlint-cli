# uxlint CLI crate dev tasks. Assumes cwd = this directory (the CLI repo root once extracted;
# client/ inside the monorepo today). This crate is its own Cargo workspace (WP41) — nothing here
# reaches outside client/.
#
# `just check` is the exact gate client/.github/workflows/ci.yml runs — green here means green
# in CI.

set shell := ["bash", "-uc"]

# List all tasks.
default:
    @just --list

[doc('cargo build (debug)')]
build:
    cargo build

[doc('cargo build --release')]
build-release:
    cargo build --release

[doc('cargo test')]
test:
    cargo test

[doc('clippy, warnings fail (same as CI)')]
lint:
    cargo clippy --all-targets -- -D warnings

[doc('cargo fmt — rewrite in place')]
fmt:
    cargo fmt

[doc('cargo fmt --check — same gate CI runs')]
fmt-check:
    cargo fmt --check

# Mirrors client/.github/workflows/ci.yml's rust job exactly: fmt-check, then lint, then test.
# Build isn't separate here — `cargo test` compiles the crate anyway.
[doc('The CI gate, locally: fmt-check + lint + test')]
check: fmt-check lint test

[doc('Install the built binary to ~/.local/bin (matches where install.sh puts it)')]
install: build-release
    mkdir -p "$HOME/.local/bin"
    install -m755 target/release/uxlint "$HOME/.local/bin/uxlint"
    @echo "installed uxlint -> $HOME/.local/bin/uxlint"

[doc('cargo run -- <args>, for quick local invocation')]
run *args:
    cargo run -- {{args}}
