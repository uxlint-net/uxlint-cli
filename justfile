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

# Publish the npm launcher — `npx -y @uxlint-net/uxlint mcp`, the one line every MCP directory and
# editor snippet wants.
#
# Scoped, because neither unscoped name was available to us: `@uxlint` belongs to a different product
# with the same name (uxlint.dev), and npm refuses the bare `uxlint` as too similar to `ux-lint`, an
# abandoned 2017 package that still holds the normalized name. `@uxlint-net` is our own org, so it is
# the namespace we actually control.
#
# A prerelease goes to the `next` dist-tag, so an rc never becomes what `npx @uxlint-net/uxlint` hands
# the world. The release workflow calls this too, so there is one definition of what "publish the npm
# package" means.
#
#   just npm-publish 0.1.26              # publish
#   DRY_RUN=1 just npm-publish 0.1.26    # show what would be published
[doc('Publish the npm launcher as both `uxlint` and `@uxlint-net/uxlint`. DRY_RUN=1 to rehearse.')]
[group('release')]
npm-publish version:
    #!/usr/bin/env bash
    set -euo pipefail
    v="{{version}}"; v="${v#v}"
    # A prerelease must never become `latest` for everyone running `npx uxlint`.
    tag=(); case "$v" in *-*) tag=(--tag next) ;; esac
    for name in @uxlint-net/uxlint; do
      work="$(mktemp -d)"
      cp -R npm/. "$work"/
      node -e '
        const fs = require("fs"), [p, name, version] = process.argv.slice(1);
        const j = JSON.parse(fs.readFileSync(p, "utf8"));
        j.name = name; j.version = version;
        fs.writeFileSync(p, JSON.stringify(j, null, "\t") + "\n");
      ' "$work/package.json" "$name" "$v"
      echo "→ publishing $name@$v" >&2
      # No --provenance flag: under trusted publishing npm mints the attestation itself, and asking
      # for it explicitly from a laptop FAILS rather than degrading (the signature needs an OIDC
      # token only CI can get). CI is the normal path. A local run is the break-glass one — and the
      # bootstrap one, since npm can only enable trusted publishing on a package that already exists.
      [ -n "${CI:-}" ] || echo "   (local publish: unsigned — CI publishes with provenance)" >&2
      if [ -n "${DRY_RUN:-}" ]; then
        (cd "$work" && npm publish --dry-run --access public "${tag[@]}")
      else
        (cd "$work" && npm publish --access public "${tag[@]}")
      fi
      rm -rf "$work"
    done
