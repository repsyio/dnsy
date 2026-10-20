set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# Format Rust code.
fmt:
    cargo fmt --all

# fmt --check, clippy (pedantic via workspace lints) with warnings as errors, cargo-deny, OpenAPI drift.
check:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo deny check
    just openapi-check

# Release binary with the web UI embedded: builds web/dist first, then `dnsy` with `embed-ui`.
# A plain `cargo build -p dnsy` needs no node and serves 404 for the UI paths.
build:
    cd web && pnpm install --frozen-lockfile && pnpm build
    cargo build --release -p dnsy --features embed-ui

# Run the Rust test suite (the end-to-end crate has its own recipe: `just e2e`).
test:
    cargo nextest run --workspace --exclude dnsy-e2e --no-tests=pass

# Line coverage gates: workspace >= 80%, dnsy-proto and dnsy-dnssec >= 90% once they have code.
cov:
    cargo llvm-cov nextest --workspace --exclude dnsy-e2e --no-tests=pass --fail-under-lines 80
    ./scripts/cov-crate-gates.sh 90 dnsy-proto dnsy-dnssec

# End-to-end suite (crate tests/e2e): builds the dnsy binary, then runs the harness tests in parallel.
e2e:
    cargo build -p dnsy
    cargo nextest run -p dnsy-e2e

# Web UI: install, lint, unit tests with coverage, build, types drift (no-op without node/pnpm or web/).
web:
    @if [ -f web/package.json ] && command -v node >/dev/null 2>&1 && command -v pnpm >/dev/null 2>&1; then cd web && pnpm install --frozen-lockfile && pnpm lint && pnpm ng test --coverage --no-watch && pnpm build && cd .. && just web-types-check; else echo "node/pnpm or web/ missing; skipping web"; fi

# Regenerate web/src/app/api/schema.d.ts from openapi/dnsy.json.
web-types:
    cd web && pnpm types && pnpm prettier --write src/app/api/schema.d.ts

# Fail when the checked-in web API types differ from openapi/dnsy.json.
web-types-check:
    cd web && pnpm types >/dev/null && pnpm prettier --write src/app/api/schema.d.ts >/dev/null
    git diff --exit-code -- web/src/app/api/schema.d.ts || { echo "web API types are stale: run 'just web-types'"; exit 1; }

# Regenerate openapi/dnsy.json from the handler annotations.
openapi:
    cargo run -q -p dnsy-api --bin gen-openapi > openapi/dnsy.json

# Fail when the checked-in openapi/dnsy.json differs from the generated spec.
openapi-check:
    cargo run -q -p dnsy-api --bin gen-openapi | diff -u openapi/dnsy.json - || { echo "openapi/dnsy.json is stale: run 'just openapi'"; exit 1; }

# Build the site into target/site/: landing (index.html), book (docs/), rustdoc (api/), shared branding/.
docs:
    #!/usr/bin/env bash
    set -euo pipefail
    target="$(realpath -m "${CARGO_TARGET_DIR:-target}")"
    rm -rf "$target/site"
    mkdir -p "$target/site"
    cargo doc --workspace --no-deps
    cp -r "$target/doc" "$target/site/api"
    cp -r branding "$target/site/branding"
    cp docs/landing/index.html "$target/site/index.html"
    if command -v mdbook >/dev/null 2>&1; then
      mdbook test docs/book
      mdbook build docs/book -d "$target/site/docs"
    else
      echo "mdbook not installed (cargo install mdbook --version 0.5.4 --locked); skipping the book"
    fi

# Local merge gate until the pipelines epic exists.
ci: check test cov web e2e

# Validate branding SVGs (wellformedness, viewBox, no external refs, size budget).
check-svg:
    ./scripts/check-svg.sh branding
