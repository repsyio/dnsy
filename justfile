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

# Run the Rust test suite.
test:
    cargo nextest run --workspace --no-tests=pass

# Line coverage gates: workspace >= 80%, dnsy-proto and dnsy-dnssec >= 90% once they have code.
cov:
    cargo llvm-cov nextest --workspace --no-tests=pass --fail-under-lines 80
    ./scripts/cov-crate-gates.sh 90 dnsy-proto dnsy-dnssec

# End-to-end suite (crate tests/e2e, added by the e2e stories).
e2e:
    @if [ -d tests/e2e ]; then cargo nextest run -p dnsy-e2e --no-tests=pass; else echo "no e2e suite yet"; fi

# Web UI: install, lint, unit tests with coverage, build (no-op until web/ exists).
web:
    @if [ -f web/package.json ]; then cd web && pnpm install --frozen-lockfile && pnpm ng lint && pnpm ng test --coverage --watch=false && pnpm ng build; else echo "no web app yet"; fi

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
ci: check test cov web

# Validate branding SVGs (wellformedness, viewBox, no external refs, size budget).
check-svg:
    ./scripts/check-svg.sh branding
