set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# Format Rust code.
fmt:
    cargo fmt --all

# fmt --check, clippy (pedantic via workspace lints) with warnings as errors, cargo-deny.
check:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo deny check

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

# Regenerate openapi/dnsy.json (implemented by the API stories).
openapi:
    @if [ -d crates/dnsy-api ] && grep -q openapi crates/dnsy-api/Cargo.toml 2>/dev/null; then cargo run -p dnsy-api --bin gen-openapi > openapi/dnsy.json; else echo "no OpenAPI spec yet"; fi

# Build rustdoc and the mdBook site into target/site/.
docs:
    cargo doc --workspace --no-deps
    @if [ -d docs/book ]; then mdbook build docs/book -d ../../target/site/book; else echo "no book yet"; fi

# Local merge gate until the pipelines epic exists.
ci: check test cov web

# Validate branding SVGs (wellformedness, viewBox, no external refs, size budget).
check-svg:
    ./scripts/check-svg.sh branding
