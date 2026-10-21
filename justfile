set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# Format Rust code.
fmt:
    cargo fmt --all

# fmt --check, clippy (pedantic via workspace lints) with warnings as errors, cargo-deny, cargo-audit (advisory, never fails the recipe), OpenAPI drift.
check:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo deny check
    -cargo audit
    just openapi-check

# Release binary with the web UI embedded: builds web/dist first, then `dnsy` with `embed-ui`.
# A plain `cargo build -p dnsy` needs no node and serves 404 for the UI paths.
build:
    cd web && pnpm install --frozen-lockfile && pnpm build
    cargo build --release -p dnsy --features embed-ui

# Run the Rust test suite (the end-to-end crate has its own recipe: `just e2e`).
test:
    cargo nextest run --workspace --exclude dnsy-e2e --exclude dnsy-bench --no-tests=pass

# Rust line coverage (unit + integration; e2e is excluded): workspace >= 80%, every crate >= 80%,
# dnsy-proto and dnsy-dnssec >= 90%. Prints a per-crate table; HTML at target/llvm-cov/html.
cov-rust:
    cargo llvm-cov nextest --workspace --exclude dnsy-e2e --exclude dnsy-bench --no-tests=pass --html
    ./scripts/cov-crate-gates.sh 80 80 dnsy-proto=90 dnsy-dnssec=90

# Web coverage gate: `ng test --coverage` fails below the thresholds in web/angular.json
# (lines/statements/functions 80%, branches 70%); prints the Vitest table (no-op without node/pnpm).
cov-web:
    @if [ -f web/package.json ] && command -v node >/dev/null 2>&1 && command -v pnpm >/dev/null 2>&1; then cd web && pnpm install --frozen-lockfile && pnpm ng test --coverage --no-watch; else echo "node/pnpm or web/ missing; skipping web coverage"; fi

# Both coverage gates, Rust then web.
cov: cov-rust cov-web

# End-to-end suite (crate tests/e2e): builds the dnsy binary, then runs the harness tests in parallel.
e2e:
    cargo build -p dnsy
    cargo nextest run -p dnsy-e2e

# Web UI: install, lint, unit tests with coverage, build, types drift (no-op without node/pnpm or web/).
web:
    @if [ -f web/package.json ] && command -v node >/dev/null 2>&1 && command -v pnpm >/dev/null 2>&1; then cd web && pnpm install --frozen-lockfile && pnpm dedupe --check && pnpm lint && pnpm ng test --coverage --no-watch && pnpm build && cd .. && just web-types-check; else echo "node/pnpm or web/ missing; skipping web"; fi

# Browser end-to-end suite (Playwright, Chromium) against the real binary with the embedded UI.
# Builds web/dist and `dnsy --features embed-ui`, installs Chromium when missing, type-checks and runs web/e2e.
e2e-ui:
    cd web && pnpm install --frozen-lockfile && pnpm build && pnpm exec playwright install chromium
    cargo build -p dnsy --features embed-ui
    cd web && DNSY_BIN="$(cargo metadata --format-version 1 --no-deps | jq -r .target_directory)/debug/dnsy" pnpm e2e

# Benchmarks (tests/bench): release `dnsy` against a fake upstream; prints UDP cache-hit and cache-miss,
# TCP (persistent, pipelined) and DoH throughput and latency. Pin CPUs with `taskset` for stable numbers.
bench:
    cargo build --release -p dnsy
    DNSY_BIN="$(cargo metadata --format-version 1 --no-deps | jq -r .target_directory)/release/dnsy" cargo run --release -p dnsy-bench --bin bench

# Criterion micro-benchmarks (codec, cache lookup).
bench-micro:
    cargo bench -p dnsy-bench --bench micro

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
# `web` already runs the web coverage gate, so only the Rust half of `cov` is listed.
ci: check test cov-rust web e2e e2e-ui

# Validate branding SVGs (XML-parsed: no active content or external refs, viewBox, size budget).
check-svg:
    ./scripts/check-svg.sh --self-test
    ./scripts/check-svg.sh branding

# Fuzz one target with libFuzzer (needs a nightly toolchain and cargo-fuzz; not part of `ci`).
# `just fuzz` runs fuzz_decode for an hour; `just fuzz fuzz_validate 600` runs the validator target.
fuzz target="fuzz_decode" seconds="3600":
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{target}}" in
      fuzz_decode) crate=dnsy-proto ;;
      fuzz_validate) crate=dnsy-dnssec ;;
      *) echo "unknown target {{target}} (fuzz_decode, fuzz_validate)"; exit 2 ;;
    esac
    cd "crates/$crate"
    cargo +nightly fuzz run "{{target}}" -- -max_total_time={{seconds}}

# The same targets on the pinned stable toolchain: a std-only mutation fuzzer without coverage
# feedback (`just fuzz-stable fuzz_validate 600`). Crashing inputs land in the fuzz dir's `crashes/`.
fuzz-stable target="fuzz_decode" seconds="600":
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{target}}" in
      fuzz_decode) crate=dnsy-proto ;;
      fuzz_validate) crate=dnsy-dnssec ;;
      *) echo "unknown target {{target}} (fuzz_decode, fuzz_validate)"; exit 2 ;;
    esac
    cd "crates/$crate/fuzz"
    RUSTFLAGS="-C overflow-checks=on" cargo run --release --bin mutate -- {{seconds}} "$RANDOM" "corpus/{{target}}"
