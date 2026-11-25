set dotenv-load
set positional-arguments

pnpm := "npx --yes pnpm@9.15.0"

default:
    @just --list

fmt:
    cargo fmt --all
    cargo fmt --manifest-path apps/tvc-gateway/Cargo.toml --all

fmt-check:
    cargo fmt --all -- --check
    cargo fmt --manifest-path apps/tvc-gateway/Cargo.toml --all -- --check

check:
    cargo check --workspace --all-targets --all-features --locked
    cargo check --manifest-path apps/tvc-gateway/Cargo.toml --all-targets --locked

lint:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo clippy --manifest-path apps/tvc-gateway/Cargo.toml --all-targets --locked -- -D warnings

test:
    cargo test --workspace --all-targets --all-features --locked
    cargo test --manifest-path apps/tvc-gateway/Cargo.toml --all-targets --locked

# Times one transfer, one indexer page, and one max-size Quorum envelope. Not part of `just ci`.
bench:
    cargo bench -p spr-tvc-decryption-service --bench decrypt --features bench

regenerate-protocol-fixtures:
    cargo test --locked -p spr-tvc-protocol --test conformance regenerate_content_addressed_fixtures -- --ignored --exact

setup:
    {{pnpm}} install --frozen-lockfile

build-ts:
    {{pnpm}} build:ts

# Send, claim and sweep on a fresh localnet. See tests/README.md.
headless-e2e port_offset="200": setup build-ts
    bash tests/localnet.sh "$1" bash tests/with-local-decryption.sh {{pnpm}} --filter spr-tvc-typescript-client-example example

ci: fmt-check lint test setup
    bash tests/with-local-decryption.sh {{pnpm}} ci:ts

image network="devnet":
    docker build --platform linux/amd64 --provenance=false --build-arg SPR_NETWORK="$1" -f enclave/Dockerfile .

decryption-e2e: setup build-ts
    bash tests/with-local-decryption.sh {{pnpm}} --filter spr-tvc-typescript-client-example test
