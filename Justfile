set dotenv-load
set positional-arguments

pnpm := "npx --yes pnpm@9.15.0"

default:
    @just --list

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

check:
    cargo check --workspace --all-targets --all-features --locked

lint:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

test:
    cargo test --workspace --all-targets --all-features --locked

regenerate-protocol-fixtures:
    cargo test --locked -p spr-tvc-protocol --test conformance regenerate_content_addressed_fixtures -- --ignored --exact

setup:
    {{pnpm}} install --frozen-lockfile

build-ts:
    {{pnpm}} build:ts

build-local-binary:
    cargo build --locked --release -p spr-tvc-decryption-service --features local-dev --bin spr-tvc-decryption-service-local

# Test the packed wallet and decryption SDKs on a fresh localnet.
headless-e2e port_offset="200": setup
    bash tests/guarded-payment.sh "$1"

ci: fmt-check lint test setup
    bash tests/with-local-decryption.sh {{pnpm}} ci:ts

image network="devnet":
    docker build --platform linux/amd64 --provenance=false --build-arg SPR_NETWORK="$1" -f enclave/Dockerfile .

decryption-e2e: setup build-ts
    bash tests/with-local-decryption.sh {{pnpm}} --filter spr-tvc-typescript-client-example test
