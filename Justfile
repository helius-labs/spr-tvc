set dotenv-load

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
    cargo test --test conformance regenerate_content_addressed_fixtures -- --ignored --exact

check-protocol-fixtures:
    #!/usr/bin/env sh
    set -eu
    fixture_status="$(git status --porcelain --untracked-files=all -- protocol/fixtures)"
    if [ -n "$fixture_status" ]; then
        echo "protocol fixtures differ from the committed conformance corpus" >&2
        echo "$fixture_status" >&2
        exit 1
    fi

setup: install-ts

install-ts:
    {{pnpm}} install --frozen-lockfile

lint-ts:
    {{pnpm}} lint:ts

typecheck-ts:
    {{pnpm}} typecheck:ts

test-ts:
    {{pnpm}} test:ts

build-ts:
    {{pnpm}} build:ts

ci-ts:
    {{pnpm}} ci:ts

# Send, claim and sweep on a fresh localnet. Requires a sibling ../zolana checkout.
headless-e2e port_offset="200":
    #!/usr/bin/env bash
    set -euo pipefail
    run_dir="$(mktemp -d)"
    wallet_keypair="${TVC_SOLANA_KEYPAIR_PATH:-$run_dir/wallet.json}"
    fixture_dir="$run_dir/fixture"
    if [ -z "${TVC_SOLANA_KEYPAIR_PATH:-}" ]; then
        solana-keygen new --no-bip39-passphrase --silent --outfile "$wallet_keypair"
    else
        test -f "$wallet_keypair" || { echo "missing TVC_SOLANA_KEYPAIR_PATH: $wallet_keypair" >&2; exit 1; }
    fi
    rpc_port=$((8899 + {{port_offset}}))
    photon_port=$((8784 + {{port_offset}}))
    prover_port=$((3001 + {{port_offset}}))
    rpc_url="http://127.0.0.1:${rpc_port}"
    indexer_url="http://127.0.0.1:${photon_port}"
    prover_url="http://127.0.0.1:${prover_port}"
    cleanup() {
        for port in "$rpc_port" "$photon_port" "$prover_port"; do
            lsof -ti "tcp:${port}" 2>/dev/null | xargs kill 2>/dev/null || true
        done
        rm -rf -- "$run_dir"
    }
    trap cleanup EXIT
    {{pnpm}} install --frozen-lockfile
    {{pnpm}} build:ts
    bash scripts/start-localnet.sh "{{port_offset}}" "$fixture_dir"
    solana airdrop 10 "$(solana address --keypair "$wallet_keypair")" --url "$rpc_url" >/dev/null
    export ZOLANA_ENDPOINT="$rpc_url" ZOLANA_INDEXER_URL="$indexer_url" ZOLANA_PROVER_URL="$prover_url"
    export TVC_SOLANA_KEYPAIR_PATH="$wallet_keypair"
    bash scripts/with-local-decryption.sh {{pnpm}} --filter spr-tvc-typescript-client-example example

ci: fmt-check lint test check-protocol-fixtures install-ts ci-ts

image network="devnet":
    docker build --platform linux/amd64 --provenance=false --build-arg SPR_NETWORK={{network}} -f enclave/Dockerfile .

decryption-e2e: install-ts build-ts
    bash scripts/with-local-decryption.sh {{pnpm}} --filter spr-tvc-typescript-client-example test

# Deploy a network's published image, sign its release policy and pin it in the decryption client; see scripts/release.mjs.
release network release_id *flags:
    node scripts/release.mjs all {{release_id}} --network {{network}} {{flags}}

