#!/usr/bin/env bash
set -euo pipefail

if (( $# < 2 )); then
    echo "usage: localnet.sh PORT_OFFSET COMMAND [ARGS...]" >&2
    exit 2
fi
offset="$1"
shift
if [[ ! "$offset" =~ ^[0-9]{1,5}$ ]] || (( 10#$offset > 55535 )); then
    echo "port offset must be an integer from 0 to 55535" >&2
    exit 2
fi
offset=$((10#$offset))

zolana_root="$(cd "${ZOLANA_DIR:-../zolana}" && pwd)"
# Scoped cleanup stops only the services started by this run.
if ! git -C "$zolana_root" grep -q 'const PROCESS_SCOPE_ENV.*ZOLANA_PROCESS_SCOPE_DIR' -- cli/src; then
    echo "Zolana checkout must support scoped process cleanup (see tests/README.md)" >&2
    exit 2
fi

run_dir="$(mktemp -d)"
run_dir="$(cd "$run_dir" && pwd -P)"
bin="$zolana_root/target/debug/zolana"
rpc_port=$((8899 + offset))
photon_port=$((8784 + offset))
prover_port=$((3001 + offset))
faucet_port=$((9900 + offset))
ports=(--rpc-port "$rpc_port" --photon-port "$photon_port" --prover-port "$prover_port"
       --faucet-port "$faucet_port")
export ZOLANA_PROCESS_SCOPE_DIR="$run_dir"
export ZOLANA_CONFIG_DIR="$run_dir/config"
export ZOLANA_ENDPOINT="http://127.0.0.1:$rpc_port"
export ZOLANA_INDEXER_URL="http://127.0.0.1:$photon_port"
export ZOLANA_PROVER_URL="http://127.0.0.1:$prover_port"

cleanup() {
    if [[ -e "$run_dir/solana-test-validator.owner" || -e "$run_dir/prover-server.owner" || -e "$run_dir/photon.owner" ]]; then
        (cd "$zolana_root" && "$bin" dev start --stop --no-use-surfpool "${ports[@]}") || true
    fi
    rm -rf -- "$run_dir"
}
trap cleanup EXIT
mkdir "$ZOLANA_CONFIG_DIR"

export TVC_SOLANA_KEYPAIR_PATH="$run_dir/wallet.json"
solana-keygen new --no-bip39-passphrase --silent --outfile "$TVC_SOLANA_KEYPAIR_PATH"

(
    cd "$zolana_root"
    if [[ -z "${ZOLANA_PREBUILT:-}" ]]; then
        ./tools/build-programs.sh --manifest-path programs/user-registry/Cargo.toml -- --locked --features bpf-entrypoint
        ./tools/build-programs.sh --manifest-path programs/shielded-pool/Cargo.toml -- --locked --features bpf-entrypoint
    fi
    ZOLANA_PORT_OFFSET="$offset" just build-prover-server build-cli ensure-photon
    ids="$(cargo run -q -p xtask -- program-ids)"
    pool="$(sed -n 's/^SHIELDED_POOL_PROGRAM_ID=//p' <<< "$ids")"
    registry="$(sed -n 's/^USER_REGISTRY_PROGRAM_ID=//p' <<< "$ids")"
    cargo run -q -p xtask -- generate-account-snapshots \
        --deploy-dir target/deploy --accounts-dir "$run_dir/accounts"

    export ZOLANA_PHOTON_BIN="$zolana_root/target/debug/photon"
    export ZOLANA_PROVER_KEYS_DIR="$zolana_root/prover/server/proving-keys"
    "$bin" dev start --no-use-surfpool "${ports[@]}" --ledger "$run_dir/ledger" \
        --account-dir "$run_dir/accounts" --limit-ledger-size 5000000 \
        --sbf-program "${pool:?missing shielded pool program ID}" target/deploy/shielded_pool_program.so \
        --sbf-program "${registry:?missing user registry program ID}" target/deploy/spr_user_registry.so \
        -- --deactivate-feature B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g
)
solana airdrop 10 "$(solana address --keypair "$TVC_SOLANA_KEYPAIR_PATH")" \
    --url "$ZOLANA_ENDPOINT" --commitment finalized >/dev/null
"$@"
