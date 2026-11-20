#!/usr/bin/env bash
set -euo pipefail

cargo build --locked -p spr-tvc-decryption-service --features local-dev --bin spr-tvc-decryption-service-local
endpoint_file="$(mktemp)"
"${CARGO_TARGET_DIR:-target}/debug/spr-tvc-decryption-service-local" --port 0 >"$endpoint_file" &
server_pid=$!
trap '
    kill %1 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    rm -f -- "$endpoint_file"
' EXIT

for _ in {1..100}; do
    if IFS= read -r address <"$endpoint_file"; then
        export DECRYPTION_SERVICE_LOCAL_ENDPOINT="http://$address"
        "$@"
        exit
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        wait "$server_pid"
        exit 1
    fi
    sleep 0.1
done
echo "local decryption service did not bind an address" >&2
exit 1
