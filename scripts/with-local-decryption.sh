#!/usr/bin/env bash
set -euo pipefail

port=44030
export DECRYPTION_SERVICE_LOCAL_ENDPOINT="http://127.0.0.1:$port"
if curl --fail --silent "$DECRYPTION_SERVICE_LOCAL_ENDPOINT/health" >/dev/null; then
    echo "a service already listens on port $port" >&2
    exit 1
fi

cargo build --locked -p spr-tvc-decryption-service --features local-dev --bin spr-tvc-decryption-service-local
target/debug/spr-tvc-decryption-service-local --port "$port" &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true' EXIT
for _ in $(seq 1 100); do
    if curl --fail --silent "$DECRYPTION_SERVICE_LOCAL_ENDPOINT/health" >/dev/null; then
        "$@"
        exit
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        wait "$server_pid"
        exit 1
    fi
    sleep 0.1
done
echo "local decryption service did not start" >&2
exit 1
