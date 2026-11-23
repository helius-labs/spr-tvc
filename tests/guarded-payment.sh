#!/usr/bin/env bash
set -euo pipefail

if (( $# < 1 || $# > 2 )) || [[ ! -f "$1" ]]; then
    echo "usage: guarded-payment.sh WALLET_TARBALL [PORT_OFFSET]" >&2
    exit 2
fi
wallet="$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
cd "$(dirname "$0")/.."
root="$PWD"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

npx --yes pnpm@9.15.0 --dir sdk pack --pack-destination "$work"
npm install --prefix "$work" --ignore-scripts --no-package-lock --no-audit --no-fund \
    "$wallet" "$work"/heliuslabs-spr-decryption-service-*.tgz @solana/kit@8.3.0
cp tests/guarded-payment.mts "$work/"
"$root/node_modules/.bin/tsc" --strict --noEmit --target es2023 --module nodenext \
    --typeRoots "$root/node_modules/@types" --types node "$work/guarded-payment.mts"

unset TVC_SOLANA_KEYPAIR_PATH
bash tests/localnet.sh "${2:-200}" \
    bash tests/with-local-decryption.sh node "$work/guarded-payment.mts"
