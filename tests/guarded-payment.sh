#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
root="$PWD"
ZOLANA_DIR="$(cd "${ZOLANA_DIR:-../zolana}" && pwd -P)"
export ZOLANA_DIR
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

(cd "$ZOLANA_DIR" && npm pack --workspace @heliuslabs/spr --pack-destination "$work")
npx --yes pnpm@9.15.0 --dir sdk pack --pack-destination "$work"
npm install --prefix "$work" --ignore-scripts --no-package-lock --no-audit --no-fund \
    "$work"/heliuslabs-spr-[0-9]*.tgz "$work"/heliuslabs-spr-decryption-service-*.tgz @solana/kit@8.3.0
cp tests/guarded-payment.mts "$work/"
"$root/node_modules/.bin/tsc" --strict --noEmit --target es2023 --module nodenext \
    --typeRoots "$root/node_modules/@types" --types node "$work/guarded-payment.mts"

bash tests/localnet.sh "${1:-200}" \
    bash tests/with-local-decryption.sh node "$work/guarded-payment.mts"
