#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
case "${1:-}" in
    native) lock=enclave/native/Cargo.lock ;;
    hosted) lock=Cargo.lock ;;
    *) printf 'usage: %s native|hosted\n' "$0" >&2; exit 2 ;;
esac

case "$(uname -s):$(uname -m)" in
    Linux:x86_64)
        platform=x86_64-unknown-linux-gnu
        checksum=ab28a1bdb54db4d5d8ad5981cf1f959410370b3d28250dbd35f6a44248620e39 ;;
    Darwin:arm64)
        platform=aarch64-apple-darwin
        checksum=ec7ca4263769593df4d909be85b94a6b79efa2897be5d2bb8ebd516e823175af ;;
    Darwin:x86_64)
        platform=x86_64-apple-darwin
        checksum=847831323de932155b226ab60ee4a180e13e5d007a019f0d4b7b4d89a6de2ab2 ;;
    *) printf 'No pinned cargo-audit release for this platform\n' >&2; exit 2 ;;
esac

version=v0.22.2
artifact="cargo-audit-$platform-$version"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
curl --fail --silent --show-error --location --retry 2 --max-time 60 \
    "https://github.com/rustsec/rustsec/releases/download/cargo-audit/$version/$artifact.tgz" \
    --output "$work/audit.tgz"
printf '%s  %s\n' "$checksum" "$work/audit.tgz" | shasum -a 256 --check
tar -xzf "$work/audit.tgz" -C "$work"
"$work/$artifact/cargo-audit" audit --db "$work/advisory-db" --file "$lock" \
    --target-os linux --target-arch x86_64 --deny unsound
printf 'RustSec advisory database %s\n' "$(git -C "$work/advisory-db" rev-parse HEAD)"
shasum -a 256 "$lock"

if [[ "$1" == native ]]; then
    source enclave/deploy/nitro/openssl.env
    curl --fail --silent --show-error --location --retry 2 --max-time 30 --max-filesize 1048576 \
        https://openssl-library.org/news/vulnerabilities-3.5/index.html --output "$work/advisories.html"
    python3 -B enclave/deploy/nitro/audit_openssl.py "$OPENSSL_REVISION" "$work/openssl.git" "$work/advisories.html"
fi
