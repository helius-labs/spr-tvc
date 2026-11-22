#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

# OpenSSL 3.5 LTS with the November security fixes, ahead of the 3.5.10 tag.
revision=d3202f0409356688ecf145c38eb0595b4990eb8b
checksum=b9066686e138fe43c8aa9e233333f3f476af5954a5cf136ab9bb11755a71b09a
curl --fail --silent --show-error --location --retry 2 --max-time 120 \
    "https://codeload.github.com/openssl/openssl/tar.gz/$revision" --output "$work/openssl.tar.gz"
printf '%s  %s\n' "$checksum" "$work/openssl.tar.gz" | sha256sum --check
tar -xzf "$work/openssl.tar.gz" -C "$work"
(
    cd "$work/openssl-$revision"
    CC=musl-gcc ./Configure linux-x86_64 no-shared no-module no-tests no-apps -fPIC \
        --prefix="$work/install" --libdir=lib --openssldir=/etc/ssl
    make -s -j "$(nproc)" install_dev
)

X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_DIR="$work/install" \
X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_STATIC=1 \
RUSTFLAGS='-C target-feature=+crt-static' \
    cargo build --locked --release --manifest-path enclave/native/Cargo.toml \
        --target x86_64-unknown-linux-musl --target-dir enclave/native/target

version=$(enclave/native/target/x86_64-unknown-linux-musl/release/spr-nitro-decryption-service --version)
printf '%s\n' "$version"
[[ "$version" == *" OpenSSL 3.5.10-dev "* ]]
