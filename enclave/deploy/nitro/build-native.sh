#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

source enclave/deploy/nitro/openssl.env
curl --fail --silent --show-error --location --retry 2 --max-time 120 \
    "https://codeload.github.com/openssl/openssl/tar.gz/$OPENSSL_REVISION" --output "$work/openssl.tar.gz"
printf '%s  %s\n' "$OPENSSL_SHA256" "$work/openssl.tar.gz" | sha256sum --check
tar -xzf "$work/openssl.tar.gz" -C "$work"
# Expose kernel headers to musl without adding the system's glibc headers.
mkdir "$work/uapi"
ln -s /usr/include/linux /usr/include/asm-generic /usr/include/x86_64-linux-gnu/asm "$work/uapi/"
(
    cd "$work/openssl-$OPENSSL_REVISION"
    CC=musl-gcc CPPFLAGS="-I../uapi" ./Configure linux-x86_64 \
        no-shared no-module no-tests no-apps no-async no-engine -fPIC \
        --prefix=/usr --libdir=lib --openssldir=/etc/ssl
    SOURCE_DATE_EPOCH=0 make -s -j "$(nproc)" DESTDIR="$work/install" install_dev
)

X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_DIR="$work/install/usr" \
X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_STATIC=1 \
RUSTFLAGS='-C target-feature=+crt-static' \
    cargo build --locked --release --manifest-path enclave/native/Cargo.toml \
        --target x86_64-unknown-linux-musl --target-dir enclave/native/target

version=$(enclave/native/target/x86_64-unknown-linux-musl/release/spr-nitro-decryption-service --version)
printf '%s\n' "$version"
[[ "$version " == *" OpenSSL $OPENSSL_VERSION "* ]]
