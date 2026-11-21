#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 6 ]]; then
    echo "usage: build-eif.sh linux-binary release-id security-domain share-1-sha256 share-2-sha256 output-dir" >&2
    exit 2
fi
binary=$1
release=$2
domain=$3
share_1=$4
share_2=$5
output=$6
[[ $release =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]]
[[ $domain =~ ^[0-9a-f]{64}$ && $domain != "$(printf '%064d' 0)" ]]
for commitment in "$share_1" "$share_2"; do
    [[ $commitment =~ ^[0-9a-f]{64}$ && $commitment != "$(printf '%064d' 0)" ]]
done
[[ $share_1 != "$share_2" ]]

mkdir "$output"
install -m 0755 "$binary" "$output/tvc_app"
cat > "$output/Dockerfile" <<DOCKER
FROM scratch
COPY --chmod=755 tvc_app /tvc_app
ENTRYPOINT ["/tvc_app","--release-id","$release","--security-domain-id","$domain","--share-1-sha256","$share_1","--share-2-sha256","$share_2"]
DOCKER

binary_digest="$(sha256sum "$output/tvc_app" | cut -d ' ' -f 1)"
image_id="$(printf '%s\n' "$binary_digest" "$release" "$domain" "$share_1" "$share_2" | sha256sum | cut -d ' ' -f 1)"
image="spr-nitro-decryption:$image_id"
docker build --platform linux/amd64 --network none --tag "$image" "$output"
nitro-cli build-enclave --docker-uri "$image" --output-file "$output/enclave.eif" > "$output/measurements.json"
jq -e '.Measurements | (.PCR0, .PCR1, .PCR2) | test("^[0-9a-f]{96}$")' "$output/measurements.json" >/dev/null
(
    cd "$output"
    sha256sum tvc_app enclave.eif > SHA256SUMS
    nitro-cli --version > NITRO_CLI_VERSION
)
