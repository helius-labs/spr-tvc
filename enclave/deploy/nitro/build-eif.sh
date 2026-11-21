#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 3 ]]; then
    echo "usage: build-eif.sh linux-binary configuration.json output-dir" >&2
    exit 2
fi
binary=$1
config=$2
output=$3

mkdir "$output"
install -m 0755 "$binary" "$output/tvc_app"
install -m 0644 "$config" "$output/configuration.json"
cat > "$output/Dockerfile" <<'DOCKER'
FROM scratch
COPY tvc_app /tvc_app
COPY configuration.json /configuration.json
ENTRYPOINT ["/tvc_app"]
DOCKER

image_id="$(cd "$output" && sha256sum tvc_app configuration.json | sha256sum | cut -d ' ' -f 1)"
image="spr-nitro-decryption:$image_id"
docker build --platform linux/amd64 --network none --tag "$image" "$output"
nitro-cli build-enclave --docker-uri "$image" --output-file "$output/enclave.eif" > "$output/build-measurements.json"
nitro-cli describe-eif --eif-path "$output/enclave.eif" > "$output/measurements.json"
jq -e -s '
  def pcrs: .Measurements | [.PCR0, .PCR1, .PCR2];
  (.[0] | pcrs) == (.[1] | pcrs) and
  (.[1] | pcrs | all(.[]; type == "string" and test("^[0-9a-f]{96}$") and test("[1-9a-f]")))
' "$output/build-measurements.json" "$output/measurements.json" >/dev/null
rm "$output/build-measurements.json"
(
    cd "$output"
    sha256sum tvc_app configuration.json enclave.eif > SHA256SUMS
    nitro-cli --version > NITRO_CLI_VERSION
)
