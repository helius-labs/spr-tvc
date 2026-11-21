"""Create and verify the release provenance for a native Nitro EIF."""

import argparse
import re
import subprocess
from pathlib import Path

from approval import canonical, file_digest, hex_digest, read_json

REPO = "helius-labs/spr-tvc"
WORKFLOW = f"{REPO}/.github/workflows/native-eif.yml"
MAIN_REF = "refs/heads/main"


def describe(build, network, source_commit):
    if network not in {"devnet", "mainnet"} or not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("expected the network and exact reviewed Git commit")
    pins = read_json(build / "measurements.json")["Measurements"]
    return {
        "network": network,
        "sourceCommit": source_commit,
        "executableSha256": file_digest(build / "tvc_app"),
        "configurationSha256": file_digest(build / "configuration.json"),
        "eifSha256": file_digest(build / "enclave.eif"),
        "pcrs": {name: hex_digest(pins[name], 48) for name in ("PCR0", "PCR1", "PCR2")},
    }


def verify(build, network, source_commit, source_ref=MAIN_REF):
    if (not re.fullmatch(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,254}", source_ref) or
            (network == "mainnet" and source_ref != MAIN_REF)):
        raise ValueError("expected a reviewed branch ref; mainnet requires refs/heads/main")
    manifest = build / "provenance.json"
    if read_json(manifest) != describe(build, network, source_commit):
        raise ValueError("artifact does not match the reviewed build attestation")
    subprocess.run([
        "gh", "attestation", "verify", str(manifest), "--bundle", str(build / "provenance.intoto.jsonl"),
        "--repo", REPO, "--signer-workflow", WORKFLOW, "--source-ref", source_ref,
        "--source-digest", source_commit, "--signer-digest", source_commit, "--deny-self-hosted-runners",
    ], check=True, timeout=30, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("network", choices=("devnet", "mainnet"))
    parser.add_argument("source_commit")
    args = parser.parse_args()
    print(canonical(describe(args.build, args.network, args.source_commit)).decode())
