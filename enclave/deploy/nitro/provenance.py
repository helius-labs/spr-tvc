"""Create and verify the release provenance for a native Nitro EIF."""

import argparse
import re
import subprocess
import sys
from pathlib import Path

from approval import MAX_DOCUMENT_BYTES, canonical, file_digest, hex_digest, parse_json, read_json

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


def require_independent_review(reviews, actor_id, attempt):
    if attempt != "1":
        raise ValueError("dispatch a new mainnet build so its artifact gets a new review")
    if not re.fullmatch(r"[1-9][0-9]{0,19}", actor_id) or not isinstance(reviews, list):
        raise ValueError("invalid GitHub release review evidence")
    actor = int(actor_id)
    for review in reviews:
        reviewer = review["user"]
        if (review["state"] == "approved" and reviewer["type"] == "User" and
                type(reviewer["id"]) is int and reviewer["id"] > 0 and reviewer["id"] != actor and
                any(environment["name"] == "image-publish" for environment in review["environments"])):
            return
    raise ValueError("mainnet build requires an image-publish approval from another GitHub user")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    emit = commands.add_parser("describe")
    emit.add_argument("build", type=Path)
    emit.add_argument("network", choices=("devnet", "mainnet"))
    emit.add_argument("source_commit")
    review = commands.add_parser("check-review")
    review.add_argument("actor_id")
    review.add_argument("attempt")
    args = parser.parse_args()
    try:
        if args.command == "describe":
            print(canonical(describe(args.build, args.network, args.source_commit)).decode())
        else:
            reviews = parse_json(sys.stdin.buffer.read(MAX_DOCUMENT_BYTES + 1))
            require_independent_review(reviews, args.actor_id, args.attempt)
    except (OSError, TypeError, ValueError, KeyError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
