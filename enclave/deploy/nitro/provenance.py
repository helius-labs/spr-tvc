"""Create and verify the release provenance for a native Nitro EIF."""

import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from approval import MAX_DOCUMENT_BYTES, canonical, fields, file_digest, hex_digest, parse_json, read_document, read_json
from eif import verify_eif

REPO = "helius-labs/spr-tvc"
WORKFLOW = f"{REPO}/.github/workflows/native-eif.yml"
MAIN_REF = "refs/heads/main"
MAIN_ENVIRONMENT = "image-publish"


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


def check_artifact(build, network, source_commit, provenance_sha256):
    contents = read_document(build / "provenance.json")
    if hashlib.sha256(contents).hexdigest() != hex_digest(provenance_sha256):
        raise ValueError("provenance does not match the independently reviewed digest")
    manifest = parse_json(contents)
    if manifest != describe(build, network, source_commit):
        raise ValueError("artifact does not match the reviewed build attestation")
    verify_eif(build / "enclave.eif", manifest)
    return manifest, contents


def verify(build, network, review_file):
    review = read_json(review_file)
    fields(review, "sourceCommit", "sourceRef", "provenanceSha256")
    source_commit, source_ref = review["sourceCommit"], review["sourceRef"]
    if (not re.fullmatch(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,254}", source_ref) or
            (network == "mainnet" and source_ref != MAIN_REF)):
        raise ValueError("expected a reviewed branch ref; mainnet requires refs/heads/main")
    manifest, contents = check_artifact(build, network, source_commit, review["provenanceSha256"])
    bundle = read_document(build / "provenance.intoto.jsonl")
    if not 0 < len(bundle) <= MAX_DOCUMENT_BYTES:
        raise ValueError("expected a nonempty GitHub provenance bundle of at most 64 KiB")
    with tempfile.TemporaryDirectory() as directory:
        subject = Path(directory) / "provenance.json"
        bundle_path = Path(directory) / "provenance.intoto.jsonl"
        subject.write_bytes(contents)
        bundle_path.write_bytes(bundle)
        subprocess.run([
            "gh", "attestation", "verify", str(subject), "--bundle", str(bundle_path),
            "--repo", REPO, "--signer-workflow", WORKFLOW, "--source-ref", source_ref,
            "--source-digest", source_commit, "--signer-digest", source_commit, "--deny-self-hosted-runners",
        ], check=True, timeout=30, stdout=subprocess.DEVNULL)
    return manifest


def release_actor(actor_id, attempt):
    if attempt != "1":
        raise ValueError("dispatch a new mainnet build so its artifact gets a new review")
    if not re.fullmatch(r"[1-9][0-9]{0,19}", actor_id):
        raise ValueError("invalid GitHub release review evidence")
    return int(actor_id)


def require_available_reviewer(environment, actor_id, attempt):
    actor = release_actor(actor_id, attempt)
    if environment["name"] != MAIN_ENVIRONMENT:
        raise ValueError("expected the image-publish release environment")
    for rule in environment["protection_rules"]:
        if rule["type"] != "required_reviewers":
            continue
        for entry in rule["reviewers"]:
            reviewer = entry["reviewer"]
            identity = reviewer["id"]
            if type(identity) is int and identity > 0 and (
                entry["type"] == "Team" or
                (entry["type"] == "User" and reviewer["type"] == "User" and identity != actor)
            ):
                return
    raise ValueError("image-publish has no required reviewer who can independently approve this dispatcher")


def require_independent_review(reviews, actor_id, attempt):
    actor = release_actor(actor_id, attempt)
    if not isinstance(reviews, list):
        raise ValueError("invalid GitHub release review evidence")
    for review in reviews:
        reviewer = review["user"]
        if (review["state"] == "approved" and reviewer["type"] == "User" and
                type(reviewer["id"]) is int and reviewer["id"] > 0 and reviewer["id"] != actor and
                any(environment["name"] == MAIN_ENVIRONMENT for environment in review["environments"])):
            return
    raise ValueError("mainnet build requires an image-publish approval from another GitHub user")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    emit = commands.add_parser("describe")
    emit.add_argument("build", type=Path)
    emit.add_argument("network", choices=("devnet", "mainnet"))
    emit.add_argument("source_commit")
    check = commands.add_parser("verify")
    check.add_argument("build", type=Path)
    check.add_argument("network", choices=("devnet", "mainnet"))
    check.add_argument("review", type=Path)
    artifact = commands.add_parser("check-artifact")
    artifact.add_argument("build", type=Path)
    artifact.add_argument("network", choices=("devnet", "mainnet"))
    artifact.add_argument("source_commit")
    artifact.add_argument("provenance_sha256")
    for command in ("check-reviewers", "check-review"):
        review = commands.add_parser(command)
        review.add_argument("actor_id")
        review.add_argument("attempt")
    args = parser.parse_args()
    try:
        if args.command == "describe":
            manifest = describe(args.build, args.network, args.source_commit)
            verify_eif(args.build / "enclave.eif", manifest)
            print(canonical(manifest).decode())
        elif args.command == "verify":
            print(canonical(verify(args.build, args.network, args.review)).decode())
        elif args.command == "check-artifact":
            check_artifact(args.build, args.network, args.source_commit, args.provenance_sha256)
        else:
            evidence = parse_json(sys.stdin.buffer.read(MAX_DOCUMENT_BYTES + 1))
            if args.command == "check-reviewers":
                require_available_reviewer(evidence, args.actor_id, args.attempt)
            else:
                require_independent_review(evidence, args.actor_id, args.attempt)
    except (OSError, TypeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
