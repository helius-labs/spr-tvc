"""Release one custody share to a quorum-approved, sealed Nitro target."""

import argparse
import base64
import json
import subprocess
from pathlib import Path
from time import time

from approval import check_approvals, key_result, kms, parse_json, read_json, require_kms_key
from custody_ledger import TARGET_APPROVAL, load_epoch, open_share
from deployment import require_registered_target, target
from kms_policy import target_context


def sealed_policy(key, expected):
    metadata = kms(key, "describe-key")["KeyMetadata"]
    require_kms_key(metadata, key, {"SYMMETRIC_DEFAULT"}, "ENCRYPT_DECRYPT")
    policy = parse_json(kms(key, "get-key-policy", ["--policy-name", "default"])["Policy"])
    if policy != expected:
        raise ValueError("installed wrapping key policy does not match the approved target")


def wrap(trust, approval, build, index):
    if index not in range(1, 7):
        raise ValueError("invalid custody slot")
    manifest = approval["manifest"]
    _, receipt, custodians = load_epoch(trust, manifest["custodyEpoch"])
    keys, policies, _ = target(trust, approval, receipt, custodians, build)
    check_approvals(keys, TARGET_APPROVAL, approval)
    wrapping_key = manifest["wrappingKeys"][index - 1]
    sealed_policy(wrapping_key, policies[index - 1])
    ctx = target_context(manifest, index)
    require_registered_target(trust, manifest)
    if time() >= manifest["expiresAt"]:
        raise ValueError("target approval expired before share release")
    plaintext = open_share(custodians[index - 1], receipt, index)
    return base64.b64decode(key_result(wrapping_key, "encrypt", [
        "--plaintext", "fileb:///dev/stdin", "--encryption-context", json.dumps(ctx),
    ], plaintext)["CiphertextBlob"], validate=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trust", type=Path)
    parser.add_argument("target", type=Path)
    parser.add_argument("build", type=Path)
    parser.add_argument("share", type=int, choices=range(1, 7))
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        trust, approval = map(read_json, (args.trust, args.target))
        ciphertext = wrap(trust, approval, args.build, args.share)
        with args.output.open("xb") as output:
            output.write(ciphertext)
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
