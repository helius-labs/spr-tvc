"""Close an old custody epoch and inventory the KMS keys that must be retired."""

import argparse
import hashlib
import subprocess
from pathlib import Path

from approval import (
    MAX_DOCUMENT_BYTES, add_approval, approval_keys, canonical, check_approvals, epoch_number, fields, hex_digest, kms,
    parse_json, read_json, sha256,
)
from custody_ledger import (
    RETIREMENT, list_objects, load_epoch, load_retirement, read_registered_target, retirement_object_name,
    verify_retirement, write_once,
)
from deployment import require_active_epoch
from kms_policy import boot_pins, key_policy, recovery_policy, target_context


def retirement_scope(trust, epoch, replacement):
    if epoch_number(replacement) <= epoch_number(epoch):
        raise ValueError("retirement requires a newer custody epoch")
    _, old, _ = load_epoch(trust, epoch)
    _, new, _ = load_epoch(trust, replacement)
    if old["custody"]["noteSeedCommitment"] != new["custody"]["noteSeedCommitment"]:
        raise ValueError("replacement epoch must preserve the note seed")
    return {
        "network": trust["network"], "securityDomainId": trust["securityDomainId"],
        "epoch": epoch, "receiptSha256": sha256(old), "replacementEpoch": replacement,
        "replacementReceiptSha256": sha256(new), "replacementCustodyDigest": sha256(new["custody"]),
        "approvalFromEpoch": trust["approvalKeys"][-1]["fromEpoch"],
    }, new["custody"]["noteSeedCommitment"]


def registered_targets(trust, epoch, receipt_digest):
    for name in list_objects(trust, f"targets/{epoch}/"):
        yield read_registered_target(trust, name, epoch, receipt_digest)


def qualified_policy(trust, wallet_trust, scope, seed):
    with wallet_trust.open("rb") as source:
        pinned_trust = source.read(MAX_DOCUMENT_BYTES + 1)
    if (len(pinned_trust) > MAX_DOCUMENT_BYTES or
            hashlib.sha256(pinned_trust).hexdigest() != hex_digest(trust["walletTrustSha256"])):
        raise ValueError("wallet trust file does not match the pinned digest")
    epoch = scope["replacementEpoch"]
    require_active_epoch(trust, epoch)
    candidates = [target for target in registered_targets(trust, epoch, scope["replacementReceiptSha256"])
                  if target["mode"] == "serve"]
    if not candidates:
        raise ValueError("no registered serving target for the replacement epoch")
    root = Path(__file__).resolve().parents[3]
    reply = subprocess.run([
        "pnpm", "--dir", str(root / "example"), "exec", "tsx", str(root / "xtask/nitro-retirement.ts"),
        scope["network"], scope["securityDomainId"], seed, epoch, scope["replacementCustodyDigest"],
    ], input=pinned_trust, stdout=subprocess.PIPE, check=True, timeout=25)
    evidence = parse_json(reply.stdout)
    fields(evidence, "policyDigest", "targets")
    for target in candidates:
        pcrs = {key.removeprefix("PCR"): value for key, value in boot_pins(target["hostRole"], target["pcrs"]).items()}
        if {"releaseId": target["releaseId"], "pcrs": pcrs} in evidence["targets"]:
            return hex_digest(evidence["policyDigest"]), sha256(target)
    raise ValueError("no attested serving target matches the registered replacement")


def qualified_manifest(trust, wallet_trust, epoch, replacement):
    scope, seed = retirement_scope(trust, epoch, replacement)
    policy_digest, target_digest = qualified_policy(trust, wallet_trust, scope, seed)
    return {**scope, "walletPolicyDigest": policy_digest, "replacementTargetSha256": target_digest}


def commit_retirement(trust, wallet_trust, document):
    manifest = document["manifest"]
    keys = approval_keys(trust)
    check_approvals(keys, RETIREMENT, document)
    qualified = qualified_manifest(trust, wallet_trust, manifest["epoch"], manifest["replacementEpoch"])
    if manifest != qualified:
        raise ValueError("retirement no longer matches the qualified replacement and wallet policy")
    write_once(trust, retirement_object_name(manifest["epoch"]), document,
               lambda stored: verify_retirement(trust, stored, manifest["epoch"]))


def key_inventory(trust, epoch, index):
    if index not in range(1, 7):
        raise ValueError("invalid custody slot")
    marker, custodians = load_retirement(trust, epoch)
    member = custodians[index - 1]
    custodian, admin = member["custodianRole"], member["retirementRole"]
    keys = {member["recoveryKeyArn"]: recovery_policy(custodian, admin, epoch)}
    for target in registered_targets(trust, epoch, marker["receiptSha256"]):
        key = target["wrappingKeys"][index - 1]
        expected = key_policy(target["hostRole"], custodian, admin, target["pcrs"], target_context(target, index))
        if keys.setdefault(key, expected) != expected:
            raise ValueError("one key appears with different retirement policies")
    return admin, keys


def inspect_keys(trust, epoch, index, check_inactive):
    role, keys = key_inventory(trust, epoch, index)
    result = []
    for key, expected in sorted(keys.items()):
        installed = parse_json(kms(key, "get-key-policy", ["--policy-name", "default"])["Policy"])
        metadata = kms(key, "describe-key")["KeyMetadata"]
        if installed != expected or metadata.get("Arn") != key:
            raise ValueError("retirement key does not match the recorded epoch policy")
        state = metadata["KeyState"]
        if check_inactive and state not in {"Disabled", "PendingDeletion"}:
            raise ValueError(f"retirement key {key} remains usable or unverified")
        result.append({"keyArn": key, "state": state})
    return {"retirementRole": role, "keys": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trust", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    draft = commands.add_parser("draft")
    draft.add_argument("wallet_trust", type=Path)
    draft.add_argument("epoch")
    draft.add_argument("replacement")
    sign = commands.add_parser("sign")
    sign.add_argument("wallet_trust", type=Path)
    sign.add_argument("candidate", type=Path)
    sign.add_argument("key")
    publish = commands.add_parser("publish")
    publish.add_argument("wallet_trust", type=Path)
    publish.add_argument("candidate", type=Path)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("epoch")
    inspect.add_argument("share", type=int, choices=range(1, 7))
    inspect.add_argument("--check-inactive", action="store_true")
    args = parser.parse_args()
    try:
        trust = read_json(args.trust)
        if args.command == "inspect":
            result = inspect_keys(trust, args.epoch, args.share, args.check_inactive)
        elif args.command == "draft":
            result = {"manifest": qualified_manifest(trust, args.wallet_trust, args.epoch, args.replacement), "signatures": []}
        else:
            document = read_json(args.candidate)
            if args.command == "publish":
                commit_retirement(trust, args.wallet_trust, document)
                return
            manifest = document["manifest"]
            if manifest != qualified_manifest(trust, args.wallet_trust, manifest["epoch"], manifest["replacementEpoch"]):
                raise ValueError("retirement no longer matches the qualified replacement and wallet policy")
            result = add_approval(approval_keys(trust), RETIREMENT, document, args.key)
        print(canonical(result).decode())
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
