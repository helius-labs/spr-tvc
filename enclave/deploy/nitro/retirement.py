"""Close an old custody epoch and inventory the KMS keys that must be retired."""

import argparse
import subprocess
from pathlib import Path

from approval import (
    add_approval, approval_keys, canonical, check_approvals, epoch_number, file_digest, hex_digest, kms,
    parse_json, read_json, sha256,
)
from custody_ledger import (
    RETIREMENT, list_objects, load_epoch, load_retirement, read_object, retirement_object_name, verify_retirement, write_once,
)
from deployment import require_active_epoch, target_object_name, verify_target_approval
from kms_policy import context, key_policy, recovery_policy


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


def qualified_policy(trust, wallet_trust, scope, seed):
    if file_digest(wallet_trust) != hex_digest(trust["walletTrustSha256"]):
        raise ValueError("wallet trust file does not match the pinned digest")
    require_active_epoch(trust, scope["replacementEpoch"])
    root = Path(__file__).resolve().parents[3]
    reply = subprocess.run([
        "pnpm", "--dir", str(root / "example"), "exec", "tsx", str(root / "xtask/nitro-retirement.ts"),
        str(wallet_trust.resolve()), scope["network"], scope["securityDomainId"], seed,
        scope["replacementEpoch"], scope["replacementCustodyDigest"],
    ], stdout=subprocess.PIPE, check=True, timeout=25)
    return hex_digest(reply.stdout.decode())


def qualified_manifest(trust, wallet_trust, epoch, replacement):
    scope, seed = retirement_scope(trust, epoch, replacement)
    return {**scope, "walletPolicyDigest": qualified_policy(trust, wallet_trust, scope, seed)}


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
    for name in list_objects(trust, f"targets/{epoch}/"):
        stored = read_object(trust, name)
        target = verify_target_approval(trust, stored, historical=True)
        if (name != target_object_name(target) or
                (target["network"], target["securityDomainId"], target["custodyEpoch"], target["receiptSha256"]) !=
                (trust["network"], trust["securityDomainId"], epoch, marker["receiptSha256"])):
            raise ValueError("target inventory does not match the retiring receipt")
        key = target["wrappingKeys"][index - 1]
        ctx = context(target["network"], target["securityDomainId"], target["releaseId"], epoch, index)
        expected = key_policy(target["hostRole"], custodian, admin, target["pcrs"], ctx)
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
