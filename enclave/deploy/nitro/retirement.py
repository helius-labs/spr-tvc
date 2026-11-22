"""Close an old custody epoch and inventory the KMS keys that must be retired."""

import argparse
import hashlib
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from approval import (
    MAX_DOCUMENT_BYTES, add_approval, approval_keys, canonical, check_approvals, epoch_number, fields, hex_digest, kms,
    parse_json, read_json, require_kms_key, sha256,
)
from custody_ledger import (
    RECOVERY_SPECS, RECOVERY_WINDOW_SECONDS, RETIREMENT, RETIREMENT_RECOVERY, list_objects, load_epoch, load_retirement,
    read_registered_target, read_retirement, recovery_deadline, require_active_epoch, retirement_approval, retirement_object_name,
    retirement_recovery, sign_share_recovery, target_attestation, verify_retirement, write_once,
)
from kms_policy import key_policy, recovery_policy, target_context


def retirement_scope(trust, epoch, replacement):
    if epoch_number(replacement) <= epoch_number(epoch):
        raise ValueError("retirement requires a newer custody epoch")
    _, old, _ = load_epoch(trust, epoch)
    _, new, custodians = load_epoch(trust, replacement)
    if old["custody"]["noteSeedCommitment"] != new["custody"]["noteSeedCommitment"]:
        raise ValueError("replacement epoch must preserve the note seed")
    return {
        "network": trust["network"], "securityDomainId": trust["securityDomainId"],
        "epoch": epoch, "receiptSha256": sha256(old), "replacementEpoch": replacement,
        "replacementReceiptSha256": sha256(new), "replacementCustodyDigest": sha256(new["custody"]),
        "approvalFromEpoch": trust["approvalKeys"][-1]["fromEpoch"],
    }, new, custodians


def require_recovery_quorum(custodians):
    def enabled(member):
        key = member["recoveryKeyArn"]
        try:
            metadata = kms(key, "describe-key")["KeyMetadata"]
            require_kms_key(metadata, key, RECOVERY_SPECS, "ENCRYPT_DECRYPT")
            return True
        except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired):
            return False

    with ThreadPoolExecutor(max_workers=len(custodians)) as workers:
        count = sum(workers.map(enabled, custodians))
    if count < 3:
        raise ValueError(f"only {count} proven replacement recovery keys are still enabled. Three are required.")


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
        attestation = target_attestation(target)
        if attestation in evidence["targets"]:
            return {"walletPolicyDigest": hex_digest(evidence["policyDigest"]),
                    "replacementTargetIdentity": sha256(attestation), "replacementTargetSha256": sha256(target)}
    raise ValueError("no attested serving target matches the registered replacement")


def qualified_manifest(trust, wallet_trust, epoch, replacement):
    scope, receipt, _ = retirement_scope(trust, epoch, replacement)
    policy = qualified_policy(trust, wallet_trust, scope, receipt["custody"]["noteSeedCommitment"])
    return {**scope, **policy, "recoveryDeadline": int(time.time()) + RECOVERY_WINDOW_SECONDS}


def require_recovery_window(manifest, remaining=0):
    deadline = recovery_deadline(manifest)
    now = time.time()
    if not deadline - RECOVERY_WINDOW_SECONDS <= now < deadline - remaining:
        raise ValueError("retirement recovery window is closed or has insufficient time remaining")


def checked_scope(trust, manifest):
    require_recovery_window(manifest)
    scope, receipt, custodians = retirement_scope(trust, manifest["epoch"], manifest["replacementEpoch"])
    if any(manifest.get(field) != value for field, value in scope.items()):
        raise ValueError("retirement no longer matches the committed receipts or approval roster")
    return scope, receipt, custodians


def prove_recovery(trust, document, index):
    manifest = retirement_approval(document)["manifest"]
    _, receipt, custodians = checked_scope(trust, manifest)
    require_active_epoch(trust, manifest["replacementEpoch"])
    proof = {"manifest": manifest, "signatures": document["recoveryProofs"]}
    signatures = sign_share_recovery(custodians, receipt, index, RETIREMENT_RECOVERY, proof)
    require_recovery_window(manifest)
    return {**document, "recoveryProofs": signatures}


def verify_qualification(trust, wallet_trust, document):
    manifest = document["manifest"]
    scope, receipt, custodians = checked_scope(trust, manifest)
    proven = retirement_recovery(document, custodians)
    policy = qualified_policy(trust, wallet_trust, scope, receipt["custody"]["noteSeedCommitment"])
    if manifest != {**scope, **policy, "recoveryDeadline": manifest["recoveryDeadline"]}:
        raise ValueError("retirement no longer matches the qualified replacement and wallet policy")
    require_recovery_quorum(proven)
    return custodians


def sign_retirement(trust, wallet_trust, document, key):
    approval = retirement_approval(document)
    verify_qualification(trust, wallet_trust, document)
    require_recovery_window(approval["manifest"])
    signed = add_approval(approval_keys(trust), RETIREMENT, approval, key)
    return {**document, "signatures": signed["signatures"]}


def commit_retirement(trust, wallet_trust, document):
    approval = retirement_approval(document)
    check_approvals(approval_keys(trust), RETIREMENT, approval)
    custodians = verify_qualification(trust, wallet_trust, document)
    manifest = approval["manifest"]
    epoch = manifest["epoch"]
    # Leave room for the AWS CLI's 25-second request deadline.
    require_recovery_window(manifest, remaining=30)

    def subject(stored):
        marker = verify_retirement(trust, stored, epoch)
        retirement_recovery(stored, custodians)
        return marker

    write_once(trust, retirement_object_name(epoch), document, subject)
    read_retirement(trust, epoch)


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
    prove = commands.add_parser("prove-recovery")
    prove.add_argument("candidate", type=Path)
    prove.add_argument("share", type=int, choices=range(1, 7))
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
            result = {"manifest": qualified_manifest(trust, args.wallet_trust, args.epoch, args.replacement),
                      "signatures": [], "recoveryProofs": []}
        else:
            document = read_json(args.candidate)
            if args.command == "publish":
                commit_retirement(trust, args.wallet_trust, document)
                return
            result = (prove_recovery(trust, document, args.share) if args.command == "prove-recovery" else
                      sign_retirement(trust, args.wallet_trust, document, args.key))
        print(canonical(result).decode())
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
