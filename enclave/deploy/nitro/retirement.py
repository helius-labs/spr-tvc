"""Close an old custody epoch and inventory the KMS keys that must be retired."""

import argparse
import hashlib
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from subprocess import run as run_command
from tempfile import TemporaryDirectory

from approval import (
    KEY_ARN, MAX_DOCUMENT_BYTES, ROLE_ARN, add_approval, approval_keys, approval_roster, arn, aws, canonical, check_approvals,
    epoch_number, fields, hex_digest, kms,
    parse_json, read_json, require_inspection_profiles, require_kms_key, require_profile_account, sha256,
)
from custody_ledger import (
    LEDGER_WRITE_MARGIN_SECONDS, RECOVERY_WINDOW_SECONDS, RETIREMENT, RETIREMENT_RECOVERY,
    find_retirement, list_objects, load_epoch,
    load_retirement, read_registered_target, recovery_deadline, require_active_epoch, retirement_approval, retirement_object_name,
    require_publication_roster, retirement_bootstrap, retirement_recovery, retirement_target, sign_share_recovery,
    target_attestation, write_once,
)
from deployment import HostUnobserved, require_host_state
from kms_policy import RSA_KEYS, key_policy
from relay import custody_recovery_policy


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
        "approvalFromEpoch": approval_roster(trust)["fromEpoch"],
    }, new, custodians


def require_recovery_quorum(trust, manifest, custodians):
    target = retirement_target(trust, manifest)
    slots = retirement_bootstrap(manifest["replacementBootstrap"])
    keys = [member["recoveryKeyArn"] for member in custodians] + [target["wrappingKeys"][slot - 1] for slot in slots]

    def require_enabled(key):
        try:
            metadata = kms(key, "describe-key")["KeyMetadata"]
            require_kms_key(metadata, key, RSA_KEYS, "ENCRYPT_DECRYPT")
        except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as error:
            raise ValueError(f"proven replacement key is unavailable: {key}") from error

    with ThreadPoolExecutor(max_workers=len(keys)) as workers:
        list(workers.map(require_enabled, keys))


def registered_targets(trust, epoch, receipt_digest):
    for name in list_objects(trust, f"targets/{epoch}/"):
        yield read_registered_target(trust, name, epoch, receipt_digest)


class ReplacementNotReady(ValueError):
    pass


def pinned_wallet_trust(trust, wallet_trust):
    with wallet_trust.open("rb") as source:
        pinned_trust = source.read(MAX_DOCUMENT_BYTES + 1)
    if (len(pinned_trust) > MAX_DOCUMENT_BYTES or
            hashlib.sha256(pinned_trust).hexdigest() != hex_digest(trust["walletTrustSha256"])):
        raise ValueError("wallet trust file does not match the pinned digest")
    return pinned_trust


def replacement_targets(trust, scope):
    epoch = scope["replacementEpoch"]
    require_active_epoch(trust, epoch)
    old_instances = {target["instanceId"] for target in registered_targets(trust, scope["epoch"], scope["receiptSha256"])}
    candidates = {
        sha256(target_attestation(target)): target
        for target in registered_targets(trust, epoch, scope["replacementReceiptSha256"])
        if target["mode"] == "serve" and target["instanceId"] not in old_instances
    }
    if not candidates:
        raise ValueError("no registered serving target on a separate replacement instance")
    return candidates


def qualified_boot(pinned_trust, candidates, scope, seed, *, after_ms=0, deadline=None, expected=None):
    timeout = 25 if deadline is None else min(25, deadline - time.monotonic())
    if timeout <= 0:
        raise ReplacementNotReady("replacement boot wait expired")
    root = Path(__file__).resolve().parents[3]
    reply = run_command([
        "pnpm", "--dir", str(root / "example"), "exec", "tsx", str(root / "xtask/nitro-retirement.ts"),
        scope["network"], scope["securityDomainId"], seed, scope["replacementEpoch"], scope["replacementCustodyDigest"],
    ], input=pinned_trust, stdout=subprocess.PIPE, check=True, timeout=timeout)
    evidence = parse_json(reply.stdout)
    fields(evidence, "policyDigest", "targets")
    for observed in evidence["targets"]:
        fields(observed, "releaseId", "pcrs", "bootstrap")
        identity = sha256({"releaseId": observed["releaseId"], "pcrs": observed["pcrs"]})
        if identity in candidates:
            bootstrap = observed["bootstrap"]
            retirement_bootstrap(bootstrap)
            booted_at = epoch_number(bootstrap["bootedAtMs"])
            if booted_at <= after_ms or booted_at // 1000 + RECOVERY_WINDOW_SECONDS <= time.time():
                continue
            qualification = {"walletPolicyDigest": hex_digest(evidence["policyDigest"]),
                             "replacementTargetIdentity": identity, "replacementTargetSha256": sha256(candidates[identity]),
                             "replacementBootstrap": bootstrap}
            if expected is not None and any(expected[field] != value for field, value in qualification.items()):
                continue
            if deadline is not None and time.monotonic() >= deadline:
                raise ReplacementNotReady("replacement boot wait expired")
            return qualification
    raise ReplacementNotReady("no fresh attested serving boot matches the registered replacement")


def qualified_policy(trust, wallet_trust, scope, seed, *, after_ms=0, expected=None):
    pinned_trust = pinned_wallet_trust(trust, wallet_trust)
    candidates = replacement_targets(trust, scope)
    return qualified_boot(pinned_trust, candidates, scope, seed, after_ms=after_ms, expected=expected)


def qualified_manifest(trust, wallet_trust, epoch, replacement):
    scope, receipt, _ = retirement_scope(trust, epoch, replacement)
    policy = qualified_policy(trust, wallet_trust, scope, receipt["custody"]["noteSeedCommitment"])
    booted_at = epoch_number(policy["replacementBootstrap"]["bootedAtMs"]) // 1000
    manifest = {**scope, **policy, "recoveryDeadline": booted_at + RECOVERY_WINDOW_SECONDS}
    require_recovery_window(manifest)
    return manifest


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


def prove_recovery(trust, document, index, relay_port):
    manifest = retirement_approval(document)["manifest"]
    _, receipt, custodians = checked_scope(trust, manifest)
    if index not in retirement_bootstrap(manifest["replacementBootstrap"]):
        raise ValueError("custodian did not supply an attested bootstrap slot")
    proof = {"manifest": manifest, "signatures": document["recoveryProofs"]}
    signatures = sign_share_recovery(trust, custodians, receipt, index, RETIREMENT_RECOVERY, proof, relay_port)
    require_recovery_window(manifest)
    return {**document, "recoveryProofs": signatures}


def verify_qualification(trust, wallet_trust, document):
    manifest = document["manifest"]
    scope, receipt, custodians = checked_scope(trust, manifest)
    proven = retirement_recovery(document, custodians)
    policy = qualified_policy(trust, wallet_trust, scope, receipt["custody"]["noteSeedCommitment"], expected=manifest)
    if manifest != {**scope, **policy, "recoveryDeadline": manifest["recoveryDeadline"]}:
        raise ValueError("retirement no longer matches the qualified replacement and wallet policy")
    require_recovery_quorum(trust, manifest, proven)
    require_active_epoch(trust, scope["replacementEpoch"])


def sign_retirement(trust, wallet_trust, document, key):
    approval = retirement_approval(document)
    verify_qualification(trust, wallet_trust, document)
    require_recovery_window(approval["manifest"])
    signed = add_approval(approval_keys(trust), RETIREMENT, approval, key)
    return {**document, "signatures": signed["signatures"]}


def commit_retirement(trust, wallet_trust, document):
    approval = retirement_approval(document)
    manifest = approval["manifest"]
    epoch = manifest["epoch"]
    existing = find_retirement(trust, epoch)
    if existing is not None:
        stored, _ = existing
        if stored != document:
            raise ValueError("a different retirement record is already committed")
        return
    check_approvals(approval_keys(trust), RETIREMENT, approval)
    verify_qualification(trust, wallet_trust, document)
    require_recovery_window(manifest, remaining=LEDGER_WRITE_MARGIN_SECONDS)
    require_publication_roster(trust, manifest["approvalFromEpoch"])

    write_once(trust, retirement_object_name(epoch), document, lambda stored: stored)
    load_retirement(trust, epoch)


def key_inventory(trust, epoch, index):
    if index not in range(1, 7):
        raise ValueError("invalid custody slot")
    document, custodians = load_retirement(trust, epoch)
    marker = document["manifest"]
    return slot_inventory(trust, epoch, custodians[index - 1], registered_targets(trust, epoch, marker["receiptSha256"]), index)


def slot_inventory(trust, epoch, member, targets, index):
    custodian, admin = member["custodianRole"], member["retirementRole"]
    keys = {member["recoveryKeyArn"]: custody_recovery_policy(trust, member, epoch)}
    for target in targets:
        key = target["wrappingKeys"][index - 1]
        expected = key_policy(target["hostRole"], custodian, admin, target["pcrs"], target["instanceId"])
        if keys.setdefault(key, expected) != expected:
            raise ValueError("one key appears with different retirement policies")
    return admin, keys


def inspect_keys(trust, epoch, index, check_inactive):
    return inspect_inventory(key_inventory(trust, epoch, index), check_inactive)


def deleted_keys(region, account, keys, **options):
    # CloudTrail indexes DeleteKey by event name. Its KMS ARN is inside the event.
    selector = {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "DeleteKey"}], "MaxResults": 20}
    missing = set(keys)
    tokens = set()
    while missing:
        page = aws(region, "cloudtrail", "lookup-events", [
            "--no-paginate", "--cli-input-json", canonical(selector).decode(),
        ], **options)
        for row in page["Events"]:
            event = parse_json(row["CloudTrailEvent"])
            event_id = event.get("eventID")
            if (event.get("eventSource") != "kms.amazonaws.com" or event.get("eventName") != "DeleteKey" or
                    event.get("eventType") != "AwsServiceEvent" or event.get("awsRegion") != region or
                    event.get("recipientAccountId") != account or
                    "errorCode" in event or not isinstance(event_id, str) or not event_id):
                continue
            for resource in event.get("resources", []):
                key = resource.get("ARN")
                if (key in missing and resource.get("type") == "AWS::KMS::Key" and
                        resource.get("accountId") == account):
                    missing.remove(key)
                    yield {"keyArn": key, "state": "Deleted", "deletionEventId": event_id}
        token = page.get("NextToken")
        if token is None or not missing:
            break
        if not isinstance(token, str) or not token or token in tokens:
            raise ValueError("invalid CloudTrail continuation token")
        tokens.add(token)
        selector["NextToken"] = token
    if missing:
        raise ValueError(f"retirement keys have no verified KMS deletion event: {', '.join(sorted(missing))}")


def inspect_inventory(inventory, check_inactive, **options):
    role, keys = inventory
    result = []
    missing = {}
    for key, expected in keys.items():
        try:
            policy = kms(key, "get-key-policy", ["--policy-name", "default"], **options)["Policy"]
            metadata = kms(key, "describe-key", **options)["KeyMetadata"]
        except (ValueError, subprocess.TimeoutExpired):
            if not check_inactive:
                raise
            region = arn(KEY_ARN, key)[1]
            missing.setdefault(region, []).append(key)
            continue
        installed = parse_json(policy)
        if installed != expected or metadata.get("Arn") != key:
            raise ValueError("retirement key does not match the recorded epoch policy")
        state = metadata["KeyState"]
        if check_inactive and state not in {"Disabled", "PendingDeletion"}:
            raise ValueError(f"retirement key {key} remains usable or unverified")
        result.append({"keyArn": key, "state": state})
    for region, absent_keys in missing.items():
        result.extend(deleted_keys(region, arn(ROLE_ARN, role)[1], absent_keys, **options))
    return {"retirementRole": role, "keys": sorted(result, key=lambda row: row["keyArn"])}


def require_terminated_parent(target, profile):
    try:
        return require_host_state(target, "terminated", profile)
    except HostUnobserved:
        # EC2 drops terminated instances from its inventory. Require a positive
        # deletion record for the exact managed resource from AWS Config.
        pass
    account = arn(ROLE_ARN, target["hostRole"])[1]
    region, instance = target["hostRegion"], target["instanceId"]
    resource_type = "AWS::EC2::Instance"
    rows = aws(region, "configservice", "get-resource-config-history", [
        "--resource-type", resource_type, "--resource-id", instance,
        "--chronological-order", "Reverse", "--limit", "1", "--no-paginate",
    ], profile=profile)["configurationItems"]
    if len(rows) != 1:
        raise ValueError(f"missing AWS Config termination evidence for {account}/{region}/{instance}")
    row = rows[0]
    capture_time = row.get("configurationItemCaptureTime")
    if (row.get("accountId") != account or row.get("awsRegion") != region or
            row.get("resourceId") != instance or row.get("resourceType") != resource_type or
            row.get("configurationItemStatus") != "ResourceDeleted" or
            not isinstance(capture_time, str) or not capture_time):
        raise ValueError(f"unverified AWS Config termination for {account}/{region}/{instance}")
    return {"account": account, "region": region, "instanceId": instance, "state": "terminated",
            "source": "aws-config", "capturedAt": capture_time}


def verify_retired(trust, wallet_trust, epoch, profiles, host_profiles, wait_seconds):
    require_inspection_profiles(profiles)
    if wait_seconds <= 0:
        raise ValueError("provide a positive replacement boot wait time")
    document, custodians = load_retirement(trust, epoch)
    marker = document["manifest"]
    _, replacement, replacement_custodians = load_epoch(trust, marker["replacementEpoch"])

    def inspect_all(*, check_profiles=False):
        targets = list(registered_targets(trust, epoch, marker["receiptSha256"]))
        hosts = {(arn(ROLE_ARN, target["hostRole"])[1], target["hostRegion"], target["instanceId"]): target
                 for target in targets}
        host_regions = {account: region for account, region, _ in hosts}
        if set(host_profiles) != host_regions.keys():
            raise ValueError("provide one host inspection profile for each old parent account")
        with ThreadPoolExecutor(max_workers=6) as workers:
            if check_profiles:
                accounts = [arn(KEY_ARN, member["recoveryKeyArn"]) for member in custodians]
                checks = [(profile, key[1], key[2]) for profile, key in zip(profiles, accounts, strict=True)]
                checks.extend((host_profiles[account], region, account) for account, region in host_regions.items())
                list(workers.map(lambda check: require_profile_account(*check), checks))
            slots = list(workers.map(
                lambda index, member, profile: inspect_inventory(
                    slot_inventory(trust, epoch, member, targets, index), True, profile=profile),
                range(1, 7), custodians, profiles,
            ))
        terminated = [require_terminated_parent(hosts[host], host_profiles[host[0]]) for host in sorted(hosts)]
        return slots, terminated

    inspect_all(check_profiles=True)
    pinned_trust = pinned_wallet_trust(trust, wallet_trust)
    candidates = replacement_targets(trust, marker)
    after_ms = int(time.time() * 1000)
    deadline = time.monotonic() + wait_seconds
    seed = replacement["custody"]["noteSeedCommitment"]
    print("All old keys are inactive and registered parents terminated. Waiting for a newer replacement boot.", file=sys.stderr, flush=True)
    while True:
        try:
            evidence = qualified_boot(pinned_trust, candidates, marker, seed, after_ms=after_ms, deadline=deadline)
            break
        except (ReplacementNotReady, subprocess.SubprocessError) as error:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("no replacement boot observed after verifying the old keys") from error
            time.sleep(min(2, remaining))

    slots, parents = inspect_all()
    recovered = retirement_bootstrap(evidence["replacementBootstrap"])
    require_recovery_quorum(trust, {**marker, **evidence}, [replacement_custodians[slot - 1] for slot in recovered])
    qualified_policy(trust, wallet_trust, marker, seed, after_ms=after_ms, expected=evidence)
    require_active_epoch(trust, marker["replacementEpoch"])
    return {"retirementSha256": sha256(document), "retirementObservedAtMs": str(after_ms),
            "replacement": evidence, "slots": slots, "terminatedParents": parents}


def write_report(path, report):
    with TemporaryDirectory(dir=path.parent) as directory:
        staged = Path(directory) / "report.json"
        staged.write_bytes(canonical(report) + b"\n")
        path.hardlink_to(staged)


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
    prove.add_argument("--relay-port", type=int, required=True)
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
    verify = commands.add_parser("verify-retired")
    verify.add_argument("wallet_trust", type=Path)
    verify.add_argument("epoch")
    verify.add_argument("--inspection-profiles", nargs=6, required=True)
    verify.add_argument("--host-inspection-profile", metavar="ACCOUNT=PROFILE", action="append", default=[])
    verify.add_argument("--wait-seconds", type=int, default=300)
    verify.add_argument("--output", type=Path, help="publish the report atomically at a new path")
    args = parser.parse_args()
    try:
        trust = read_json(args.trust)
        if args.command == "inspect":
            result = inspect_keys(trust, args.epoch, args.share, args.check_inactive)
        elif args.command == "verify-retired":
            if args.output is not None and args.output.exists():
                raise ValueError("retirement report already exists")
            profiles = {}
            for mapping in args.host_inspection_profile:
                account, _, profile = mapping.partition("=")
                if not re.fullmatch(r"[0-9]{12}", account) or not profile or account in profiles:
                    raise ValueError("provide distinct host inspection profiles as ACCOUNT=PROFILE")
                profiles[account] = profile
            result = verify_retired(trust, args.wallet_trust, args.epoch, args.inspection_profiles, profiles, args.wait_seconds)
            if args.output is not None:
                write_report(args.output, result)
                return
        elif args.command == "draft":
            result = {"manifest": qualified_manifest(trust, args.wallet_trust, args.epoch, args.replacement),
                      "signatures": [], "recoveryProofs": []}
        else:
            document = read_json(args.candidate)
            if args.command == "publish":
                commit_retirement(trust, args.wallet_trust, document)
                return
            result = (prove_recovery(trust, document, args.share, args.relay_port) if args.command == "prove-recovery" else
                      sign_retirement(trust, args.wallet_trust, document, args.key))
        print(canonical(result).decode())
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
