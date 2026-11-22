"""Verify historical custody receipts and checkpoint the complete ledger."""

import argparse
import csv
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote

from approval import (
    MAX_DOCUMENT_BYTES, add_approval, approval_keys, approval_roster, canonical, check_approvals, epoch_number,
    fields, hex_digest, open_regular, parse_json, read_json, require_profile_account, sha256, unique_object,
)
from custody_ledger import (
    LABEL, RETIREMENT, TARGET_APPROVAL, check_custody_history_entry, check_recovery_bucket, ledger_object, ledger_prefix,
    ledger_record_fingerprint, ledger_record_version, ledger_replica, list_ledger_versions, load_retirement,
    publication_time, read_registered_target, read_replicated_record, read_stored_object, read_stored_payload,
    replica_trust, require_frozen_ledger, require_pinned_replication, retirement_object_name, rotation_target_name,
    storage, target_object_name, verify_ceremony_capture,
)

MAX_ARCHIVE_ENTRY_BYTES = 2 * MAX_DOCUMENT_BYTES + 256
REPAIR_APPROVAL = "ledger-repair"
REPAIR_WINDOW_SECONDS = 24 * 60 * 60
RECEIPT_NAME = re.compile(r"([1-9][0-9]{0,19})\.json")
TARGET_NAME = re.compile(r"targets/([1-9][0-9]{0,19})/[0-9a-f]{64}\.json")
RETIREMENT_NAME = re.compile(r"retired/([1-9][0-9]{0,19})\.json")


def custody_history(trust, epoch, **options):
    previous = None
    for index in range(1, epoch_number(epoch) + 1):
        current = str(index)
        document, receipt_metadata = read_stored_object(trust, ledger_object(trust, current), **options)
        rotation = None
        if previous is not None:
            manifest = document["authorization"]["manifest"]
            approval, metadata = read_stored_object(trust, rotation_target_name(manifest, str(index - 1)), **options)
            rotation = {"approval": approval, "publishedAt": metadata["LastModified"]}
        entry = {"document": document, "publishedAt": receipt_metadata["LastModified"], "rotation": rotation}
        previous = check_custody_history_entry(trust, current, entry, previous)
        yield current, entry, previous[0]


def archive(trust, epoch, output):
    for _, entry, _ in custody_history(trust, epoch):
        output.write(canonical(entry) + b"\n")


def verify_archive(trust, epoch, source, expected_digest):
    digest = hex_digest(expected_digest)
    count = epoch_number(epoch)
    previous = None
    checksum = hashlib.sha256()
    for index in range(1, count + 1):
        payload = source.readline(MAX_ARCHIVE_ENTRY_BYTES + 1)
        if len(payload) > MAX_ARCHIVE_ENTRY_BYTES or not payload.endswith(b"\n"):
            raise ValueError("missing or oversized custody archive entry")
        checksum.update(payload)
        entry = json.loads(payload, object_pairs_hook=unique_object)
        previous = check_custody_history_entry(trust, str(index), entry, previous)
        verify_ceremony_capture(entry["document"]["authorization"]["manifest"]["capture"])
    if source.read(1) or checksum.hexdigest() != digest:
        raise ValueError("archive does not match the pinned custody archive digest")
    return previous[0]


def verify_ledger_records(trust, names, **options):
    receipts = {name for name in names if "/" not in name}
    if receipts != {f"{epoch}.json" for epoch in range(1, len(receipts) + 1)}:
        raise ValueError("custody ledger receipts must be consecutive from genesis")
    receipt_pins = {}
    for epoch, entry, receipt in custody_history(trust, str(len(receipts)), **options):
        verify_ceremony_capture(entry["document"]["authorization"]["manifest"]["capture"])
        receipt_pins[epoch] = sha256(receipt), publication_time({"LastModified": entry["publishedAt"]})
    for name in names:
        if name in receipts:
            continue
        if target := TARGET_NAME.fullmatch(name):
            epoch = target[1]
            if epoch not in receipt_pins:
                raise ValueError("registered target is missing its custody receipt")
            digest, receipt_at = receipt_pins[epoch]
            read_registered_target(trust, name, epoch, digest, receipt_at=receipt_at, **options)
        elif retirement := RETIREMENT_NAME.fullmatch(name):
            load_retirement(trust, retirement[1], **options)
        else:
            raise ValueError(f"unexpected custody ledger record {name}")


def ledger_checkpoint(trust, expected=None, **options):
    return checkpoint(trust, expected, **options)[0]


def checkpoint(trust, expected, *, excluded=None, **options):
    if expected is not None:
        hex_digest(expected)
    require_frozen_ledger(trust, **options)
    _, prefix = ledger_prefix(trust)
    replica = ledger_replica(trust)
    destination = replica_trust(trust, replica) if replica is not None else None
    checksum = hashlib.sha256(b"SPR/native-nitro/ledger-checkpoint/v1\0" + prefix.encode())
    versions = list_ledger_versions(trust, **options)
    excluded = excluded or {}
    if any(versions.get(name) != version for name, version in excluded.items()):
        raise ValueError("excluded record does not match the frozen ledger version")
    names = tuple(name for name in sorted(versions) if name not in excluded)
    if "1.json" not in names:
        raise ValueError("custody ledger checkpoint requires a committed genesis")
    records = {}
    for name in names:
        if destination is None:
            payload, metadata = read_stored_payload(trust, name, **options)
            fingerprint = ledger_record_fingerprint(name, payload, metadata)
        else:
            _, fingerprint = read_replicated_record(trust, destination, name, **options)
        if fingerprint[0] != versions[name]:
            raise ValueError(f"custody ledger record {name} differs from its listed version")
        checksum.update(canonical([name, *fingerprint]) + b"\n")
        records[name] = fingerprint
    actual = checksum.hexdigest()
    if expected is not None and actual != expected:
        raise ValueError("custody ledger differs from the independently pinned checkpoint")
    verify_ledger_records(trust, names, checkpoint_records=records, **options)
    if versions != list_ledger_versions(trust, **options):
        raise ValueError("custody ledger changed during checkpoint")
    if destination is not None and versions != list_ledger_versions(destination, **options):
        raise ValueError("pinned replica versions differ from the custody ledger")
    require_frozen_ledger(trust, **options)
    return actual, {name: versions[name] for name in names}


def check_promotion_scope(trust, promoted):
    source, _ = ledger_prefix(trust)
    recovered, _ = ledger_prefix(promoted)
    original = {name: value for name, value in trust.items() if name != "ledgerReplica"}
    promoted_scope = {name: value for name, value in promoted.items() if name != "ledgerReplica"}
    if original != {**promoted_scope, "ledger": source}:
        raise ValueError("promotion must preserve the custody trust outside the ledger locations")
    if any(source[field] == recovered[field] for field in ("bucket", "region", "account")):
        raise ValueError("promotion requires a separate recovered bucket, region and account")
    next_replica = ledger_replica(promoted)
    if next_replica is None and trust["network"] == "mainnet":
        raise ValueError("mainnet promotion requires a new pinned replica")
    if next_replica is not None and next_replica["bucket"] == source["bucket"]:
        raise ValueError("promotion must keep the original ledger frozen")
    return original, next_replica


def check_repair_name(prefix, name):
    if not isinstance(name, str) or len((prefix + name).encode()) > 1024:
        raise ValueError("invalid excluded ledger record name")


def approval_for_slot(trust, name, label, document):
    try:
        if label == LABEL:
            approval = document["authorization"]
            scope = approval["manifest"]["capture"]["receipt"]
            expected = ledger_object(trust, scope["custody"]["epoch"])
        else:
            scope = document["manifest"]
            approval = {"manifest": scope, "signatures": document["signatures"]}
            if label == TARGET_APPROVAL:
                if not isinstance(scope["hostRole"], str):
                    return None
                expected = target_object_name(scope)
            else:
                expected = retirement_object_name(scope["epoch"])
        if (name == expected and
                (scope["network"], scope["securityDomainId"]) == (trust["network"], trust["securityDomainId"])):
            return approval
    except (KeyError, TypeError, ValueError):
        return None
    return None


def require_unapproved_record(trust, name, version, **options):
    label = next((label for pattern, label in (
        (RECEIPT_NAME, LABEL), (TARGET_NAME, TARGET_APPROVAL), (RETIREMENT_NAME, RETIREMENT)
    ) if pattern.fullmatch(name)), None)
    if label is None:
        return
    _, prefix = ledger_prefix(trust)
    head = storage(trust, "head-object", ["--key", prefix + name], **options)
    if ledger_record_version(name, head) != version:
        raise ValueError("excluded record does not match the frozen ledger version")
    size = head.get("ContentLength")
    if type(size) is not int or size < 0:
        raise ValueError("excluded record is missing its S3 length")
    if size == 0 or size > MAX_DOCUMENT_BYTES:
        return
    payload, metadata = read_stored_payload(trust, name, **options)
    published_at = publication_time(head)
    if (len(payload) != size or ledger_record_version(name, metadata) != version or
            publication_time(metadata) != published_at):
        raise ValueError("excluded ledger record changed during verification")
    try:
        document = parse_json(payload)
    except ValueError:
        return
    approval = approval_for_slot(trust, name, label, document)
    if approval is None:
        return
    keys = approval_keys(trust, name.removesuffix(".json")) if label == LABEL else approval_roster(trust, at=published_at)["keys"]
    try:
        check_approvals(keys, label, approval)
    except (ValueError, TypeError):
        return
    raise ValueError(f"cannot exclude {name} with a valid custody approval quorum for that slot")


def repair_bindings(trust, promoted, expected):
    original, _ = check_promotion_scope(trust, promoted)
    replica = ledger_replica(trust)
    if replica is None or promoted["ledger"]["bucket"] == replica["bucket"]:
        raise ValueError("repair requires a pinned replica and a fresh recovery bucket")
    bindings = {"sourceTrustSha256": sha256(trust), "recoveredTrustSha256": sha256(promoted),
                "checkpointSha256": hex_digest(expected), "approvalFromEpoch": approval_roster(trust)["fromEpoch"]}
    return original, bindings


def require_current_repair(trust, manifest):
    if time.time() >= manifest["expiresAt"] or approval_roster(trust)["fromEpoch"] != manifest["approvalFromEpoch"]:
        raise ValueError("repair approval expired or its roster changed during verification")


def require_unchanged_versions(trust, versions, *, profile):
    if list_ledger_versions(trust, profile=profile) != versions:
        raise ValueError(f"custody bucket {trust['ledger']['bucket']} changed after verification")


def repair_source(trust, promoted, expected, plan, profile, *, minimum):
    original, bindings = repair_bindings(trust, promoted, expected)
    fields(plan, "manifest", "signatures")
    manifest = plan["manifest"]
    fields(manifest, *bindings, "expiresAt", "excluded")
    expires, excluded = manifest["expiresAt"], manifest["excluded"]
    now = time.time()
    if (any(manifest[field] != value for field, value in bindings.items()) or type(expires) is not int or
            not now < expires <= now + REPAIR_WINDOW_SECONDS):
        raise ValueError("repair must match the pinned checkpoint, trust bundles, current quorum and deadline")
    if not isinstance(excluded, dict) or not excluded:
        raise ValueError("repair requires at least one excluded ledger version")
    source, prefix = ledger_prefix(original)
    for name, version in excluded.items():
        check_repair_name(prefix, name)
        ledger_record_version(name, {"VersionId": version})
    check_approvals(approval_keys(trust), REPAIR_APPROVAL, plan, minimum=minimum)
    require_profile_account(profile, source["region"], source["account"])
    _, versions = checkpoint(original, expected, excluded=excluded, profile=profile)
    for name, version in excluded.items():
        require_unapproved_record(original, name, version, profile=profile)
    require_unchanged_versions(original, {**versions, **excluded}, profile=profile)
    require_frozen_ledger(original, profile=profile)
    require_current_repair(trust, manifest)
    return versions


def draft_repair(trust, promoted, expected, names, profile):
    original, bindings = repair_bindings(trust, promoted, expected)
    source, prefix = ledger_prefix(original)
    if not isinstance(names, list) or not names:
        raise ValueError("provide distinct excluded ledger record names")
    for name in names:
        check_repair_name(prefix, name)
    if len(set(names)) != len(names):
        raise ValueError("provide distinct excluded ledger record names")
    require_profile_account(profile, source["region"], source["account"])
    require_frozen_ledger(original, profile=profile)
    versions = list_ledger_versions(original, profile=profile)
    if any(name not in versions for name in names):
        raise ValueError("excluded record is missing from the frozen ledger")
    excluded = {name: versions[name] for name in names}
    plan = {"manifest": {**bindings, "excluded": excluded, "expiresAt": int(time.time()) + REPAIR_WINDOW_SECONDS},
            "signatures": []}
    repair_source(trust, promoted, expected, plan, profile, minimum=0)
    return plan


def sign_repair(trust, promoted, expected, plan, profile, key):
    repair_source(trust, promoted, expected, plan, profile, minimum=0)
    signed = add_approval(approval_keys(trust), REPAIR_APPROVAL, plan, key)
    require_current_repair(trust, plan["manifest"])
    return signed


def repair_transfer(trust, promoted, expected, plan, source_profile, recovery_profile, output):
    versions = repair_source(trust, promoted, expected, plan, source_profile, minimum=2)
    source, prefix = ledger_prefix(trust)
    destination = {**promoted["ledger"], "role": ledger_replica(trust)["role"]}
    transfer = {**trust, "ledgerReplica": destination}
    require_pinned_replication(transfer, profile=source_profile)
    check_recovery_bucket(transfer, destination, recovery_profile)
    require_unchanged_versions(trust, {**versions, **plan["manifest"]["excluded"]}, profile=source_profile)
    require_frozen_ledger(trust, profile=source_profile)
    require_current_repair(trust, plan["manifest"])
    csv.writer(output, lineterminator="\n").writerows(
        (source["bucket"], quote(prefix + name), version) for name, version in versions.items()
    )


def verify_promotion(trust, promoted, expected, source_profile, recovery_profile, *, replica_profile=None, repair=None):
    hex_digest(expected)
    recovery, _ = ledger_prefix(promoted)
    replica = ledger_replica(trust)
    if repair is None and (replica is None or recovery != replica_trust(trust, replica)["ledger"]):
        raise ValueError("promotion must use the original ledger's pinned replica")
    original, next_replica = check_promotion_scope(trust, promoted)
    source = original["ledger"]
    if next_replica is not None and not replica_profile:
        raise ValueError("provide --replica-profile to verify the new ledger replica")

    require_profile_account(source_profile, source["region"], source["account"])
    require_profile_account(recovery_profile, recovery["region"], recovery["account"])
    require_frozen_ledger(original, profile=source_profile)
    _, recovered_versions = checkpoint(promoted, expected, profile=recovery_profile)
    # Re-read the original history after checking the recovered copy.
    if repair is None:
        _, original_versions = checkpoint(original, expected, profile=source_profile)
    else:
        preserved = repair_source(trust, promoted, expected, repair, source_profile, minimum=2)
        original_versions = {**preserved, **repair["manifest"]["excluded"]}
    require_pinned_replication(promoted, profile=recovery_profile)
    require_unchanged_versions(original, original_versions, profile=source_profile)
    require_unchanged_versions(promoted, recovered_versions, profile=recovery_profile)
    if next_replica is not None:
        require_unchanged_versions(replica_trust(promoted, next_replica), recovered_versions, profile=recovery_profile)
        check_recovery_bucket(promoted, next_replica, replica_profile)
    require_frozen_ledger(promoted, profile=recovery_profile)
    require_frozen_ledger(original, profile=source_profile)
    if repair is not None:
        require_current_repair(trust, repair["manifest"])
    return expected


def print_repair(plan):
    payload = canonical(plan) + b"\n"
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise ValueError("repair plan exceeds the ledger document limit")
    sys.stdout.buffer.write(payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trust", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export")
    export.add_argument("epoch")
    verify = commands.add_parser("verify")
    verify.add_argument("epoch")
    verify.add_argument("archive", type=Path)
    verify.add_argument("sha256")
    checkpoint = commands.add_parser("ledger-checkpoint")
    checkpoint.add_argument("--expect", metavar="SHA256")
    promote = commands.add_parser("verify-promotion")
    draft = commands.add_parser("draft-repair")
    sign = commands.add_parser("sign-repair")
    transfer = commands.add_parser("repair-transfer")
    for command in (promote, draft, sign, transfer):
        command.add_argument("recovered_trust", type=Path)
        command.add_argument("--expect", required=True, metavar="SHA256")
        command.add_argument("--source-profile", required=True)
    draft.add_argument("records", type=Path, help="JSON array of names relative to the custody ledger prefix")
    sign.add_argument("plan", type=Path)
    sign.add_argument("key", help="custody approval KMS key ARN")
    transfer.add_argument("plan", type=Path)
    promote.add_argument("--repair", type=Path, help="signed repair plan for a clean recovery bucket")
    for command in (promote, transfer):
        command.add_argument("--recovery-profile", required=True)
    promote.add_argument("--replica-profile", help="read-only profile in the new replica bucket owner's account")
    args = parser.parse_args()
    try:
        trust = read_json(args.trust)
        if args.command == "export":
            archive(trust, args.epoch, sys.stdout.buffer)
        elif args.command == "ledger-checkpoint":
            print(ledger_checkpoint(trust, args.expect))
        elif args.command == "verify-promotion":
            repair = read_json(args.repair) if args.repair is not None else None
            if args.repair is not None:
                fields(repair, "manifest", "signatures")
            print(verify_promotion(trust, read_json(args.recovered_trust), args.expect,
                                   args.source_profile, args.recovery_profile, replica_profile=args.replica_profile,
                                   repair=repair))
        elif args.command == "draft-repair":
            plan = draft_repair(trust, read_json(args.recovered_trust), args.expect, read_json(args.records), args.source_profile)
            print_repair(plan)
        elif args.command == "sign-repair":
            plan = sign_repair(trust, read_json(args.recovered_trust), args.expect,
                               read_json(args.plan), args.source_profile, args.key)
            print_repair(plan)
        elif args.command == "repair-transfer":
            repair_transfer(trust, read_json(args.recovered_trust), args.expect, read_json(args.plan),
                            args.source_profile, args.recovery_profile, sys.stdout)
        else:
            with open_regular(args.archive) as source:
                receipt = verify_archive(trust, args.epoch, source, args.sha256)
            print(canonical(receipt).decode())
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
