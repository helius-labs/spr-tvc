"""Verify historical custody receipts and checkpoint the complete ledger."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from approval import MAX_DOCUMENT_BYTES, canonical, epoch_number, hex_digest, read_json, require_profile_account, unique_object
from custody_ledger import (
    check_custody_history_entry, check_recovery_bucket,
    ledger_object, ledger_prefix, ledger_record_fingerprint, ledger_replica,
    list_objects, read_object, read_replicated_record, read_stored_object, read_stored_payload,
    replica_trust, require_frozen_ledger, require_pinned_replication, rotation_target_name, verify_ceremony_capture,
)

MAX_ARCHIVE_ENTRY_BYTES = 2 * MAX_DOCUMENT_BYTES + 256


def archive(trust, epoch, output):
    previous = None
    for index in range(1, epoch_number(epoch) + 1):
        current = str(index)
        document = read_object(trust, ledger_object(trust, current))
        rotation = None
        if previous is not None:
            manifest = document["authorization"]["manifest"]
            approval, metadata = read_stored_object(trust, rotation_target_name(manifest, str(index - 1)))
            rotation = {"approval": approval, "publishedAt": metadata["LastModified"]}
        entry = {"document": document, "rotation": rotation}
        previous = check_custody_history_entry(trust, current, entry, previous)
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


def ledger_checkpoint(trust, expected=None, **options):
    if expected is not None:
        hex_digest(expected)
    require_frozen_ledger(trust, **options)
    _, prefix = ledger_prefix(trust)
    replica = ledger_replica(trust)
    destination = replica_trust(trust, replica) if replica is not None else None
    checksum = hashlib.sha256(b"SPR/native-nitro/ledger-checkpoint/v1\0" + prefix.encode())
    names = tuple(list_objects(trust, "", **options))
    if "1.json" not in names:
        raise ValueError("custody ledger checkpoint requires a committed genesis")
    for name in names:
        if destination is None:
            payload, metadata = read_stored_payload(trust, name, **options)
            fingerprint = ledger_record_fingerprint(name, payload, metadata)
        else:
            _, fingerprint = read_replicated_record(trust, destination, name, **options)
        checksum.update(canonical([name, *fingerprint]) + b"\n")
    if names != tuple(list_objects(trust, "", **options)):
        raise ValueError("custody ledger changed during checkpoint")
    if destination is not None and names != tuple(list_objects(destination, "", **options)):
        raise ValueError("pinned replica namespace differs from the custody ledger")
    require_frozen_ledger(trust, **options)
    actual = checksum.hexdigest()
    if expected is not None and actual != expected:
        raise ValueError("custody ledger differs from the independently pinned checkpoint")
    return actual


def verify_promotion(trust, promoted, expected, source_profile, recovery_profile, *, replica_profile=None):
    hex_digest(expected)
    source, _ = ledger_prefix(trust)
    recovery, _ = ledger_prefix(promoted)
    replica = ledger_replica(trust)
    if replica is None or recovery != replica_trust(trust, replica)["ledger"]:
        raise ValueError("promotion must use the original ledger's pinned replica")
    original = {name: value for name, value in trust.items() if name != "ledgerReplica"}
    promoted_scope = {name: value for name, value in promoted.items() if name != "ledgerReplica"}
    if original != {**promoted_scope, "ledger": source}:
        raise ValueError("promotion must preserve the custody trust outside the ledger locations")
    next_replica = ledger_replica(promoted)
    if next_replica is None and trust["network"] == "mainnet":
        raise ValueError("mainnet promotion requires a new pinned replica")
    if next_replica is not None:
        if next_replica["bucket"] == source["bucket"]:
            raise ValueError("promotion must keep the original ledger frozen")
        if not replica_profile:
            raise ValueError("provide --replica-profile to verify the new ledger replica")

    require_profile_account(source_profile, source["region"], source["account"])
    require_profile_account(recovery_profile, recovery["region"], recovery["account"])
    require_frozen_ledger(original, profile=source_profile)
    ledger_checkpoint(promoted, expected, profile=recovery_profile)
    require_pinned_replication(promoted, profile=recovery_profile)
    # Re-read the original history after checking the recovered copy.
    ledger_checkpoint(original, expected, profile=source_profile)
    if next_replica is not None:
        check_recovery_bucket(promoted, next_replica, replica_profile)
    require_frozen_ledger(promoted, profile=recovery_profile)
    return expected


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
    promote.add_argument("recovered_trust", type=Path)
    promote.add_argument("--expect", required=True, metavar="SHA256")
    promote.add_argument("--source-profile", required=True)
    promote.add_argument("--recovery-profile", required=True)
    promote.add_argument("--replica-profile", help="read-only profile in the new replica bucket owner's account")
    args = parser.parse_args()
    try:
        trust = read_json(args.trust)
        if args.command == "export":
            archive(trust, args.epoch, sys.stdout.buffer)
        elif args.command == "ledger-checkpoint":
            print(ledger_checkpoint(trust, args.expect))
        elif args.command == "verify-promotion":
            print(verify_promotion(trust, read_json(args.recovered_trust), args.expect,
                                   args.source_profile, args.recovery_profile, replica_profile=args.replica_profile))
        else:
            with args.archive.open("rb") as source:
                receipt = verify_archive(trust, args.epoch, source, args.sha256)
            print(canonical(receipt).decode())
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
