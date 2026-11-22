"""Verify historical custody receipts and checkpoint the complete ledger."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from approval import MAX_DOCUMENT_BYTES, canonical, epoch_number, fields, hex_digest, read_json, sha256, unique_object
from custody_ledger import (
    check_commit, check_predecessor, check_registered_target, check_rotation_target,
    ledger_object, ledger_prefix, ledger_record_fingerprint, ledger_replica,
    list_objects, publication_time, read_object, read_stored_object, read_stored_payload, record,
    require_frozen_ledger, require_record_replication, rotation_target_name, verify_ceremony_capture,
)

MAX_ARCHIVE_ENTRY_BYTES = 2 * MAX_DOCUMENT_BYTES + 256


def check_archive_entry(trust, epoch, entry, previous):
    fields(entry, "document", "rotation")
    document, rotation = entry["document"], entry["rotation"]
    receipt, custodians = record(trust, document)
    if receipt["custody"]["epoch"] != epoch:
        raise ValueError("archive custody epochs must be consecutive from genesis")
    check_commit(trust, document, receipt, custodians)
    manifest = document["authorization"]["manifest"]
    if previous is None:
        if rotation is not None:
            raise ValueError("genesis archive cannot include a rotation")
    else:
        predecessor, previous_roster = previous
        check_predecessor(document, receipt, predecessor, previous_roster)
        fields(rotation, "approval", "publishedAt")
        prior_epoch = predecessor["custody"]["epoch"]
        target = check_registered_target(
            trust, rotation_target_name(manifest, prior_epoch), prior_epoch, sha256(predecessor),
            rotation["approval"], publication_time({"LastModified": rotation["publishedAt"]}),
        )
        check_rotation_target(manifest, target)
        if manifest["rotationTargetSha256"] != sha256(target):
            raise ValueError("custody record does not pin the registered rotation target")
    return receipt, custodians


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
        previous = check_archive_entry(trust, current, entry, previous)
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
        previous = check_archive_entry(trust, str(index), entry, previous)
        verify_ceremony_capture(entry["document"]["authorization"]["manifest"]["capture"])
    if source.read(1) or checksum.hexdigest() != digest:
        raise ValueError("archive does not match the pinned custody archive digest")
    return previous[0]


def ledger_checkpoint(trust, expected=None):
    if expected is not None:
        hex_digest(expected)
    require_frozen_ledger(trust)
    _, prefix = ledger_prefix(trust)
    replica = ledger_replica(trust)
    checksum = hashlib.sha256(b"SPR/native-nitro/ledger-checkpoint/v1\0" + prefix.encode())
    names = tuple(list_objects(trust, ""))
    if "1.json" not in names:
        raise ValueError("custody ledger checkpoint requires a committed genesis")
    for name in names:
        payload, metadata = read_stored_payload(trust, name)
        if replica is not None:
            require_record_replication(name, metadata)
        checksum.update(canonical([name, *ledger_record_fingerprint(name, payload, metadata)]) + b"\n")
    if names != tuple(list_objects(trust, "")):
        raise ValueError("custody ledger changed during checkpoint")
    require_frozen_ledger(trust)
    actual = checksum.hexdigest()
    if expected is not None and actual != expected:
        raise ValueError("custody ledger differs from the independently pinned checkpoint")
    return actual


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
    args = parser.parse_args()
    try:
        trust = read_json(args.trust)
        if args.command == "export":
            archive(trust, args.epoch, sys.stdout.buffer)
        elif args.command == "ledger-checkpoint":
            print(ledger_checkpoint(trust, args.expect))
        else:
            with args.archive.open("rb") as source:
                receipt = verify_archive(trust, args.epoch, source, args.sha256)
            print(canonical(receipt).decode())
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
