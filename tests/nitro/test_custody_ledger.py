import base64
import copy
import hashlib
import json
import pathlib
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from io import BytesIO
from threading import Lock
from types import SimpleNamespace
from unittest.mock import ANY, call, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from approval import approval_keys, approval_roster, canonical, sha256
from custody_archive import MAX_ARCHIVE_ENTRY_BYTES, archive, ledger_checkpoint, verify_archive
from custody_ledger import (
    ACKNOWLEDGEMENT, LABEL, RECOVERY_WINDOW_SECONDS, RETIREMENT, RETIREMENT_RECOVERY, TARGET_APPROVAL, acknowledge,
    check_custody_roster, check_installed_ledger, check_serving_policy, draft, ledger_policy, ledger_reader_policy,
    list_objects, load_epoch, publish, read_registered_target,
    record, require_active_epoch,
    sign_epoch, target_attestation,
    target_object_name, write_once,
)
from deployment import register_target, require_registered_target
from kms_policy import acknowledgement_policy, boot_pins
from nitro_fixtures import DOMAIN, HOST, INSTANCE, REGION, key, pin, schedule, sign
from provenance import describe
from retirement import (commit_retirement, inspect_keys, prove_recovery, qualified_manifest, qualified_policy,
                        main as retirement_main, replacement_targets, retirement_inventory, retirement_scope,
                        sign_retirement, verify_retired)

READ_ROLE = "arn:aws:iam::000000000001:role/custodian"
PUBLISHER = "arn:aws:iam::000000000008:role/publisher"
ADMIN = "arn:aws:iam::000000000008:role/ledger-admin"
PINS = {f"PCR{i}": f"{i+1:02x}" * 48 for i in range(3)}


def listing(prefix, keys=(), **metadata):
    page = {"Name": "custody-journal", "Prefix": prefix, "KeyCount": len(keys), "IsTruncated": False}
    if keys:
        page["Contents"] = [{"Key": key} for key in keys]
    return {**page, **metadata}


class CustodyLedgerTests(unittest.TestCase):
    def setUp(self):
        self.trust = {
            "network": "devnet", "securityDomainId": DOMAIN, "approvalKeys": [schedule()],
            "ledger": {"bucket": "custody-journal", "account": "000000000008", "region": "eu-north-1"},
            "recoveryRelays": {str(epoch): {"hostRole": HOST, "pcrs": PINS} for epoch in range(1, 4)},
        }
        self.objects = {}
        self.timestamps = {}
        self.versions = {}
        self.bucket_policy = ledger_policy(self.trust, ADMIN, PUBLISHER, [READ_ROLE])
        self.lifecycle = None
        self.lock = Lock()
        self.now = int(time.time())
        self.booted_at_ms = self.now * 1000
        self.enterContext(patch("time.time", side_effect=lambda: self.now))
        self.enterContext(patch("custody_ledger.aws", side_effect=self.aws))
        self.enterContext(patch("approval.kms", side_effect=AssertionError("receipt verification must not call KMS")))
        self.capture_verifier = self.enterContext(patch("custody_ledger.verify_ceremony_capture"))

    def rotate_approvals(self, epoch):
        self.now += 60
        self.trust["approvalKeys"].append(schedule(epoch, 9, self.now))

    def document(self, epoch, predecessor=None, variant="ab"):
        roster = [{
            "recoveryKeyArn": key(index, epoch), "acknowledgementKey": pin(key(index, 8)),
            "custodianRole": f"arn:aws:iam::{index:012}:role/custodian",
            "retirementRole": f"arn:aws:iam::{index:012}:role/retirement",
        } for index in range(1, 7)]
        custody = {"epoch": str(epoch), "noteSeedCommitment": "34" * 32, "shareCommitments": [variant * 32] * 6}
        receipt = {
            "network": "devnet", "securityDomainId": DOMAIN, "releaseId": f"custody-{epoch}",
            "custody": custody, "packages": [{}] * 6,
        }
        deployment = {"mode": "initialize", "recipientPublicKeys": []}
        if predecessor:
            deployment = {**deployment, "mode": "rotate", "previous": predecessor["custody"]}
        configuration = {"releaseId": receipt["releaseId"], "securityDomainId": DOMAIN, "deployment": deployment}
        manifest = {
            "capture": {"receipt": receipt, "evidence": "aa", "nonce": "88" * 32, "verifiedAtMs": "1",
                        "configuration": configuration, "pcrs": {key.removeprefix("PCR"): value
                                                                    for key, value in boot_pins(HOST, PINS).items()}},
            "ceremonyEifSha256": hashlib.sha256(b"rotation EIF fixture").hexdigest(), "ceremonyHostRole": HOST,
            "custodians": roster, "relay": copy.deepcopy(self.trust["recoveryRelays"][str(epoch)]), "previousReceiptSha256": sha256(predecessor) if predecessor else None,
            "rotationTargetSha256": None,
        }
        return {"authorization": {"manifest": manifest, "signatures": []}, "acknowledgements": []}

    def rotation_document(self, predecessor, variant="fe", register=True):
        document = self.document(2, predecessor, variant)
        manifest = document["authorization"]["manifest"]
        target = {"network": "devnet", "securityDomainId": DOMAIN, "receiptSha256": sha256(predecessor),
                  "custodyEpoch": "1", "approvalFromEpoch": approval_roster(self.trust)["fromEpoch"], "expiresAt": self.now + 3600,
                  "releaseId": manifest["capture"]["receipt"]["releaseId"], "mode": "rotate", "hostRole": HOST,
                  "hostRegion": REGION, "instanceId": INSTANCE, "pcrs": PINS, "eifSha256": manifest["ceremonyEifSha256"],
                  "executableSha256": hashlib.sha256(b"rotation executable fixture").hexdigest(),
                  "configurationSha256": sha256(manifest["capture"]["configuration"]),
                  "nextCustodians": copy.deepcopy(manifest["custodians"]), "nextRelay": copy.deepcopy(manifest["relay"]),
                  "wrappingKeys": [key(i, 21) for i in range(1, 7)]}
        manifest["capture"]["pcrs"] = target_attestation(target)["pcrs"]
        manifest["rotationTargetSha256"] = sha256(target)
        approval = self.signed_subject(TARGET_APPROVAL, target)
        if register:
            register_target(self.trust, approval)
        return document, approval

    def sign(self, document, approvals=None):
        manifest = document["authorization"]["manifest"]
        if approvals is None:
            approvals = approval_keys(self.trust, manifest["capture"]["receipt"]["custody"]["epoch"])
        document["authorization"]["signatures"] = [sign(LABEL, manifest, key["keyArn"]) for key in approvals[:2]]
        document["acknowledgements"] = [sign(ACKNOWLEDGEMENT, manifest, c["acknowledgementKey"]["keyArn"])
                                        for c in manifest["custodians"]]
        return document

    def aws(self, region, service, operation, args, **options):
        self.assertEqual((region, service), ("eu-north-1", "s3api"))
        self.assertEqual(args[args.index("--expected-bucket-owner") + 1], "000000000008")
        if operation == "get-bucket-policy":
            return {"Policy": canonical(self.bucket_policy).decode()}
        if operation == "get-bucket-lifecycle-configuration":
            self.assertEqual(options, {"absent": "NoSuchLifecycleConfiguration"})
            return self.lifecycle
        if operation == "list-objects-v2":
            prefix = args[args.index("--prefix") + 1]
            self.assertTrue(prefix.startswith(f"spr-custody/devnet/{DOMAIN}/"))
            with self.lock:
                return listing(prefix, [name for name in sorted(self.objects) if name.startswith(prefix)])
        name = args[args.index("--key") + 1]
        self.assertTrue(name.startswith(f"spr-custody/devnet/{DOMAIN}/"))
        now = datetime.fromtimestamp(time.time(), timezone.utc).isoformat()
        with self.lock:
            if operation == "put-object":
                self.assertEqual(args[args.index("--if-none-match") + 1], "*")
                if name in self.objects:
                    raise ValueError("precondition failed")
                self.objects[name] = pathlib.Path(args[-1]).read_bytes()
                self.timestamps[name] = now
            elif operation == "get-object" and name in self.objects:
                pathlib.Path(args[-1]).write_bytes(self.objects[name])
                return {"LastModified": self.timestamps.get(name, now),
                        "VersionId": self.versions.get(name, hashlib.sha256(name.encode()).hexdigest())}
            else:
                raise ValueError("object missing")
        return {}

    def test_one_concurrent_commit_wins_and_retry_reads_winner(self):
        left, right = [self.sign(self.document(1, variant=variant)) for variant in ("ab", "fe")]

        def commit(document):
            try:
                publish(self.trust, document)
                return True
            except ValueError:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(commit, (left, right))), 1)
        winner, receipt, _ = load_epoch(self.trust, "1")
        self.assertIn(winner, (left, right))
        self.assertEqual(receipt, record(self.trust, winner)[0])
        publish(self.trust, winner)

    def test_mainnet_admits_only_the_signed_relay(self):
        self.trust["network"] = "mainnet"
        document = self.document(1)
        manifest = document["authorization"]["manifest"]
        manifest["capture"]["receipt"]["network"] = "mainnet"
        self.sign(document)
        custody = record(self.trust, document)[0]["custody"]
        self.assertEqual(custody["epoch"], "1")
        legacy = copy.deepcopy(document)
        del legacy["authorization"]["manifest"]["relay"]
        with self.assertRaisesRegex(ValueError, "expected document fields"):
            record(self.trust, self.sign(legacy))
        missing = {**self.trust, "recoveryRelays": {}}
        with self.assertRaisesRegex(ValueError, "requires a pinned recovery relay"):
            record(missing, document)
        relay = manifest["relay"]
        for substituted in (
            {**relay, "hostRole": "arn:aws:iam::000000000009:role/relay"},
            {**relay, "pcrs": {**relay["pcrs"], "PCR0": "ef" * 48}},
        ):
            with self.subTest(substituted=substituted), self.assertRaisesRegex(ValueError, "pinned recovery relay"):
                record({**self.trust, "recoveryRelays": {"1": substituted}}, document)

    def test_reports_both_failures_when_a_ledger_write_cannot_be_confirmed(self):
        with patch("custody_ledger.storage", side_effect=[ValueError("write timed out"), ValueError("read denied")]):
            with self.assertRaisesRegex(ValueError, r"could not confirm ledger write \(write timed out\).*\(read denied\)"):
                write_once(self.trust, "1.json", {}, lambda document: document)

    def test_retirement_requires_an_explicit_complete_listing_from_the_pinned_bucket(self):
        prefix = f"spr-custody/devnet/{DOMAIN}/retired/1.json"
        empty = listing(prefix)
        with patch("custody_ledger.storage", return_value=empty):
            require_active_epoch(self.trust, "1")
        for invalid in (
            {},
            {name: value for name, value in empty.items() if name != "IsTruncated"},
            {**empty, "IsTruncated": "false"},
            {**empty, "Name": "wrong-bucket"},
            {**empty, "Prefix": prefix + ".wrong"},
            {**empty, "KeyCount": 1},
            {**empty, "IsTruncated": True},
            {**empty, "NextContinuationToken": "next"},
        ):
            with (self.subTest(listing=invalid), patch("custody_ledger.storage", return_value=invalid),
                  self.assertRaisesRegex(ValueError, "invalid custody ledger")):
                require_active_epoch(self.trust, "1")

    def test_target_inventory_follows_only_advancing_pages_in_the_requested_prefix(self):
        prefix = f"spr-custody/devnet/{DOMAIN}/targets/1/"
        first = listing(prefix, [prefix + "a.json"], IsTruncated=True, NextContinuationToken="next")
        last = listing(prefix, [prefix + "b.json"])
        with patch("custody_ledger.storage", side_effect=[first, last]) as storage:
            self.assertEqual(list(list_objects(self.trust, "targets/1/")), ["targets/1/a.json", "targets/1/b.json"])
            self.assertEqual(storage.call_args.args[2][-2:], ["--continuation-token", "next"])
        for invalid in (
            listing(prefix, [prefix + "a.json"]),
            listing(prefix, [prefix.removesuffix("1/") + "2/foreign.json"]),
            {**last, "IsTruncated": True, "NextContinuationToken": "next"},
        ):
            with (self.subTest(listing=invalid), patch("custody_ledger.storage", side_effect=[first, invalid]),
                  self.assertRaisesRegex(ValueError, "invalid")):
                list(list_objects(self.trust, "targets/1/"))

    def test_rotated_receipt_requires_current_predecessor_and_new_recovery_keys(self):
        first = self.sign(self.document(1))
        publish(self.trust, first)
        _, previous, roster = load_epoch(self.trust, "1")
        new, _ = self.rotation_document(previous)
        bad = copy.deepcopy(new)
        bad["authorization"]["manifest"]["previousReceiptSha256"] = "11" * 32
        with self.assertRaisesRegex(ValueError, "canonical previous receipt"):
            publish(self.trust, self.sign(bad))
        bad = copy.deepcopy(new)
        bad["authorization"]["manifest"]["custodians"] = roster
        with self.assertRaisesRegex(ValueError, "fresh recovery keys"):
            publish(self.trust, self.sign(bad))
        publish(self.trust, self.sign(new))
        self.assertEqual(load_epoch(self.trust, "2")[1]["custody"]["noteSeedCommitment"], previous["custody"]["noteSeedCommitment"])

    def test_signs_only_a_ceremony_bound_to_verified_provenance(self):
        publish(self.trust, self.sign(self.document(1)))
        document, _ = self.rotation_document(load_epoch(self.trust, "1")[1])
        capture = document["authorization"]["manifest"]["capture"]
        capture["receipt"]["packages"] = [{"recipientSha256": f"{index:02x}" * 32} for index in range(1, 7)]
        build = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        (build / "enclave.eif").write_bytes(b"rotation EIF fixture")
        (build / "tvc_app").write_bytes(b"rotation executable fixture")
        (build / "configuration.json").write_bytes(canonical(capture["configuration"]))
        (build / "measurements.json").write_bytes(canonical({"Measurements": PINS}))
        commit = "ab" * 20
        reviewed = describe(build, "devnet", commit)
        review = pathlib.Path("ceremony-review.json")
        self.capture_verifier.reset_mock()
        with (patch("custody_ledger.verify_build") as verify_build,
              patch("custody_ledger.check_custody_roster"),
              patch("custody_ledger.add_approval", return_value=document["authorization"]) as sign_record):
            for field in ("configurationSha256", "eifSha256", "executableSha256", "pcrs"):
                value = {**PINS, "PCR0": "aa" * 48} if field == "pcrs" else "aa" * 32
                verify_build.return_value = {**reviewed, field: value}
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, "verified build provenance"):
                    sign_epoch(self.trust, document, key(8, 7), build, review)
            self.capture_verifier.assert_not_called()
            sign_record.assert_not_called()
            verify_build.return_value = reviewed
            self.assertEqual(sign_epoch(self.trust, document, key(8, 7), build, review), document)
            verify_build.assert_called_with(build, "devnet", review)
            self.capture_verifier.assert_called_once_with(capture)
            sign_record.assert_called_once()

    def test_rotation_receipt_must_match_the_registered_image_and_successor_roster(self):
        publish(self.trust, self.sign(self.document(1)))
        _, previous, _ = load_epoch(self.trust, "1")
        document, approval = self.rotation_document(previous, register=False)
        manifest = document["authorization"]["manifest"]
        capture = manifest["capture"]
        roster = manifest["custodians"]
        with tempfile.TemporaryDirectory() as directory:
            build = pathlib.Path(directory)
            (build / "enclave.eif").write_bytes(b"rotation EIF fixture")
            (build / "configuration.json").write_bytes(canonical(capture["configuration"]))
            (build / "measurements.json").write_bytes(canonical({"Measurements": PINS}))
            with self.assertRaisesRegex(ValueError, "object missing"):
                draft(self.trust, capture, build, HOST, roster)
            with self.assertRaisesRegex(ValueError, "object missing"):
                publish(self.trust, self.sign(document))
            register_target(self.trust, approval)
            self.assertEqual(draft(self.trust, capture, build, HOST, roster)["authorization"]["manifest"], manifest)

            with (build / "configuration.json").open("ab") as configuration:
                configuration.write(b"\n")
            with self.assertRaisesRegex(ValueError, "configuration does not match"):
                draft(self.trust, capture, build, HOST, roster)
            with patch("custody_ledger.verify_build") as provenance:
                with self.assertRaisesRegex(ValueError, "configuration does not match"):
                    sign_epoch(self.trust, document, key(8, 7), build, pathlib.Path("ceremony-review.json"))
                provenance.assert_not_called()

            for change, message in (
                ({"custodians": [{**roster[0], "acknowledgementKey": pin(key(1, 33))}, *roster[1:]]}, "successor roster"),
                ({"ceremonyEifSha256": "ff" * 32}, "ceremony image"),
                ({"rotationTargetSha256": "ab" * 32}, "does not pin"),
                ({"capture": {**capture, "pcrs": {**capture["pcrs"], "3": "ef" * 48}}}, "object missing"),
                ({"capture": {**capture, "pcrs": {**capture["pcrs"], "4": "ef" * 48}}}, "object missing"),
            ):
                bad = copy.deepcopy(document)
                bad["authorization"]["manifest"].update(copy.deepcopy(change))
                self.sign(bad)
                with (patch("custody_ledger.verify_build") as provenance, patch("custody_ledger.prove_share") as share):
                    with self.assertRaisesRegex(ValueError, message):
                        sign_epoch(self.trust, bad, key(8, 7), build, pathlib.Path("ceremony-review.json"))
                    with self.assertRaisesRegex(ValueError, message):
                        acknowledge(self.trust, bad, 1, 7443, build, pathlib.Path("ceremony-review.json"))
                    with self.assertRaisesRegex(ValueError, message):
                        publish(self.trust, bad)
                    provenance.assert_not_called()
                    share.assert_not_called()

                name = f"spr-custody/devnet/{DOMAIN}/2.json"
                self.objects[name] = canonical(bad)
                with self.assertRaisesRegex(ValueError, message):
                    load_epoch(self.trust, "2")
                del self.objects[name]
        publish(self.trust, document)

    def test_unapproved_roster_or_insufficient_acknowledgements_never_commits(self):
        document = self.sign(self.document(1))
        document["acknowledgements"].pop()
        with self.assertRaisesRegex(ValueError, "signing quorum"):
            publish(self.trust, document)
        document = self.sign(self.document(1))
        roster = document["authorization"]["manifest"]["custodians"]
        roster[0]["retirementRole"] += "2"
        with self.assertRaisesRegex(ValueError, "approval signature"):
            publish(self.trust, document)
        roster[0] = roster[1]
        with self.assertRaisesRegex(ValueError, "distinct accounts"):
            publish(self.trust, self.sign(document))
        self.assertEqual(self.objects, {})

    def test_approval_rotation_keeps_old_receipts_verifiable_but_cannot_approve_new_epochs(self):
        publish(self.trust, self.sign(self.document(1)))
        self.rotate_approvals("2")
        _, previous, _ = load_epoch(self.trust, "1")
        draft, _ = self.rotation_document(previous)
        with self.assertRaisesRegex(ValueError, "invalid or duplicate approval"):
            publish(self.trust, self.sign(draft, approval_keys(self.trust, "1")))
        publish(self.trust, self.sign(draft))
        self.assertEqual(load_epoch(self.trust, "1")[1], previous)
        self.assertEqual(load_epoch(self.trust, "2")[1]["custody"]["epoch"], "2")

    def test_custody_approval_keys_cannot_also_acknowledge_shares(self):
        document = self.document(1)
        member = document["authorization"]["manifest"]["custodians"][0]["acknowledgementKey"]
        original = self.trust["approvalKeys"][0]["keys"][0]
        for reused in (member, {**original, "publicKey": member["publicKey"]}):
            self.trust["approvalKeys"][0]["keys"][0] = reused
            with self.subTest(reused=reused["keyArn"]), self.assertRaisesRegex(ValueError, "separate signing keys"):
                record(self.trust, document)

        self.trust["approvalKeys"][0]["keys"][0] = original
        publish(self.trust, self.sign(document))
        rotated, target = self.rotation_document(load_epoch(self.trust, "1")[1], register=False)
        member = rotated["authorization"]["manifest"]["custodians"][0]["acknowledgementKey"]
        self.trust["approvalKeys"].append({
            "fromEpoch": "2", "activeFrom": self.now + 60, "keys": [member, pin(key(9, 9)), pin(key(10, 9))],
        })
        with self.assertRaisesRegex(ValueError, "separate signing keys"):
            register_target(self.trust, target)

    def test_archive_verifies_rotation_history_under_the_historical_rosters(self):
        first = self.sign(self.document(1))
        publish(self.trust, first)
        self.rotate_approvals("2")
        second, approval = self.rotation_document(record(self.trust, first)[0])
        publish(self.trust, self.sign(second))
        output = BytesIO()
        archive(self.trust, "2", output)
        payload = output.getvalue()
        self.now = approval["manifest"]["expiresAt"] + 1
        self.rotate_approvals("3")
        entries = [json.loads(line) for line in payload.splitlines()]

        def verify(payload, *, epoch="2", pin=None):
            digest = hashlib.sha256(payload).hexdigest()
            return verify_archive(self.trust, epoch, BytesIO(payload), pin or digest)

        def encode(entries):
            return b"".join(canonical(entry) + b"\n" for entry in entries)

        with (patch("custody_ledger.aws", side_effect=AssertionError("archive must verify offline")),
              patch("custody_archive.verify_ceremony_capture") as evidence):
            self.assertEqual(verify(payload), record(self.trust, second)[0])
            self.assertEqual([call.args[0] for call in evidence.call_args_list],
                             [document["authorization"]["manifest"]["capture"] for document in (first, second)])
            with self.assertRaisesRegex(ValueError, "pinned custody archive digest"):
                verify(payload, pin="ff" * 32)
            with self.assertRaisesRegex(ValueError, "pinned custody archive digest"):
                verify(payload, epoch="1")
            with self.assertRaisesRegex(ValueError, "missing or oversized"):
                verify(encode(entries[:1]))
            with self.assertRaisesRegex(ValueError, "missing or oversized"):
                verify(b"x" * (MAX_ARCHIVE_ENTRY_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "consecutive"):
                verify(encode(entries[::-1]))

            changed = copy.deepcopy(entries)
            changed[1]["rotation"]["publishedAt"] = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
            with self.assertRaisesRegex(ValueError, "approval has expired"):
                verify(encode(changed))
            changed = copy.deepcopy(entries)
            changed[1]["rotation"]["approval"]["signatures"].pop()
            with self.assertRaisesRegex(ValueError, "signing quorum"):
                verify(encode(changed))

            changed = copy.deepcopy(entries)
            changed[0]["document"] = self.sign(self.document(1, variant="cd"))
            with self.assertRaisesRegex(ValueError, "canonical previous receipt"):
                verify(encode(changed))
            changed = copy.deepcopy(entries)
            changed[0]["document"]["acknowledgements"][0]["signature"] = first["authorization"]["signatures"][0]["signature"]
            with self.assertRaisesRegex(ValueError, "invalid custody approval signature"):
                verify(encode(changed))
            evidence.side_effect = ValueError("invalid ceremony evidence")
            with self.assertRaisesRegex(ValueError, "invalid ceremony evidence"):
                verify(payload)

    def test_ledger_checkpoint_requires_every_original_record_and_s3_version(self):
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        rotated, rotation = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        replacement = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, replacement))
        with (patch("retirement.qualified_policy", return_value=self.qualification(replacement)),
              patch("retirement.require_recovery_quorum")):
            marker = qualified_manifest(self.trust, None, "1", "2")
            commit_retirement(self.trust, None, self.signed_retirement(marker))

        self.bucket_policy = ledger_policy(self.trust, ADMIN, PUBLISHER, [READ_ROLE], frozen=True)
        pinned = ledger_checkpoint(self.trust)
        self.now = max(marker["recoveryDeadline"], rotation["manifest"]["expiresAt"]) + 1
        prefix = f"spr-custody/devnet/{DOMAIN}/"
        target = prefix + target_object_name(replacement)
        retired = prefix + "retired/1.json"
        changed_time = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
        replica = {**self.trust, "ledger": {"bucket": "custody-recovery", "account": "000000000010", "region": "eu-west-1"}}
        replica_policy = ledger_policy(replica, ADMIN.replace("000000000008", "000000000010"),
                                       PUBLISHER.replace("000000000008", "000000000010"), [READ_ROLE], frozen=True)

        def replica_aws(region, service, operation, args, **options):
            self.assertEqual(region, "eu-west-1")
            self.assertEqual(args[:4], ["--bucket", "custody-recovery", "--expected-bucket-owner", "000000000010"])
            if operation == "get-bucket-policy":
                return {"Policy": canonical(replica_policy).decode()}
            original = ["--bucket", "custody-journal", "--expected-bucket-owner", "000000000008", *args[4:]]
            reply = self.aws("eu-north-1", service, operation, original, **options)
            return {**reply, "Name": "custody-recovery"} if operation == "list-objects-v2" else reply

        with patch("custody_ledger.aws", side_effect=replica_aws):
            self.assertEqual(ledger_checkpoint(replica, pinned), pinned)
            with self.assertRaisesRegex(ValueError, "custody epoch is retired"):
                require_active_epoch(replica, "1")

        for objects in (
            {name: body for name, body in self.objects.items() if name != retired},
            {name: body for name, body in self.objects.items() if name != target},
            {**self.objects, prefix + "3.json": self.objects[prefix + "2.json"]},
            {**self.objects, target: self.objects[target] + b" "},
        ):
            with patch.dict(self.objects, objects, clear=True):
                with self.assertRaisesRegex(ValueError, "differs from the independently pinned checkpoint"):
                    ledger_checkpoint(self.trust, pinned)
        with patch.dict(self.timestamps, {target: changed_time}):
            with self.assertRaisesRegex(ValueError, "independently pinned checkpoint"):
                ledger_checkpoint(self.trust, pinned)
        with patch.dict(self.versions, {target: "copy-version"}):
            with self.assertRaisesRegex(ValueError, "independently pinned checkpoint"):
                ledger_checkpoint(self.trust, pinned)
        with patch.dict(self.versions, {target: "null"}):
            with self.assertRaisesRegex(ValueError, "requires an original S3 version"):
                ledger_checkpoint(self.trust, pinned)

        names = [name.removeprefix(prefix) for name in sorted(self.objects)]
        with patch("custody_archive.list_objects", side_effect=[iter(names), iter(names[:-1])]):
            with self.assertRaisesRegex(ValueError, "changed during checkpoint"):
                ledger_checkpoint(self.trust, pinned)

    def test_ledger_checkpoint_requires_the_frozen_policy_before_and_after_reading(self):
        publish(self.trust, self.sign(self.document(1)))
        live = self.bucket_policy
        frozen = ledger_policy(self.trust, ADMIN, PUBLISHER, [READ_ROLE], frozen=True)
        guarded, = [rule for rule in frozen["Statement"] if rule["Sid"] == "PreserveCustodyHistory"]
        self.assertEqual(guarded["Principal"], "*")
        self.assertEqual(guarded["Effect"], "Deny")
        self.assertIn("s3:PutObject", guarded["Action"])
        self.assertNotIn("Condition", guarded)
        with self.assertRaisesRegex(ValueError, "requires the frozen bucket policy"):
            ledger_checkpoint(self.trust)
        self.bucket_policy = frozen
        pinned = ledger_checkpoint(self.trust)
        weakened = {**frozen, "Statement": [
            {**rule, "Condition": {"StringNotEquals": {"aws:PrincipalArn": PUBLISHER}}} if rule is guarded else rule
            for rule in frozen["Statement"]
        ]}
        with patch.object(self, "bucket_policy", weakened):
            with self.assertRaisesRegex(ValueError, "requires the frozen bucket policy"):
                ledger_checkpoint(self.trust, pinned)
        with patch.object(self, "lifecycle", {"Rules": [{"Expiration": {"Days": 1}}]}):
            with self.assertRaisesRegex(ValueError, "no lifecycle configuration"):
                ledger_checkpoint(self.trust, pinned)
        with patch("custody_ledger.installed_ledger_policy", side_effect=[frozen, live]):
            with self.assertRaisesRegex(ValueError, "requires the frozen bucket policy"):
                ledger_checkpoint(self.trust, pinned)

    def test_retirement_inventory_requires_the_actual_replicas_of_its_dependencies(self):
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        replacement = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, replacement))
        original_target = {**replacement, "custodyEpoch": "1", "receiptSha256": sha256(old), "releaseId": "old-serving",
                           "instanceId": INSTANCE, "wrappingKeys": [key(slot, 31) for slot in range(1, 7)]}
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, original_target))
        with (patch("retirement.qualified_policy", return_value=self.qualification(replacement)),
              patch("retirement.require_recovery_quorum")):
            marker = qualified_manifest(self.trust, None, "1", "2")
            commit_retirement(self.trust, None, self.signed_retirement(marker))

        self.trust["ledgerReplica"] = {"bucket": "custody-recovery", "account": "000000000010", "region": "eu-west-1",
                                      "role": "arn:aws:iam::000000000008:role/replication"}
        prefix = f"spr-custody/devnet/{DOMAIN}/"
        source_status = {}
        copied = set()
        marker_key = prefix + "retired/1.json"
        replica_change = {}

        def aws(region, service, operation, args, **options):
            if region == "eu-north-1":
                reply = self.aws(region, service, operation, args, **options)
                if operation == "get-object":
                    name = args[args.index("--key") + 1]
                    reply["ReplicationStatus"] = source_status.get(name, "COMPLETED")
                return reply
            self.assertEqual((region, service, operation), ("eu-west-1", "s3api", "get-object"))
            self.assertEqual(args[:4], ["--bucket", "custody-recovery", "--expected-bucket-owner", "000000000010"])
            name = args[args.index("--key") + 1]
            copied.add(name)
            change = replica_change.copy() if name == marker_key else {}
            if change.pop("missing", False):
                raise ValueError("object missing")
            original = ["--bucket", "custody-journal", "--expected-bucket-owner", "000000000008", *args[4:]]
            reply = self.aws("eu-north-1", service, operation, original, **options)
            if "body" in change:
                pathlib.Path(args[-1]).write_bytes(change.pop("body"))
            return {**reply, "ReplicationStatus": "REPLICA", **change}

        with patch("custody_ledger.aws", side_effect=aws):
            _, _, keys = retirement_inventory(self.trust, "1", 1)
            self.assertIn(original_target["wrappingKeys"][0], keys)
            self.assertEqual(copied, set(self.objects))
            source_status[prefix + "1.json"] = "REPLICA"
            self.assertEqual(retirement_inventory(self.trust, "1", 1)[2], keys)
            for name in self.objects:
                with self.subTest(pending=name), patch.dict(source_status, {name: "PENDING"}):
                    with self.assertRaisesRegex(ValueError, "has not completed S3 replication"):
                        retirement_inventory(self.trust, "1", 1)
            changed_time = datetime.fromtimestamp(self.now + 1, timezone.utc).isoformat()
            for change in ({"VersionId": "new-version"}, {"LastModified": changed_time},
                           {"ReplicationStatus": "PENDING"}, {"body": b"{}"}):
                with self.subTest(change=change), patch.dict(replica_change, change):
                    with self.assertRaisesRegex(ValueError, "differs from the pinned replica"):
                        retirement_inventory(self.trust, "1", 1)
            with patch.dict(replica_change, {"missing": True}):
                with self.assertRaisesRegex(ValueError, "could not read.*retired/1.json from the pinned replica"):
                    retirement_inventory(self.trust, "1", 1)
            with (patch("retirement.check_recovery_bucket") as check_bucket,
                  patch("retirement.inspect_inventory", return_value={"keys": []}) as inspect,
                  patch("retirement.qualify_key_retirement", return_value={"boot": "replacement"})):
                wallet = pathlib.Path("wallet-trust.json")
                with self.assertRaisesRegex(ValueError, "provide --replica-profile"):
                    inspect_keys(self.trust, "1", 1, False, wallet_trust=wallet)
                check_bucket.side_effect = ValueError("custody ledger bucket must have no lifecycle configuration")
                with self.assertRaisesRegex(ValueError, "must have no lifecycle"):
                    inspect_keys(self.trust, "1", 1, False, wallet_trust=wallet, replica_profile="recovery-read")
                inspect.assert_not_called()
                check_bucket.side_effect = None
                result = inspect_keys(self.trust, "1", 1, False, wallet_trust=wallet, replica_profile="recovery-read")
                self.assertEqual(result, {"keys": [], "replacement": {"boot": "replacement"}})
                check_bucket.assert_called_with(self.trust, self.trust["ledgerReplica"], "recovery-read")
            source_status[marker_key] = "PENDING"
            with self.assertRaisesRegex(ValueError, "has not completed S3 replication"):
                verify_retired(self.trust, None, "1", [f"slot-{n}" for n in range(1, 7)], {}, 1)
            with self.assertRaisesRegex(ValueError, "custody epoch is retired"):
                require_active_epoch(self.trust, "1")

    def test_genesis_host_role_must_match_the_captured_identity_before_publication(self):
        document = self.document(1)
        document["authorization"]["manifest"]["capture"]["pcrs"]["3"] = "ef" * 48
        with self.assertRaisesRegex(ValueError, "genesis capture does not match the ceremony host role"):
            publish(self.trust, self.sign(document))
        self.capture_verifier.assert_not_called()
        self.assertEqual(self.objects, {})

    def test_publication_rechecks_ceremony_evidence_before_the_immutable_write(self):
        document = self.sign(self.document(1))
        capture = document["authorization"]["manifest"]["capture"]
        self.capture_verifier.side_effect = ValueError("unverified ceremony evidence")
        with self.assertRaisesRegex(ValueError, "unverified ceremony evidence"):
            publish(self.trust, document)
        self.capture_verifier.assert_called_once_with(capture)
        self.assertEqual(self.objects, {})
        self.capture_verifier.side_effect = None
        publish(self.trust, document)
        self.assertEqual(load_epoch(self.trust, "1")[0], document)

    @patch("custody_ledger.verify_reviewed_ceremony")
    @patch("custody_ledger.prove_share")
    @patch("custody_ledger.add_approval")
    @patch("custody_ledger.kms")
    def test_acknowledgement_requires_reviewed_ceremony_and_attested_share_proof(self, kms, approve, prove, review):
        document = self.sign(self.document(1))
        document["acknowledgements"] = []
        manifest = document["authorization"]["manifest"]
        member = manifest["custodians"][0]
        build, review_file = pathlib.Path("build"), pathlib.Path("ceremony-review.json")
        review.side_effect = ValueError("unreviewed ceremony")
        with self.assertRaisesRegex(ValueError, "unreviewed ceremony"):
            acknowledge(self.trust, document, 1, 7443, build, review_file)
        review.assert_called_once_with(manifest, None, build, review_file)
        kms.assert_not_called()
        prove.assert_not_called()
        approve.assert_not_called()
        review.side_effect = None
        kms.return_value = {"Policy": "{}"}
        with self.assertRaisesRegex(ValueError, "installed acknowledgement policy"):
            acknowledge(self.trust, document, 1, 7443, build, review_file)
        prove.assert_not_called()
        kms.return_value = {"Policy": json.dumps(acknowledgement_policy(member["custodianRole"], member["retirementRole"]))}
        prove.side_effect = ValueError("unverified relay proof")
        with self.assertRaisesRegex(ValueError, "unverified relay proof"):
            acknowledge(self.trust, document, 1, 7443, build, review_file)
        approve.assert_not_called()
        prove.side_effect = None
        approve.return_value = {"signatures": ["fixture"]}
        result = acknowledge(self.trust, document, 1, 7443, build, review_file)
        self.assertEqual(result["acknowledgements"], ["fixture"])
        _, args_receipt, args_member, slot, port, check = prove.call_args.args
        self.assertEqual(args_receipt["custody"]["epoch"], "1")
        self.assertEqual((args_member, slot, port), (member, 1, 7443))
        check()

    @patch("custody_ledger.kms")
    @patch("custody_ledger.get_signing_key")
    @patch("custody_ledger.sealed_rsa_key")
    @patch("custody_ledger.verify_relay_build")
    @patch("custody_ledger.require_profile_account")
    def test_custody_approval_checks_the_relay_and_both_installed_keys_per_slot(self, identity, provenance, inspect, signing, kms):
        roster = self.document(1)["authorization"]["manifest"]["custodians"]
        keys = [bytes([i]) * 264 for i in range(1, 7)]
        fingerprints = [hashlib.sha256(key).hexdigest() for key in keys]
        with self.assertRaisesRegex(ValueError, "six distinct read-only inspection profiles"):
            check_custody_roster(self.trust, "1", roster, fingerprints, ["same"] * 6)
        inspect.assert_not_called()
        profiles = [f"slot-{i}-inspect" for i in range(1, 7)]
        with self.assertRaisesRegex(ValueError, "recovery relay build and independent review"):
            check_custody_roster(self.trust, "1", roster, fingerprints, profiles)
        reviewed = (pathlib.Path("relay-build"), pathlib.Path("relay-review.json"))
        provenance.side_effect = ValueError("unreviewed relay build")
        with self.assertRaisesRegex(ValueError, "unreviewed relay build"):
            check_custody_roster(self.trust, "1", roster, fingerprints, profiles, reviewed)
        inspect.assert_not_called()
        provenance.side_effect = None
        identity.side_effect = ValueError("inspection profile is in the wrong account")
        with self.assertRaisesRegex(ValueError, "wrong account"):
            check_custody_roster(self.trust, "1", roster, fingerprints, profiles, reviewed)
        inspect.assert_not_called()
        identity.side_effect = None
        acknowledgements = {member["acknowledgementKey"]["keyArn"]: member for member in roster}

        def checked_member(key, profile):
            member = acknowledgements[key]
            self.assertEqual(profile, profiles[roster.index(member)])
            return member

        def signing_pin(key, *, profile):
            return checked_member(key, profile)["acknowledgementKey"]

        def policy(key, operation, args, *, profile):
            member = checked_member(key, profile)
            self.assertEqual((operation, args), ("get-key-policy", ["--policy-name", "default"]))
            return {"Policy": json.dumps(acknowledgement_policy(member["custodianRole"], member["retirementRole"]))}

        signing.side_effect = signing_pin
        kms.side_effect = policy
        inspect.side_effect = keys[:-1] + [ValueError("unsealed source key")]
        with self.assertRaisesRegex(ValueError, "unsealed source key"):
            check_custody_roster(self.trust, "1", roster, fingerprints, profiles, reviewed)
        inspect.side_effect = keys
        signing.side_effect = lambda key, profile: {**signing_pin(key, profile=profile), "publicKey": "wrong"}
        with self.assertRaisesRegex(ValueError, "acknowledgement public key"):
            check_custody_roster(self.trust, "1", roster, fingerprints, profiles, reviewed)

        inspect.side_effect = keys
        signing.side_effect = signing_pin
        kms.side_effect = lambda *_args, **_options: {"Policy": "{}"}
        with self.assertRaisesRegex(ValueError, "installed acknowledgement policy"):
            check_custody_roster(self.trust, "1", roster, fingerprints, profiles, reviewed)

        inspect.reset_mock()
        kms.reset_mock()
        identity.reset_mock()
        inspect.side_effect = keys
        kms.side_effect = policy
        check_custody_roster(self.trust, "1", roster, fingerprints, profiles, reviewed)
        provenance.assert_called_with(self.trust, "1", *reviewed)
        self.assertEqual([call.args for call in identity.call_args_list],
                         [(profile, REGION, f"{slot:012d}") for slot, profile in enumerate(profiles, 1)])
        self.assertEqual([call.kwargs["profile"] for call in inspect.call_args_list], profiles)
        self.assertEqual([call.args[0] for call in inspect.call_args_list], [member["recoveryKeyArn"] for member in roster])
        self.assertEqual([call.args[0] for call in kms.call_args_list], list(acknowledgements))

    def test_bucket_policy_enforces_single_publisher_and_conditional_creation(self):
        statements = {item["Sid"]: item for item in ledger_policy(self.trust, ADMIN, PUBLISHER, [READ_ROLE])["Statement"]}
        self.assertEqual(statements["RequireWriteOnce"]["Condition"], {"StringNotEquals": {"s3:if-none-match": "*"}})
        self.assertEqual(statements["RequireWriteOnce"]["Principal"], "*")
        self.assertEqual(statements["RestrictPublisher"]["Condition"], {"StringNotEquals": {"aws:PrincipalArn": PUBLISHER}})
        self.assertIn("s3:DeleteObject", statements["PreserveCustodyHistory"]["Action"])
        readers = ledger_reader_policy(self.trust)["Statement"]
        for statement in readers:
            self.assertEqual(statements[statement["Sid"]], {**statement, "Principal": {"AWS": [READ_ROLE, PUBLISHER]}})
        self.assertEqual(readers[0]["Resource"], f"arn:aws:s3:::custody-journal/spr-custody/devnet/{DOMAIN}/*")
        self.assertEqual(readers[1]["Condition"], {
            "StringLike": {"s3:prefix": [f"spr-custody/devnet/{DOMAIN}/",
                                        f"spr-custody/devnet/{DOMAIN}/targets/*",
                                        f"spr-custody/devnet/{DOMAIN}/retired/*"]},
        })
        guard = statements["RestrictBucketAdministration"]
        self.assertEqual(guard["Resource"], "arn:aws:s3:::custody-journal")
        self.assertEqual(guard["Effect"], "Deny")
        self.assertEqual(guard["Principal"], "*")
        self.assertEqual(guard["Condition"], {"StringNotEquals": {"aws:PrincipalArn": ADMIN}})
        self.assertTrue({"s3:PutBucketPolicy", "s3:PutBucketVersioning", "s3:PutLifecycleConfiguration",
                         "s3:PutReplicationConfiguration"}.issubset(guard["Action"]))
        for name in ("RestrictRecordReads", "RestrictBucketListing"):
            self.assertEqual(statements[name]["Condition"], {
                "StringNotEquals": {"aws:PrincipalArn": [ADMIN, READ_ROLE, PUBLISHER]},
            })
        for administrator, readers in ((PUBLISHER, [READ_ROLE]), (READ_ROLE, [READ_ROLE]), (ADMIN, [ADMIN])):
            with self.assertRaisesRegex(ValueError, "administrator must be a separate role"):
                ledger_policy(self.trust, administrator, PUBLISHER, readers)

    def test_installed_ledger_requires_each_control_on_the_pinned_bucket(self):
        expected = ledger_policy(self.trust, ADMIN, PUBLISHER, [READ_ROLE])
        responses = {
            "get-bucket-policy": {"Policy": json.dumps(expected)},
            "get-bucket-versioning": {"Status": "Enabled"},
            "get-bucket-ownership-controls": {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}},
            "get-public-access-block": {"PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            }},
            "get-bucket-lifecycle-configuration": None,
            "get-bucket-replication": None,
        }
        errors = {
            "get-bucket-lifecycle-configuration": "NoSuchLifecycleConfiguration",
            "get-bucket-replication": "ReplicationConfigurationNotFoundError",
        }
        bucket = ["--bucket", "custody-journal", "--expected-bucket-owner", "000000000008"]
        with patch("custody_ledger.aws", side_effect=lambda _region, _service, operation, _args, **_options: responses[operation]) as aws:
            check_installed_ledger(self.trust, expected)
            self.assertEqual(aws.call_args_list, [
                call("eu-north-1", "s3api", operation, bucket, **({"absent": errors[operation]} if operation in errors else {}))
                for operation in responses
            ])

            drift = [
                ("get-bucket-policy", {"Policy": "{}"}, "policy differs"),
                ("get-bucket-versioning", {"Status": "Suspended"}, "requires versioning"),
                ("get-bucket-ownership-controls", {"OwnershipControls": {"Rules": [{"ObjectOwnership": "ObjectWriter"}]}},
                 "bucket-owner-enforced"),
                ("get-public-access-block", {"PublicAccessBlockConfiguration": {}}, "public access blocks"),
                ("get-bucket-lifecycle-configuration", {"Rules": [{"Expiration": {"Days": 1}}]}, "no lifecycle"),
                ("get-bucket-replication", {"ReplicationConfiguration": {"Rules": []}}, "no replication"),
            ]
            for operation, value, message in drift:
                with self.subTest(operation=operation), patch.dict(responses, {operation: value}):
                    with self.assertRaisesRegex(ValueError, message):
                        check_installed_ledger(self.trust, expected)

    def signed_subject(self, label, manifest):
        return {"manifest": manifest, "signatures": [sign(label, manifest, member["keyArn"])
                                                    for member in approval_keys(self.trust)[:2]]}

    def qualification(self, target, policy_digest="fe" * 32):
        return {"walletPolicyDigest": policy_digest, "replacementTargetIdentity": sha256(target_attestation(target)),
                "replacementTargetSha256": sha256(target),
                "replacementBootstrap": {"bootKeyId": "de" * 32, "bootedAtMs": str(self.booted_at_ms), "slots": [1, 2, 3]}}

    def signed_retirement(self, manifest, slots=(1, 2, 3)):
        result = self.signed_subject(RETIREMENT, manifest)
        _, _, roster = load_epoch(self.trust, manifest["replacementEpoch"])
        result["recoveryProofs"] = [sign(RETIREMENT_RECOVERY, manifest, roster[index - 1]["acknowledgementKey"]["keyArn"])
                                    for index in slots]
        return result

    def replacement_target(self, **overrides):
        _, receipt, _ = load_epoch(self.trust, "2")
        return {"network": "devnet", "securityDomainId": DOMAIN, "custodyEpoch": "2",
                "receiptSha256": sha256(receipt), "approvalFromEpoch": approval_roster(self.trust)["fromEpoch"],
                "releaseId": "new-slot", "mode": "serve", "hostRole": HOST, "expiresAt": self.now + 3600,
                "hostRegion": REGION, "instanceId": "i-1234567890abcdef1",
                "executableSha256": "ab" * 32, "configurationSha256": "bc" * 32, "eifSha256": "cd" * 32,
                "nextCustodians": None, "nextRelay": None, "wrappingKeys": [key(i, 22) for i in range(1, 7)],
                "pcrs": {f"PCR{i}": f"{i+1:02x}" * 48 for i in range(3)}, **overrides}

    def test_wallet_activation_requires_each_target_registered_for_the_current_receipt(self):
        publish(self.trust, self.sign(self.document(1)))
        _, previous, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(previous)
        publish(self.trust, self.sign(rotated))
        _, replacement, _ = load_epoch(self.trust, "2")
        registered = self.replacement_target(expiresAt=self.now + 60)
        replica = {**target_attestation(registered), "custodyEpoch": "2",
                   "executableSha256": registered["executableSha256"], "custodyDigest": sha256(replacement["custody"])}
        policy = {"action": "activate", "recoveryOnly": False, "network": "devnet", "securityDomainId": DOMAIN,
                  "noteSeedCommitment": replacement["custody"]["noteSeedCommitment"], "minimumCustodyEpoch": "2",
                  "targets": [replica]}

        def check(custody_signer=None, **overrides):
            return check_serving_policy(self.trust, {"policy": {**policy, **overrides}, "signatures": [],
                                                    "custodySignatures": []}, custody_signer)

        with self.assertRaisesRegex(ValueError, "object missing"):
            check()
        name = f"spr-custody/devnet/{DOMAIN}/{target_object_name(registered)}"
        roster = rotated["authorization"]["manifest"]["custodians"]
        rotation = {**registered, "mode": "rotate", "nextCustodians": roster, "nextRelay": self.trust["recoveryRelays"]["3"]}
        for subject, message in ((rotation, "custody-approved target"),
                                 ({**registered, "receiptSha256": "aa" * 32}, "committed custody receipt")):
            self.objects[name] = canonical(self.signed_subject(TARGET_APPROVAL, subject))
            with self.assertRaisesRegex(ValueError, message):
                check()
        self.objects[name] = canonical({"manifest": registered, "signatures": []})
        with self.assertRaisesRegex(ValueError, "signing quorum"):
            check()
        del self.objects[name]
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, registered))
        key_pin = approval_roster(self.trust)["keys"][0]
        signer = (key_pin["keyArn"], base64.b64decode(key_pin["publicKey"])[-65:].hex())
        check(custody_signer=signer, recoveryOnly=True)
        with self.assertRaisesRegex(ValueError, "expected a recoveryOnly boolean"):
            check(recoveryOnly="true")
        with self.assertRaisesRegex(ValueError, "active custody approval roster"):
            check(custody_signer=(signer[0], "04" + "00" * 64))
        # The wrap deadline can pass after a valid registration.
        self.now = registered["expiresAt"]
        check()
        published_at = self.timestamps[name]
        self.timestamps[name] = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
        with self.assertRaisesRegex(ValueError, "target approval has expired"):
            check()
        self.timestamps[name] = published_at
        with self.assertRaisesRegex(ValueError, "committed note seed"):
            check(noteSeedCommitment="aa" * 32)
        for changes, message in (({"custodyDigest": "aa" * 32}, "committed custody record"),
                                 ({"executableSha256": "aa" * 32}, "custody-approved target"),
                                 ({"pcrs": {**replica["pcrs"], "3": "aa" * 48}}, "object missing"),
                                 ({"pcrs": {**replica["pcrs"], "4": "aa" * 48}}, "object missing"),
                                 ({"custodyEpoch": "1"}, "below the wallet custody floor")):
            with self.assertRaisesRegex(ValueError, message):
                check(targets=[replica, {**replica, **changes}])
        old = {**registered, "custodyEpoch": "1", "receiptSha256": sha256(previous), "releaseId": "old-slot",
               "expiresAt": self.now + 3600}
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, old))
        check(minimumCustodyEpoch="1", targets=[replica, {**replica, **target_attestation(old), "custodyEpoch": "1",
                                                          "custodyDigest": sha256(previous["custody"])}])
        incoming = schedule("3", 9, self.now + 60)
        self.trust["approvalKeys"].append(incoming)
        self.assertEqual(check(), {"custodyKeys": [base64.b64decode(pin["publicKey"])[-65:].hex()
                                                   for pin in self.trust["approvalKeys"][0]["keys"]],
                                   "nextCutover": str(incoming["activeFrom"])})
        self.now = incoming["activeFrom"]
        with self.assertRaisesRegex(ValueError, "active custody approval roster"):
            check(custody_signer=signer)
        next_pin = approval_roster(self.trust)["keys"][0]
        self.assertEqual(check(custody_signer=(next_pin["keyArn"], base64.b64decode(next_pin["publicKey"])[-65:].hex())),
                         {"custodyKeys": [base64.b64decode(pin["publicKey"])[-65:].hex() for pin in incoming["keys"]],
                          "nextCutover": None})
        def close_during_target_read(*args):
            subject = read_registered_target(*args)
            if subject["mode"] == "serve":
                self.objects[f"spr-custody/devnet/{DOMAIN}/retired/2.json"] = b"{}"
            return subject

        with patch("custody_ledger.read_registered_target", side_effect=close_during_target_read):
            with self.assertRaisesRegex(ValueError, "cannot verify retirement"):
                check()

    @patch("retirement.require_recovery_quorum")
    @patch("retirement.qualified_policy")
    def test_closing_an_epoch_freezes_share_release_and_preserves_the_full_key_inventory(self, qualification, _):
        first = self.sign(self.document(1))
        publish(self.trust, first)
        _, old, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        target = {
            "network": "devnet", "securityDomainId": DOMAIN, "custodyEpoch": "1", "receiptSha256": sha256(old),
            "approvalFromEpoch": "1", "releaseId": "old-slot", "hostRole": HOST, "expiresAt": self.now + 3600,
            "hostRegion": REGION, "instanceId": "i-1234567890abcdef2",
            "mode": "serve", "nextCustodians": None, "nextRelay": None,
            "executableSha256": "ab" * 32, "configurationSha256": "bc" * 32, "eifSha256": "cd" * 32,
            "wrappingKeys": [key(account, 11) for account in range(1, 7)],
            "pcrs": {f"PCR{i}": f"{i+1:02x}" * 48 for i in range(3)},
        }
        target_doc = self.signed_subject(TARGET_APPROVAL, target)
        with self.assertRaisesRegex(ValueError, "object missing"):
            require_registered_target(self.trust, target)
        register_target(self.trust, target_doc)
        require_registered_target(self.trust, target)

        replacement = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, replacement))
        qualification.return_value = self.qualification(replacement)
        marker = qualified_manifest(self.trust, None, "1", "2")
        retired = self.signed_retirement(marker)
        qualification.return_value = self.qualification(replacement, "cd" * 32)
        with self.assertRaisesRegex(ValueError, "no longer matches"):
            commit_retirement(self.trust, None, retired)
        require_registered_target(self.trust, target)
        qualification.return_value = self.qualification(replacement)
        concurrent = {**target, "releaseId": "other-slot", "wrappingKeys": [key(account, 12) for account in range(1, 7)]}

        def register_during_retirement(*args):
            write_once(*args)
            commit_retirement(self.trust, None, retired)

        with patch("deployment.write_once", side_effect=register_during_retirement):
            with self.assertRaisesRegex(ValueError, "retired"):
                register_target(self.trust, self.signed_subject(TARGET_APPROVAL, concurrent))
        with self.assertRaisesRegex(ValueError, "retired"):
            require_registered_target(self.trust, target)
        with self.assertRaisesRegex(ValueError, "retired"):
            register_target(self.trust, target_doc)
        with patch("custody_ledger.kms") as kms, patch("custody_ledger.verify_reviewed_ceremony"):
            with self.assertRaisesRegex(ValueError, "custody epoch is retired"):
                acknowledge(self.trust, first, 1, 7443, pathlib.Path("build"), pathlib.Path("ceremony-review.json"))
            kms.assert_not_called()

        self.rotate_approvals("3")
        _, role, inventory = retirement_inventory(self.trust, "1", 1)
        self.assertTrue(role.endswith(":role/retirement"))
        self.assertEqual(set(inventory), {key(1), key(1, 11), key(1, 12), key(1, 21)})

        states = {key(1): "PendingDeletion", key(1, 11): "Enabled", key(1, 12): "PendingDeletion", key(1, 21): "Disabled"}

        def describe(arn, operation, args=()):
            if operation == "get-key-policy":
                return {"Policy": json.dumps(inventory[arn])}
            return {"KeyMetadata": {"Arn": arn, "KeyState": states[arn]}}

        with patch("retirement.kms", side_effect=describe):
            with self.assertRaisesRegex(ValueError, "remains usable"):
                inspect_keys(self.trust, "1", 1, True)
            states[key(1, 11)] = "Disabled"
            self.assertEqual({row["state"] for row in inspect_keys(self.trust, "1", 1, True)["keys"]}, set(states.values()))

    @patch("retirement.require_recovery_quorum")
    @patch("retirement.qualified_policy")
    def test_unverified_retirement_halts_share_release_without_authorizing_key_retirement(self, qualification, _):
        wallet = pathlib.Path("wallet.json")
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        self.rotate_approvals("2")
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        path = f"spr-custody/devnet/{DOMAIN}/retired/1.json"
        self.objects[path] = b"{}"
        with self.assertRaisesRegex(ValueError, "cannot verify retirement record"):
            require_active_epoch(self.trust, "1")
        with patch("retirement.kms") as kms, self.assertRaises(ValueError):
            inspect_keys(self.trust, "1", 1, False, wallet_trust=wallet)
        kms.assert_not_called()

        replacement = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, replacement))
        qualification.return_value = self.qualification(replacement)
        marker = qualified_manifest(self.trust, None, "1", "2")
        wrong = self.signed_retirement({**marker, "replacementReceiptSha256": "ab" * 32})
        self.objects[path] = json.dumps(wrong).encode()
        with patch("retirement.kms") as kms, self.assertRaisesRegex(ValueError, "retirement receipts do not match the ledger"):
            inspect_keys(self.trust, "1", 1, False, wallet_trust=wallet)
        kms.assert_not_called()

        wrong = self.signed_retirement({**marker, "replacementTargetSha256": "ab" * 32})
        self.objects[path] = json.dumps(wrong).encode()
        with patch("retirement.kms") as kms, self.assertRaisesRegex(ValueError, "does not match the registered serving"):
            inspect_keys(self.trust, "1", 1, False, wallet_trust=wallet)
        kms.assert_not_called()

        self.objects[path] = json.dumps(self.signed_retirement(marker)).encode()
        stale = {**self.trust, "approvalKeys": self.trust["approvalKeys"][:1]}
        with self.assertRaisesRegex(ValueError, "cannot verify.*approval roster does not match"):
            require_active_epoch(stale, "1")
        with self.assertRaisesRegex(ValueError, "custody epoch is retired"):
            require_active_epoch(self.trust, "1")

    def test_pre_deletion_inspection_reattests_the_exact_replacement_and_proven_slots(self):
        publish(self.trust, self.sign(self.document(1)))
        rotated, _ = self.rotation_document(load_epoch(self.trust, "1")[1])
        publish(self.trust, self.sign(rotated))
        replacement = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, replacement))
        with (patch("retirement.qualified_policy", return_value=self.qualification(replacement)),
              patch("retirement.require_recovery_quorum")):
            marker = qualified_manifest(self.trust, None, "1", "2")
            commit_retirement(self.trust, None, self.signed_retirement(marker))

        self.now = marker["recoveryDeadline"] + 1
        directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        wallet = directory / "wallet.json"
        wallet.write_bytes(b"{}")
        self.trust["walletTrustSha256"] = hashlib.sha256(wallet.read_bytes()).hexdigest()
        boot = {**marker["replacementBootstrap"], "bootKeyId": "ae" * 32, "bootedAtMs": str(self.now * 1000)}
        observed = {**target_attestation(replacement), "bootstrap": boot}
        policy_digest = "bf" * 32
        expected = {**self.qualification(replacement, policy_digest), "replacementBootstrap": boot}

        def evidence(target):
            return json.dumps({"policyDigest": policy_digest, "targets": [target]}).encode()

        with (patch("retirement.inspect_inventory", side_effect=lambda *_args: {"keys": []}) as inspect,
              patch("retirement.require_recovery_quorum") as quorum, patch("retirement.run_command") as query):
            with self.assertRaisesRegex(ValueError, "provide --wallet-trust"):
                inspect_keys(self.trust, "1", 1, False)
            with self.assertRaisesRegex(ValueError, "mainnet key retirement requires a pinned custody ledger replica"):
                inspect_keys({**self.trust, "network": "mainnet"}, "1", 1, False, wallet_trust=wallet)
            inspect.assert_not_called()

            query.return_value.stdout = evidence(observed)
            self.assertEqual(inspect_keys(self.trust, "1", 1, False, wallet_trust=wallet)["replacement"], expected)
            self.assertEqual(query.call_args.kwargs["input"], b"{}")
            _, _, members = load_epoch(self.trust, "2")
            quorum.assert_called_once_with(self.trust, marker, [members[slot - 1] for slot in boot["slots"]])

            different_slots = [4, 5, 6] if boot["slots"] != [4, 5, 6] else [1, 2, 3]
            for other in (
                {**observed, "bootstrap": {**boot, "slots": different_slots}},
                {**observed, "bootstrap": marker["replacementBootstrap"]},
                {**observed, "pcrs": {**observed["pcrs"], "4": "ab" * 48}},
            ):
                query.return_value.stdout = evidence(other)
                with self.subTest(other=other), self.assertRaisesRegex(ValueError, "no fresh attested serving boot"):
                    inspect_keys(self.trust, "1", 1, False, wallet_trust=wallet)
            query.return_value.stdout = evidence(observed)
            with patch("retirement.require_active_epoch", side_effect=[None, ValueError("custody epoch is retired")]):
                with self.assertRaisesRegex(ValueError, "custody epoch is retired"):
                    inspect_keys(self.trust, "1", 1, False, wallet_trust=wallet)
            query.reset_mock()
            quorum.side_effect = ValueError("proven replacement key is unavailable")
            with self.assertRaisesRegex(ValueError, "replacement key is unavailable"):
                inspect_keys(self.trust, "1", 1, False, wallet_trust=wallet)
            query.assert_not_called()
            self.assertEqual(inspect_keys(self.trust, "1", 1, True), {"keys": []})
            query.assert_not_called()

    def test_retirement_qualifies_only_a_live_registered_serving_replica_on_a_new_parent(self):
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        scope, receipt, _ = retirement_scope(self.trust, "1", "2")
        seed = receipt["custody"]["noteSeedCommitment"]
        registered = self.replacement_target()
        pins = target_attestation(registered)["pcrs"]
        observed = {"releaseId": registered["releaseId"], "pcrs": pins,
                    "bootstrap": self.qualification(registered)["replacementBootstrap"]}
        evidence = {"policyDigest": "fe" * 32, "targets": [observed]}

        with tempfile.TemporaryDirectory() as directory:
            wallet_trust = pathlib.Path(directory) / "wallet.json"
            body = b'{"wallet":"trust fixture"}\n'
            wallet_trust.write_bytes(body)
            self.trust["walletTrustSha256"] = hashlib.sha256(body).hexdigest()
            with patch("retirement.run_command") as query:
                query.return_value.stdout = json.dumps(evidence).encode()
                with self.assertRaisesRegex(ValueError, "no registered serving target"):
                    qualified_policy(self.trust, wallet_trust, scope, seed)

                rotation = {**registered, "mode": "rotate", "pcrs": {**registered["pcrs"], "PCR2": "ef" * 48},
                            "nextCustodians": rotated["authorization"]["manifest"]["custodians"],
                            "nextRelay": self.trust["recoveryRelays"]["3"]}
                register_target(self.trust, self.signed_subject(TARGET_APPROVAL, rotation))
                same_parent = {**registered, "instanceId": INSTANCE, "wrappingKeys": [key(i, 23) for i in range(1, 7)]}
                register_target(self.trust, self.signed_subject(TARGET_APPROVAL, same_parent))
                with self.assertRaisesRegex(ValueError, "no registered serving target on a separate replacement instance"):
                    qualified_policy(self.trust, wallet_trust, scope, seed)
                query.assert_not_called()

                register_target(self.trust, self.signed_subject(TARGET_APPROVAL, registered))
                for pcr in ("3", "4"):
                    query.return_value.stdout = json.dumps({**evidence, "targets": [
                        {**observed, "pcrs": {**pins, pcr: "ab" * 48}},
                    ]}).encode()
                    with self.subTest(pcr=pcr), self.assertRaisesRegex(ValueError, "no fresh attested serving boot"):
                        qualified_policy(self.trust, wallet_trust, scope, seed)

                for slots in ([1, 2], [1, 1, 2], [1, 2, 7], [True, 2, 3], [3, 2, 1]):
                    bootstrap = {**observed["bootstrap"], "slots": slots}
                    query.return_value.stdout = json.dumps({**evidence, "targets": [{**observed, "bootstrap": bootstrap}]}).encode()
                    with self.assertRaisesRegex(ValueError, "three distinct attested bootstrap slots"):
                        qualified_policy(self.trust, wallet_trust, scope, seed)
                query.return_value.stdout = json.dumps(evidence).encode()
                self.assertEqual(qualified_policy(self.trust, wallet_trust, scope, seed), self.qualification(registered))
                with self.assertRaisesRegex(ValueError, "no fresh attested serving boot"):
                    qualified_policy(self.trust, wallet_trust, scope, seed, after_ms=self.booted_at_ms)
                with patch("retirement.time.time", return_value=self.now + RECOVERY_WINDOW_SECONDS):
                    with self.assertRaisesRegex(ValueError, "no fresh attested serving boot"):
                        qualified_policy(self.trust, wallet_trust, scope, seed)
                sibling = {**registered, "instanceId": "i-1234567890abcdef4", "wrappingKeys": [key(i, 24) for i in range(1, 7)]}
                register_target(self.trust, self.signed_subject(TARGET_APPROVAL, sibling))
                other = {**target_attestation(sibling), "bootstrap": observed["bootstrap"]}
                query.return_value.stdout = json.dumps({**evidence, "targets": [other, observed]}).encode()
                self.assertEqual(qualified_policy(self.trust, wallet_trust, scope, seed), self.qualification(sibling))
                self.assertEqual(qualified_policy(self.trust, wallet_trust, scope, seed, expected=self.qualification(registered)),
                                 self.qualification(registered))
                self.assertEqual(query.call_args.kwargs["input"], body)
                self.assertNotIn(str(wallet_trust), query.call_args.args[0])
                query.reset_mock()
                wallet_trust.write_bytes(b"{}")
                with self.assertRaisesRegex(ValueError, "does not match the pinned digest"):
                    qualified_policy(self.trust, wallet_trust, scope, seed)
                query.assert_not_called()

    def test_retirement_report_requires_all_old_keys_inactive_and_a_later_boot(self):
        publish(self.trust, self.sign(self.document(1)))
        rotated, _ = self.rotation_document(load_epoch(self.trust, "1")[1])
        publish(self.trust, self.sign(rotated))
        other_instance = "i-1234567890abcdef2"
        other_host = {**self.replacement_target(), "mode": "serve", "releaseId": "old-service", "custodyEpoch": "1",
                      "receiptSha256": sha256(load_epoch(self.trust, "1")[1]), "instanceId": other_instance,
                      "hostRole": "arn:aws:iam::000000000010:role/host", "hostRegion": "eu-west-1",
                      "wrappingKeys": [key(i, 31) for i in range(1, 7)]}
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, other_host))
        replacement = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, replacement))
        with (patch("retirement.qualified_policy", return_value=self.qualification(replacement)),
              patch("retirement.require_recovery_quorum")):
            marker = qualified_manifest(self.trust, None, "1", "2")
            retired = self.signed_retirement(marker)
            commit_retirement(self.trust, None, retired)

        profiles = [f"old-slot-{index}" for index in range(1, 7)]
        inventory = {arn: (profile, policy) for index, profile in enumerate(profiles, 1)
                     for arn, policy in retirement_inventory(self.trust, "1", index)[2].items()}
        host_profiles = {"000000000007": "old-rotation", "000000000010": "old-service"}
        active = key(6, 21)
        parents = [{"account": "000000000007", "region": REGION, "instanceId": INSTANCE, "state": "terminated"},
                   {"account": "000000000010", "region": "eu-west-1", "instanceId": other_instance, "state": "terminated"}]
        visited = []

        def require_host_state(manifest, state, profile):
            parent, = [item for item in parents if item["instanceId"] == manifest["instanceId"]]
            self.assertEqual((state, profile), ("terminated", host_profiles[parent["account"]]))
            return parent

        def kms(arn, operation, args=(), *, profile):
            expected_profile, policy = inventory[arn]
            self.assertEqual(profile, expected_profile)
            if operation == "get-key-policy":
                return {"Policy": json.dumps(policy)}
            self.assertEqual(operation, "describe-key")
            visited.append(arn)
            return {"KeyMetadata": {"Arn": arn, "KeyState": "Enabled" if arn == active else "PendingDeletion"}}

        boot = self.qualification(replacement)["replacementBootstrap"]
        observed = {**target_attestation(replacement), "bootstrap": boot}
        stale = json.dumps({"policyDigest": "fe" * 32, "targets": [observed]}).encode()
        fresh = {**boot, "bootKeyId": "be" * 32, "bootedAtMs": str(self.booted_at_ms + 1_000)}
        ready = json.dumps({"policyDigest": "fe" * 32, "targets": [{**observed, "bootstrap": fresh}]}).encode()

        wallet = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory())) / "wallet.json"
        wallet.write_bytes(b"{}")
        self.trust["walletTrustSha256"] = hashlib.sha256(wallet.read_bytes()).hexdigest()
        with (patch("retirement.kms", side_effect=kms),
              patch("retirement.require_profile_account") as identity,
              patch("retirement.run_command") as query, patch("retirement.time.sleep"),
              patch("retirement.require_host_state", side_effect=require_host_state) as host_state,
              patch("retirement.require_recovery_quorum") as quorum):
            identity.side_effect = ValueError("inspection profile is in the wrong account")
            with self.assertRaisesRegex(ValueError, "wrong account"):
                verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5)
            self.assertEqual(visited, [])
            host_state.assert_not_called()
            identity.side_effect = None
            with self.assertRaisesRegex(ValueError, active):
                verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5)
            query.assert_not_called()
            active = None
            with self.assertRaisesRegex(ValueError, "provide one host inspection profile"):
                verify_retired(self.trust, wallet, "1", profiles, {"000000000007": "old-rotation"}, 5)
            with patch("retirement.require_host_state", side_effect=ValueError("old parent remains running")):
                with self.assertRaisesRegex(ValueError, "old parent remains running"):
                    verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5)
            query.assert_not_called()
            visited.clear()
            with patch("retirement.time.monotonic", side_effect=[0, 0, 6, 6]):
                query.return_value.stdout = ready
                with self.assertRaisesRegex(ValueError, "no replacement boot observed"):
                    verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5)
                self.assertEqual(query.call_args.kwargs["timeout"], 5)
            quorum.assert_not_called()
            for changed in ({"policyDigest": "ad" * 32, "targets": [{**observed, "bootstrap": fresh}]},
                            {"policyDigest": "fe" * 32, "targets": [{**observed, "bootstrap": {**fresh, "bootKeyId": "da" * 32}}]}):
                with self.subTest(changed=changed):
                    query.side_effect = [SimpleNamespace(stdout=body) for body in (ready, json.dumps(changed).encode())]
                    with self.assertRaisesRegex(ValueError, "no fresh attested serving boot"):
                        verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5)
            visited.clear()
            host_state.reset_mock()
            identity.reset_mock()
            query.reset_mock()
            quorum.reset_mock()

            def attest(*_args, **_options):
                self.assertEqual(registrations.call_count, 2 if query.call_count == 3 else 1)
                if query.call_count == 3:
                    self.assertEqual(host_state.call_count, 4)
                    self.assertEqual(len(visited), 2 * len(inventory))
                return SimpleNamespace(stdout=stale if query.call_count == 1 else ready)

            query.side_effect = attest
            with patch("retirement.replacement_targets", wraps=replacement_targets) as registrations:
                report = verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5)
            self.assertEqual(query.call_count, 3)
            self.assertEqual(set(inventory), set(visited))
            self.assertEqual(len(visited), 2 * len(inventory))
            self.assertEqual(report["retirementSha256"], sha256(retired))
            self.assertEqual(report["retirementObservedAtMs"], str(self.booted_at_ms))
            self.assertEqual({call.args for call in identity.call_args_list},
                             {(profile, REGION, f"{slot:012d}") for slot, profile in enumerate(profiles, 1)} |
                             {(host_profiles[parent["account"]], parent["region"], parent["account"]) for parent in parents})
            self.assertEqual(report["terminatedParents"], parents)
            self.assertEqual(host_state.call_count, 4)
            host_state.assert_called_with(other_host, "terminated", "old-service")
            self.assertEqual(report["replacement"]["replacementBootstrap"], fresh)
            self.assertEqual({row["keyArn"] for slot in report["slots"] for row in slot["keys"]}, set(inventory))
            quorum.assert_called_once()

    def test_retirement_cli_publishes_the_completed_report_without_overwriting(self):
        directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        trust, wallet, report = (directory / name for name in ("trust.json", "wallet.json", "report.json"))
        trust.write_bytes(canonical(self.trust))
        profiles = [f"slot-{index}" for index in range(1, 7)]
        argv = ["retirement.py", str(trust), "verify-retired", str(wallet), "1",
                "--inspection-profiles", *profiles, "--output", str(report)]
        result = {"retirementObservedAtMs": "100"}

        def verify(*_args):
            self.assertFalse(report.exists())
            return result

        with patch("sys.argv", argv), patch("retirement.verify_retired", side_effect=verify) as verify_retired:
            retirement_main()
            verify_retired.assert_called_once_with(self.trust, wallet, "1", profiles, {}, 300)
            self.assertEqual(report.read_bytes(), canonical(result) + b"\n")
            with self.assertRaisesRegex(SystemExit, "retirement report already exists"):
                retirement_main()
            verify_retired.assert_called_once()
            self.assertEqual(report.read_bytes(), canonical(result) + b"\n")

            concurrent = report.with_name("concurrent.json")
            argv[-1] = str(concurrent)

            def concurrent_writer(*_args):
                concurrent.write_bytes(b"another operator's report")
                return result

            verify_retired.side_effect = concurrent_writer
            with self.assertRaises(SystemExit):
                retirement_main()
            self.assertEqual(concurrent.read_bytes(), b"another operator's report")

    def test_one_wrapping_set_per_attested_identity_and_reauthorizing_keeps_the_registration(self):
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        original = self.replacement_target(expiresAt=self.now + 60, wrappingKeys=[key(i, 3) for i in range(1, 7)])
        changed = {**original, "wrappingKeys": [key(i, 4) for i in range(1, 7)]}
        self.assertEqual(target_object_name(original), target_object_name(changed))
        with ThreadPoolExecutor(max_workers=2) as workers:
            pending = [workers.submit(register_target, self.trust, self.signed_subject(TARGET_APPROVAL, value))
                       for value in (original, changed)]
        self.assertEqual(sum(task.exception() is None for task in pending), 1)
        winner = original if pending[0].exception() is None else changed
        loser = changed if winner is original else original
        with self.assertRaisesRegex(ValueError, "does not match"):
            require_registered_target(self.trust, loser)

        self.rotate_approvals("3")
        renewed = {**winner, "expiresAt": self.now + 60, "approvalFromEpoch": "3"}
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, renewed))
        require_registered_target(self.trust, renewed)
        sibling = {**renewed, "instanceId": "i-1234567890abcdef3", "wrappingKeys": [key(i, 5) for i in range(1, 7)]}
        self.assertNotEqual(target_object_name(renewed), target_object_name(sibling))
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, sibling))
        require_registered_target(self.trust, sibling)
        self.assertEqual(len([name for name in self.objects if "/targets/2/" in name]), 2)

    def test_target_registration_refuses_a_deadline_inside_the_write_budget(self):
        publish(self.trust, self.sign(self.document(1)))
        draft, _ = self.rotation_document(load_epoch(self.trust, "1")[1])
        publish(self.trust, self.sign(draft))
        candidate = self.replacement_target(expiresAt=self.now + 30)
        approval = self.signed_subject(TARGET_APPROVAL, candidate)
        with patch("deployment.write_once") as write:
            with self.assertRaisesRegex(ValueError, "target approval deadline is too close"):
                register_target(self.trust, approval)
            write.assert_not_called()

    def test_target_registration_checks_domain_and_committed_receipt_before_writing(self):
        publish(self.trust, self.sign(self.document(1)))
        draft, _ = self.rotation_document(load_epoch(self.trust, "1")[1])
        publish(self.trust, self.sign(draft))
        target = self.replacement_target()
        for change, problem in (
            ({"securityDomainId": "98" * 32}, "pinned custody domain"),
            ({"network": "mainnet"}, "pinned custody domain"),
            ({"receiptSha256": "98" * 32}, "committed custody receipt"),
        ):
            approval = self.signed_subject(TARGET_APPROVAL, {**target, **change})
            with self.subTest(change=change), patch("deployment.write_once") as write:
                with self.assertRaisesRegex(ValueError, problem):
                    register_target(self.trust, approval)
                write.assert_not_called()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, target))
        require_registered_target(self.trust, target)

    def test_target_registration_uses_the_roster_active_at_s3_publication(self):
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        existing = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, existing))

        cutoff = self.now + 60
        self.trust["approvalKeys"].append(schedule("3", 9, cutoff))
        candidate = {**existing, "releaseId": "new-roster", "approvalFromEpoch": "3"}
        future = {"manifest": candidate, "signatures": [
            sign(TARGET_APPROVAL, candidate, member["keyArn"]) for member in approval_keys(self.trust, "3")[:2]
        ]}
        with self.assertRaisesRegex(ValueError, "approval roster does not match"):
            register_target(self.trust, future)

        old_target = {**existing, "releaseId": "late-old-roster"}
        old_approval = self.signed_subject(TARGET_APPROVAL, old_target)
        self.now = cutoff - 10
        with self.assertRaisesRegex(ValueError, "cutover is too close"):
            register_target(self.trust, old_approval)

        self.now = cutoff
        require_registered_target(self.trust, existing)
        name = target_object_name(old_target)
        with self.assertRaisesRegex(ValueError, "approval roster does not match"):
            register_target(self.trust, old_approval)
        path = f"spr-custody/devnet/{DOMAIN}/{name}"
        self.objects[path] = canonical(old_approval)
        self.timestamps[path] = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
        with self.assertRaisesRegex(ValueError, "approval roster does not match its publication time"):
            read_registered_target(self.trust, name, "2", old_target["receiptSha256"])
        register_target(self.trust, future)
        require_registered_target(self.trust, candidate)

    def test_approval_schedule_rejects_ambiguous_activation_times(self):
        for entries in (
            [schedule(active_from=1)],
            [schedule(), schedule("2", 9, 0)],
            [schedule(), schedule("2", 9, True)],
            [schedule(), schedule("2", 9, "60")],
            [schedule(), schedule("2", 9, 2**53)],
        ):
            with self.subTest(times=[entry["activeFrom"] for entry in entries]):
                with self.assertRaisesRegex(ValueError, "activation times"):
                    approval_roster({**self.trust, "approvalKeys": entries})

    @patch("retirement.qualified_policy")
    def test_retirement_requires_the_recovery_and_wrapping_keys_for_the_three_bootstrap_slots(self, qualification):
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        _, _, custodians = load_epoch(self.trust, "2")
        replacement = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, replacement))
        recovery_keys = [item["recoveryKeyArn"] for item in custodians]
        wrapping_keys = replacement["wrappingKeys"]
        proven = {*recovery_keys[:3], *wrapping_keys[:3]}
        states = dict.fromkeys(proven, "Enabled")
        states[recovery_keys[2]] = "Disabled"
        inspected = set()

        def describe(arn, operation):
            self.assertEqual(operation, "describe-key")
            inspected.add(arn)
            state = states[arn]
            return {"KeyMetadata": {"Arn": arn if state != "foreign" else key(99), "Origin": "AWS_KMS", "MultiRegion": False,
                                    "KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "RSA_2048",
                                    "KeyState": "Enabled" if state == "foreign" else state}}

        with patch("retirement.kms", side_effect=describe):
            qualification.return_value = self.qualification(replacement)
            marker = qualified_manifest(self.trust, None, "1", "2")
            retirement = self.signed_retirement(marker)
            with self.assertRaisesRegex(ValueError, recovery_keys[2]):
                commit_retirement(self.trust, None, retirement)
            self.assertIn(recovery_keys[2], inspected)
            states[recovery_keys[2]] = "Enabled"
            inspected.clear()
            with patch("retirement.add_approval", return_value={"signatures": retirement["signatures"]}):
                self.assertEqual(sign_retirement(self.trust, None, {**retirement, "signatures": []},
                                                 approval_keys(self.trust)[0]["keyArn"]), retirement)
            self.assertEqual(inspected, proven)
            states[wrapping_keys[1]] = "PendingDeletion"
            with self.assertRaisesRegex(ValueError, wrapping_keys[1]):
                commit_retirement(self.trust, None, retirement)
            states[wrapping_keys[1]] = "foreign"
            with self.assertRaisesRegex(ValueError, wrapping_keys[1]):
                commit_retirement(self.trust, None, retirement)
            self.assertTrue(all("/retired/" not in name for name in self.objects))
            with self.assertRaisesRegex(ValueError, "invalid or duplicate approval"):
                commit_retirement(self.trust, None, self.signed_retirement(marker, (1, 2, 4)))
            states[wrapping_keys[1]] = "Enabled"
            qualification.return_value = {**self.qualification(replacement),
                                          "replacementBootstrap": {**marker["replacementBootstrap"], "bootKeyId": "bc" * 32}}
            with self.assertRaisesRegex(ValueError, "no longer matches the qualified replacement"):
                commit_retirement(self.trust, None, retirement)
            qualification.return_value = self.qualification(replacement)
            commit_retirement(self.trust, None, retirement)

    @patch("retirement.require_recovery_quorum")
    @patch("retirement.qualified_policy")
    def test_retirement_binds_three_distinct_proofs_to_one_candidate_and_publication_window(self, qualification, quorum):
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        replacement = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, replacement))
        qualification.return_value = self.qualification(replacement)
        marker = qualified_manifest(self.trust, None, "1", "2")
        retired = self.signed_retirement(marker)
        proofs = retired["recoveryProofs"]
        other = self.signed_retirement({**marker, "recoveryDeadline": marker["recoveryDeadline"] - 1})
        path = f"spr-custody/devnet/{DOMAIN}/retired/1.json"
        for invalid, message in ((proofs[:2], "signing quorum"), ([*proofs[:2], proofs[0]], "duplicate approval"),
                                 (rotated["acknowledgements"][:3], "invalid custody approval signature"),
                                 (other["recoveryProofs"], "invalid custody approval signature")):
            bad = {**retired, "recoveryProofs": invalid}
            with self.assertRaisesRegex(ValueError, message):
                sign_retirement(self.trust, None, bad, approval_keys(self.trust)[0]["keyArn"])
            with self.assertRaisesRegex(ValueError, message):
                commit_retirement(self.trust, None, bad)
            self.objects[path] = canonical(bad)
            with self.assertRaisesRegex(ValueError, message):
                retirement_inventory(self.trust, "1", 1)
            del self.objects[path]
        quorum.assert_not_called()

        deadline = marker["recoveryDeadline"]
        with self.assertRaisesRegex(ValueError, "measured from the replacement boot"):
            sign_retirement(self.trust, None, other, approval_keys(self.trust)[0]["keyArn"])
        for now in (deadline - RECOVERY_WINDOW_SECONDS - 1, deadline, deadline - 1):
            with patch("retirement.time.time", return_value=now):
                with self.assertRaisesRegex(ValueError, "recovery window"):
                    commit_retirement(self.trust, None, retired)
        self.assertNotIn(path, self.objects)
        commit_retirement(self.trust, None, retired)
        commit_retirement(self.trust, None, retired)
        self.rotate_approvals("3")
        qualification.reset_mock()
        quorum.reset_mock()
        with patch("retirement.time.time", return_value=deadline + 1):
            with patch("retirement.write_once") as write:
                commit_retirement(self.trust, None, retired)
                for conflict in (other, {**retired, "recoveryProofs": proofs[:2]}):
                    with self.assertRaisesRegex(ValueError, "different retirement record"):
                        commit_retirement(self.trust, None, conflict)
                write.assert_not_called()
            self.assertIn(key(1), retirement_inventory(self.trust, "1", 1)[2])
        qualification.assert_not_called()
        quorum.assert_not_called()
        self.timestamps[path] = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
        with self.assertRaisesRegex(ValueError, "approval roster does not match its publication time"):
            retirement_inventory(self.trust, "1", 1)
        self.timestamps[path] = datetime.fromtimestamp(deadline, timezone.utc).isoformat()
        with self.assertRaisesRegex(ValueError, "outside the recovery window"):
            retirement_inventory(self.trust, "1", 1)
        with self.assertRaisesRegex(ValueError, "outside the recovery window"):
            commit_retirement(self.trust, None, retired)

    @patch("retirement.qualified_policy")
    def test_replacement_custodian_proves_recovery_only_after_opening_the_committed_share(self, qualification):
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        qualification.return_value = self.qualification(self.replacement_target())
        marker = qualified_manifest(self.trust, None, "1", "2")
        candidate = {"manifest": marker, "signatures": [], "recoveryProofs": []}
        _, receipt, roster = load_epoch(self.trust, "2")
        member = roster[1]
        key_arn = member["acknowledgementKey"]["keyArn"]
        policy = acknowledgement_policy(member["custodianRole"], member["retirementRole"])
        with (patch("custody_ledger.kms", return_value={"Policy": json.dumps(policy)}) as kms,
              patch("custody_ledger.prove_share", side_effect=ValueError("recovery failed")) as prove_share,
              patch("custody_ledger.add_approval") as approval):
            with self.assertRaisesRegex(ValueError, "committed receipts"):
                prove_recovery(self.trust, {**candidate, "manifest": {**marker, "replacementReceiptSha256": "ab" * 32}}, 2, 7443)
            with self.assertRaisesRegex(ValueError, "did not supply an attested bootstrap slot"):
                prove_recovery(self.trust, candidate, 4, 7443)
            kms.assert_not_called()
            with self.assertRaisesRegex(ValueError, "recovery failed"):
                prove_recovery(self.trust, candidate, 2, 7443)
            prove_share.assert_called_once_with(self.trust, receipt, member, 2, 7443, ANY)
            approval.assert_not_called()
            prove_share.side_effect = None
            approval.return_value = {"signatures": [sign(RETIREMENT_RECOVERY, marker, key_arn)]}
            proven = prove_recovery(self.trust, candidate, 2, 7443)
            self.assertEqual(len(proven["recoveryProofs"]), 1)
            approval.assert_called_once_with([item["acknowledgementKey"] for item in roster], RETIREMENT_RECOVERY,
                                             {"manifest": marker, "signatures": []}, key_arn)
