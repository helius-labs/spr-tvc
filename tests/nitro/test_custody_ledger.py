import base64
import copy
import hashlib
import json
import os
import pathlib
import stat
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from io import BytesIO, StringIO
from subprocess import CalledProcessError
from threading import Lock
from types import SimpleNamespace
from unittest.mock import ANY, call, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from approval import MAX_DOCUMENT_BYTES, ApprovalVerificationUnavailable, approval_keys, approval_roster, canonical, sha256
from custody_archive import (
    MAX_ARCHIVE_ENTRY_BYTES, archive, draft_repair, ledger_checkpoint, main as archive_main, repair_transfer,
    require_uncommitted_record, sign_repair, verify_archive, verify_ledger_records, verify_promotion,
)
from custody_ledger import (
    ACKNOWLEDGEMENT, LABEL, RECOVERY_WINDOW_SECONDS, RETIREMENT, RETIREMENT_RECOVERY, TARGET_APPROVAL, acknowledge,
    check_custody_roster, check_installed_ledger, check_release_policy, draft, ledger_policy, ledger_reader_policy,
    ledger_record_fingerprint, ledger_replica_plan,
    list_ledger_versions, list_objects, load_epoch, publish as publish_receipt, read_registered_target, read_stored_object, read_stored_payload,
    record, replication_configuration, require_active_epoch, require_payment_recovery_quorums,
    sign_epoch, storage, target_attestation,
    target_object_name, write_once,
)
from deployment import register_target, require_registered_target
from kms_policy import acknowledgement_policy, boot_pins
from nitro_fixtures import DOMAIN, HOST, INSTANCE, REGION, key, pin, replication_role_responses, schedule, sign
from provenance import describe
from relay import custody_recovery_policy
from retirement import (LiveBoot, commit_retirement, confirm_retirement_policy, inspect_keys, prove_recovery, qualified_manifest,
                        qualified_policy, qualify_key_retirement, main as retirement_main, replacement_targets,
                        retirement_inventory, retirement_scope, sign_retirement, slot_inventory, verify_boot_registration,
                        verify_retired)

READ_ROLE = "arn:aws:iam::000000000001:role/custodian"
PUBLISHER = "arn:aws:iam::000000000008:role/publisher"
ADMIN = "arn:aws:iam::000000000008:role/ledger-admin"
RECOVERY_ROLES = {
    "administratorRole": "arn:aws:iam::000000000010:role/ledger-admin",
    "publisherRole": "arn:aws:iam::000000000010:role/publisher", "readerRoles": [READ_ROLE],
}
NEXT_ROLES = {
    "administratorRole": "arn:aws:iam::000000000011:role/ledger-admin",
    "publisherRole": "arn:aws:iam::000000000011:role/publisher", "readerRoles": [READ_ROLE],
}
PINS = {f"PCR{i}": f"{i+1:02x}" * 48 for i in range(3)}
HOST_ACCOUNT = HOST.split(":")[4]
KEY_PROFILES = {f"{slot:012d}": f"key-read-{slot}" for slot in range(1, 7)}
PAYMENT_PROFILES = {
    "source_profile": "source-read", "replica_profile": "replica-read",
    "key_profiles": {**KEY_PROFILES, HOST_ACCOUNT: "host-read"},
}
REPLACEMENT_PROFILES = {**{f"{index:012d}": f"replacement-{index}" for index in range(1, 7)}, HOST_ACCOUNT: "host-read"}


def publish(trust, document, *, key_profiles=KEY_PROFILES):
    return publish_receipt(trust, document, key_profiles=key_profiles)


def listing(prefix, keys=(), **metadata):
    page = {"Name": "custody-journal", "Prefix": prefix, "KeyCount": len(keys), "IsTruncated": False}
    if keys:
        page["Contents"] = [{"Key": key} for key in keys]
    return {**page, **metadata}


class CustodyLedgerTests(unittest.TestCase):
    def setUp(self):
        self.trust = {
            "network": "devnet", "securityDomainId": DOMAIN, "approvalKeys": [schedule()],
            "publications": [
                {"bucket": "release-primary", "region": "eu-north-1", "account": "000000000011"},
                {"bucket": "release-mirror", "region": "eu-west-1", "account": "000000000012"},
            ],
            "ledger": {"bucket": "custody-journal", "account": "000000000008", "region": "eu-north-1",
                       "administratorRole": ADMIN, "publisherRole": PUBLISHER, "readerRoles": [READ_ROLE]},
            "recoveryRelays": {str(epoch): {"hostRole": HOST, "pcrs": PINS} for epoch in range(1, 4)},
        }
        self.wallet_pins = canonical({"publications": self.trust["publications"]})
        self.objects = {}
        self.replica_objects = {}
        self.timestamps = {}
        self.versions = {}
        self.bucket_policy = ledger_policy(self.trust)
        self.lifecycle = None
        self.lock = Lock()
        self.now = int(time.time())
        self.booted_at_ms = self.now * 1000
        self.enterContext(patch("time.time", side_effect=lambda: self.now))
        self.enterContext(patch("custody_ledger.aws", side_effect=self.aws))
        self.enterContext(patch("deployment.require_live_registration"))
        self.payment_host = self.enterContext(patch("custody_ledger.require_bootstrap_access"))
        self.retirement_host = self.enterContext(patch("retirement.require_bootstrap_access"))
        self.enterContext(patch("approval.kms", side_effect=AssertionError("receipt verification must not call KMS")))
        self.key_metadata = {}
        self.key_policies = {}
        self.key_inspection = self.enterContext(patch("custody_ledger.kms", side_effect=self.describe_custody_key))
        self.recovery_inspection = self.enterContext(patch("relay.kms", side_effect=self.describe_custody_key))
        self.key_identity = self.enterContext(patch("custody_ledger.require_profile_account", side_effect=self.check_receipt_profile))
        self.capture_verifier = self.enterContext(patch("custody_ledger.verify_ceremony_capture"))
        self.archive_capture_verifier = self.enterContext(patch("custody_archive.verify_ceremony_capture"))

    def describe_custody_key(self, arn, operation, args=(), *, profile=None):
        self.assertEqual(profile, PAYMENT_PROFILES["key_profiles"][arn.split(":")[4]])
        if operation == "get-key-policy":
            self.assertEqual(args, ["--policy-name", "default"])
            return {"Policy": json.dumps(self.key_policies[arn])}
        self.assertEqual(operation, "describe-key")
        acknowledgement = arn in {key(slot, 8) for slot in range(1, 7)}
        return {"KeyMetadata": {
            "Arn": arn, "Origin": "AWS_KMS", "MultiRegion": False, "KeyState": "Enabled",
            "KeySpec": "ECC_NIST_P256" if acknowledgement else "RSA_2048",
            "KeyUsage": "SIGN_VERIFY" if acknowledgement else "ENCRYPT_DECRYPT",
            **self.key_metadata.get(arn, {}),
        }}

    def check_receipt_profile(self, profile, region, account):
        if PAYMENT_PROFILES["key_profiles"].get(account) != profile:
            raise ValueError("wrong inspection profile for the custody account")

    def rotate_approvals(self, epoch):
        self.now += 60
        self.trust["approvalKeys"].append(schedule(epoch, 9, self.now))

    def document(self, epoch, predecessor=None, variant="ab"):
        roster = [{
            "recoveryKeyArn": key(index, epoch), "acknowledgementKey": pin(key(index, 8)),
            "custodianRole": f"arn:aws:iam::{index:012}:role/custodian",
            "retirementRole": f"arn:aws:iam::{index:012}:role/retirement",
        } for index in range(1, 7)]
        for member in roster:
            self.key_policies[member["recoveryKeyArn"]] = custody_recovery_policy(self.trust, member, str(epoch))
            self.key_policies[member["acknowledgementKey"]["keyArn"]] = acknowledgement_policy(
                member["custodianRole"], member["retirementRole"],
            )
        custody = {"epoch": str(epoch), "noteSeedCommitment": "34" * 32, "canaryDigest": "35" * 32,
                   "shareCommitments": [variant * 32] * 6}
        receipt = {
            "network": self.trust["network"], "securityDomainId": DOMAIN, "releaseId": f"custody-{epoch}",
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
        previous = predecessor["custody"]["epoch"]
        epoch = int(previous) + 1
        document = self.document(epoch, predecessor, variant)
        manifest = document["authorization"]["manifest"]
        target = {"network": self.trust["network"], "securityDomainId": DOMAIN, "receiptSha256": sha256(predecessor),
                  "custodyEpoch": previous, "approvalFromEpoch": approval_roster(self.trust)["fromEpoch"], "expiresAt": self.now + 3600,
                  "releaseId": manifest["capture"]["receipt"]["releaseId"], "mode": "rotate", "hostRole": HOST,
                  "hostRegion": REGION, "instanceId": INSTANCE, "pcrs": PINS, "eifSha256": manifest["ceremonyEifSha256"],
                  "executableSha256": hashlib.sha256(b"rotation executable fixture").hexdigest(),
                  "configurationSha256": sha256(manifest["capture"]["configuration"]),
                  "nextCustodians": copy.deepcopy(manifest["custodians"]), "nextRelay": copy.deepcopy(manifest["relay"]),
                  "wrappingKeys": [key(i, 19 + epoch) for i in range(1, 7)]}
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
        replica = self.trust.get("ledgerReplica")
        bucket = args[args.index("--bucket") + 1]
        if replica and bucket == replica["bucket"] and operation == "list-object-versions":
            self.assertEqual((region, service), (replica["region"], "s3api"))
            self.assertEqual(args[args.index("--expected-bucket-owner") + 1], replica["account"])
            prefix = args[args.index("--prefix") + 1]
            self.assertTrue(prefix.startswith(f"spr-custody/{self.trust['network']}/{DOMAIN}/"))
            with self.lock:
                names = [name for name in sorted(self.replica_objects) if name.startswith(prefix)]
            entries = [{"Key": name, "IsLatest": True, "VersionId": hashlib.sha256(name.encode()).hexdigest()}
                       for name in names]
            return {"Name": bucket, "Prefix": prefix, "Versions": entries, "IsTruncated": False}
        self.assertEqual((region, service), ("eu-north-1", "s3api"))
        self.assertEqual(args[args.index("--expected-bucket-owner") + 1], "000000000008")
        if operation == "get-bucket-policy":
            return {"Policy": canonical(self.bucket_policy).decode()}
        if operation == "get-bucket-lifecycle-configuration":
            self.assertEqual(options, {"absent": "NoSuchLifecycleConfiguration"})
            return self.lifecycle
        if operation == "get-bucket-versioning":
            return {"Status": "Enabled"}
        if operation == "get-bucket-ownership-controls":
            return {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}}
        if operation == "get-public-access-block":
            return {"PublicAccessBlockConfiguration": {
                flag: True for flag in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
            }}
        if operation == "list-objects-v2":
            prefix = args[args.index("--prefix") + 1]
            self.assertTrue(prefix.startswith(f"spr-custody/{self.trust['network']}/{DOMAIN}/"))
            with self.lock:
                return listing(prefix, [name for name in sorted(self.objects) if name.startswith(prefix)])
        now = datetime.fromtimestamp(time.time(), timezone.utc).isoformat()

        def metadata(name):
            return {"LastModified": self.timestamps.get(name, now),
                    "VersionId": self.versions.get(name, hashlib.sha256(name.encode()).hexdigest())}

        if operation == "list-object-versions":
            prefix = args[args.index("--prefix") + 1]
            with self.lock:
                entries = [{"Key": name, "IsLatest": True, **metadata(name)}
                           for name in sorted(self.objects) if name.startswith(prefix)]
            return {"Name": "custody-journal", "Prefix": prefix, "Versions": entries, "IsTruncated": False}
        name = args[args.index("--key") + 1]
        self.assertTrue(name.startswith(f"spr-custody/{self.trust['network']}/{DOMAIN}/"))
        with self.lock:
            if operation == "put-object":
                self.assertEqual(args[args.index("--if-none-match") + 1], "*")
                if name in self.objects:
                    raise ValueError("precondition failed")
                self.objects[name] = pathlib.Path(args[args.index("--body") + 1]).read_bytes()
                self.timestamps[name] = now
                return {"VersionId": metadata(name)["VersionId"]}
            elif operation == "get-object" and name in self.objects:
                pathlib.Path(args[-1]).write_bytes(self.objects[name])
                return metadata(name)
            elif operation == "head-object" and name in self.objects:
                return {**metadata(name), "ContentLength": len(self.objects[name])}
            else:
                raise ValueError("object missing")
        return {}

    def replicated_record(self, trust, _destination, name, **options):
        payload, metadata = read_stored_payload(trust, name, **options)
        return payload, ledger_record_fingerprint(name, payload, metadata)

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
        publish(self.trust, {**winner, "acknowledgements": winner["acknowledgements"][::-1]})
        self.assertEqual(load_epoch(self.trust, "1")[0], winner)

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
        empty = {"Name": "custody-journal", "Prefix": f"spr-custody/devnet/{DOMAIN}/1.json", "IsTruncated": False}
        with patch("custody_ledger.storage", side_effect=[empty, ValueError("write timed out"), ValueError("read denied")]):
            with self.assertRaisesRegex(ValueError, r"could not confirm ledger write \(write timed out\).*\(read denied\)"):
                write_once(self.trust, "1.json", {}, lambda version: read_stored_object(
                    self.trust, "1.json", expected_version=version))

    def test_custody_publish_requires_an_authenticated_readback(self):
        document = self.sign(self.document(1))
        name = f"spr-custody/devnet/{DOMAIN}/1.json"

        def lost_response(region, service, operation, args, **options):
            reply = self.aws(region, service, operation, args, **options)
            if operation == "put-object":
                raise ValueError("write acknowledgement lost")
            return reply

        with patch("custody_ledger.aws", side_effect=lost_response):
            publish(self.trust, document)
        self.assertEqual(load_epoch(self.trust, "1")[0], document)

        with patch.dict(self.objects, {name: canonical({**document, "acknowledgements": []})}):
            with patch("custody_ledger.aws", side_effect=lost_response):
                with self.assertRaisesRegex(ValueError, "signing quorum"):
                    publish(self.trust, document)
        for version in (None, "", "null"):
            with self.subTest(version=version), patch.dict(self.versions, {name: version}):
                with self.assertRaisesRegex(ValueError, "requires an original S3 version"):
                    publish(self.trust, document)

    def test_custody_publish_requires_the_record_after_a_successful_response(self):
        def unconfirmed_write(region, service, operation, args, **options):
            if operation == "put-object":
                return {}
            return self.aws(region, service, operation, args, **options)

        with patch("custody_ledger.aws", side_effect=unconfirmed_write):
            with self.assertRaisesRegex(ValueError, "object missing"):
                publish(self.trust, self.sign(self.document(1)))

    def test_custody_publish_pins_readback_to_the_committed_version(self):
        document = self.sign(self.document(1))
        path = f"spr-custody/devnet/{DOMAIN}/1.json"
        for change in ("acknowledgement", "readback", "retry"):
            with self.subTest(change=change), patch.dict(self.objects), patch.dict(self.timestamps):
                if change == "retry":
                    publish(self.trust, document)

                def aws(region, service, operation, args, **options):
                    reply = self.aws(region, service, operation, args, **options)
                    if path in args and operation == "put-object":
                        if change == "readback":
                            raise ValueError("write acknowledgement lost")
                        return {"VersionId": "unexpected-acknowledgement"}
                    if path in args and operation == "get-object" and change != "acknowledgement":
                        return {**reply, "VersionId": "unexpected-readback"}
                    return reply

                with patch("custody_ledger.aws", side_effect=aws) as request:
                    with self.assertRaisesRegex(ValueError, "version"):
                        publish(self.trust, document)
                    operations = [entry.args[2] for entry in request.call_args_list]
                    self.assertEqual(operations.count("put-object"), 0 if change == "retry" else 1)
                self.assertEqual(load_epoch(self.trust, "1")[0], document)

    def test_lost_acknowledgement_can_only_confirm_a_consistent_replica(self):
        self.trust["ledgerReplica"] = {
            "bucket": "custody-recovery", "account": "000000000010", "region": "eu-west-1",
            **RECOVERY_ROLES, "role": "arn:aws:iam::000000000008:role/replication",
        }
        document = self.sign(self.document(1))
        path = f"spr-custody/devnet/{DOMAIN}/1.json"

        def aws(region, service, operation, args, **options):
            if path in args and operation == "get-object" and region == "eu-west-1":
                pathlib.Path(args[-1]).write_bytes(b"{}")
                return {"LastModified": self.timestamps[path], "VersionId": hashlib.sha256(path.encode()).hexdigest(),
                        "ReplicationStatus": "REPLICA"}
            reply = self.aws(region, service, operation, args, **options)
            if path in args and operation == "put-object":
                self.replica_objects[path] = b"{}"
                raise ValueError("write acknowledgement lost")
            if path in args and operation == "get-object":
                reply["ReplicationStatus"] = "COMPLETED"
            return reply

        with patch("custody_ledger.aws", side_effect=aws) as request:
            with self.assertRaisesRegex(ValueError, "write acknowledgement lost.*differs from the pinned replica"):
                publish(self.trust, document)
            self.assertEqual([entry.args[2] for entry in request.call_args_list].count("put-object"), 1)
        self.assertEqual(load_epoch(self.trust, "1")[0], document)

    def test_publish_cannot_replace_a_replica_only_custody_receipt(self):
        original = self.sign(self.document(1))
        publish(self.trust, original)
        name = f"spr-custody/devnet/{DOMAIN}/1.json"
        self.trust["ledgerReplica"] = {
            "bucket": "custody-recovery", "account": "000000000010", "region": "eu-west-1",
            **RECOVERY_ROLES, "role": "arn:aws:iam::000000000008:role/replication",
        }
        self.replica_objects[name] = self.objects.pop(name)
        alternative = self.sign(self.document(1, variant="ce"))
        with patch("custody_ledger.storage", wraps=storage) as access:
            for candidate in (original, alternative):
                with self.assertRaisesRegex(ValueError, "slot 1.json exists in the pinned replica"):
                    publish(self.trust, candidate)
            self.assertNotIn("put-object", [entry.args[1] for entry in access.call_args_list])
        self.assertNotIn(name, self.objects)

    def test_new_rotation_write_rechecks_the_predecessor_after_slot_inspection(self):
        publish(self.trust, self.sign(self.document(1)))
        rotated, _ = self.rotation_document(load_epoch(self.trust, "1")[1])
        document = self.sign(rotated)
        prefix = f"spr-custody/devnet/{DOMAIN}/"
        marker = prefix + "retired/1.json"

        def close_during_inspection(trust, operation, args=(), **options):
            result = storage(trust, operation, args, **options)
            if operation == "list-object-versions" and prefix + "2.json" in args:
                self.objects[marker] = b"{}"
            return result

        with patch("custody_ledger.storage", side_effect=close_during_inspection) as access:
            with self.assertRaisesRegex(ValueError, "cannot verify retirement record"):
                publish(self.trust, document)
            self.assertNotIn("put-object", [entry.args[1] for entry in access.call_args_list])
        del self.objects[marker]
        self.assertNotIn(prefix + "2.json", self.objects)
        publish(self.trust, document)
        self.objects[marker] = b"{}"
        with patch("custody_ledger.storage", wraps=storage) as access:
            publish(self.trust, document)
            self.assertNotIn("put-object", [entry.args[1] for entry in access.call_args_list])

    def test_retirement_requires_an_explicit_complete_listing_from_the_pinned_bucket(self):
        prefix = f"spr-custody/devnet/{DOMAIN}/retired/1.json"
        empty = {"Name": "custody-journal", "Prefix": prefix, "IsTruncated": False}
        with patch("custody_ledger.storage", return_value=empty):
            require_active_epoch(self.trust, "1")
        with patch("custody_ledger.storage", return_value={**empty, "DeleteMarkers": [{"Key": prefix}]}):
            with self.assertRaisesRegex(ValueError, "custody ledger contains delete markers"):
                require_active_epoch(self.trust, "1")
        for invalid in (
            {},
            {name: value for name, value in empty.items() if name != "IsTruncated"},
            {**empty, "IsTruncated": "false"},
            {**empty, "Name": "wrong-bucket"},
            {**empty, "Prefix": prefix + ".wrong"},
            {**empty, "Versions": None},
            {**empty, "IsTruncated": True},
            {**empty, "NextKeyMarker": prefix},
        ):
            with (self.subTest(listing=invalid), patch("custody_ledger.storage", return_value=invalid),
                  self.assertRaisesRegex(ValueError, "invalid custody ledger")):
                require_active_epoch(self.trust, "1")

    def test_retirement_checks_the_pinned_replica_before_the_source(self):
        replica = {"bucket": "custody-recovery", "account": "000000000010", "region": "eu-west-1",
                   **RECOVERY_ROLES, "role": "arn:aws:iam::000000000008:role/replication"}
        self.trust["ledgerReplica"] = replica
        marker = f"spr-custody/devnet/{DOMAIN}/retired/1.json"
        self.replica_objects[marker + ".note"] = b"unrelated"
        require_active_epoch(self.trust, "1")
        with patch.dict(self.replica_objects, {marker: b"{}"}):
            with self.assertRaisesRegex(ValueError, "retirement record in the pinned replica"):
                require_active_epoch(self.trust, "1")
        hidden = {"Name": replica["bucket"], "Prefix": marker, "IsTruncated": False,
                  "DeleteMarkers": [{"Key": marker, "IsLatest": True}]}
        with patch("custody_ledger.storage", return_value=hidden):
            with self.assertRaisesRegex(ValueError, "custody ledger contains delete markers"):
                require_active_epoch(self.trust, "1")

        def aws(region, service, operation, args, **options):
            result = self.aws(region, service, operation, args, **options)
            if region == replica["region"] and operation == "list-object-versions":
                self.objects[marker] = b"{}"
            return result

        with patch("custody_ledger.aws", side_effect=aws):
            with self.assertRaisesRegex(ValueError, "cannot verify retirement record"):
                require_active_epoch(self.trust, "1")
        del self.objects[marker]

        def broken_replica(region, service, operation, args, **options):
            if region == replica["region"]:
                raise OSError("replica unreachable")
            return self.aws(region, service, operation, args, **options)

        with patch("custody_ledger.aws", side_effect=broken_replica):
            with self.assertRaisesRegex(OSError, "replica unreachable"):
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
        bad["authorization"]["manifest"]["capture"]["receipt"]["custody"]["canaryDigest"] = "12" * 32
        with self.assertRaisesRegex(ValueError, "canonical previous receipt"):
            publish(self.trust, self.sign(bad))
        bad = copy.deepcopy(new)
        bad["authorization"]["manifest"]["custodians"] = roster
        with self.assertRaisesRegex(ValueError, "fresh recovery keys"):
            publish(self.trust, self.sign(bad))
        publish(self.trust, self.sign(new))
        self.assertEqual(load_epoch(self.trust, "2")[1]["custody"]["noteSeedCommitment"], previous["custody"]["noteSeedCommitment"])
        self.assertEqual(load_epoch(self.trust, "2")[1]["custody"]["canaryDigest"], previous["custody"]["canaryDigest"])

    def test_receipt_requires_a_nonzero_canonical_canary_digest(self):
        for value in (None, "00" * 32, "ff", "AA" * 32):
            document = self.document(1)
            custody = document["authorization"]["manifest"]["capture"]["receipt"]["custody"]
            if value is None:
                del custody["canaryDigest"]
            else:
                custody["canaryDigest"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                record(self.trust, document)

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

    def test_rotation_signatures_require_the_original_predecessor_and_registration(self):
        publish(self.trust, self.sign(self.document(1)))
        _, predecessor, _ = load_epoch(self.trust, "1")
        rotation, registration = self.rotation_document(predecessor)
        rotation["authorization"]["manifest"]["capture"]["receipt"]["packages"] = [
            {"recipientSha256": f"{index:02x}" * 32} for index in range(1, 7)
        ]
        document = self.sign(rotation)
        build, review = pathlib.Path("build"), pathlib.Path("ceremony-review.json")
        prefix = f"spr-custody/devnet/{DOMAIN}/"
        registration_path = prefix + target_object_name(registration["manifest"])

        def switch_registration(*_args):
            self.versions[registration_path] = "changed-registration"

        def change_predecessor_during_recovery(*args):
            require_current = args[-1]
            require_current()
            self.versions[prefix + "1.json"] = "changed-predecessor"
            require_current()

        with self.subTest(operation="approval"):
            with (patch.dict(self.versions), patch("custody_ledger.verify_reviewed_ceremony"),
                  patch("custody_ledger.add_approval", return_value=document["authorization"]) as sign_record,
                  patch("custody_ledger.check_custody_roster", side_effect=switch_registration),
                  self.assertRaisesRegex(ValueError, "changed during verification")):
                sign_epoch(self.trust, document, key(8, 7), build, review)
            sign_record.assert_not_called()

        with self.subTest(operation="acknowledgement"):
            with (patch.dict(self.versions), patch("custody_ledger.verify_reviewed_ceremony"),
                  patch("custody_ledger.check_acknowledgement_policy"),
                  patch("custody_ledger.add_approval", return_value=document["authorization"]) as sign_record,
                  patch("custody_ledger.prove_share", side_effect=change_predecessor_during_recovery),
                  self.assertRaisesRegex(ValueError, "changed during verification")):
                acknowledge(self.trust, document, 1, 7443, build, review)
            sign_record.assert_not_called()

    def test_rotation_signature_files_recheck_lineage_after_staging(self):
        publish(self.trust, self.sign(self.document(1)))
        _, predecessor, _ = load_epoch(self.trust, "1")
        rotation, _ = self.rotation_document(predecessor)
        rotation["authorization"]["manifest"]["capture"]["receipt"]["packages"] = [
            {"recipientSha256": f"{index:02x}" * 32} for index in range(1, 7)
        ]
        document = self.sign(rotation)
        output = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory())) / "signed.json"
        build, review = pathlib.Path("build"), pathlib.Path("ceremony-review.json")
        fsync = os.fsync

        def change_while_staging(fd):
            fsync(fd)
            self.assertFalse(output.exists())
            self.versions[f"spr-custody/devnet/{DOMAIN}/1.json"] = "changed-predecessor"

        with (patch("custody_ledger.verify_reviewed_ceremony"),
              patch("custody_ledger.check_custody_roster"),
              patch("custody_ledger.check_acknowledgement_policy"),
              patch("custody_ledger.prove_share"),
              patch("custody_ledger.add_approval", return_value=document["authorization"])):
            for operation in (
                lambda: sign_epoch(self.trust, document, key(8, 7), build, review, output=output),
                lambda: acknowledge(self.trust, document, 1, 7443, build, review, output=output),
            ):
                with (patch.dict(self.versions), patch("approval.os.fsync", side_effect=change_while_staging),
                      self.assertRaisesRegex(ValueError, "changed during verification")):
                    operation()
                self.assertFalse(output.exists())
                signed = operation()
                self.assertEqual(output.read_bytes(), canonical(signed) + b"\n")
                output.unlink()

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

    def test_retired_roster_cannot_sign_acknowledge_or_publish_a_receipt(self):
        first = self.sign(self.document(1))
        publish(self.trust, first)
        successor, _ = self.rotation_document(record(self.trust, first)[0])
        receipt, _ = record(self.trust, successor)
        receipt["packages"] = [{"recipientSha256": f"{index:02x}" * 32} for index in range(1, 7)]
        successor = self.sign(successor)
        cutoff = self.now + 60
        self.trust["approvalKeys"].append(schedule("3", 9, cutoff))
        stored = dict(self.objects)
        self.now = cutoff - 30
        with self.assertRaisesRegex(ValueError, "receipt approval roster has retired"):
            publish(self.trust, successor)
        self.now = cutoff
        with self.assertRaisesRegex(ValueError, "receipt approval roster has retired"):
            publish(self.trust, successor)
        self.assertEqual(self.objects, stored)

        build, review = pathlib.Path("unused-build"), pathlib.Path("unused-review.json")
        with (patch("custody_ledger.verify_reviewed_ceremony"), patch("custody_ledger.check_custody_roster"),
              patch("custody_ledger.add_approval") as sign_approval,
              patch("custody_ledger.prove_share") as prove_share):
            with self.assertRaisesRegex(ValueError, "receipt approval roster has retired"):
                sign_epoch(self.trust, successor, key(7, 7), build, review)
            with self.assertRaisesRegex(ValueError, "receipt approval roster has retired"):
                acknowledge(self.trust, successor, 1, 1, build, review)
        sign_approval.assert_not_called()
        prove_share.assert_not_called()

    def test_receipt_history_uses_its_recorded_publication_time(self):
        first = self.sign(self.document(1))
        publish(self.trust, first)
        cutoff = self.now + 60
        self.trust["approvalKeys"].append(schedule("2", 9, cutoff))
        self.now = cutoff
        name = f"spr-custody/devnet/{DOMAIN}/1.json"
        original = self.objects[name], self.timestamps[name]
        _, metadata = read_stored_object(self.trust, "1.json")
        version = metadata["VersionId"]
        publish(self.trust, first)
        self.assertEqual((self.objects[name], self.timestamps[name]), original)
        self.assertEqual(load_epoch(self.trust, "1")[0], first)
        with self.assertRaisesRegex(ValueError, "cannot exclude"):
            require_uncommitted_record(self.trust, "1.json", version)

        out = BytesIO()
        archive(self.trust, "1", out)
        entry = json.loads(out.getvalue())
        published_at = datetime.fromtimestamp(cutoff, timezone.utc).isoformat()
        with patch.dict(self.timestamps, {name: published_at}):
            with self.assertRaisesRegex(ValueError, "receipt approval roster has retired"):
                load_epoch(self.trust, "1")
            require_uncommitted_record(self.trust, "1.json", version)
        entry["publishedAt"] = published_at
        payload = canonical(entry) + b"\n"
        with self.assertRaisesRegex(ValueError, "receipt approval roster has retired"):
            verify_archive(self.trust, "1", BytesIO(payload), hashlib.sha256(payload).hexdigest())
        self.archive_capture_verifier.assert_not_called()

    def test_incoming_receipt_roster_can_commission_before_cutover(self):
        first = self.sign(self.document(1))
        publish(self.trust, first)
        cutoff = self.now + 120
        self.trust["approvalKeys"].append(schedule("2", 9, cutoff))
        incoming, _ = self.rotation_document(record(self.trust, first)[0])
        publish(self.trust, self.sign(incoming))
        self.assertEqual(load_epoch(self.trust, "2")[0], incoming)
        self.now = cutoff
        self.assertEqual(load_epoch(self.trust, "2")[0], incoming)

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
        self.trust["approvalKeys"].append(schedule("2", 9, self.now + 60))
        second, approval = self.rotation_document(record(self.trust, first)[0])
        publish(self.trust, self.sign(second))
        prefix = f"spr-custody/devnet/{DOMAIN}/"
        registered_at = datetime.fromisoformat(self.timestamps[prefix + target_object_name(approval["manifest"])]).timestamp()
        for name, at in (("1.json", registered_at + 1), ("2.json", registered_at - 1)):
            edited = datetime.fromtimestamp(at, timezone.utc).isoformat()
            with self.subTest(out_of_order=name), patch.dict(self.timestamps, {prefix + name: edited}):
                with self.assertRaisesRegex(ValueError, "rotation registration must be recorded between"):
                    load_epoch(self.trust, "2")
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

            for index, at in ((0, registered_at + 1), (1, registered_at - 1)):
                changed = copy.deepcopy(entries)
                changed[index]["publishedAt"] = datetime.fromtimestamp(at, timezone.utc).isoformat()
                with self.assertRaisesRegex(ValueError, "rotation registration must be recorded between"):
                    verify(encode(changed))
            changed = copy.deepcopy(entries)
            del changed[0]["publishedAt"]
            with self.assertRaisesRegex(ValueError, "publishedAt"):
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
        with (patch("retirement.qualified_policy", return_value=self.live_qualification(replacement)),
              patch("retirement.require_recovery_quorum")):
            marker = qualified_manifest(self.trust, None, "1", "2")
            commit_retirement(self.trust, None, self.signed_retirement(marker))

        self.bucket_policy = ledger_policy(self.trust, frozen=True)
        pinned = ledger_checkpoint(self.trust)
        self.assertEqual(self.archive_capture_verifier.call_count, 2)
        self.archive_capture_verifier.side_effect = ValueError("invalid historical Nitro evidence")
        with self.assertRaisesRegex(ValueError, "invalid historical Nitro evidence"):
            ledger_checkpoint(self.trust)
        self.archive_capture_verifier.side_effect = None
        self.now = max(marker["recoveryDeadline"], rotation["manifest"]["expiresAt"]) + 1
        prefix = f"spr-custody/devnet/{DOMAIN}/"
        target = prefix + target_object_name(replacement)
        retired = prefix + "retired/1.json"
        retired_at = datetime.fromisoformat(self.timestamps[retired]).timestamp()
        after_retirement = datetime.fromtimestamp(retired_at + 1, timezone.utc).isoformat()
        with patch.dict(self.timestamps, {prefix + "2.json": after_retirement, target: after_retirement}):
            with self.assertRaisesRegex(ValueError, "retirement precedes a custody receipt"):
                ledger_checkpoint(self.trust)
        with patch.dict(self.timestamps, {target: after_retirement}):
            with self.assertRaisesRegex(ValueError, "retirement precedes its replacement target registration"):
                ledger_checkpoint(self.trust)
        changed_time = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
        replica = {**self.trust, "ledger": {"bucket": "custody-recovery", "account": "000000000010",
                                           "region": "eu-west-1", **RECOVERY_ROLES}}
        replica_policy = ledger_policy(replica, frozen=True)

        def replica_aws(region, service, operation, args, **options):
            self.assertEqual(region, "eu-west-1")
            self.assertEqual(args[:4], ["--bucket", "custody-recovery", "--expected-bucket-owner", "000000000010"])
            if operation == "get-bucket-policy":
                return {"Policy": canonical(replica_policy).decode()}
            original = ["--bucket", "custody-journal", "--expected-bucket-owner", "000000000008", *args[4:]]
            reply = self.aws("eu-north-1", service, operation, original, **options)
            return {**reply, "Name": "custody-recovery"} if operation in {"list-objects-v2", "list-object-versions"} else reply

        with patch("custody_ledger.aws", side_effect=replica_aws):
            self.assertEqual(ledger_checkpoint(replica, pinned), pinned)
            with self.assertRaisesRegex(ValueError, "custody epoch is retired"):
                require_active_epoch(replica, "1")

        original = {**self.trust, "ledgerReplica": {
            **replica["ledger"], "role": "arn:aws:iam::000000000008:role/replication",
        }}

        def read_both(region, service, operation, args, *, profile, **options):
            self.assertEqual(profile, "source-read" if region == "eu-north-1" else "recovery-read")
            if operation == "get-bucket-replication":
                self.assertEqual(region, "eu-west-1")
                return None
            read = self.aws if region == "eu-north-1" else replica_aws
            return read(region, service, operation, args, **options)

        with (patch("custody_ledger.aws", side_effect=read_both),
              patch("custody_archive.require_profile_account")):
            def promote(digest):
                return verify_promotion(original, replica, digest, "source-read", "recovery-read")

            self.assertEqual(promote(pinned), pinned)
            genesis = prefix + "1.json"
            for name in (genesis, target, retired):
                document = json.loads(self.objects[name])
                document["acknowledgements" if name == genesis else "signatures"] = []
                with self.subTest(name=name), patch.dict(self.objects, {name: canonical(document)}):
                    with self.assertRaisesRegex(ValueError, "signing quorum"):
                        ledger_checkpoint(self.trust, profile="source-read")
                    with patch("custody_archive.verify_ledger_records"):
                        corrupt_pin = ledger_checkpoint(self.trust, profile="source-read")
                    with self.assertRaisesRegex(ValueError, "signing quorum"):
                        promote(corrupt_pin)

            def change_after_checkpoint(*args, **options):
                with patch.dict(self.objects, {genesis: self.objects[genesis] + b" "}):
                    return verify_ledger_records(*args, **options)

            with patch("custody_archive.verify_ledger_records", side_effect=change_after_checkpoint):
                with self.assertRaisesRegex(ValueError, "changed after checkpoint"):
                    promote(pinned)
            with patch.dict(self.objects, {prefix + "unexpected/key.json": b"{}"}):
                with self.assertRaisesRegex(ValueError, "unexpected custody ledger record"):
                    ledger_checkpoint(self.trust, profile="source-read")
            with patch.dict(self.objects, {prefix + "4.json": self.objects[prefix + "2.json"]}):
                with self.assertRaisesRegex(ValueError, "receipts must be consecutive"):
                    ledger_checkpoint(self.trust, profile="source-read")

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

        versions = list_ledger_versions(self.trust)
        changed_versions = dict(versions)
        changed_versions.pop(target.removeprefix(prefix))
        with patch("custody_archive.list_ledger_versions", side_effect=[versions, changed_versions]):
            with self.assertRaisesRegex(ValueError, "changed during checkpoint"):
                ledger_checkpoint(self.trust, pinned)

    def test_ledger_checkpoint_requires_the_frozen_policy_before_and_after_reading(self):
        publish(self.trust, self.sign(self.document(1)))
        live = self.bucket_policy
        frozen = ledger_policy(self.trust, frozen=True)
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

    def test_repair_preserves_the_pinned_history_and_excludes_only_the_approved_versions(self):
        publish(self.trust, self.sign(self.document(1)))
        rotation, _ = self.rotation_document(load_epoch(self.trust, "1")[1])
        publish(self.trust, self.sign(rotation))
        target = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, target))
        with (patch("retirement.qualified_policy", return_value=self.live_qualification(target)),
              patch("retirement.require_recovery_quorum")):
            retired = self.signed_retirement(qualified_manifest(self.trust, None, "1", "2"))
            commit_retirement(self.trust, None, retired)

        self.bucket_policy = ledger_policy(self.trust, frozen=True)
        pin = ledger_checkpoint(self.trust)
        original = {**self.trust, "ledgerReplica": {"bucket": "old-replica", "region": "eu-west-1",
                    "account": "000000000010", **RECOVERY_ROLES,
                    "role": "arn:aws:iam::000000000008:role/replication"}}
        recovered = {**self.trust, "ledger": {"bucket": "clean-recovery", "region": "eu-west-2",
                                               "account": "000000000011", **NEXT_ROLES}}
        prefix = f"spr-custody/devnet/{DOMAIN}/"
        retired_name = "retired/1.json"
        retired_key = prefix + retired_name
        retired_version = hashlib.sha256(retired_key.encode()).hexdigest()
        with self.assertRaisesRegex(ValueError, "complete custody approval"):
            require_uncommitted_record(self.trust, retired_name, retired_version)
        for name in ("1.json", target_object_name(target), retired_name):
            version = hashlib.sha256((prefix + name).encode()).hexdigest()
            for status in (0, 1, -9):
                unavailable = SimpleNamespace(returncode=status, stdout=b"", stderr=b"OpenSSL unavailable")
                with (self.subTest(name=name, status=status), patch("approval.subprocess.run", return_value=unavailable),
                      self.assertRaisesRegex(ValueError, "could not verify custody approval signature")):
                    require_uncommitted_record(self.trust, name, version)
        with patch("custody_archive.load_epoch", side_effect=ValueError("replacement read unavailable")):
            with self.assertRaisesRegex(ValueError, "replacement read unavailable"):
                require_uncommitted_record(self.trust, retired_name, retired_version)
        with patch("custody_archive.retirement_recovery",
                   side_effect=ApprovalVerificationUnavailable("could not verify custody approval signature")):
            with self.assertRaisesRegex(ValueError, "could not verify custody approval signature"):
                require_uncommitted_record(self.trust, retired_name, retired_version)
        invalid_proofs = copy.deepcopy(retired)
        invalid_proofs["recoveryProofs"][0]["signature"] = retired["signatures"][0]["signature"]
        with patch.dict(self.objects, {retired_key: canonical(invalid_proofs)}):
            require_uncommitted_record(self.trust, retired_name, retired_version)
        with patch.dict(self.objects, {retired_key: b"[" * 2048 + b"]" * 2048}):
            require_uncommitted_record(self.trust, retired_name, retired_version)

        bad = "retired/2.json"
        bad_key = prefix + bad
        other = "operator note-é"
        other_key = prefix + other
        exclusions = [bad, other]
        good = dict(self.objects)
        copied = canonical(retired)
        self.objects.update({bad_key: copied, other_key: b"{}"})
        recovered_policy = ledger_policy(recovered, frozen=True)
        transfer = {**recovered["ledger"], "role": original["ledgerReplica"]["role"]}
        transfer_rule = replication_configuration(original, transfer)
        transfer_plan = ledger_replica_plan({**original, "ledgerReplica": transfer})
        receiving = transfer_plan["destinationPolicy"]
        iam_responses = replication_role_responses(transfer["role"], transfer_plan)
        recovery_policy = recovered_policy

        def aws(region, service, operation, args, *, profile, **options):
            if region == "eu-north-1":
                self.assertEqual(profile, "source-read")
                if service == "iam":
                    self.assertEqual(args[:2], ["--role-name", "replication"])
                    return iam_responses[operation]
                if operation == "get-bucket-replication":
                    return {"ReplicationConfiguration": transfer_rule}
                return self.aws(region, service, operation, args, **options)
            self.assertEqual((region, profile), ("eu-west-2", "recovery-read"))
            self.assertEqual(args[:4], ["--bucket", "clean-recovery", "--expected-bucket-owner", "000000000011"])
            if operation == "get-bucket-policy":
                return {"Policy": json.dumps(recovery_policy)}
            if operation == "get-bucket-replication":
                return None
            source_args = ["--bucket", "custody-journal", "--expected-bucket-owner", "000000000008", *args[4:]]
            with patch.object(self, "objects", good):
                result = self.aws("eu-north-1", service, operation, source_args, **options)
            return {**result, "Name": "clean-recovery"} if operation == "list-object-versions" else result

        with (patch("custody_ledger.aws", side_effect=aws), patch("custody_archive.require_profile_account"),
              patch("custody_ledger.require_profile_account"),
              patch("custody_archive.add_approval", side_effect=lambda _keys, label, plan, key_arn: {
                  **plan, "signatures": [*plan["signatures"], sign(label, plan["manifest"], key_arn)],
              })):
            with self.assertRaisesRegex(ValueError, "distinct excluded ledger record names"):
                draft_repair(original, recovered, pin, [bad, bad], "source-read")
            with self.assertRaisesRegex(ValueError, "missing from the frozen ledger"):
                draft_repair(original, recovered, pin, [*exclusions, "absent.json"], "source-read")
            with self.assertRaisesRegex(ValueError, "independently pinned checkpoint"):
                draft_repair(original, recovered, pin, [bad], "source-read")
            plan = draft_repair(original, recovered, pin, exclusions, "source-read")
            self.assertEqual(plan["manifest"]["excluded"], {
                name: hashlib.sha256((prefix + name).encode()).hexdigest() for name in exclusions
            })

            def sign_after_excluded_version_changes(_keys, label, candidate, key_arn):
                self.versions[bad_key] = "changed-during-signing"
                return {**candidate, "signatures": [sign(label, candidate["manifest"], key_arn)]}

            with (patch.dict(self.versions),
                  patch("custody_archive.add_approval", side_effect=sign_after_excluded_version_changes)):
                with self.assertRaisesRegex(ValueError, "custody bucket custody-journal changed after verification"):
                    sign_repair(original, recovered, pin, plan, "source-read", approval_keys(original)[0]["keyArn"])

            for signer in approval_keys(original)[:2]:
                plan = sign_repair(original, recovered, pin, plan, "source-read", signer["keyArn"])
            self.assertEqual(len(plan["signatures"]), 2)
            csv = StringIO()
            with self.assertRaisesRegex(ValueError, "custody recovery bucket policy differs from the pinned policy"):
                repair_transfer(original, recovered, pin, plan, "source-read", "recovery-read", csv)
            self.assertEqual(csv.getvalue(), "")
            recovery_policy = receiving
            with patch.dict(iam_responses, {"get-role-policy": {"PolicyDocument": {}}}):
                with self.assertRaisesRegex(ValueError, "replication role permissions differ"):
                    repair_transfer(original, recovered, pin, plan, "source-read", "recovery-read", csv)
            self.assertEqual(csv.getvalue(), "")

            def source_changes(*_args, **_options):
                self.objects[prefix + "late.json"] = b"{}"

            with (patch.dict(self.objects),
                  patch("custody_archive.check_recovery_bucket", side_effect=source_changes)):
                with self.assertRaisesRegex(ValueError, "custody bucket custody-journal changed after verification"):
                    repair_transfer(original, recovered, pin, plan, "source-read", "recovery-read", csv)
            self.assertEqual(csv.getvalue(), "")
            with (patch.dict(self.objects),
                  patch("custody_archive.require_uncommitted_record", side_effect=source_changes)):
                with self.assertRaisesRegex(ValueError, "custody bucket custody-journal changed after verification"):
                    draft_repair(original, recovered, pin, exclusions, "source-read")

            repair_transfer(original, recovered, pin, plan, "source-read", "recovery-read", csv)
            recovery_policy = recovered_policy
            self.assertEqual(csv.getvalue().splitlines(), [
                f"custody-journal,{name},{hashlib.sha256(name.encode()).hexdigest()}" for name in sorted(good)
            ])
            self.assertEqual(self.objects[bad_key], copied)
            self.assertEqual(self.objects[other_key], b"{}")

            def promote(repair=plan):
                return verify_promotion(original, recovered, pin, "source-read", "recovery-read", repair=repair)

            self.assertEqual(promote(), pin)
            with self.assertRaisesRegex(ValueError, "original ledger's pinned replica"):
                promote(repair=None)
            with self.assertRaisesRegex(ValueError, "signing quorum"):
                promote({**plan, "signatures": plan["signatures"][:1]})
            different = {**recovered, "ledger": {**recovered["ledger"], "bucket": "different-recovery"}}
            with self.assertRaisesRegex(ValueError, "pinned checkpoint, trust bundles"):
                repair_transfer(original, different, pin, plan, "source-read", "recovery-read", StringIO())
            with patch.dict(self.versions, {bad_key: "changed"}):
                with self.assertRaisesRegex(ValueError, "does not match the frozen ledger version"):
                    promote()
            with patch.dict(good, {bad_key: b"{}"}):
                with self.assertRaisesRegex(ValueError, "independently pinned checkpoint"):
                    promote()
            with patch.dict(self.objects, {prefix + "unexpected.json": b"{}"}):
                with self.assertRaisesRegex(ValueError, "independently pinned checkpoint"):
                    promote()
            with patch.dict(transfer_rule, {}, clear=True):
                with self.assertRaisesRegex(ValueError, "does not match the pinned ledger replica"):
                    repair_transfer(original, recovered, pin, plan, "source-read", "recovery-read", StringIO())
            with patch("time.time", return_value=plan["manifest"]["expiresAt"]):
                with self.assertRaisesRegex(ValueError, "current quorum and deadline"):
                    promote()
            for invalid in (b"", b"x" * (MAX_DOCUMENT_BYTES + 1)):
                with (self.subTest(size=len(invalid)), patch.dict(self.objects, {bad_key: invalid}),
                      patch.dict(self.versions, {bad_key: f"invalid-{len(invalid)}"})):
                    plan_with_invalid = draft_repair(original, recovered, pin, exclusions, "source-read")
                    self.assertEqual(plan_with_invalid["manifest"]["excluded"][bad], f"invalid-{len(invalid)}")
            approved = self.signed_subject(RETIREMENT, {**retired["manifest"], "epoch": "2", "replacementEpoch": "3"})
            self.objects[bad_key] = canonical({**approved, "recoveryProofs": []})
            self.assertEqual(draft_repair(original, recovered, pin, exclusions, "source-read")["manifest"], plan["manifest"])

    def test_receipt_and_target_approvals_protect_only_their_signed_slots(self):
        prefix = f"spr-custody/devnet/{DOMAIN}/"
        receipt = self.sign(self.document(1))
        publish(self.trust, receipt)
        target = self.replacement_target(epoch="1")
        target_name = target_object_name(target)
        invalid_acks = copy.deepcopy(receipt)
        invalid_acks["acknowledgements"][0]["signature"] = receipt["authorization"]["signatures"][0]["signature"]
        for name, payload, protected in (
            ("1.json", receipt, True),
            ("1.json", {**receipt, "acknowledgements": []}, False),
            ("1.json", invalid_acks, False),
            ("2.json", receipt, False),
            (target_name, self.signed_subject(TARGET_APPROVAL, target), True),
            (target_name, self.signed_subject(TARGET_APPROVAL, {**target, "expiresAt": self.now}), False),
            (target_name, self.signed_subject(TARGET_APPROVAL, {**target, "releaseId": "different"}), False),
            (target_name, self.signed_subject(TARGET_APPROVAL, {**target, "securityDomainId": "fa" * 32}), False),
            (target_name, {"manifest": {**target, "hostRole": 0}, "signatures": []}, False),
        ):
            with self.subTest(name=name, protected=protected):
                key_name = prefix + name
                self.objects[key_name] = canonical(payload)
                version = hashlib.sha256(key_name.encode()).hexdigest()
                if protected:
                    with self.assertRaisesRegex(ValueError, "complete custody approval"):
                        require_uncommitted_record(self.trust, name, version)
                else:
                    require_uncommitted_record(self.trust, name, version)

    def test_retirement_inventory_requires_the_actual_replicas_of_its_dependencies(self):
        self.trust["network"] = "mainnet"
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        replacement = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, replacement))
        original_target = {**replacement, "custodyEpoch": "1", "receiptSha256": sha256(old), "releaseId": "old-serving",
                           "instanceId": INSTANCE, "wrappingKeys": [key(slot, 31) for slot in range(1, 7)]}
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, original_target))
        with patch("retirement.qualified_policy", return_value=self.live_qualification(replacement)):
            marker = qualified_manifest(self.trust, None, "1", "2")
            retirement = self.signed_retirement(marker)
            with self.assertRaisesRegex(ValueError, "mainnet retirement requires a pinned custody ledger replica"):
                commit_retirement(self.trust, None, retirement)

        self.trust["ledgerReplica"] = {"bucket": "custody-recovery", "account": "000000000010", "region": "eu-west-1",
                                      **RECOVERY_ROLES,
                                      "role": "arn:aws:iam::000000000008:role/replication"}
        prefix = f"spr-custody/mainnet/{DOMAIN}/"
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
            if operation == "list-object-versions":
                return self.aws(region, service, operation, args, **options)
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
            with (patch("retirement.qualified_policy", return_value=self.live_qualification(replacement)),
                  patch("retirement.require_recovery_quorum")):
                for name in sorted(self.objects):
                    with self.subTest(before_closure=name), patch.dict(source_status, {name: "PENDING"}):
                        with patch("retirement.add_approval") as sign:
                            with self.assertRaisesRegex(ValueError, "has not completed S3 replication"):
                                sign_retirement(self.trust, None, retirement, approval_keys(self.trust)[0]["keyArn"])
                            sign.assert_not_called()
                        with self.assertRaisesRegex(ValueError, "has not completed S3 replication"):
                            commit_retirement(self.trust, None, retirement)
                        self.assertNotIn(marker_key, self.objects)
                self.assertNotIn(marker_key, copied)
                commit_retirement(self.trust, None, retirement)
            with patch.dict(self.objects), patch.dict(self.replica_objects, {marker_key: self.objects[marker_key]}):
                saved = self.objects.pop(marker_key)
                with self.assertRaisesRegex(ValueError, "retirement record in the pinned replica"):
                    require_active_epoch(self.trust, "1")
                with patch("retirement.kms") as kms, self.assertRaisesRegex(ValueError, "object missing"):
                    inspect_keys(self.trust, "1", 1, False, wallet_trust=pathlib.Path("wallet.json"),
                                 replica_profile="recovery-read")
                kms.assert_not_called()

                with (patch("retirement.verify_qualification") as qualify,
                      patch("custody_ledger.storage", wraps=storage) as access):
                    with self.assertRaisesRegex(ValueError, "slot retired/1.json exists in the pinned replica"):
                        commit_retirement(self.trust, None, retirement)
                    self.assertNotIn(marker_key, self.objects)

                    def concurrent_commit(*_args, **_options):
                        self.objects[marker_key] = saved
                        return LiveBoot({"boot": "replacement"}, (self.now + 60) * 1000)

                    qualify.side_effect = concurrent_commit
                    commit_retirement(self.trust, None, retirement)
                    self.assertNotIn("put-object", [entry.args[1] for entry in access.call_args_list])
            with patch.dict(self.replica_objects, {marker_key: self.objects[marker_key]}):
                with patch("custody_ledger.storage", wraps=storage) as access:
                    commit_retirement(self.trust, None, retirement)
                    with patch.dict(replica_change, {"body": b"{}"}):
                        with self.assertRaisesRegex(ValueError, "differs from the pinned replica"):
                            commit_retirement(self.trust, None, retirement)
                    self.assertNotIn("put-object", [entry.args[1] for entry in access.call_args_list])
            _, _, keys, _, _ = retirement_inventory(self.trust, "1", 1)
            self.assertIn(original_target["wrappingKeys"][0], keys)
            self.assertEqual(copied, set(self.objects))
            old_path = prefix + target_object_name(original_target)
            changed_target = {**original_target, "wrappingKeys": [key(slot, 32) for slot in range(1, 7)]}
            changed_body = canonical(self.signed_subject(TARGET_APPROVAL, changed_target))
            old_source_reads = 0

            def changed_inventory(region, service, operation, args, **options):
                nonlocal old_source_reads
                reply = aws(region, service, operation, args, **options)
                if operation != "get-object" or old_path not in args:
                    return reply
                if region == "eu-north-1":
                    old_source_reads += 1
                    if old_source_reads == 1:
                        return reply
                pathlib.Path(args[-1]).write_bytes(changed_body)
                return {**reply, "VersionId": "changed-target-version"}

            with (patch("custody_ledger.aws", side_effect=changed_inventory),
                  patch("retirement.slot_inventory", wraps=slot_inventory) as inventory):
                with self.assertRaisesRegex(ValueError, "changed during verification"):
                    retirement_inventory(self.trust, "1", 1)
                inventory.assert_not_called()
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
            boot = self.live_qualification(replacement)
            with (patch("retirement.check_recovery_bucket") as check_bucket,
                  patch("retirement.inspect_inventory", return_value={"keys": []}) as inspect,
                  patch("retirement.inspect_old_parents", return_value=[]),
                  patch("retirement.pinned_wallet_trust", return_value=self.wallet_pins),
                  patch("retirement.run_command"),
                  patch("retirement.qualify_key_retirement", return_value=boot) as qualify):
                wallet = pathlib.Path("wallet-trust.json")
                with self.assertRaisesRegex(ValueError, "provide --replica-profile"):
                    inspect_keys(self.trust, "1", 1, False, wallet_trust=wallet)
                def check_after_qualification(*_args):
                    inspect.assert_called_once()
                    qualify.assert_called_once()
                    raise ValueError("custody ledger bucket must have no lifecycle configuration")

                check_bucket.side_effect = check_after_qualification
                with self.assertRaisesRegex(ValueError, "must have no lifecycle"):
                    inspect_keys(self.trust, "1", 1, False, wallet_trust=wallet, replica_profile="recovery-read")
                check_bucket.side_effect = None
                result = inspect_keys(self.trust, "1", 1, False, wallet_trust=wallet, replica_profile="recovery-read")
                self.assertEqual(result, {"keys": [], "terminatedParents": [], "replacement": boot.evidence,
                                          "validUntilMs": str(boot.valid_until_ms)})
                check_bucket.assert_called_with(self.trust, self.trust["ledgerReplica"], "recovery-read")
            source_status[marker_key] = "PENDING"
            with self.assertRaisesRegex(ValueError, "has not completed S3 replication"):
                verify_retired(self.trust, None, "1", [f"slot-{n}" for n in range(1, 7)], {}, 1,
                               replica_profile="recovery-read")
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

    def test_first_receipt_write_requires_all_acknowledged_keys_and_policies(self):
        document = self.sign(self.document(1))
        roster = document["authorization"]["manifest"]["custodians"]
        recovery = roster[0]["recoveryKeyArn"]
        acknowledgement = roster[-1]["acknowledgementKey"]["keyArn"]
        with self.assertRaisesRegex(ValueError, "provide --custody-key-profiles"):
            publish_receipt(self.trust, document)
        self.key_inspection.assert_not_called()
        self.recovery_inspection.assert_not_called()
        accounts = KEY_PROFILES
        with self.assertRaisesRegex(ValueError, "missing read-only inspection profile"):
            publish(self.trust, document, key_profiles={account: name for account, name in accounts.items() if int(account) != 1})
        with self.assertRaisesRegex(ValueError, "wrong inspection profile"):
            publish(self.trust, document, key_profiles={**accounts, f"{1:012d}": "wrong-account"})
        for arn, metadata in ((recovery, {"KeyState": "PendingDeletion"}),
                              (acknowledgement, {"KeyState": "Disabled"}),
                              (recovery, {"Arn": acknowledgement})):
            with self.subTest(arn=arn, metadata=metadata), patch.dict(self.key_metadata, {arn: metadata}):
                with self.assertRaisesRegex(ValueError, "expected an enabled, single-region key"):
                    publish(self.trust, document)
                self.assertEqual(self.objects, {})
        for arn in (recovery, acknowledgement):
            with self.subTest(arn=arn), patch.dict(self.key_policies, {arn: {}}):
                with self.assertRaisesRegex(ValueError, "installed .*policy"):
                    publish(self.trust, document)
                self.assertEqual(self.objects, {})
        self.key_inspection.reset_mock()
        self.recovery_inspection.reset_mock()
        self.key_identity.reset_mock()
        publish(self.trust, document)
        self.assertCountEqual([request.args[2] for request in self.key_identity.call_args_list], accounts)
        for requests, keys in (
            (self.recovery_inspection.call_args_list, [member["recoveryKeyArn"] for member in roster]),
            (self.key_inspection.call_args_list, [member["acknowledgementKey"]["keyArn"] for member in roster]),
        ):
            self.assertCountEqual([request.args[0] for request in requests if request.args[1] == "describe-key"], keys)
            self.assertCountEqual([request.args[0] for request in requests if request.args[1] == "get-key-policy"], keys)
        self.key_inspection.reset_mock()
        self.recovery_inspection.reset_mock()
        self.key_identity.reset_mock()
        self.key_inspection.side_effect = AssertionError("an authenticated receipt retry must not need KMS")
        self.recovery_inspection.side_effect = AssertionError("an authenticated receipt retry must not need KMS")
        publish_receipt(self.trust, document)
        self.key_inspection.assert_not_called()
        self.recovery_inspection.assert_not_called()
        self.key_identity.assert_not_called()

    def test_rotation_receipt_rechecks_its_dependencies_through_publication(self):
        publish(self.trust, self.sign(self.document(1)))
        _, predecessor, _ = load_epoch(self.trust, "1")
        rotation, registration = self.rotation_document(predecessor)
        document = self.sign(rotation)
        prefix = f"spr-custody/devnet/{DOMAIN}/"
        successor = prefix + "2.json"

        for name in ("1.json", target_object_name(registration["manifest"])):
            for change_after_write in (False, True):
                with (self.subTest(name=name, change_after_write=change_after_write),
                      patch.dict(self.versions), patch.dict(self.objects), patch.dict(self.timestamps)):
                    def change_dependency():
                        self.versions[prefix + name] = "changed-version"

                    def inspect_keys(*_args):
                        if not change_after_write:
                            change_dependency()

                    def aws(region, service, operation, args, **options):
                        result = self.aws(region, service, operation, args, **options)
                        if operation == "put-object" and successor in args:
                            self.assertTrue(change_after_write, "the receipt must fail before S3 PutObject")
                            change_dependency()
                        return result

                    with (patch("custody_ledger.require_receipt_keys", side_effect=inspect_keys),
                          patch("custody_ledger.aws", side_effect=aws),
                          self.assertRaisesRegex(ValueError, "changed during verification")):
                        publish(self.trust, document)
                    self.assertEqual(successor in self.objects, change_after_write)

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

        approve.reset_mock()
        with patch("custody_ledger.require_active_epoch", side_effect=[None, None, ValueError("custody epoch is retired")]):
            with self.assertRaisesRegex(ValueError, "custody epoch is retired"):
                acknowledge(self.trust, document, 1, 7443, build, review_file)
        approve.assert_called_once()

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
        statements = {item["Sid"]: item for item in ledger_policy(self.trust)["Statement"]}
        self.assertEqual(statements["RequireWriteOnce"]["Condition"], {"StringNotEquals": {"s3:if-none-match": "*"}})
        self.assertEqual(statements["RequireWriteOnce"]["Principal"], "*")
        self.assertEqual(statements["RestrictPublisher"]["Condition"], {"StringNotEquals": {"aws:PrincipalArn": PUBLISHER}})
        self.assertIn("s3:DeleteObject", statements["PreserveCustodyHistory"]["Action"])
        readers = ledger_reader_policy(self.trust)["Statement"]
        for statement in readers:
            self.assertEqual(statements[statement["Sid"]], {**statement, "Principal": {"AWS": [READ_ROLE, PUBLISHER]}})
        self.assertEqual(readers[0]["Resource"], f"arn:aws:s3:::custody-journal/spr-custody/devnet/{DOMAIN}/*")
        self.assertEqual(readers[1]["Condition"], {
            "StringLike": {"s3:prefix": f"spr-custody/devnet/{DOMAIN}/*"},
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
        for administrator, readers, message in (
            (PUBLISHER, [READ_ROLE], "administrator must be a separate role"),
            (READ_ROLE, [READ_ROLE], "administrator must be in the custody ledger account"),
            (ADMIN, [ADMIN], "administrator must be a separate role"),
        ):
            with patch.dict(self.trust["ledger"], administratorRole=administrator, readerRoles=readers):
                with self.assertRaisesRegex(ValueError, message):
                    ledger_policy(self.trust)

    def test_installed_ledger_requires_each_control_on_the_pinned_bucket(self):
        expected = ledger_policy(self.trust)
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

    def live_qualification(self, target, policy_digest="fe" * 32):
        return LiveBoot(self.qualification(target, policy_digest), (self.now + 60) * 1000)

    def attestation_reply(self, evidence):
        targets = [{"validUntilMs": str((self.now + 60) * 1000), **target} for target in evidence["targets"]]
        return canonical({**evidence, "targets": targets})

    def signed_retirement(self, manifest, slots=(1, 2, 3)):
        result = self.signed_subject(RETIREMENT, manifest)
        _, _, roster = load_epoch(self.trust, manifest["replacementEpoch"])
        result["recoveryProofs"] = [sign(RETIREMENT_RECOVERY, manifest, roster[index - 1]["acknowledgementKey"]["keyArn"])
                                    for index in slots]
        return result

    def replacement_target(self, *, epoch="2", **overrides):
        _, receipt, _ = load_epoch(self.trust, epoch)
        return {"network": self.trust["network"], "securityDomainId": DOMAIN, "custodyEpoch": epoch,
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
                  "publications": self.trust["publications"], "targets": [replica]}

        def check(custody_signer=None, *, source_profile=None, replica_profile=None, key_profiles=None, **overrides):
            document = {"policy": {**policy, **overrides}, "signatures": [], "custodySignatures": []}
            return check_release_policy(self.trust, document, custody_signer,
                                        source_profile=source_profile, replica_profile=replica_profile, key_profiles=key_profiles)

        with self.assertRaisesRegex(ValueError, "object missing"):
            check()
        with self.assertRaisesRegex(ValueError, "pinned primary and mirror"):
            check(publications=self.trust["publications"][::-1])
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
        ledger_digest = check()["ledgerDigest"]
        alternate = self.signed_subject(TARGET_APPROVAL, {
            **registered, "wrappingKeys": [key(i, 23) for i in range(1, 7)],
        })
        for records, value in (
            (self.versions, "different-version"),
            (self.timestamps, datetime.fromtimestamp(self.now + 1, timezone.utc).isoformat()),
            (self.objects, canonical(alternate)),
        ):
            with patch.dict(records, {name: value}):
                self.assertNotEqual(check()["ledgerDigest"], ledger_digest)
        self.assertEqual(check()["ledgerDigest"], ledger_digest)
        with self.assertRaisesRegex(ValueError, "requires both --source-profile and --replica-profile"):
            check(replica_profile="replica-read")
        with self.assertRaisesRegex(ValueError, "payment recovery verification requires a pinned custody ledger replica"):
            check(**PAYMENT_PROFILES)
        backup = {"bucket": "custody-recovery", "account": "000000000010", "region": "eu-west-1",
                  **RECOVERY_ROLES,
                  "role": "arn:aws:iam::000000000008:role/replication"}
        with (patch.dict(self.trust, {"ledgerReplica": backup}), patch("custody_ledger.require_replicated_custody"),
              patch("custody_ledger.require_payment_recovery_quorums") as recovery,
              patch("custody_ledger.check_source_ledger") as inspect_source,
              patch("custody_ledger.check_recovery_bucket") as inspect_replica):
            check(**PAYMENT_PROFILES)
            recovery.assert_called_once()
            inspect_source.assert_called_once_with(self.trust, "source-read")
            inspect_replica.assert_called_once_with(self.trust, backup, "replica-read")
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
                                   "nextCutover": str(incoming["activeFrom"]), "canaryDigest": "35" * 32,
                                   "ledgerDigest": ledger_digest})
        self.now = incoming["activeFrom"]
        with self.assertRaisesRegex(ValueError, "active custody approval roster"):
            check(custody_signer=signer)
        next_pin = approval_roster(self.trust)["keys"][0]
        self.assertEqual(check(custody_signer=(next_pin["keyArn"], base64.b64decode(next_pin["publicKey"])[-65:].hex())),
                         {"custodyKeys": [base64.b64decode(pin["publicKey"])[-65:].hex() for pin in incoming["keys"]],
                          "nextCutover": None, "canaryDigest": "35" * 32, "ledgerDigest": ledger_digest})
        def close_during_target_read(*args, **options):
            subject = read_registered_target(*args, **options)
            if subject["mode"] == "serve":
                self.objects[f"spr-custody/devnet/{DOMAIN}/retired/2.json"] = b"{}"
            return subject

        with patch("custody_ledger.read_registered_target", side_effect=close_during_target_read):
            with self.assertRaisesRegex(ValueError, "cannot verify retirement"):
                check()

    def test_mainnet_activation_requires_matching_replicas_of_custody_history_and_serving_targets(self):
        self.trust["network"] = "mainnet"
        publish(self.trust, self.sign(self.document(1)))
        _, previous, _ = load_epoch(self.trust, "1")
        rotated, rotation_approval = self.rotation_document(previous)
        publish(self.trust, self.sign(rotated))
        _, second, _ = load_epoch(self.trust, "2")
        rotated, second_rotation_approval = self.rotation_document(second, variant="cd")
        publish(self.trust, self.sign(rotated))
        _, receipt, _ = load_epoch(self.trust, "3")
        registered = self.replacement_target(epoch="3")
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, registered))
        target = {**target_attestation(registered), "custodyEpoch": "3",
                  "executableSha256": registered["executableSha256"], "custodyDigest": sha256(receipt["custody"])}
        policy = {"action": "activate", "recoveryOnly": False, "network": "mainnet", "securityDomainId": DOMAIN,
                  "noteSeedCommitment": receipt["custody"]["noteSeedCommitment"], "minimumCustodyEpoch": "3",
                  "publications": self.trust["publications"], "targets": [target]}
        document = {"policy": policy, "signatures": [], "custodySignatures": []}
        with self.assertRaisesRegex(ValueError, "mainnet activation requires a pinned custody ledger replica"):
            check_release_policy(self.trust, document)

        replica = {"bucket": "custody-recovery", "account": "000000000010", "region": "eu-west-1",
                   **RECOVERY_ROLES,
                   "role": "arn:aws:iam::000000000008:role/replication"}
        self.trust["ledgerReplica"] = replica
        expected = {"1.json", "2.json", "3.json", target_object_name(rotation_approval["manifest"]),
                    target_object_name(second_rotation_approval["manifest"]), target_object_name(registered)}
        copied = set()
        missing = set()
        changes = {}

        def read(trust, name):
            payload, metadata = read_stored_payload(self.trust, name)
            if trust is self.trust:
                return payload, {**metadata, "ReplicationStatus": "COMPLETED"}
            self.assertEqual(trust["ledger"], {field: value for field, value in replica.items() if field != "role"})
            copied.add(name)
            if name in missing:
                raise ValueError("object missing")
            return payload, {**metadata, "ReplicationStatus": "REPLICA", **changes.get(name, {})}

        for inspection in ({}, {"source_profile": "source-read"}, {"replica_profile": "replica-read"}):
            with self.subTest(inspection=inspection):
                with self.assertRaisesRegex(ValueError, "requires both --source-profile and --replica-profile"):
                    check_release_policy(self.trust, document, **inspection)

        with (patch("custody_ledger.read_stored_payload", side_effect=read),
              patch("custody_ledger.require_payment_recovery_quorums"),
              patch("custody_ledger.check_source_ledger") as inspect_source,
              patch("custody_ledger.check_recovery_bucket") as inspect_replica):
            fingerprint = check_release_policy(self.trust, document, **PAYMENT_PROFILES)["ledgerDigest"]
            self.assertEqual(copied, expected)
            inspect_source.assert_called_once_with(self.trust, "source-read")
            inspect_replica.assert_called_once_with(self.trust, replica, "replica-read")
            selected = target_object_name(registered)
            substituted = {**registered, "wrappingKeys": [key(slot, 55) for slot in range(1, 7)]}
            substituted_body = canonical(self.signed_subject(TARGET_APPROVAL, substituted))
            selected_reads = 0

            def changed_registration(trust, name):
                nonlocal selected_reads
                payload, metadata = read(trust, name)
                if name != selected:
                    return payload, metadata
                selected_reads += 1
                if selected_reads == 1:
                    return payload, metadata
                return substituted_body, {**metadata, "VersionId": "changed-target-version"}

            with patch("custody_ledger.read_stored_payload", side_effect=changed_registration):
                with self.assertRaisesRegex(ValueError, "changed during verification"):
                    check_release_policy(self.trust, document, **PAYMENT_PROFILES)
            prefix = f"spr-custody/mainnet/{DOMAIN}/"
            registration_path = prefix + selected
            with patch.dict(self.versions):
                def replace_during_bucket_inspection(*_):
                    self.versions[registration_path] = "changed-target-version"

                inspect_replica.side_effect = replace_during_bucket_inspection
                with self.assertRaisesRegex(ValueError, "changed during verification"):
                    check_release_policy(self.trust, document, **PAYMENT_PROFILES)
                inspect_replica.side_effect = None
            with patch.dict(self.replica_objects, {prefix + "retired/3.json": b"{}"}):
                with self.assertRaisesRegex(ValueError, "retirement record in the pinned replica"):
                    check_release_policy(self.trust, document, **PAYMENT_PROFILES)
            receipt_at = datetime.fromisoformat(self.timestamps[prefix + "3.json"]).timestamp()
            before_receipt = datetime.fromtimestamp(receipt_at - 1, timezone.utc).isoformat()
            with patch.dict(self.timestamps, {prefix + target_object_name(registered): before_receipt}):
                with self.assertRaisesRegex(ValueError, "target registration precedes its custody receipt"):
                    check_release_policy(self.trust, document, **PAYMENT_PROFILES)
            genesis_path = prefix + "1.json"
            for old_record in (genesis_path, prefix + target_object_name(rotation_approval["manifest"])):
                with self.subTest(old_record=old_record), patch.dict(self.versions, {old_record: "historical-replacement"}):
                    self.assertNotEqual(
                        check_release_policy(self.trust, document, **PAYMENT_PROFILES)["ledgerDigest"], fingerprint,
                    )
            genesis = json.loads(self.objects[genesis_path])
            with patch.dict(self.objects, {genesis_path: canonical({**genesis, "acknowledgements": []})}):
                with self.assertRaisesRegex(ValueError, "signing quorum"):
                    check_release_policy(self.trust, document, **PAYMENT_PROFILES)
            unrelated_genesis = self.sign(self.document(1, variant="cd"))
            with patch.dict(self.objects, {genesis_path: canonical(unrelated_genesis)}):
                with self.assertRaisesRegex(ValueError, "canonical previous receipt"):
                    check_release_policy(self.trust, document, **PAYMENT_PROFILES)
            first_rotation = rotation_approval["manifest"]
            registered_at = datetime.fromisoformat(self.timestamps[prefix + target_object_name(first_rotation)]).timestamp()
            early_successor = datetime.fromtimestamp(registered_at - 1, timezone.utc).isoformat()
            with patch.dict(self.timestamps, {prefix + "2.json": early_successor}):
                with self.assertRaisesRegex(ValueError, "rotation registration must be recorded between"):
                    check_release_policy(self.trust, document, **PAYMENT_PROFILES)
            late_write = datetime.fromtimestamp(first_rotation["expiresAt"], timezone.utc).isoformat()
            with patch.dict(self.timestamps, {prefix + target_object_name(first_rotation): late_write}):
                with self.assertRaisesRegex(ValueError, "target approval has expired"):
                    check_release_policy(self.trust, document, **PAYMENT_PROFILES)
            for name in sorted(expected):
                missing.add(name)
                with self.subTest(missing=name), self.assertRaisesRegex(ValueError, "from the pinned replica"):
                    check_release_policy(self.trust, document, **PAYMENT_PROFILES)
                missing.clear()
            changes[target_object_name(registered)] = {"VersionId": "a-different-version"}
            with self.assertRaisesRegex(ValueError, "differs from the pinned replica"):
                check_release_policy(self.trust, document, **PAYMENT_PROFILES)

    def test_mainnet_payments_require_three_qualified_pairs_on_every_registered_target(self):
        self.trust["network"] = "mainnet"
        publish(self.trust, self.sign(self.document(1)))
        _, receipt, custodians = load_epoch(self.trust, "1")
        self.trust["ledgerReplica"] = {"bucket": "custody-recovery", "account": "000000000010", "region": "eu-west-1",
                                       **RECOVERY_ROLES,
                                       "role": "arn:aws:iam::000000000008:role/replication"}
        primary = self.replacement_target(epoch="1", releaseId="primary")
        standby = self.replacement_target(epoch="1", releaseId="standby", wrappingKeys=[key(i, 55) for i in range(1, 7)])
        targets = []
        for registered in (primary, standby):
            register_target(self.trust, self.signed_subject(TARGET_APPROVAL, registered))
            targets.append({**target_attestation(registered), "custodyEpoch": "1",
                            "executableSha256": registered["executableSha256"], "custodyDigest": sha256(receipt["custody"])})
        policy = {"action": "activate", "recoveryOnly": False, "network": "mainnet", "securityDomainId": DOMAIN,
                  "noteSeedCommitment": receipt["custody"]["noteSeedCommitment"], "minimumCustodyEpoch": "1",
                  "publications": self.trust["publications"], "targets": targets}
        document = {"policy": policy, "signatures": [], "custodySignatures": []}
        recovery = [member["recoveryKeyArn"] for member in custodians]
        unavailable = set(recovery[:2])
        bad_metadata = set()
        bad_policy = set()
        installed = {
            key_arn: policy for slot, member in enumerate(custodians, 1)
            for key_arn, policy in slot_inventory(self.trust, "1", member, [primary, standby], slot)[1].items()
        }

        def describe(arn, operation, args=(), *, profile):
            self.assertEqual(profile, PAYMENT_PROFILES["key_profiles"][arn.split(":")[4]])
            if operation == "get-key-policy":
                self.assertEqual(args, ["--policy-name", "default"])
                return {"Policy": json.dumps({} if arn in bad_policy else installed[arn])}
            self.assertEqual(operation, "describe-key")
            if arn in unavailable:
                raise ValueError("key temporarily unavailable")
            return {"KeyMetadata": {"Arn": arn, "KeySpec": "RSA_2048", "KeyUsage": "ENCRYPT_DECRYPT",
                                    "Origin": "AWS_KMS", "MultiRegion": False,
                                    "KeyState": "PendingDeletion" if arn in bad_metadata else "Enabled"}}

        def verify_profile(profile, region, account):
            if profile != PAYMENT_PROFILES["key_profiles"][account]:
                raise ValueError("wrong profile account")

        with (patch("custody_ledger.require_replicated_custody"),
              patch("relay.kms", side_effect=describe) as kms,
              patch("custody_ledger.require_profile_account", side_effect=verify_profile) as sts,
              patch("custody_ledger.check_source_ledger") as inspect_source,
              patch("custody_ledger.check_recovery_bucket") as inspect_replica):
            ledger_profiles = {name: value for name, value in PAYMENT_PROFILES.items() if name != "key_profiles"}
            with self.assertRaisesRegex(ValueError, "provide --custody-key-profiles"):
                check_release_policy(self.trust, document, **ledger_profiles)
            check_release_policy(self.trust, document, **PAYMENT_PROFILES)
            self.assertCountEqual([call.args[0] for call in kms.call_args_list if call.args[1] == "describe-key"],
                                  [*recovery, *primary["wrappingKeys"], *standby["wrappingKeys"]])
            self.assertEqual(sts.call_count, 6)
            self.assertCountEqual(self.payment_host.call_args_list, [call(target, "host-read", slots={3, 4, 5, 6}, minimum=3) for target in (primary, standby)])

            def inspect_parent(target, profile, **_options):
                if profile is None or target == standby:
                    raise ValueError("host bootstrap policy differs")

            self.payment_host.side_effect = inspect_parent
            with self.assertRaisesRegex(ValueError, "host bootstrap policy differs"):
                check_release_policy(self.trust, document, **PAYMENT_PROFILES)
            self.payment_host.side_effect = None
            profiles = {**PAYMENT_PROFILES["key_profiles"], "000000000003": "unexpected-profile"}
            kms.reset_mock()
            check_release_policy(self.trust, document, key_profiles=profiles, **ledger_profiles)
            self.assertTrue(all(request.args[0].split(":")[4] != "000000000003" for request in kms.call_args_list))
            with self.assertRaisesRegex(ValueError, "unavailable attested bootstrap slot"):
                check_release_policy(self.trust, document, key_profiles=profiles, **ledger_profiles,
                                     bootstrap_slots=[[3, 4, 5], [3, 4, 5]])
            profiles = {account: profile for account, profile in PAYMENT_PROFILES["key_profiles"].items()
                        if int(account) in {3, 4, 5} or account == HOST_ACCOUNT}
            check_release_policy(self.trust, document, key_profiles=profiles, **ledger_profiles)
            for arn in (recovery[2], standby["wrappingKeys"][2]):
                bad_policy.add(arn)
                with self.assertRaisesRegex(ValueError, "unavailable attested bootstrap slot"):
                    check_release_policy(self.trust, document, **PAYMENT_PROFILES, bootstrap_slots=[[3, 4, 5], [3, 4, 5]])
                bad_policy.remove(arn)
            bad_metadata.add(standby["wrappingKeys"][-1])
            check_release_policy(self.trust, document, **PAYMENT_PROFILES,
                                 bootstrap_slots=[[3, 4, 6], [3, 4, 5]])
            with self.assertRaisesRegex(ValueError, "target standby has an unavailable attested bootstrap slot"):
                check_release_policy(self.trust, document, **PAYMENT_PROFILES,
                                     bootstrap_slots=[[3, 4, 5], [3, 4, 6]])
            for invalid in ([[3, 4, 5]], [[3, 3, 4], [3, 4, 5]], [[3, 4, 7], [3, 4, 5]]):
                with self.subTest(slots=invalid), self.assertRaisesRegex(ValueError, "three distinct attested bootstrap slots"):
                    check_release_policy(self.trust, document, **PAYMENT_PROFILES, bootstrap_slots=invalid)
            # Each set has four keys, but only two slots have both keys.
            bad_metadata.update(standby["wrappingKeys"][-2:])
            with self.assertRaisesRegex(ValueError, "target standby requires three enabled recovery and wrapping pairs"):
                check_release_policy(self.trust, document, **PAYMENT_PROFILES)
            check_release_policy(self.trust, {**document, "policy": {**policy, "targets": targets[:1]}},
                                 **PAYMENT_PROFILES)

            kms.reset_mock()
            inspect_replica.reset_mock()
            inspect_source.side_effect = ValueError("unsafe source bucket")
            with self.assertRaisesRegex(ValueError, "unsafe source bucket"):
                check_release_policy(self.trust, {**document, "policy": {**policy, "targets": targets[:1]}},
                                     **PAYMENT_PROFILES)
            inspect_source.side_effect = None
            with patch("custody_ledger.check_recovery_bucket", side_effect=ValueError("unsafe replica bucket")):
                with self.assertRaisesRegex(ValueError, "unsafe replica bucket"):
                    check_release_policy(self.trust, {**document, "policy": {**policy, "targets": targets[:1]}},
                                         **PAYMENT_PROFILES)
            kms.reset_mock()
            self.payment_host.reset_mock()
            inspect_source.reset_mock()
            inspect_replica.reset_mock()
            check_release_policy(self.trust, {**document, "policy": {**policy, "recoveryOnly": True}})
            kms.assert_not_called()
            self.payment_host.assert_not_called()
            inspect_source.assert_not_called()
            inspect_replica.assert_not_called()

            prefix = f"spr-custody/mainnet/{DOMAIN}/"
            standby_path = prefix + target_object_name(standby)
            other_slots = {**standby, "wrappingKeys": standby["wrappingKeys"][::-1]}
            with patch.dict(self.objects, {standby_path: canonical(self.signed_subject(TARGET_APPROVAL, other_slots))}):
                with self.assertRaisesRegex(ValueError, "six custody slots|separate keys and roles"):
                    check_release_policy(self.trust, document, **PAYMENT_PROFILES)
            kms.assert_not_called()

            bad_metadata.clear()
            def retire_after_key_read(arn, operation, args=(), **options):
                self.objects[prefix + "retired/1.json"] = b"{}"
                return describe(arn, operation, args, **options)

            kms.side_effect = retire_after_key_read
            with self.assertRaisesRegex(ValueError, "cannot verify retirement"):
                check_release_policy(self.trust, document, **PAYMENT_PROFILES)

    def test_payment_checks_profiles_for_both_custody_rosters_in_an_overlap(self):
        targets, profiles, policies = [], {HOST_ACCOUNT: "host-read"}, {}
        for epoch, first in (("1", 21), ("2", 31)):
            accounts = range(first, first + 6)
            members = [{
                "recoveryKeyArn": key(account, 1),
                "custodianRole": f"arn:aws:iam::{account:012d}:role/custodian",
                "retirementRole": f"arn:aws:iam::{account:012d}:role/retirement",
            } for account in accounts]
            target = {
                "hostRole": HOST, "hostRegion": REGION, "instanceId": INSTANCE, "releaseId": f"release-{epoch}", "pcrs": PINS,
                "wrappingKeys": [key(account, 2) for account in accounts],
            }
            pairs = [(member["recoveryKeyArn"], wrapping)
                     for member, wrapping in zip(members, target["wrappingKeys"], strict=True)]
            targets.append((epoch, target, members, pairs, [1, 3, 5]))
            for slot in (1, 3, 5):
                account = first + slot - 1
                profiles[f"{account:012d}"] = f"key-read-{account}"
                policies.update(slot_inventory(self.trust, epoch, members[slot - 1], [target], slot)[1])

        def inspect(key_arn, *, profile):
            self.assertEqual(profile, profiles[key_arn.split(":")[4]])
            return {}, policies[key_arn]

        with (patch("custody_ledger.require_profile_account") as identity,
              patch("custody_ledger.inspect_rsa_key", side_effect=inspect) as keys):
            require_payment_recovery_quorums(self.trust, targets, profiles)
            self.assertCountEqual([request.args[2] for request in identity.call_args_list], set(profiles) - {HOST_ACCOUNT})
            self.assertCountEqual([request.args[0] for request in keys.call_args_list], policies)
            self.assertCountEqual(self.payment_host.call_args_list, [call(entry[1], "host-read", slots=[1, 3, 5], minimum=3) for entry in targets])
            del profiles[f"{35:012d}"]
            with self.assertRaisesRegex(ValueError, "custody epoch 2 target release-2 requires three"):
                require_payment_recovery_quorums(self.trust, targets, profiles)

    def test_revocation_checks_the_pinned_pair_without_reading_the_ledger(self):
        policy = {"action": "revoke", "recoveryOnly": True, "targets": [], "network": "devnet",
                  "securityDomainId": DOMAIN, "publications": self.trust["publications"]}
        with patch("custody_ledger.storage", side_effect=AssertionError("revocation needs only local pins")):
            document = {"policy": policy, "signatures": [], "custodySignatures": []}
            self.assertIsNone(check_release_policy(self.trust, document))
            self.assertIsNone(check_release_policy({**self.trust, "network": "mainnet"},
                                                   {**document, "policy": {**policy, "network": "mainnet"}}))
            for alternate in (None, self.trust["publications"][::-1]):
                with self.assertRaisesRegex(ValueError, "pinned primary and mirror"):
                    check_release_policy(self.trust, {**document, "policy": {**policy, "publications": alternate}})

    def test_key_deletion_rechecks_the_pinned_replacement_receipt(self):
        receipt = record(self.trust, self.document(1))[0]
        other = record(self.trust, self.document(1, variant="cd"))[0]
        qualification = {"replacementEpoch": "1", "replacementReceiptSha256": sha256(receipt),
                         "replacementBootstrap": {"bootKeyId": "de" * 32, "bootedAtMs": str(self.booted_at_ms),
                                                  "slots": [1, 2, 3]}}
        with (patch("retirement.pinned_wallet_trust", return_value=self.wallet_pins),
              patch("retirement.load_epoch", return_value=(None, other, [])),
              patch("retirement.replacement_targets") as targets, patch("retirement.attested_boots"),
              patch("retirement.ready_boot")):
            with self.assertRaisesRegex(ValueError, "replacement custody receipt changed"):
                qualify_key_retirement(self.trust, None, qualification, 0)
            targets.assert_not_called()

    def test_later_boot_cannot_change_an_already_qualified_registration(self):
        qualified = {"replacementTargetIdentity": "ab" * 32, "replacementTargetSha256": "cd" * 32}
        changed = {**qualified, "replacementTargetSha256": "ef" * 32}
        with self.assertRaisesRegex(ValueError, "registration changed during verification"):
            verify_boot_registration(self.trust, qualified, changed)

    def test_retirement_rechecks_replica_records_after_inspecting_bucket_protections(self):
        replica = {"bucket": "custody-recovery", "account": "000000000010", "region": "eu-west-1",
                   **RECOVERY_ROLES, "role": "arn:aws:iam::000000000008:role/replication"}
        qualification = {"network": "devnet", "securityDomainId": DOMAIN, "epoch": "1", "replacementEpoch": "2",
                         "replacementCustodyDigest": "ab" * 32, "replacementTargetIdentity": "bc" * 32}
        boot = LiveBoot({"walletPolicyDigest": "cd" * 32, "replacementTargetIdentity": "de" * 32},
                        (self.now + 60) * 1000)
        with (patch("retirement.check_recovery_bucket") as check, patch("retirement.read_replicated_record") as read,
              patch("retirement.pinned_wallet_trust", return_value=self.wallet_pins), patch("retirement.run_command") as query):
            receipt, selected = "2.json", f"targets/2/{boot.evidence['replacementTargetIdentity']}.json"
            recorded = {name: ("version", "2026-11-01T00:00:00+00:00", "ab" * 32) for name in (receipt, selected)}

            def missing_registration(_trust, _destination, name, *, checkpoint_records):
                check.assert_called_once_with(self.trust, replica, "replica-read")
                self.assertIs(checkpoint_records, recorded)
                if name == receipt:
                    return b"{}", recorded[receipt]
                self.assertEqual(name, selected)
                raise ValueError("selected replacement has disappeared from the pinned replica")

            read.side_effect = missing_registration
            with self.assertRaisesRegex(ValueError, "selected replacement has disappeared"):
                confirm_retirement_policy(self.trust, None, qualification, boot, replica, "replica-read", targets=(),
                                          observed_records=recorded)
            self.assertCountEqual([entry.args[2] for entry in read.call_args_list], [receipt, selected])
            query.assert_not_called()

    @patch("retirement.require_recovery_quorum")
    def test_retirement_checks_the_signed_replacement_after_the_write_inventory(self, quorum):
        publish(self.trust, self.sign(self.document(1)))
        rotated, _ = self.rotation_document(load_epoch(self.trust, "1")[1])
        publish(self.trust, self.sign(rotated))
        target = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, target))
        old = self.live_qualification(target)
        marker = f"spr-custody/devnet/{DOMAIN}/retired/1.json"
        with patch("retirement.qualified_policy", return_value=old):
            document = self.signed_retirement(qualified_manifest(self.trust, None, "1", "2"))

        for change, error in (
            ("revocation", "wallet policy revoked"),
            ("policy", "wallet policy changed before retirement"),
            ("new boot", "wallet policy changed before retirement"),
            ("key loss", "key is unavailable"),
            ("predecessor changed", "changed during verification"),
            ("replacement closure", "cannot verify retirement record for epoch 2"),
            ("stable", None),
        ):
            with self.subTest(change=change), patch.dict(self.versions), patch.dict(self.objects):
                after_inventory = False

                def inspect_then_publish(trust, name, record, confirm, *, before_write):
                    def checked_write():
                        nonlocal after_inventory
                        after_inventory = True
                        before_write()
                    return write_once(trust, name, record, confirm, before_write=checked_write)

                def qualified(*_args, **_kwargs):
                    if not after_inventory or change in ("stable", "predecessor changed"):
                        return old
                    if change == "revocation":
                        raise ValueError("wallet policy revoked")
                    if change == "replacement closure":
                        # A record occupied the closure slot during re-attestation.
                        self.objects[f"spr-custody/devnet/{DOMAIN}/retired/2.json"] = b"{}"
                        return old
                    evidence = copy.deepcopy(old.evidence)
                    if change == "policy":
                        evidence["walletPolicyDigest"] = "f0" * 32
                    else:
                        evidence["replacementBootstrap"]["bootKeyId"] = "f1" * 32
                    return LiveBoot(evidence, old.valid_until_ms)

                def check_keys(*_args, **_kwargs):
                    if after_inventory and change == "key loss":
                        raise ValueError("proven replacement key is unavailable")
                    if after_inventory and change == "predecessor changed":
                        self.versions[f"spr-custody/devnet/{DOMAIN}/1.json"] = "changed-version"

                quorum.side_effect = check_keys

                with (patch("retirement.qualified_policy", side_effect=qualified),
                      patch("retirement.write_once", side_effect=inspect_then_publish),
                      patch("custody_ledger.storage", wraps=storage) as storage_call):
                    if error is None:
                        commit_retirement(self.trust, None, document)
                        self.assertIn(marker, self.objects)
                    else:
                        with self.assertRaisesRegex(ValueError, error):
                            commit_retirement(self.trust, None, document)
                        self.assertNotIn("put-object", [entry.args[1] for entry in storage_call.call_args_list])
                        self.assertNotIn(marker, self.objects)
    @patch("retirement.require_recovery_quorum")
    @patch("retirement.qualified_policy")
    def test_retirement_readback_rejects_a_changed_predecessor_version(self, qualification, _keys):
        publish(self.trust, self.sign(self.document(1)))
        rotation, _ = self.rotation_document(load_epoch(self.trust, "1")[1])
        publish(self.trust, self.sign(rotation))
        target = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, target))
        qualification.return_value = self.live_qualification(target)
        document = self.signed_retirement(qualified_manifest(self.trust, None, "1", "2"))
        prefix = f"spr-custody/devnet/{DOMAIN}/"
        marker = prefix + "retired/1.json"

        def change_on_write(region, service, operation, args, **options):
            result = self.aws(region, service, operation, args, **options)
            if operation == "put-object" and marker in args:
                self.versions[prefix + "1.json"] = "changed-version"
            return result

        with (patch("custody_ledger.aws", side_effect=change_on_write),
              self.assertRaisesRegex(ValueError, "changed during verification")):
            commit_retirement(self.trust, None, document)
        self.assertIn(marker, self.objects)

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
        qualification.return_value = self.live_qualification(replacement)
        marker = qualified_manifest(self.trust, None, "1", "2")
        retired = self.signed_retirement(marker)
        qualification.return_value = self.live_qualification(replacement, "cd" * 32)
        with self.assertRaisesRegex(ValueError, "no longer matches"):
            commit_retirement(self.trust, None, retired)
        require_registered_target(self.trust, target)
        qualification.return_value = self.live_qualification(replacement)
        concurrent = {**target, "releaseId": "other-slot", "wrappingKeys": [key(account, 12) for account in range(1, 7)]}

        def register_during_retirement(region, service, operation, args, **options):
            reply = self.aws(region, service, operation, args, **options)
            if operation == "put-object" and args[args.index("--key") + 1].endswith("/" + target_object_name(concurrent)):
                commit_retirement(self.trust, None, retired)
            return reply

        with patch("custody_ledger.aws", side_effect=register_during_retirement):
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
        _, role, inventory, _, _ = retirement_inventory(self.trust, "1", 1)
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
        qualification.return_value = self.live_qualification(replacement)
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

    def test_pre_deletion_inspection_requires_a_post_commit_boot_with_the_proven_slots(self):
        publish(self.trust, self.sign(self.document(1)))
        rotated, _ = self.rotation_document(load_epoch(self.trust, "1")[1])
        publish(self.trust, self.sign(rotated))
        replacement = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, replacement))
        with (patch("retirement.qualified_policy", return_value=self.live_qualification(replacement)),
              patch("retirement.require_recovery_quorum")):
            marker = qualified_manifest(self.trust, None, "1", "2")
            self.now += 2
            commit_retirement(self.trust, None, self.signed_retirement(marker))
        published_at = self.now

        self.now += 1
        directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        wallet = directory / "wallet.json"
        wallet.write_bytes(self.wallet_pins)
        self.trust["walletTrustSha256"] = hashlib.sha256(wallet.read_bytes()).hexdigest()
        boot = {**marker["replacementBootstrap"], "bootKeyId": "ae" * 32, "bootedAtMs": str(self.now * 1000)}
        observed = {**target_attestation(replacement), "bootstrap": boot}
        policy_digest = "bf" * 32
        expected = {**self.qualification(replacement, policy_digest), "replacementBootstrap": boot}
        host_profiles = {"000000000007": "old-host-read"}
        def inspect_slot():
            return inspect_keys(self.trust, "1", 1, False, wallet_trust=wallet, host_profiles=host_profiles)

        def evidence(*targets):
            return self.attestation_reply({"policyDigest": policy_digest, "targets": list(targets)})

        with (patch("retirement.inspect_inventory", side_effect=lambda *_args: {"keys": []}) as inspect,
              patch("retirement.require_recovery_quorum") as quorum, patch("retirement.run_command") as query,
              patch("retirement.require_profile_account") as identity, patch("retirement.require_terminated_parent") as parent):
            with self.assertRaisesRegex(ValueError, "provide --wallet-trust"):
                inspect_keys(self.trust, "1", 1, False)
            with self.assertRaisesRegex(ValueError, "mainnet key retirement requires a pinned custody ledger replica"):
                inspect_keys({**self.trust, "network": "mainnet"}, "1", 1, False, wallet_trust=wallet)
            inspect.assert_not_called()

            with self.assertRaisesRegex(ValueError, "provide one host inspection profile"):
                inspect_keys(self.trust, "1", 1, False, wallet_trust=wallet)
            identity.side_effect = ValueError("host profile is in the wrong account")
            with self.assertRaisesRegex(ValueError, "wrong account"):
                inspect_slot()
            identity.assert_called_once_with("old-host-read", REGION, "000000000007")
            parent.assert_not_called()
            identity.side_effect = None
            parent.side_effect = ValueError("old parent is still running")
            with self.assertRaisesRegex(ValueError, "old parent is still running"):
                inspect_slot()
            query.assert_not_called()
            parent.side_effect = None
            parent.return_value = {"instanceId": INSTANCE, "state": "terminated"}
            query.return_value.stdout = evidence(observed)
            result = inspect_slot()
            self.assertEqual(result["terminatedParents"], [parent.return_value])
            self.assertEqual(result["replacement"], expected)
            self.assertEqual(query.call_count, 3)
            self.assertEqual(query.call_args.args[0][-2:], ["policy", policy_digest])
            self.assertEqual(query.call_args.kwargs["input"], self.wallet_pins)
            _, _, members = load_epoch(self.trust, "2")
            quorum.assert_called_once_with(self.trust, {**marker, **expected}, [members[slot - 1] for slot in boot["slots"]], None)

            prefix = f"spr-custody/devnet/{DOMAIN}/"
            for ledger, name, value, error in (
                (self.versions, "retired/1.json", "new-version", "retired/1.json changed after checkpoint"),
                (self.objects, f"targets/1/{'cd' * 32}.json", b"{}", "retired target inventory changed"),
            ):
                with self.subTest(name=name), patch.dict(ledger):
                    def change_ledger(*_args):
                        ledger[prefix + name] = value

                    quorum.side_effect = change_ledger
                    query.reset_mock()
                    with self.assertRaisesRegex(ValueError, error):
                        inspect_slot()
                    self.assertEqual(query.call_count, 2)
            quorum.side_effect = None

            different_slots = [4, 5, 6] if boot["slots"] != [4, 5, 6] else [1, 2, 3]
            for other in (
                {**observed, "bootstrap": {**boot, "slots": different_slots}},
                {**observed, "bootstrap": marker["replacementBootstrap"]},
                {**observed, "bootstrap": {**boot, "bootedAtMs": str(published_at * 1000 - 1)}},
                {**observed, "bootstrap": {**boot, "bootedAtMs": str(published_at * 1000 + 999)}},
                {**observed, "pcrs": {**observed["pcrs"], "4": "ab" * 48}},
            ):
                query.return_value.stdout = evidence(other)
                with self.subTest(other=other), self.assertRaisesRegex(ValueError, "no fresh attested serving boot"):
                    inspect_slot()
            query.return_value.stdout = evidence(observed)
            with patch("retirement.require_active_epoch", side_effect=[None, ValueError("custody epoch is retired")]):
                with self.assertRaisesRegex(ValueError, "custody epoch is retired"):
                    inspect_slot()

            def check_epoch_after_expiry(_trust, _epoch):
                if check_epoch.call_count == 2:
                    self.now += 1

            query.return_value.stdout = evidence({**observed, "validUntilMs": str((self.now + 1) * 1000)})
            with (patch.object(self, "now", self.now),
                  patch("retirement.require_active_epoch", side_effect=check_epoch_after_expiry) as check_epoch):
                with self.assertRaisesRegex(ValueError, "replacement evidence expired"):
                    inspect_slot()
            query.return_value.stdout = evidence(observed)
            query.reset_mock()
            quorum.side_effect = ValueError("proven replacement key is unavailable")
            with self.assertRaisesRegex(ValueError, "replacement key is unavailable"):
                inspect_slot()
            query.assert_called_once()
            quorum.side_effect = None
            query.reset_mock()
            self.assertEqual(inspect_keys(self.trust, "1", 1, True), {"keys": []})
            query.assert_not_called()

            standby = {**replacement, "instanceId": "i-1234567890abcdefc", "releaseId": "standby",
                       "wrappingKeys": [key(slot, 39) for slot in range(1, 7)]}
            standby_observed = {**target_attestation(standby), "bootstrap": boot}
            query.return_value.stdout = evidence(standby_observed)
            with self.assertRaisesRegex(ValueError, "no fresh attested serving boot"):
                inspect_slot()
            standby_approval = self.signed_subject(TARGET_APPROVAL, standby)
            register_target(self.trust, standby_approval)
            standby_expected = {**self.qualification(standby, policy_digest), "replacementBootstrap": boot}
            self.assertEqual(inspect_slot()["replacement"], standby_expected)
            quorum.assert_called_with(self.trust, {**marker, **standby_expected}, [members[slot - 1] for slot in boot["slots"]], None)

            standby_restart = {**standby_observed, "bootstrap": {**boot, "bootKeyId": "ab" * 32}}
            query.side_effect = [SimpleNamespace(stdout=evidence(target)) for target in (standby_observed, standby_restart)]
            with self.assertRaisesRegex(ValueError, "no fresh attested serving boot"):
                inspect_slot()
            query.side_effect = None

            replica = {"bucket": "custody-recovery", "account": "000000000011", "region": "eu-west-1",
                       **NEXT_ROLES,
                       "role": "arn:aws:iam::000000000008:role/replication"}
            with (patch.dict(self.trust, {"ledgerReplica": replica}), patch("retirement.require_retirement_replication"),
                  patch("retirement.check_recovery_bucket") as check_bucket,
                  patch("retirement.read_replicated_record", side_effect=self.replicated_record) as read_replica):
                options = {"wallet_trust": wallet, "host_profiles": host_profiles, "replica_profile": "recovery-read"}
                query.return_value.stdout = evidence(observed)
                query.reset_mock()

                def revoke_during_replica_check(args, **_kwargs):
                    if args[-2] == "policy":
                        check_bucket.assert_called_once_with(self.trust, replica, "recovery-read")
                        self.assertEqual(args[-2:], ["policy", policy_digest])
                        raise CalledProcessError(1, args)
                    check_bucket.assert_not_called()
                    return query.return_value

                query.side_effect = revoke_during_replica_check
                with self.assertRaisesRegex(ValueError, "could not confirm the replacement wallet policy after AWS checks"):
                    inspect_keys(self.trust, "1", 1, False, **options)
                self.assertEqual(query.call_count, 3)

                def policy_read_crosses_deadline(args, **_kwargs):
                    if args[-2] == "policy":
                        self.now += 60
                    return query.return_value

                query.side_effect = policy_read_crosses_deadline
                with patch.object(self, "now", self.now), self.assertRaisesRegex(ValueError, "replacement evidence expired"):
                    inspect_keys(self.trust, "1", 1, False, **options)
                query.side_effect = None
                query.return_value.stdout = evidence(standby_observed)
                standby_name = target_object_name(standby)

                def unavailable_standby(trust, destination, name, **options):
                    if name == standby_name:
                        raise ValueError("registered standby has not completed S3 replication")
                    return self.replicated_record(trust, destination, name, **options)

                read_replica.side_effect = unavailable_standby
                with self.assertRaisesRegex(ValueError, "standby has not completed S3 replication"):
                    inspect_keys(self.trust, "1", 1, False, **options)
                query.return_value.stdout = evidence(standby_observed, observed)
                self.assertEqual(inspect_keys(self.trust, "1", 1, False, **options)["replacement"], expected)
                query.return_value.stdout = evidence(standby_observed)
                read_replica.side_effect = self.replicated_record
                self.assertEqual(inspect_keys(self.trust, "1", 1, False, **options)["replacement"], standby_expected)
                checked_standbys = [entry.kwargs["checkpoint_records"] for entry in read_replica.call_args_list
                                    if entry.args[-1] == standby_name and "checkpoint_records" in entry.kwargs]
                records, = checked_standbys
                self.assertIn(standby_name, records)

    def test_retirement_qualifies_only_a_live_registered_serving_replica_on_a_new_parent(self):
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        scope, receipt, _, _ = retirement_scope(self.trust, "1", "2")
        custody = receipt["custody"]
        registered = self.replacement_target()
        pins = target_attestation(registered)["pcrs"]
        observed = {"releaseId": registered["releaseId"], "pcrs": pins,
                    "bootstrap": self.qualification(registered)["replacementBootstrap"]}
        evidence = {"policyDigest": "fe" * 32, "targets": [observed]}

        with tempfile.TemporaryDirectory() as directory:
            wallet_trust = pathlib.Path(directory) / "wallet.json"
            body = self.wallet_pins + b"\n"
            wallet_trust.write_bytes(body)
            self.trust["walletTrustSha256"] = hashlib.sha256(body).hexdigest()
            with patch("retirement.run_command") as query:
                query.return_value.stdout = self.attestation_reply(evidence)
                with self.assertRaisesRegex(ValueError, "no registered serving target"):
                    qualified_policy(self.trust, wallet_trust, scope, custody)

                rotation = {**registered, "mode": "rotate", "pcrs": {**registered["pcrs"], "PCR2": "ef" * 48},
                            "nextCustodians": rotated["authorization"]["manifest"]["custodians"],
                            "nextRelay": self.trust["recoveryRelays"]["3"]}
                register_target(self.trust, self.signed_subject(TARGET_APPROVAL, rotation))
                same_parent = {**registered, "instanceId": INSTANCE, "wrappingKeys": [key(i, 23) for i in range(1, 7)]}
                register_target(self.trust, self.signed_subject(TARGET_APPROVAL, same_parent))
                with self.assertRaisesRegex(ValueError, "no registered serving target on a separate replacement instance"):
                    qualified_policy(self.trust, wallet_trust, scope, custody)
                query.assert_not_called()

                register_target(self.trust, self.signed_subject(TARGET_APPROVAL, registered))
                name = f"spr-custody/devnet/{DOMAIN}/{target_object_name(registered)}"
                early = datetime.fromtimestamp(self.now - 1, timezone.utc).isoformat()
                with patch.dict(self.timestamps, {name: early}):
                    with self.assertRaisesRegex(ValueError, "target registration precedes its custody receipt"):
                        qualified_policy(self.trust, wallet_trust, scope, custody)
                    query.assert_not_called()
                for pcr in ("3", "4"):
                    query.return_value.stdout = self.attestation_reply({**evidence, "targets": [
                        {**observed, "pcrs": {**pins, pcr: "ab" * 48}},
                    ]})
                    with self.subTest(pcr=pcr), self.assertRaisesRegex(ValueError, "no fresh attested serving boot"):
                        qualified_policy(self.trust, wallet_trust, scope, custody)

                for slots in ([1, 2], [1, 1, 2], [1, 2, 7], [True, 2, 3], [3, 2, 1]):
                    bootstrap = {**observed["bootstrap"], "slots": slots}
                    query.return_value.stdout = self.attestation_reply({**evidence, "targets": [{**observed, "bootstrap": bootstrap}]})
                    with self.assertRaisesRegex(ValueError, "three distinct attested bootstrap slots"):
                        qualified_policy(self.trust, wallet_trust, scope, custody)
                query.return_value.stdout = self.attestation_reply(evidence)
                self.assertEqual(qualified_policy(self.trust, wallet_trust, scope, custody).evidence, self.qualification(registered))
                with self.assertRaisesRegex(ValueError, "no fresh attested serving boot"):
                    qualified_policy(self.trust, wallet_trust, scope, custody, after_ms=self.booted_at_ms)
                with patch("retirement.time.time", return_value=self.now + RECOVERY_WINDOW_SECONDS):
                    with self.assertRaisesRegex(ValueError, "no fresh attested serving boot"):
                        qualified_policy(self.trust, wallet_trust, scope, custody)
                sibling = {**registered, "instanceId": "i-1234567890abcdef4", "wrappingKeys": [key(i, 24) for i in range(1, 7)]}
                register_target(self.trust, self.signed_subject(TARGET_APPROVAL, sibling))
                other = {**target_attestation(sibling), "bootstrap": observed["bootstrap"]}
                query.return_value.stdout = self.attestation_reply({**evidence, "targets": [other, observed]})
                self.assertEqual(qualified_policy(self.trust, wallet_trust, scope, custody).evidence, self.qualification(sibling))
                self.assertEqual(qualified_policy(self.trust, wallet_trust, scope, custody, expected=self.qualification(registered)).evidence,
                                 self.qualification(registered))
                self.assertEqual(query.call_args.kwargs["input"], body)
                self.assertIn(custody["canaryDigest"], query.call_args.args[0])
                self.assertNotIn(str(wallet_trust), query.call_args.args[0])
                query.reset_mock()
                wallet_trust.write_bytes(b"{}")
                with self.assertRaisesRegex(ValueError, "does not match the pinned digest"):
                    qualified_policy(self.trust, wallet_trust, scope, custody)
                wrong_pair = canonical({"publications": self.trust["publications"][::-1]})
                wallet_trust.write_bytes(wrong_pair)
                self.trust["walletTrustSha256"] = hashlib.sha256(wrong_pair).hexdigest()
                with self.assertRaisesRegex(ValueError, "pinned primary and mirror"):
                    qualified_policy(self.trust, wallet_trust, scope, custody)
                query.assert_not_called()

    def test_retirement_selects_a_standby_when_an_attested_replica_cannot_qualify(self):
        publish(self.trust, self.sign(self.document(1)))
        rotation, _ = self.rotation_document(load_epoch(self.trust, "1")[1])
        publish(self.trust, self.sign(rotation))
        primary = self.replacement_target()
        standby = self.replacement_target(releaseId="standby", instanceId="i-1234567890abcdefc",
                                           wrappingKeys=[key(slot, 39) for slot in range(1, 7)])
        for target in (primary, standby):
            register_target(self.trust, self.signed_subject(TARGET_APPROVAL, target))
        wallet = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory())) / "wallet.json"
        wallet.write_bytes(self.wallet_pins)
        self.trust["walletTrustSha256"] = hashlib.sha256(self.wallet_pins).hexdigest()
        primary_boot = self.qualification(primary)["replacementBootstrap"]
        standby_boot = {**primary_boot, "bootKeyId": "ae" * 32}
        unavailable = set()
        mismatched_policy = set()
        _, _, members = load_epoch(self.trust, "2")
        targets = [primary, standby]

        def describe(key_arn, operation, args=(), *, profile):
            account = key_arn.split(":")[4]
            self.assertEqual(profile, REPLACEMENT_PROFILES[account])
            slot = int(account)
            if operation == "get-key-policy":
                _, policies = slot_inventory(self.trust, "2", members[slot - 1], targets, slot)
                return {"Policy": json.dumps({} if key_arn in mismatched_policy else policies[key_arn])}
            self.assertEqual(operation, "describe-key")
            return {"KeyMetadata": {
                "Arn": key_arn, "KeySpec": "RSA_2048", "KeyUsage": "ENCRYPT_DECRYPT", "Origin": "AWS_KMS",
                "MultiRegion": False, "KeyState": "Disabled" if key_arn in unavailable else "Enabled",
            }}

        def observation(*targets, policy="fe" * 32):
            return SimpleNamespace(stdout=self.attestation_reply({"policyDigest": policy, "targets": list(targets)}))

        with (patch("retirement.run_command") as query, patch("relay.kms", side_effect=describe),
              patch("retirement.inspect_inventory", return_value={"keys": []}),
              patch("retirement.inspect_old_parents", return_value=[]), patch("retirement.require_profile_account")):
            primary_observed = {**target_attestation(primary), "bootstrap": primary_boot}
            standby_observed = {**target_attestation(standby), "bootstrap": standby_boot}
            query.return_value = observation(primary_observed, standby_observed)
            marker = qualified_manifest(self.trust, wallet, "1", "2", replacement_profiles=REPLACEMENT_PROFILES)
            self.assertEqual(marker["replacementTargetSha256"], sha256(primary))
            signed = self.signed_retirement(marker)
            commit_retirement(self.trust, wallet, signed, replacement_profiles=REPLACEMENT_PROFILES)
            self.now += 1
            for observed in (primary_observed, standby_observed):
                observed["bootstrap"]["bootedAtMs"] = str(self.now * 1000)
            query.return_value = observation(primary_observed, standby_observed)
            host_profiles = {"000000000007": "old-parent"}

            def inspect():
                return inspect_keys(self.trust, "1", 1, False, wallet_trust=wallet, host_profiles=host_profiles,
                                    replacement_profiles=REPLACEMENT_PROFILES)

            mismatched_policy.add(primary["wrappingKeys"][0])
            with self.subTest(stage="draft"):
                drafted = qualified_manifest(self.trust, wallet, "1", "2", requalify=True,
                                             replacement_profiles=REPLACEMENT_PROFILES)
                self.assertEqual(drafted["replacementTargetSha256"], sha256(standby))
            with self.subTest(stage="inspect"):
                self.assertEqual(inspect()["replacement"]["replacementTargetSha256"], sha256(standby))
            with self.subTest(stage="report"):
                for observed in (primary_observed, standby_observed):
                    observed["bootstrap"]["bootedAtMs"] = str((self.now + 1) * 1000)
                query.return_value = observation(primary_observed, standby_observed)
                profiles = [f"slot-{slot}" for slot in range(1, 7)]
                report = verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5,
                                        replacement_profiles=REPLACEMENT_PROFILES)
                self.assertEqual(report["replacement"]["replacementTargetSha256"], sha256(standby))
            with self.subTest(stage="standby arrives on a later poll"), patch("retirement.sleep") as sleep:
                query.side_effect = [
                    observation(primary_observed), observation(primary_observed, standby_observed),
                    observation(standby_observed), SimpleNamespace(),
                ]
                report = verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5,
                                        replacement_profiles=REPLACEMENT_PROFILES)
                self.assertEqual(report["retirementObservedAtMs"], str(self.now * 1000))
                self.assertEqual(report["replacement"]["replacementTargetSha256"], sha256(standby))
                sleep.assert_called_once()
            with self.subTest(stage="standby is registered during the wait"):
                late = self.replacement_target(releaseId="late-standby", instanceId="i-1234567890abcdefd",
                                               wrappingKeys=[key(slot, 40) for slot in range(1, 7)])
                targets.append(late)
                late_observed = {**target_attestation(late), "bootstrap": {**standby_boot, "bootKeyId": "af" * 32}}
                approved = self.signed_subject(TARGET_APPROVAL, late)
                query.side_effect = [
                    observation(primary_observed), observation(late_observed),
                    observation(late_observed), SimpleNamespace(),
                ]
                with patch("retirement.sleep", side_effect=lambda _: register_target(self.trust, approved)) as sleep:
                    report = verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5,
                                            replacement_profiles=REPLACEMENT_PROFILES)
                self.assertEqual(report["retirementObservedAtMs"], str(self.now * 1000))
                self.assertEqual(report["replacement"]["replacementTargetSha256"], sha256(late))
                sleep.assert_called_once()
            query.side_effect = None

            unavailable.add(standby["wrappingKeys"][1])
            with self.assertRaisesRegex(ValueError, "no attested replacement qualified") as rejected:
                inspect()
            self.assertIn(primary["wrappingKeys"][0], str(rejected.exception))
            self.assertIn(standby["wrappingKeys"][1], str(rejected.exception))

            unavailable.clear()
            mismatched_policy.clear()
            restarted = {**primary_observed, "bootstrap": {**primary_boot, "bootKeyId": "1a" * 32}}
            query.side_effect = [observation(primary_observed, standby_observed), observation(restarted, standby_observed),
                                 observation(restarted, standby_observed), SimpleNamespace()]
            self.assertEqual(inspect()["replacement"]["replacementTargetSha256"], sha256(standby))
            different_policy = observation(restarted, standby_observed, policy="df" * 32)
            query.side_effect = [observation(primary_observed, standby_observed), different_policy, different_policy]
            with self.assertRaisesRegex(ValueError, "no attested replacement qualified"):
                inspect()

            def close_while_confirming(command, **_options):
                if command[-2] == "policy":
                    self.objects[f"spr-custody/devnet/{DOMAIN}/retired/2.json"] = b"{}"
                    return SimpleNamespace()
                return observation(primary_observed, standby_observed)

            query.side_effect = close_while_confirming
            with self.assertRaisesRegex(ValueError, "cannot verify retirement record for epoch 2"):
                inspect()

    def test_closed_epoch_can_requalify_with_a_fresh_trio_and_keep_its_original_record(self):
        publish(self.trust, self.sign(self.document(1)))
        rotation, _ = self.rotation_document(load_epoch(self.trust, "1")[1])
        publish(self.trust, self.sign(rotation))
        target = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, target))
        wallet = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory())) / "wallet.json"
        wallet.write_bytes(self.wallet_pins)
        self.trust["walletTrustSha256"] = hashlib.sha256(self.wallet_pins).hexdigest()
        host_profiles = {"000000000007": "old-parent"}
        profiles = [f"slot-{slot}" for slot in range(1, 7)]
        new_slots = [2, 4, 6]

        with (patch("retirement.run_command") as query, patch("retirement.require_recovery_quorum") as quorum,
              patch("retirement.inspect_inventory", return_value={"keys": []}),
              patch("retirement.inspect_old_parents", return_value=[]), patch("retirement.require_profile_account")):
            def observe(boot):
                query.return_value.stdout = self.attestation_reply({
                    "policyDigest": "fe" * 32, "targets": [{**target_attestation(target), "bootstrap": boot}],
                })

            observe(self.qualification(target)["replacementBootstrap"])
            marker = qualified_manifest(self.trust, wallet, "1", "2")
            closure = self.signed_retirement(marker)
            commit_retirement(self.trust, wallet, closure)
            original = dict(self.objects)
            with self.assertRaisesRegex(ValueError, "no fresh attested serving boot"):
                qualified_manifest(self.trust, wallet, "1", "2", requalify=True)

            self.now += 1
            new_boot = {"bootKeyId": "ab" * 32, "bootedAtMs": str(self.now * 1000), "slots": new_slots}
            observe(new_boot)
            options = {"wallet_trust": wallet, "host_profiles": host_profiles}
            with self.assertRaisesRegex(ValueError, "no fresh attested serving boot"):
                inspect_keys(self.trust, "1", 1, False, **options)
            manifest = qualified_manifest(self.trust, wallet, "1", "2", requalify=True)
            self.assertEqual(manifest["priorRetirementSha256"], sha256(closure))
            self.assertEqual(manifest["replacementBootstrap"], new_boot)
            document = self.signed_retirement(manifest, new_slots)
            with patch("retirement.add_approval", return_value={"signatures": document["signatures"]}):
                self.assertEqual(sign_retirement(self.trust, wallet, {**document, "signatures": []},
                                                 approval_keys(self.trust)[0]["keyArn"]), document)

            bad_anchor = self.signed_retirement({**manifest, "priorRetirementSha256": "ef" * 32}, new_slots)
            early_boot = {**new_boot, "bootedAtMs": str(self.booted_at_ms + 999)}
            early = self.signed_retirement({**manifest, "replacementBootstrap": early_boot,
                                            "recoveryDeadline": closure["manifest"]["recoveryDeadline"]}, new_slots)
            for supplied, error in (
                (bad_anchor, "does not match the committed retirement"),
                (early, "requires a boot after the committed retirement"),
                ({**document, "signatures": document["signatures"][:1]}, "signing quorum"),
                ({**document, "recoveryProofs": document["recoveryProofs"][:2]}, "signing quorum"),
                (self.signed_retirement(manifest, (1, 4, 6)), "invalid or duplicate approval"),
            ):
                with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                    inspect_keys(self.trust, "1", 1, False, requalification=supplied, **options)
            with patch("time.time", return_value=manifest["recoveryDeadline"]):
                with self.assertRaisesRegex(ValueError, "outside the recovery window"):
                    inspect_keys(self.trust, "1", 1, False, requalification=document, **options)
            with self.assertRaisesRegex(ValueError, "retirement record is already committed"):
                commit_retirement(self.trust, wallet, document)

            inspected = inspect_keys(self.trust, "1", 1, False, requalification=document, **options)
            self.assertEqual(inspected["requalificationSha256"], sha256(document))
            self.assertEqual(inspected["replacement"]["replacementBootstrap"], new_boot)
            _, _, members = load_epoch(self.trust, "2")
            self.assertEqual(quorum.call_args.args[2], [members[slot - 1] for slot in new_slots])

            later_boot = {**new_boot, "bootKeyId": "cd" * 32, "bootedAtMs": str((self.now + 1) * 1000)}
            observe(later_boot)
            report = verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5, requalification=document)
            self.assertEqual(report["replacement"]["replacementBootstrap"], later_boot)
            self.assertEqual(report["retirementSha256"], sha256(closure))
            self.assertEqual(report["requalificationSha256"], sha256(document))
            self.assertEqual(original, self.objects)
            self.rotate_approvals("3")
            with self.assertRaisesRegex(ValueError, "approval roster does not match the verification time"):
                inspect_keys(self.trust, "1", 1, False, requalification=document, **options)
            with self.assertRaisesRegex(ValueError, "custody epoch is retired"):
                require_active_epoch(self.trust, "1")

    def test_requalification_can_follow_a_later_custody_epoch_and_requires_its_replication(self):
        publish(self.trust, self.sign(self.document(1)))
        for epoch in ("1", "2"):
            rotation, _ = self.rotation_document(load_epoch(self.trust, epoch)[1])
            publish(self.trust, self.sign(rotation))
        replacement = self.replacement_target()
        latest = self.replacement_target(epoch="3", releaseId="epoch-three", instanceId="i-1234567890abcdefc",
                                         wrappingKeys=[key(slot, 33) for slot in range(1, 7)])
        for target in (replacement, latest):
            register_target(self.trust, self.signed_subject(TARGET_APPROVAL, target))
        with patch("retirement.qualified_policy") as qualify, patch("retirement.require_recovery_quorum"):
            qualify.return_value = self.live_qualification(replacement)
            closure = self.signed_retirement(qualified_manifest(self.trust, None, "1", "2"))
            commit_retirement(self.trust, None, closure)
            self.now += 1
            evidence = self.qualification(latest)
            evidence["replacementBootstrap"]["bootedAtMs"] = str(self.now * 1000)
            qualify.return_value = LiveBoot(evidence, (self.now + 60) * 1000)
            second_closure = self.signed_retirement(qualified_manifest(self.trust, None, "2", "3"))
            commit_retirement(self.trust, None, second_closure)
            with self.assertRaisesRegex(ValueError, "custody epoch is retired"):
                replacement_targets(self.trust, closure["manifest"])
            manifest = qualified_manifest(self.trust, None, "1", "3", requalify=True)
            requalification = self.signed_retirement(manifest)

        replica = {"bucket": "custody-recovery", "account": "000000000011", "region": "eu-west-1",
                   **NEXT_ROLES,
                   "role": "arn:aws:iam::000000000008:role/replication"}
        with (patch.dict(self.trust, {"ledgerReplica": replica}),
              patch("retirement.require_replicated_custody") as copies):
            qualified, _, keys, _, _ = retirement_inventory(self.trust, "1", 1, requalification=requalification)
            self.assertEqual(qualified["replacementEpoch"], "3")
            self.assertIn(key(1, 1), keys)
            self.assertNotIn(key(1, 3), keys)
            _, _, epoch, records = copies.call_args.args
            self.assertEqual(epoch, "3")
            for name in ("retired/1.json", target_object_name(replacement), target_object_name(latest)):
                payload, metadata = read_stored_payload(self.trust, name)
                self.assertEqual(records[name], (metadata["VersionId"], metadata["LastModified"],
                                                 hashlib.sha256(payload).hexdigest()))
            copies.side_effect = ValueError("new replacement registration has not replicated")
            with self.assertRaisesRegex(ValueError, "has not replicated"):
                retirement_inventory(self.trust, "1", 1, requalification=requalification)

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
        with (patch("retirement.qualified_policy", return_value=self.live_qualification(replacement)),
              patch("retirement.require_recovery_quorum")):
            marker = qualified_manifest(self.trust, None, "1", "2")
            retired = self.signed_retirement(marker)
            commit_retirement(self.trust, None, retired)
        self.now += 1
        observed_at_ms = self.now * 1000

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
        stale = self.attestation_reply({"policyDigest": "fe" * 32, "targets": [observed]})
        fresh = {**boot, "bootKeyId": "be" * 32, "bootedAtMs": str(observed_at_ms + 1_000)}
        ready = self.attestation_reply({"policyDigest": "fe" * 32, "targets": [{**observed, "bootstrap": fresh}]})

        wallet = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory())) / "wallet.json"
        wallet.write_bytes(self.wallet_pins)
        self.trust["walletTrustSha256"] = hashlib.sha256(wallet.read_bytes()).hexdigest()
        with (patch("retirement.kms", side_effect=kms),
              patch("retirement.require_profile_account") as identity,
              patch("retirement.run_command") as query, patch("retirement.sleep"),
              patch("retirement.require_host_state", side_effect=require_host_state) as host_state,
              patch("retirement.require_recovery_quorum") as quorum):
            original_receipt = load_epoch(self.trust, "1")[1]
            changed_receipt = {**original_receipt, "custody": {**original_receipt["custody"], "epoch": "9"}}
            with patch("retirement.load_epoch", return_value=(None, changed_receipt, [])):
                with self.assertRaisesRegex(ValueError, "retired custody receipt changed"):
                    verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5)
            query.assert_not_called()
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
                    query.side_effect = [SimpleNamespace(stdout=body) for body in (ready, self.attestation_reply(changed))]
                    with (patch("retirement.time.monotonic", side_effect=[0, 0, 0, 0, 0, 5]),
                          self.assertRaisesRegex(ValueError, "no fresh attested serving boot")):
                        verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5)
            query.side_effect = [SimpleNamespace(stdout=ready)] * 2
            with (patch("retirement.time.monotonic", side_effect=[0, 0, 0, 4, 5, 5]),
                  self.assertRaisesRegex(ValueError, "replacement boot wait expired")):
                verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5)
            self.assertEqual(query.call_args.kwargs["timeout"], 1)
            visited.clear()
            host_state.reset_mock()
            identity.reset_mock()
            query.reset_mock()
            quorum.reset_mock()

            def attest(*_args, **_options):
                self.assertEqual(registrations.call_count, min(query.call_count, 3))
                if query.call_count >= 3:
                    self.assertEqual(host_state.call_count, 4)
                    self.assertEqual(len(visited), 2 * len(inventory))
                return SimpleNamespace(stdout=stale if query.call_count == 1 else ready)

            query.side_effect = attest
            with patch("retirement.replacement_targets", wraps=replacement_targets) as registrations:
                report = verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5)
            self.assertEqual(query.call_count, 4)
            self.assertEqual(query.call_args.args[0][-2:], ["policy", "fe" * 32])
            self.assertEqual(set(inventory), set(visited))
            self.assertEqual(len(visited), 2 * len(inventory))
            self.assertEqual(report["retirementSha256"], sha256(retired))
            self.assertEqual(report["retirementObservedAtMs"], str(observed_at_ms))
            self.assertEqual(report["retired"], {
                "network": self.trust["network"], "securityDomainId": self.trust["securityDomainId"],
                "custodyEpoch": "1", "custodyDigest": sha256(load_epoch(self.trust, "1")[1]["custody"]),
                "publishedAtMs": str(self.booted_at_ms),
            })
            self.assertEqual(report["replacement"]["custodyEpoch"], "2")
            self.assertEqual(report["replacement"]["custodyDigest"], sha256(load_epoch(self.trust, "2")[1]["custody"]))
            self.assertEqual({call.args for call in identity.call_args_list},
                             {(profile, REGION, f"{slot:012d}") for slot, profile in enumerate(profiles, 1)} |
                             {(host_profiles[parent["account"]], parent["region"], parent["account"]) for parent in parents})
            self.assertEqual(report["terminatedParents"], parents)
            self.assertEqual(host_state.call_count, 4)
            host_state.assert_called_with(other_host, "terminated", "old-service")
            self.assertEqual(report["replacement"]["replacementBootstrap"], fresh)
            self.assertEqual({row["keyArn"] for slot in report["slots"] for row in slot["keys"]}, set(inventory))
            quorum.assert_called_once()
            with self.assertRaisesRegex(ValueError, "mainnet key retirement requires a pinned custody ledger replica"):
                verify_retired({**self.trust, "network": "mainnet"}, wallet, "1", profiles, host_profiles, 5)
            standby = {**replacement, "instanceId": "i-1234567890abcdefc", "releaseId": "standby",
                       "wrappingKeys": [key(slot, 39) for slot in range(1, 7)]}
            register_target(self.trust, self.signed_subject(TARGET_APPROVAL, standby))
            replica = {"bucket": "custody-recovery", "account": "000000000011", "region": "eu-west-1",
                       **NEXT_ROLES,
                       "role": "arn:aws:iam::000000000008:role/replication"}
            query.side_effect = None
            query.return_value.stdout = ready
            with (patch.dict(self.trust, {"ledgerReplica": replica}), patch("retirement.require_retirement_replication"),
                  patch("retirement.check_recovery_bucket") as check_bucket,
                  patch("retirement.read_replicated_record", side_effect=self.replicated_record)):
                query.reset_mock()
                with self.assertRaisesRegex(ValueError, "provide --replica-profile"):
                    verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5)
                query.assert_not_called()

                def check_replica(*_args):
                    self.assertEqual(query.call_count, 2)
                    raise ValueError("custody ledger bucket must have no lifecycle configuration")

                check_bucket.side_effect = check_replica
                with self.assertRaisesRegex(ValueError, "must have no lifecycle"):
                    verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5, replica_profile="recovery-read")
                check_bucket.assert_called_once_with(self.trust, replica, "recovery-read")
                check_bucket.side_effect = None
                verified = verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5, replica_profile="recovery-read")
                self.assertEqual(verified, report)

                for name in (target_object_name(replacement), target_object_name(other_host), "1.json", "retired/1.json"):
                    with self.subTest(name=name), patch.dict(self.versions):
                        def replace_record_during_replica_check(*_args):
                            self.versions[f"spr-custody/devnet/{DOMAIN}/{name}"] = "changed-version"

                        query.reset_mock()
                        check_bucket.side_effect = replace_record_during_replica_check
                        with self.assertRaisesRegex(ValueError, "changed after checkpoint"):
                            verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5, replica_profile="recovery-read")
                        self.assertEqual(query.call_count, 2)
                check_bucket.side_effect = None

                query.reset_mock()
                check_bucket.reset_mock()

                def change_policy_after_replica_check(args, **_kwargs):
                    if args[-2] == "policy":
                        check_bucket.assert_called_once_with(self.trust, replica, "recovery-read")
                        self.assertEqual(args[-2:], ["policy", "fe" * 32])
                        raise CalledProcessError(1, args)
                    check_bucket.assert_not_called()
                    return query.return_value

                query.side_effect = change_policy_after_replica_check
                with self.assertRaisesRegex(ValueError, "could not confirm the replacement wallet policy after AWS checks"):
                    verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5, replica_profile="recovery-read")
                self.assertEqual(query.call_count, 3)
                query.side_effect = None

                def replica_check_crosses_deadline(*_args):
                    self.now += 60

                check_bucket.side_effect = replica_check_crosses_deadline
                with patch.object(self, "now", self.now), self.assertRaisesRegex(ValueError, "replacement evidence expired"):
                    verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5, replica_profile="recovery-read")
                check_bucket.side_effect = None

                query.return_value.stdout = self.attestation_reply({
                    "policyDigest": "fe" * 32, "targets": [{**target_attestation(standby), "bootstrap": fresh}],
                })
                query.reset_mock()
                with (patch("retirement.read_replicated_record", side_effect=ValueError("standby replication pending")) as read,
                      patch("retirement.time.monotonic", side_effect=[0, 0, 0, 1, 1, 5]),
                      self.assertRaisesRegex(ValueError, "standby replication pending")):
                    verify_retired(self.trust, wallet, "1", profiles, host_profiles, 5, replica_profile="recovery-read")
                with self.subTest(stage="registration refresh reaches the original deadline"):
                    query.assert_called_once()
                    self.assertEqual(read.call_args.args[-1], target_object_name(standby))

    def test_archive_cli_publishes_only_a_complete_synced_new_file(self):
        directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        trust, destination = directory / "trust.json", directory / "custody.jsonl"
        trust.write_bytes(canonical(self.trust))
        argv = ["custody_archive.py", str(trust), "export", "2", str(destination)]
        records = [("1", {"epoch": "1"}, None), ("2", {"epoch": "2"}, None)]
        fsync = os.fsync
        sync_order = []

        def interrupted(*_args):
            yield records[0]
            raise ValueError("could not read the second receipt")

        def sync(fd):
            is_directory = stat.S_ISDIR(os.fstat(fd).st_mode)
            self.assertEqual(destination.exists(), is_directory)
            sync_order.append(is_directory)
            fsync(fd)

        with patch("sys.argv", argv), patch("custody_archive.custody_history", side_effect=interrupted) as history:
            with self.assertRaisesRegex(SystemExit, "could not read the second receipt"):
                archive_main()
            self.assertFalse(destination.exists())

            history.side_effect = lambda *_args: iter(records)
            with patch("approval.os.fsync", side_effect=OSError("cannot sync data")):
                with self.assertRaisesRegex(SystemExit, "cannot sync data"):
                    archive_main()
            self.assertFalse(destination.exists())

            with patch("approval.os.fsync", side_effect=sync):
                archive_main()
            self.assertEqual(sync_order, [False, True])
            full = b"".join(canonical(entry) + b"\n" for _, entry, _ in records)
            self.assertEqual(destination.read_bytes(), full)

            history.reset_mock()
            with self.assertRaisesRegex(SystemExit, "custody archive already exists"):
                archive_main()
            history.assert_not_called()
            self.assertEqual(destination.read_bytes(), full)

    def test_retirement_cli_publishes_the_completed_report_without_overwriting(self):
        directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        trust, wallet, report = (directory / name for name in ("trust.json", "wallet.json", "report.json"))
        trust.write_bytes(canonical(self.trust))
        profiles = [f"slot-{index}" for index in range(1, 7)]
        key_profiles = directory / "key-profiles.json"
        key_profiles.write_bytes(canonical(REPLACEMENT_PROFILES))
        argv = ["retirement.py", str(trust), "verify-retired", str(wallet), "1",
                "--inspection-profiles", *profiles, "--custody-key-profiles", str(key_profiles),
                "--replica-profile", "recovery-read", "--output", str(report)]
        result = {"retirementObservedAtMs": "100"}

        def verify(*_args, **_options):
            self.assertFalse(report.exists())
            return result

        with patch("sys.argv", argv), patch("retirement.verify_retired", side_effect=verify) as verify_retired:
            retirement_main()
            verify_retired.assert_called_once_with(self.trust, wallet, "1", profiles, {}, 300,
                                                   replica_profile="recovery-read", requalification=None,
                                                   replacement_profiles=REPLACEMENT_PROFILES)
            self.assertEqual(report.read_bytes(), canonical(result) + b"\n")
            with self.assertRaisesRegex(SystemExit, "retirement report already exists"):
                retirement_main()
            verify_retired.assert_called_once()
            self.assertEqual(report.read_bytes(), canonical(result) + b"\n")

            concurrent = report.with_name("concurrent.json")
            argv[-1] = str(concurrent)

            def concurrent_writer(*_args, **_options):
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
        registered_version = require_registered_target(self.trust, winner)
        with self.assertRaisesRegex(ValueError, "does not match"):
            require_registered_target(self.trust, loser)

        self.rotate_approvals("3")
        renewed = {**winner, "expiresAt": self.now + 60, "approvalFromEpoch": "3"}
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, renewed))
        self.assertEqual(require_registered_target(self.trust, renewed), registered_version)
        sibling = {**renewed, "instanceId": "i-1234567890abcdef3", "wrappingKeys": [key(i, 5) for i in range(1, 7)]}
        self.assertNotEqual(target_object_name(renewed), target_object_name(sibling))
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, sibling))
        self.assertNotEqual(require_registered_target(self.trust, sibling), registered_version)
        self.assertEqual(len([name for name in self.objects if "/targets/2/" in name]), 2)

    def test_target_registration_refuses_a_deadline_inside_the_write_budget(self):
        publish(self.trust, self.sign(self.document(1)))
        draft, _ = self.rotation_document(load_epoch(self.trust, "1")[1])
        publish(self.trust, self.sign(draft))
        candidate = self.replacement_target(expiresAt=self.now + 60)
        approval = self.signed_subject(TARGET_APPROVAL, candidate)
        name = f"spr-custody/devnet/{DOMAIN}/{target_object_name(candidate)}"

        def slow_inspection(trust, operation, args=(), **options):
            result = storage(trust, operation, args, **options)
            if operation == "list-object-versions" and name in args:
                self.now = candidate["expiresAt"] - 30
            return result

        with patch("custody_ledger.storage", side_effect=slow_inspection) as access:
            with self.assertRaisesRegex(ValueError, "target approval deadline is too close"):
                register_target(self.trust, approval)
            self.assertNotIn("put-object", [entry.args[1] for entry in access.call_args_list])
        self.assertNotIn(name, self.objects)

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

    def test_target_registration_rechecks_its_receipt_through_publication(self):
        publish(self.trust, self.sign(self.document(1)))
        rotation, _ = self.rotation_document(load_epoch(self.trust, "1")[1])
        publish(self.trust, self.sign(rotation))
        approval = self.signed_subject(TARGET_APPROVAL, self.replacement_target())
        prefix = f"spr-custody/devnet/{DOMAIN}/"
        receipt_path = prefix + "2.json"
        registration_path = prefix + target_object_name(approval["manifest"])

        for change_after_write in (False, True):
            with (self.subTest(change_after_write=change_after_write),
                  patch.dict(self.versions), patch.dict(self.objects), patch.dict(self.timestamps)):
                def inspect_target(*_args):
                    if not change_after_write:
                        self.versions[receipt_path] = "changed-version"

                def aws(region, service, operation, args, **options):
                    result = self.aws(region, service, operation, args, **options)
                    if operation == "put-object" and registration_path in args:
                        self.assertTrue(change_after_write, "the registration must fail before S3 PutObject")
                        self.versions[receipt_path] = "changed-version"
                    return result

                with (patch("deployment.require_live_registration", side_effect=inspect_target),
                      patch("custody_ledger.aws", side_effect=aws),
                      self.assertRaisesRegex(ValueError, "changed during verification")):
                    register_target(self.trust, approval)
                self.assertEqual(registration_path in self.objects, change_after_write)

        register_target(self.trust, approval)

        def retry_with_changed_receipt(region, service, operation, args, **options):
            result = self.aws(region, service, operation, args, **options)
            if operation == "list-object-versions" and registration_path in args:
                self.versions[receipt_path] = "changed-version"
            return result

        with (patch("custody_ledger.aws", side_effect=retry_with_changed_receipt),
              patch("deployment.require_live_registration", side_effect=AssertionError("retry must skip KMS")),
              self.assertRaisesRegex(ValueError, "changed during verification")):
            register_target(self.trust, approval)

    def test_target_registration_uses_the_roster_active_at_s3_publication(self):
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        existing = self.replacement_target()
        existing_approval = self.signed_subject(TARGET_APPROVAL, existing)
        register_target(self.trust, existing_approval)

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
        with patch("deployment.write_once") as write:
            register_target(self.trust, existing_approval)
            with patch.object(self, "now", existing["expiresAt"]):
                register_target(self.trust, existing_approval)
            existing_path = f"spr-custody/devnet/{DOMAIN}/{target_object_name(existing)}"
            with patch.dict(self.timestamps, {existing_path: datetime.fromtimestamp(cutoff, timezone.utc).isoformat()}):
                with self.assertRaisesRegex(ValueError, "approval roster does not match its publication time"):
                    register_target(self.trust, existing_approval)
            write.assert_not_called()
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

    def test_registered_target_retry_rejects_a_conflicting_replica(self):
        publish(self.trust, self.sign(self.document(1)))
        draft, _ = self.rotation_document(load_epoch(self.trust, "1")[1])
        publish(self.trust, self.sign(draft))
        target = self.replacement_target()
        approval = self.signed_subject(TARGET_APPROVAL, target)
        register_target(self.trust, approval)
        self.trust["ledgerReplica"] = {"bucket": "custody-recovery", "account": "000000000010", "region": "eu-west-1",
                                      **RECOVERY_ROLES, "role": "arn:aws:iam::000000000008:role/replication"}
        name = target_object_name(target)
        path = f"spr-custody/devnet/{DOMAIN}/{name}"

        def payload(trust, name, **options):
            original, metadata = read_stored_payload(self.trust, name, **options)
            if trust["ledger"]["bucket"] == "custody-recovery":
                return self.replica_objects[path], {**metadata, "ReplicationStatus": "REPLICA"}
            return original, {**metadata, "ReplicationStatus": "COMPLETED"}

        with patch("custody_ledger.storage", wraps=storage) as access:
            register_target(self.trust, approval)  # A source-only record can still be replicating.
            with (patch.dict(self.replica_objects, {path: self.objects[path]}),
                  patch("custody_ledger.read_stored_payload", side_effect=payload)):
                register_target(self.trust, approval)
                require_registered_target(self.trust, target)
                self.replica_objects[path] = b"{}"
                with self.assertRaisesRegex(ValueError, "differs from the pinned replica"):
                    register_target(self.trust, approval)
                with self.assertRaisesRegex(ValueError, "differs from the pinned replica"):
                    require_registered_target(self.trust, target)
            self.assertNotIn("put-object", [entry.args[1] for entry in access.call_args_list])

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
        policies = {key: policy for slot, member in enumerate(custodians[:3], 1)
                    for key, policy in slot_inventory(self.trust, "2", member, [replacement], slot)[1].items()}
        policy_reads = set()
        mismatched_policies = set()
        unreadable_policies = set()

        def describe(arn, operation, args=(), *, profile):
            self.assertEqual(profile, REPLACEMENT_PROFILES[arn.split(":")[4]])
            if operation == "get-key-policy":
                self.assertEqual(args, ["--policy-name", "default"])
                policy_reads.add(arn)
                if arn in unreadable_policies:
                    raise ValueError("AWS KMS GetKeyPolicy failed")
                return {"Policy": json.dumps({} if arn in mismatched_policies else policies[arn])}
            self.assertEqual(operation, "describe-key")
            inspected.add(arn)
            state = states[arn]
            return {"KeyMetadata": {"Arn": arn if state != "foreign" else key(99), "Origin": "AWS_KMS", "MultiRegion": False,
                                    "KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "RSA_2048",
                                    "KeyState": "Enabled" if state == "foreign" else state}}

        def caller_identity(region, service, operation, args, *, profile):
            self.assertEqual((service, operation, args), ("sts", "get-caller-identity", []))
            return {"Account": next(account for account, name in REPLACEMENT_PROFILES.items() if name == profile)}

        def commit(document):
            return commit_retirement(self.trust, None, document, replacement_profiles=REPLACEMENT_PROFILES)

        with (patch("relay.kms", side_effect=describe) as kms,
              patch("approval.aws", side_effect=caller_identity)):
            qualification.return_value = self.live_qualification(replacement)
            marker = qualified_manifest(self.trust, None, "1", "2")
            retirement = self.signed_retirement(marker)
            with self.assertRaisesRegex(ValueError, "provide --custody-key-profiles"):
                commit_retirement(self.trust, None, retirement)
            kms.assert_not_called()
            swapped = {**REPLACEMENT_PROFILES, f"{1:012d}": "replacement-2", f"{2:012d}": "replacement-1"}
            with self.assertRaisesRegex(ValueError, "inspection profile .* must belong to account"):
                commit_retirement(self.trust, None, retirement, replacement_profiles=swapped)
            with self.assertRaisesRegex(ValueError, recovery_keys[2]):
                commit(retirement)
            self.assertIn(recovery_keys[2], inspected)
            states[recovery_keys[2]] = "Enabled"
            for key_arn in (recovery_keys[2], wrapping_keys[1]):
                mismatched_policies.add(key_arn)
                with patch("retirement.write_once") as write:
                    with self.assertRaisesRegex(ValueError, "installed KMS policy"):
                        commit(retirement)
                    write.assert_not_called()
                mismatched_policies.remove(key_arn)
            unreadable_policies.add(recovery_keys[0])
            with patch("retirement.write_once") as write:
                with self.assertRaisesRegex(ValueError, "GetKeyPolicy failed"):
                    commit(retirement)
                write.assert_not_called()
            unreadable_policies.clear()
            self.retirement_host.side_effect = ValueError("host bootstrap policy differs")
            with patch("retirement.write_once") as write:
                with self.assertRaisesRegex(ValueError, "host bootstrap policy differs"):
                    commit(retirement)
                write.assert_not_called()
            self.retirement_host.assert_called_with(replacement, "host-read", slots=[1, 2, 3])
            self.retirement_host.side_effect = None
            journal = f"spr-custody/devnet/{DOMAIN}/"
            early_target = datetime.fromtimestamp(self.now - 1, timezone.utc).isoformat()
            late_receipt = datetime.fromtimestamp(self.now + 1, timezone.utc).isoformat()
            for timestamps, error in (
                ({journal + target_object_name(replacement): early_target}, "target registration precedes its custody receipt"),
                ({journal + "2.json": late_receipt}, "retirement cannot precede a committed custody receipt"),
            ):
                with patch.dict(self.timestamps, timestamps), patch("retirement.write_once") as write:
                    with self.assertRaisesRegex(ValueError, error):
                        commit(retirement)
                    write.assert_not_called()
            inspected.clear()
            policy_reads.clear()
            with patch("retirement.add_approval", return_value={"signatures": retirement["signatures"]}):
                self.assertEqual(sign_retirement(self.trust, None, {**retirement, "signatures": []},
                                                 approval_keys(self.trust)[0]["keyArn"],
                                                 replacement_profiles=REPLACEMENT_PROFILES), retirement)
            self.assertEqual(inspected, proven)
            self.assertEqual(policy_reads, proven)
            states[wrapping_keys[1]] = "PendingDeletion"
            with self.assertRaisesRegex(ValueError, wrapping_keys[1]):
                commit(retirement)
            states[wrapping_keys[1]] = "foreign"
            with self.assertRaisesRegex(ValueError, wrapping_keys[1]):
                commit(retirement)
            self.assertTrue(all("/retired/" not in name for name in self.objects))
            with self.assertRaisesRegex(ValueError, "invalid or duplicate approval"):
                commit(self.signed_retirement(marker, (1, 2, 4)))
            states[wrapping_keys[1]] = "Enabled"
            changed = {**self.qualification(replacement),
                       "replacementBootstrap": {**marker["replacementBootstrap"], "bootKeyId": "bc" * 32}}
            qualification.return_value = LiveBoot(changed, (self.now + 60) * 1000)
            with self.assertRaisesRegex(ValueError, "no longer matches the qualified replacement"):
                commit(retirement)
            qualification.return_value = LiveBoot(self.qualification(replacement), (self.now + 1) * 1000)
            with patch("custody_ledger.storage", wraps=storage) as access:
                with self.assertRaisesRegex(ValueError, "replacement evidence expired or has insufficient time"):
                    commit(retirement)
                self.assertNotIn("put-object", [entry.args[1] for entry in access.call_args_list])
            qualification.return_value = self.live_qualification(replacement)
            commit(retirement)

    @patch("retirement.require_recovery_quorum")
    @patch("retirement.qualified_policy")
    def test_retirement_binds_three_distinct_proofs_to_one_candidate_and_publication_window(self, qualification, quorum):
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        replacement = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, replacement))
        qualification.return_value = self.live_qualification(replacement)
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
        qualification.return_value = LiveBoot(self.qualification(replacement), deadline * 1000)
        for now in (deadline - RECOVERY_WINDOW_SECONDS - 1, deadline, deadline - 1):
            with patch("retirement.time.time", return_value=now):
                with self.assertRaisesRegex(ValueError, "recovery window"):
                    commit_retirement(self.trust, None, retired)
        self.assertNotIn(path, self.objects)
        qualification.return_value = self.live_qualification(replacement)
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
        target = self.replacement_target()
        qualification.return_value = self.live_qualification(target)
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
            with self.assertRaisesRegex(ValueError, "object missing"):
                prove_recovery(self.trust, candidate, 2, 7443)
            kms.assert_not_called()
            register_target(self.trust, self.signed_subject(TARGET_APPROVAL, target))
            with self.assertRaisesRegex(ValueError, "recovery failed"):
                prove_recovery(self.trust, candidate, 2, 7443)
            prove_share.assert_called_once_with(self.trust, receipt, member, 2, 7443, ANY)
            approval.assert_not_called()

            def changed_registration(*args):
                require_current = args[-1]
                require_current()
                path = f"spr-custody/devnet/{DOMAIN}/{target_object_name(target)}"
                self.versions[path] = "changed-registration"
                require_current()

            prove_share.side_effect = changed_registration
            with patch.dict(self.versions), self.assertRaisesRegex(ValueError, "changed during verification"):
                prove_recovery(self.trust, candidate, 2, 7443)
            approval.assert_not_called()

            prove_share.side_effect = None
            approval.return_value = {"signatures": [sign(RETIREMENT_RECOVERY, marker, key_arn)]}
            proven = prove_recovery(self.trust, candidate, 2, 7443)
            self.assertEqual(len(proven["recoveryProofs"]), 1)
            approval.assert_called_once_with([item["acknowledgementKey"] for item in roster], RETIREMENT_RECOVERY,
                                             {"manifest": marker, "signatures": []}, key_arn)

            def late_signature(*_args):
                self.now = marker["recoveryDeadline"]
                return approval.return_value

            approval.side_effect = late_signature
            with patch.object(self, "now", self.now), self.assertRaisesRegex(ValueError, "recovery window"):
                prove_recovery(self.trust, candidate, 2, 7443)
            approval.side_effect = None
            approval.reset_mock()

            def late_decrypt(*args):
                require_authorized = args[-1]
                require_authorized()
                self.now = marker["recoveryDeadline"]
                require_authorized()

            prove_share.side_effect = late_decrypt
            with patch.object(self, "now", self.now), self.assertRaisesRegex(ValueError, "recovery window"):
                prove_recovery(self.trust, candidate, 2, 7443)
            approval.assert_not_called()

    @patch("retirement.require_recovery_quorum")
    @patch("retirement.qualified_policy")
    def test_retirement_signer_rechecks_receipts_and_live_policy_after_signing(self, qualification, _keys):
        publish(self.trust, self.sign(self.document(1)))
        rotation, _ = self.rotation_document(load_epoch(self.trust, "1")[1])
        publish(self.trust, self.sign(rotation))
        target = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, target))
        boot = self.live_qualification(target)
        qualification.return_value = boot
        document = self.signed_retirement(qualified_manifest(self.trust, None, "1", "2"))
        key_arn = approval_keys(self.trust)[0]["keyArn"]

        def change_receipt(*_args):
            self.versions[f"spr-custody/devnet/{DOMAIN}/1.json"] = "changed-receipt"
            return document

        def change_policy(*_args):
            qualification.return_value = self.live_qualification(target, "cd" * 32)
            return document

        for change, message in (
            (change_receipt, "changed during verification"),
            (change_policy, "no longer matches the qualified replacement and wallet policy"),
        ):
            qualification.return_value = boot
            with (self.subTest(change=change.__name__), patch.dict(self.versions),
                  patch("retirement.add_approval", side_effect=change),
                  self.assertRaisesRegex(ValueError, message)):
                sign_retirement(self.trust, None, {**document, "signatures": []}, key_arn)
