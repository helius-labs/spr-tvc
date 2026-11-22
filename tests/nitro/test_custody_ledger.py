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
from threading import Lock
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from approval import approval_keys, canonical, sha256
from custody_ledger import (
    ACKNOWLEDGEMENT, LABEL, RECOVERY_WINDOW_SECONDS, RETIREMENT, RETIREMENT_RECOVERY, TARGET_APPROVAL, acknowledge,
    check_serving_policy, draft, ledger_policy, ledger_reader_policy, load_epoch, publish, record, require_active_epoch,
    sign_epoch, target_attestation,
    target_object_name, verify_archive, write_once,
)
from deployment import register_target, require_registered_target
from kms_policy import acknowledgement_policy, boot_pins
from nitro_fixtures import DOMAIN, HOST, key, pin, schedule, sign
from retirement import (commit_retirement, inspect_keys, key_inventory, prove_recovery, qualified_manifest, qualified_policy,
                        retirement_scope, sign_retirement)

READ_ROLE = "arn:aws:iam::000000000001:role/custodian"
PUBLISHER = "arn:aws:iam::000000000008:role/publisher"
ADMIN = "arn:aws:iam::000000000008:role/ledger-admin"
PINS = {f"PCR{i}": f"{i+1:02x}" * 48 for i in range(3)}


class CustodyLedgerTests(unittest.TestCase):
    def setUp(self):
        self.trust = {
            "network": "devnet", "securityDomainId": DOMAIN, "approvalKeys": [schedule()],
            "ledger": {"bucket": "custody-journal", "account": "000000000008", "region": "eu-north-1"},
        }
        self.objects = {}
        self.timestamps = {}
        self.lock = Lock()
        self.enterContext(patch("custody_ledger.aws", side_effect=self.aws))
        self.enterContext(patch("approval.kms", side_effect=AssertionError("receipt verification must not call KMS")))

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
            "custodians": roster, "previousReceiptSha256": sha256(predecessor) if predecessor else None,
            "rotationTargetSha256": None,
        }
        return {"authorization": {"manifest": manifest, "signatures": []}, "acknowledgements": []}

    def rotation_document(self, predecessor, variant="fe", register=True):
        document = self.document(2, predecessor, variant)
        manifest = document["authorization"]["manifest"]
        target = {"network": "devnet", "securityDomainId": DOMAIN, "receiptSha256": sha256(predecessor),
                  "custodyEpoch": "1", "approvalFromEpoch": self.trust["approvalKeys"][-1]["fromEpoch"],
                  "releaseId": manifest["capture"]["receipt"]["releaseId"], "mode": "rotate", "hostRole": HOST,
                  "pcrs": PINS, "eifSha256": manifest["ceremonyEifSha256"],
                  "configurationSha256": sha256(manifest["capture"]["configuration"]),
                  "nextCustodians": copy.deepcopy(manifest["custodians"]), "wrappingKeys": [key(i, 21) for i in range(1, 7)]}
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

    def aws(self, region, service, operation, args):
        self.assertEqual((region, service), ("eu-north-1", "s3api"))
        self.assertEqual(args[args.index("--expected-bucket-owner") + 1], "000000000008")
        if operation == "list-objects-v2":
            prefix = args[args.index("--prefix") + 1]
            self.assertTrue(prefix.startswith(f"spr-custody/devnet/{DOMAIN}/"))
            with self.lock:
                return {"Contents": [{"Key": name} for name in sorted(self.objects) if name.startswith(prefix)]}
        name = args[args.index("--key") + 1]
        self.assertTrue(name.startswith(f"spr-custody/devnet/{DOMAIN}/"))
        with self.lock:
            if operation == "put-object":
                self.assertEqual(args[args.index("--if-none-match") + 1], "*")
                if name in self.objects:
                    raise ValueError("precondition failed")
                self.objects[name] = pathlib.Path(args[-1]).read_bytes()
                self.timestamps[name] = datetime.now(timezone.utc).isoformat()
            elif operation == "get-object" and name in self.objects:
                pathlib.Path(args[-1]).write_bytes(self.objects[name])
                return {"LastModified": self.timestamps.get(name, datetime.now(timezone.utc).isoformat())}
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
                    sign_epoch(self.trust, document, key(8, 7), build, "", "")
                provenance.assert_not_called()

            for change, message in (
                ({"custodians": [{**roster[0], "acknowledgementKey": pin(key(1, 33))}, *roster[1:]]}, "successor roster"),
                ({"ceremonyEifSha256": "ff" * 32}, "ceremony image"),
                ({"rotationTargetSha256": "ab" * 32}, "does not pin"),
                ({"capture": {**capture, "pcrs": {**capture["pcrs"], "3": "ef" * 48}}}, "ceremony image"),
            ):
                bad = copy.deepcopy(document)
                bad["authorization"]["manifest"].update(copy.deepcopy(change))
                self.sign(bad)
                with (patch("custody_ledger.verify_build") as provenance, patch("custody_ledger.open_share") as share):
                    with self.assertRaisesRegex(ValueError, message):
                        sign_epoch(self.trust, bad, key(8, 7), build, "", "")
                    with self.assertRaisesRegex(ValueError, message):
                        acknowledge(self.trust, bad, 1)
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
        with patch("custody_ledger.aws", side_effect=AssertionError("archive verification must work offline")):
            self.assertEqual(verify_archive(self.trust, document, sha256(document)), capture["receipt"])

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
        self.trust["approvalKeys"].append(schedule("2", 9))
        _, previous, _ = load_epoch(self.trust, "1")
        draft, _ = self.rotation_document(previous)
        with self.assertRaisesRegex(ValueError, "invalid or duplicate approval"):
            publish(self.trust, self.sign(draft, approval_keys(self.trust, "1")))
        publish(self.trust, self.sign(draft))
        self.assertEqual(load_epoch(self.trust, "1")[1], previous)
        self.assertEqual(load_epoch(self.trust, "2")[1]["custody"]["epoch"], "2")

    def test_archive_verifies_without_s3_or_kms_and_requires_the_exact_document_pin(self):
        document = self.sign(self.document(1))
        digest = sha256(document)
        with patch("custody_ledger.aws", side_effect=AssertionError("archive verification must not call S3")):
            self.assertEqual(verify_archive(self.trust, document, digest), record(self.trust, document)[0])
            document["acknowledgements"][0]["signature"] = document["authorization"]["signatures"][0]["signature"]
            with self.assertRaisesRegex(ValueError, "pinned custody document digest"):
                verify_archive(self.trust, document, digest)
            with self.assertRaisesRegex(ValueError, "invalid custody approval signature"):
                verify_archive(self.trust, document, sha256(document))

    @patch("custody_ledger.add_approval")
    @patch("custody_ledger.open_share", side_effect=ValueError("recovery package failed"))
    @patch("custody_ledger.kms")
    def test_custodian_acknowledges_only_a_recovered_share(self, kms, open_share, approval):
        document = self.sign(self.document(1))
        document["acknowledgements"] = []
        member = document["authorization"]["manifest"]["custodians"][0]
        kms.return_value = {"Policy": "{}"}
        with self.assertRaisesRegex(ValueError, "installed acknowledgement policy"):
            acknowledge(self.trust, document, 1)
        open_share.assert_not_called()
        kms.return_value = {"Policy": json.dumps(acknowledgement_policy(member["custodianRole"], member["retirementRole"]))}
        with self.assertRaisesRegex(ValueError, "recovery package failed"):
            acknowledge(self.trust, document, 1)
        open_share.assert_called_once()
        approval.assert_not_called()

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
            "StringLike": {"s3:prefix": [f"spr-custody/devnet/{DOMAIN}/{part}/*" for part in ("targets", "retired")]},
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

    def signed_subject(self, label, manifest):
        return {"manifest": manifest, "signatures": [sign(label, manifest, member["keyArn"])
                                                    for member in approval_keys(self.trust)[:2]]}

    def qualification(self, target, policy_digest="fe" * 32):
        return {"walletPolicyDigest": policy_digest, "replacementTargetIdentity": sha256(target_attestation(target)),
                "replacementTargetSha256": sha256(target)}

    def signed_retirement(self, manifest, slots=(1, 2, 3)):
        result = self.signed_subject(RETIREMENT, manifest)
        _, _, roster = load_epoch(self.trust, manifest["replacementEpoch"])
        result["recoveryProofs"] = [sign(RETIREMENT_RECOVERY, manifest, roster[index - 1]["acknowledgementKey"]["keyArn"])
                                    for index in slots]
        return result

    def replacement_target(self, **overrides):
        _, receipt, _ = load_epoch(self.trust, "2")
        return {"network": "devnet", "securityDomainId": DOMAIN, "custodyEpoch": "2",
                "receiptSha256": sha256(receipt), "approvalFromEpoch": self.trust["approvalKeys"][-1]["fromEpoch"],
                "releaseId": "new-slot", "mode": "serve", "hostRole": HOST,
                "executableSha256": "ab" * 32,
                "pcrs": {f"PCR{i}": f"{i+1:02x}" * 48 for i in range(3)}, **overrides}

    def test_wallet_activation_requires_each_target_registered_for_the_current_receipt(self):
        publish(self.trust, self.sign(self.document(1)))
        _, previous, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(previous)
        publish(self.trust, self.sign(rotated))
        _, replacement, _ = load_epoch(self.trust, "2")
        registered = self.replacement_target(expiresAt=1)
        replica = {**target_attestation(registered), "custodyEpoch": "2",
                   "executableSha256": registered["executableSha256"], "custodyDigest": sha256(replacement["custody"])}
        policy = {"action": "activate", "network": "devnet", "securityDomainId": DOMAIN,
                  "noteSeedCommitment": replacement["custody"]["noteSeedCommitment"], "minimumCustodyEpoch": "2",
                  "targets": [replica]}

        def check(**overrides):
            check_serving_policy(self.trust, {"policy": {**policy, **overrides}, "signatures": []})

        with self.assertRaisesRegex(ValueError, "object missing"):
            check()
        name = f"spr-custody/devnet/{DOMAIN}/{target_object_name(registered)}"
        for subject, message in (({**registered, "mode": "rotate"}, "custody-approved target"),
                                 ({**registered, "receiptSha256": "aa" * 32}, "committed custody receipt")):
            self.objects[name] = canonical(self.signed_subject(TARGET_APPROVAL, subject))
            with self.assertRaisesRegex(ValueError, message):
                check()
        self.objects[name] = canonical({"manifest": registered, "signatures": []})
        with self.assertRaisesRegex(ValueError, "signing quorum"):
            check()
        del self.objects[name]
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, registered))
        check()
        with self.assertRaisesRegex(ValueError, "committed note seed"):
            check(noteSeedCommitment="aa" * 32)
        for changes, message in (({"custodyDigest": "aa" * 32}, "committed custody record"),
                                 ({"executableSha256": "aa" * 32}, "custody-approved target"),
                                 ({"pcrs": {**replica["pcrs"], "3": "aa" * 48}}, "object missing"),
                                 ({"custodyEpoch": "1"}, "below the wallet custody floor")):
            with self.assertRaisesRegex(ValueError, message):
                check(targets=[replica, {**replica, **changes}])
        old = {**registered, "custodyEpoch": "1", "receiptSha256": sha256(previous), "releaseId": "old-slot"}
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, old))
        check(minimumCustodyEpoch="1", targets=[replica, {**replica, **target_attestation(old), "custodyEpoch": "1",
                                                          "custodyDigest": sha256(previous["custody"])}])
        self.objects[f"spr-custody/devnet/{DOMAIN}/retired/2.json"] = b"{}"
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
            "approvalFromEpoch": "1", "releaseId": "old-slot", "hostRole": HOST,
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

        self.trust["approvalKeys"].append(schedule("3", 9))
        role, inventory = key_inventory(self.trust, "1", 1)
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
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        self.trust["approvalKeys"].append(schedule("2", 9))
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        path = f"spr-custody/devnet/{DOMAIN}/retired/1.json"
        self.objects[path] = b"{}"
        with self.assertRaisesRegex(ValueError, "cannot verify retirement record"):
            require_active_epoch(self.trust, "1")
        with patch("retirement.kms") as kms, self.assertRaises(ValueError):
            inspect_keys(self.trust, "1", 1, False)
        kms.assert_not_called()

        replacement = self.replacement_target()
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, replacement))
        qualification.return_value = self.qualification(replacement)
        marker = qualified_manifest(self.trust, None, "1", "2")
        wrong = self.signed_retirement({**marker, "replacementReceiptSha256": "ab" * 32})
        self.objects[path] = json.dumps(wrong).encode()
        with patch("retirement.kms") as kms, self.assertRaisesRegex(ValueError, "retirement receipts do not match the ledger"):
            inspect_keys(self.trust, "1", 1, False)
        kms.assert_not_called()

        wrong = self.signed_retirement({**marker, "replacementTargetSha256": "ab" * 32})
        self.objects[path] = json.dumps(wrong).encode()
        with patch("retirement.kms") as kms, self.assertRaisesRegex(ValueError, "does not match the registered serving"):
            inspect_keys(self.trust, "1", 1, False)
        kms.assert_not_called()

        self.objects[path] = json.dumps(self.signed_retirement(marker)).encode()
        stale = {**self.trust, "approvalKeys": self.trust["approvalKeys"][:1]}
        with self.assertRaisesRegex(ValueError, "cannot verify.*unknown retirement approval roster"):
            require_active_epoch(stale, "1")
        with self.assertRaisesRegex(ValueError, "custody epoch is retired"):
            require_active_epoch(self.trust, "1")

    def test_retirement_qualifies_only_a_live_registered_serving_image_and_role(self):
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        scope, receipt, _ = retirement_scope(self.trust, "1", "2")
        seed = receipt["custody"]["noteSeedCommitment"]
        registered = self.replacement_target()
        pins = {key.removeprefix("PCR"): value for key, value in boot_pins(HOST, registered["pcrs"]).items()}
        evidence = {"policyDigest": "fe" * 32, "targets": [{"releaseId": registered["releaseId"], "pcrs": pins}]}

        with tempfile.TemporaryDirectory() as directory:
            wallet_trust = pathlib.Path(directory) / "wallet.json"
            body = b'{"wallet":"trust fixture"}\n'
            wallet_trust.write_bytes(body)
            self.trust["walletTrustSha256"] = hashlib.sha256(body).hexdigest()
            with patch("retirement.subprocess") as subprocess:
                subprocess.run.return_value.stdout = json.dumps(evidence).encode()
                with self.assertRaisesRegex(ValueError, "no registered serving target"):
                    qualified_policy(self.trust, wallet_trust, scope, seed)

                rotation = {**registered, "mode": "rotate", "pcrs": {**registered["pcrs"], "PCR2": "ef" * 48}}
                register_target(self.trust, self.signed_subject(TARGET_APPROVAL, rotation))
                with self.assertRaisesRegex(ValueError, "no registered serving target"):
                    qualified_policy(self.trust, wallet_trust, scope, seed)
                subprocess.run.assert_not_called()

                register_target(self.trust, self.signed_subject(TARGET_APPROVAL, registered))
                subprocess.run.return_value.stdout = json.dumps({**evidence, "targets": [
                    {"releaseId": registered["releaseId"], "pcrs": {**pins, "3": "ab" * 48}},
                ]}).encode()
                with self.assertRaisesRegex(ValueError, "no attested serving target"):
                    qualified_policy(self.trust, wallet_trust, scope, seed)

                subprocess.run.return_value.stdout = json.dumps(evidence).encode()
                self.assertEqual(qualified_policy(self.trust, wallet_trust, scope, seed), self.qualification(registered))
                self.assertEqual(subprocess.run.call_args.kwargs["input"], body)
                self.assertNotIn(str(wallet_trust), subprocess.run.call_args.args[0])
                subprocess.run.reset_mock()
                wallet_trust.write_bytes(b"{}")
                with self.assertRaisesRegex(ValueError, "does not match the pinned digest"):
                    qualified_policy(self.trust, wallet_trust, scope, seed)
                subprocess.run.assert_not_called()

    def test_one_wrapping_set_per_attested_identity_and_reauthorizing_keeps_the_registration(self):
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        original = self.replacement_target(expiresAt=1, wrappingKeys=[key(i, 3) for i in range(1, 7)])
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

        self.trust["approvalKeys"].append(schedule("3", 9))
        renewed = {**winner, "expiresAt": 2, "approvalFromEpoch": "3"}
        register_target(self.trust, self.signed_subject(TARGET_APPROVAL, renewed))
        require_registered_target(self.trust, renewed)
        self.assertEqual(len([name for name in self.objects if "/targets/2/" in name]), 1)

    @patch("retirement.qualified_policy")
    def test_retirement_requires_three_proven_replacement_keys_to_stay_enabled(self, qualification):
        publish(self.trust, self.sign(self.document(1)))
        _, old, _ = load_epoch(self.trust, "1")
        rotated, _ = self.rotation_document(old)
        publish(self.trust, self.sign(rotated))
        _, _, custodians = load_epoch(self.trust, "2")
        keys = [item["recoveryKeyArn"] for item in custodians]
        states = ["Enabled", "Enabled", "Disabled", "Enabled", None, "foreign"]

        def describe(arn, operation):
            self.assertEqual(operation, "describe-key")
            state = states[keys.index(arn)]
            if state is None:
                raise ValueError("unavailable account")
            return {"KeyMetadata": {"Arn": arn if state != "foreign" else key(99), "Origin": "AWS_KMS", "MultiRegion": False,
                                    "KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "RSA_2048",
                                    "KeyState": "Enabled" if state == "foreign" else state}}

        with patch("retirement.kms", side_effect=describe):
            qualification.return_value = self.qualification(self.replacement_target())
            marker = qualified_manifest(self.trust, None, "1", "2")
            retirement = self.signed_retirement(marker)
            with self.assertRaisesRegex(ValueError, "only 2 proven replacement recovery keys"):
                commit_retirement(self.trust, None, retirement)
            states[2] = "Enabled"
            with patch("retirement.add_approval", return_value={"signatures": retirement["signatures"]}):
                self.assertEqual(sign_retirement(self.trust, None, {**retirement, "signatures": []},
                                                 approval_keys(self.trust)[0]["keyArn"]), retirement)
            states[2] = "PendingDeletion"
            with self.assertRaisesRegex(ValueError, "only 2 proven replacement recovery keys"):
                commit_retirement(self.trust, None, retirement)
            self.assertTrue(all("/retired/" not in name for name in self.objects))
            commit_retirement(self.trust, None, self.signed_retirement(marker, (1, 2, 4)))

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
                                 (rotated["acknowledgements"], "invalid custody approval signature"),
                                 (other["recoveryProofs"], "invalid custody approval signature")):
            bad = {**retired, "recoveryProofs": invalid}
            with self.assertRaisesRegex(ValueError, message):
                sign_retirement(self.trust, None, bad, approval_keys(self.trust)[0]["keyArn"])
            with self.assertRaisesRegex(ValueError, message):
                commit_retirement(self.trust, None, bad)
            self.objects[path] = canonical(bad)
            with self.assertRaisesRegex(ValueError, message):
                key_inventory(self.trust, "1", 1)
            del self.objects[path]
        quorum.assert_not_called()

        deadline = marker["recoveryDeadline"]
        for now in (deadline - RECOVERY_WINDOW_SECONDS - 1, deadline, deadline - 1):
            with patch("retirement.time.time", return_value=now):
                with self.assertRaisesRegex(ValueError, "recovery window"):
                    commit_retirement(self.trust, None, retired)
        self.assertNotIn(path, self.objects)
        commit_retirement(self.trust, None, retired)
        commit_retirement(self.trust, None, retired)
        with patch("retirement.time.time", return_value=deadline + 1):
            self.assertIn(key(1), key_inventory(self.trust, "1", 1)[1])
        self.timestamps[path] = datetime.fromtimestamp(deadline, timezone.utc).isoformat()
        with self.assertRaisesRegex(ValueError, "outside the recovery window"):
            key_inventory(self.trust, "1", 1)

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
              patch("custody_ledger.open_share", side_effect=ValueError("recovery failed")) as open_share,
              patch("custody_ledger.add_approval") as approval):
            with self.assertRaisesRegex(ValueError, "committed receipts"):
                prove_recovery(self.trust, {**candidate, "manifest": {**marker, "replacementReceiptSha256": "ab" * 32}}, 2)
            kms.assert_not_called()
            with self.assertRaisesRegex(ValueError, "recovery failed"):
                prove_recovery(self.trust, candidate, 2)
            open_share.assert_called_once_with(member, receipt, 2)
            approval.assert_not_called()
            open_share.side_effect = None
            approval.return_value = {"signatures": [sign(RETIREMENT_RECOVERY, marker, key_arn)]}
            proven = prove_recovery(self.trust, candidate, 2)
            self.assertEqual(len(proven["recoveryProofs"]), 1)
            approval.assert_called_once_with([item["acknowledgementKey"] for item in roster], RETIREMENT_RECOVERY,
                                             {"manifest": marker, "signatures": []}, key_arn)
