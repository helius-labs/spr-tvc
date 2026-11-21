import copy
import json
import pathlib
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from approval import approval_keys, sha256
from custody_ledger import ACKNOWLEDGEMENT, LABEL, acknowledge, ledger_policy, load_epoch, publish, record, verify_archive
from kms_policy import acknowledgement_policy
from nitro_fixtures import DOMAIN, HOST, key, pin, schedule, sign

READ_ROLE = "arn:aws:iam::000000000001:role/custodian"
PUBLISHER = "arn:aws:iam::000000000008:role/publisher"


class CustodyLedgerTests(unittest.TestCase):
    def setUp(self):
        self.trust = {
            "network": "devnet", "securityDomainId": DOMAIN, "approvalKeys": [schedule()],
            "ledger": {"bucket": "custody-journal", "account": "000000000008", "region": "eu-north-1"},
        }
        self.objects = {}
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
        deployment = {"mode": "initialize"} if not predecessor else {"mode": "rotate", "previous": predecessor["custody"]}
        manifest = {
            "capture": {"receipt": receipt, "evidence": "aa", "nonce": "88" * 32, "verifiedAtMs": "1",
                        "configuration": {"deployment": deployment}, "pcrs": {}},
            "ceremonyEifSha256": "aa" * 32, "ceremonyHostRole": HOST,
            "custodians": roster, "previousReceiptSha256": sha256(predecessor) if predecessor else None,
        }
        return {"authorization": {"manifest": manifest, "signatures": []}, "acknowledgements": []}

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
        name = args[args.index("--key") + 1]
        self.assertTrue(name.startswith(f"spr-custody/devnet/{DOMAIN}/"))
        with self.lock:
            if operation == "put-object":
                self.assertEqual(args[args.index("--if-none-match") + 1], "*")
                if name in self.objects:
                    raise ValueError("precondition failed")
                self.objects[name] = pathlib.Path(args[-1]).read_bytes()
            elif operation == "get-object" and name in self.objects:
                pathlib.Path(args[-1]).write_bytes(self.objects[name])
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
        new = self.document(2, previous, variant="fe")
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
        draft = self.document(2, previous)
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
        statements = {item["Sid"]: item for item in ledger_policy(self.trust, PUBLISHER, [READ_ROLE])["Statement"]}
        self.assertEqual(statements["RequireWriteOnce"]["Condition"], {"StringNotEquals": {"s3:if-none-match": "*"}})
        self.assertEqual(statements["RequireWriteOnce"]["Principal"], "*")
        self.assertEqual(statements["RestrictPublisher"]["Condition"], {"StringNotEquals": {"aws:PrincipalArn": PUBLISHER}})
        self.assertIn("s3:DeleteObject", statements["PreserveCustodyHistory"]["Action"])
        self.assertEqual(statements["AllowReaders"]["Principal"], {"AWS": [READ_ROLE, PUBLISHER]})
