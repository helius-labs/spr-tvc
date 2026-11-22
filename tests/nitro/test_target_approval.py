import base64
import hashlib
import io
import json
import pathlib
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from approval import sha256
from custody_ledger import TARGET_APPROVAL
from deployment import file_digest, main, target
from kms_policy import recovery_policy
from nitro_fixtures import DOMAIN, HOST, key, pin, schedule, sign
from provenance import describe
from wrap_share import wrap

PINS = {f"PCR{index}": byte * 48 for index, byte in enumerate(("12", "23", "34"))}


class TargetApprovalTests(unittest.TestCase):
    def setUp(self):
        self.build = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.trust = {"network": "devnet", "securityDomainId": DOMAIN, "approvalKeys": [schedule()]}
        self.share = (5).to_bytes(8, "big") + b"\x01" + bytes([0x44]) * 32
        commitment = hashlib.sha256(b"SPR/native-nitro/custody-share/v1" + bytes.fromhex(DOMAIN) + self.share).hexdigest()
        spki = hashlib.sha256(b"public").hexdigest()
        custody = {"epoch": "5", "shareCommitments": [commitment]}
        self.receipt = {
            "network": "devnet", "securityDomainId": DOMAIN, "custody": custody,
            "packages": [{"recipientSha256": spki, "ciphertext": "66" * 256}],
        }
        (self.build / "configuration.json").write_text(json.dumps({
            "releaseId": "release-a", "securityDomainId": DOMAIN, "deployment": {"mode": "serve", "custody": custody},
        }))
        (self.build / "measurements.json").write_text(json.dumps({"Measurements": PINS}))
        (self.build / "enclave.eif").write_bytes(b"EIF fixture")
        (self.build / "tvc_app").write_bytes(b"executable fixture")
        self.custodians = [{
            "recoveryKeyArn": key(i), "acknowledgementKey": pin(key(i, 3)),
            "custodianRole": f"arn:aws:iam::{i:012}:role/custodian",
            "retirementRole": f"arn:aws:iam::{i:012}:role/retirement",
        } for i in range(1, 7)]
        self.manifest = {
            "network": "devnet", "securityDomainId": DOMAIN, "receiptSha256": sha256(self.receipt),
            "custodyEpoch": "5", "approvalFromEpoch": "1",
            "releaseId": "release-a", "mode": "serve", "expiresAt": int(time.time()) + 3600,
            "eifSha256": file_digest(self.build / "enclave.eif"),
            "executableSha256": file_digest(self.build / "tvc_app"),
            "configurationSha256": file_digest(self.build / "configuration.json"),
            "pcrs": PINS, "hostRole": HOST, "wrappingAlgorithm": "SYMMETRIC_DEFAULT", "wrappingKeys": [key(i, 2) for i in range(1, 7)], "nextCustodians": None,
        }
        self.approval = {"manifest": self.manifest, "signatures": [
            sign(TARGET_APPROVAL, self.manifest, signer["keyArn"]) for signer in self.trust["approvalKeys"][0]["keys"][:2]
        ]}
        _, policies, _ = target(self.trust, self.approval, self.receipt, self.custodians, self.build)
        self.policy = policies[0]
        self.recovery_policy = recovery_policy(self.custodians[0]["custodianRole"], self.custodians[0]["retirementRole"], "5")
        self.calls = []
        self.policy_key = key(1, 2)
        self.key_metadata = {"Arn": self.policy_key, "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT",
                             "Origin": "AWS_KMS", "MultiRegion": False, "KeyState": "Enabled"}
        self.recovery_metadata = {**self.key_metadata, "Arn": key(1), "KeySpec": "RSA_2048"}
        self.enterContext(patch("approval.kms", side_effect=self.kms))
        self.enterContext(patch("custody_ledger.kms", side_effect=self.kms))
        self.enterContext(patch("wrap_share.kms", side_effect=self.kms))
        self.ledger = self.enterContext(patch("wrap_share.load_epoch", side_effect=self.load_epoch))
        self.registry = self.enterContext(patch("wrap_share.require_registered_target"))
        self.active = self.enterContext(patch("wrap_share.require_active_epoch"))

    def load_epoch(self, trust, epoch):
        self.assertEqual(trust, self.trust)
        self.assertEqual(epoch, "5")
        return {}, self.receipt, self.custodians

    def kms(self, arn, operation, args=(), body=None):
        self.calls.append(operation)
        if operation == "describe-key":
            return {"KeyMetadata": self.key_metadata if arn == self.policy_key else self.recovery_metadata}
        if operation == "get-key-policy":
            return {"Policy": json.dumps(self.policy if arn == self.policy_key else self.recovery_policy)}
        if operation == "get-public-key":
            return {"KeyId": arn, "PublicKey": base64.b64encode(b"public").decode(), "KeyUsage": "ENCRYPT_DECRYPT",
                    "KeySpec": "RSA_2048", "EncryptionAlgorithms": ["RSAES_OAEP_SHA_256"]}
        if operation == "decrypt":
            return {"KeyId": arn, "Plaintext": base64.b64encode(self.share).decode()}
        if operation == "encrypt":
            self.assertEqual(arn, self.policy_key)
            self.assertEqual(body, self.share)
            self.assertEqual(json.loads(args[-1])["custody-epoch"], "5")
            return {"KeyId": arn, "CiphertextBlob": "d3JhcHBlZA=="}
        self.fail(operation)

    def wrap(self):
        return wrap(self.trust, self.approval, self.build, 1)

    def test_quorum_and_installed_policy_checked_before_opening_one_share(self):
        self.assertEqual(self.wrap(), b"wrapped")
        self.registry.assert_called_once_with(self.trust, self.manifest)
        self.assertEqual(self.active.call_count, 3)
        self.assertEqual(self.calls, ["describe-key", "get-key-policy", "get-key-policy", "describe-key",
                                      "get-public-key", "decrypt", "encrypt"])

    def test_no_decrypt_without_quorum_or_with_duplicate_signer(self):
        signers = self.approval["signatures"]
        for signatures in [signers[:1], [signers[0], signers[0]], [signers[0], {**signers[1], "keyArn": key(12)}]]:
            with self.subTest(signatures=signatures):
                self.approval["signatures"] = signatures
                with self.assertRaises(ValueError):
                    self.wrap()
        self.assertEqual(self.calls, [])

    def test_replacement_wrapping_key_invalidates_approvals(self):
        self.manifest["wrappingKeys"][0] = key(1, 4)
        with self.assertRaisesRegex(ValueError, "signature"):
            self.wrap()
        self.assertEqual(self.calls, [])

    def test_changed_executable_fails_before_opening_a_share(self):
        (self.build / "tvc_app").write_bytes(b"different executable")
        with self.assertRaisesRegex(ValueError, "target artifacts do not match"):
            self.wrap()
        self.assertEqual(self.calls, [])

    def test_signs_only_the_target_bound_to_verified_provenance(self):
        trust_path, target_path, output = (self.build / name for name in ("trust.json", "target.json", "approved.json"))
        trust_path.write_text(json.dumps(self.trust))
        target_path.write_text(json.dumps(self.approval))
        commit = "ab" * 20
        signing_key = self.trust["approvalKeys"][0]["keys"][2]["keyArn"]
        argv = ["deployment.py", str(trust_path), str(self.build), "sign", str(target_path),
                signing_key, str(output), "--source-commit", commit]
        reviewed = describe(self.build, "devnet", commit)
        with (patch("sys.argv", argv), patch("deployment.load_epoch", side_effect=self.load_epoch),
              patch("deployment.require_active_epoch"), patch("deployment.verify_build") as verify_build,
              patch("deployment.add_approval", return_value=self.approval) as sign_target):
            for field in ("configurationSha256", "eifSha256", "executableSha256", "pcrs"):
                value = {**PINS, "PCR0": "aa" * 48} if field == "pcrs" else "aa" * 32
                verify_build.return_value = {**reviewed, field: value}
                with self.subTest(field=field), self.assertRaisesRegex(SystemExit, "verified build provenance"):
                    main()
            sign_target.assert_not_called()
            self.assertFalse(output.exists())
            verify_build.return_value = reviewed
            main()
            self.assertEqual(json.loads(output.read_bytes()), self.approval)
            sign_target.assert_called_once()

    def test_host_policy_command_requires_the_registered_quorum_approved_target(self):
        trust_path, target_path = self.build / "trust.json", self.build / "target.json"
        trust_path.write_text(json.dumps(self.trust))
        argv = ["deployment.py", str(trust_path), str(self.build), "host-policy", str(target_path)]
        with (patch("sys.argv", argv), patch("deployment.load_epoch", side_effect=self.load_epoch),
              patch("deployment.require_registered_target") as registered, patch("sys.stdout", new_callable=io.StringIO) as output):
            target_path.write_text(json.dumps({**self.approval, "signatures": []}))
            with self.assertRaisesRegex(SystemExit, "signing quorum"):
                main()
            registered.assert_not_called()
            target_path.write_text(json.dumps(self.approval))
            registered.side_effect = ValueError("target is unregistered")
            with self.assertRaisesRegex(SystemExit, "unregistered"):
                main()
            self.assertEqual(output.getvalue(), "")
            registered.side_effect = None
            main()
            self.assertEqual([rule["Resource"] for rule in json.loads(output.getvalue())["Statement"]],
                             self.manifest["wrappingKeys"])

    def test_rejects_receipt_and_eif_substitution(self):
        self.receipt["packages"][0]["ciphertext"] = "00" * 256
        with self.assertRaisesRegex(ValueError, "receipt"):
            self.wrap()
        self.receipt["packages"][0]["ciphertext"] = "66" * 256
        (self.build / "enclave.eif").write_bytes(b"wrong EIF")
        with self.assertRaisesRegex(ValueError, "artifacts"):
            self.wrap()
        self.assertEqual(self.calls, [])

    def test_rejects_permissive_policy_before_invoking_recovery_key(self):
        self.policy["Statement"].pop(0)
        with self.assertRaisesRegex(ValueError, "installed wrapping key policy"):
            self.wrap()
        self.assertEqual(self.calls, ["describe-key", "get-key-policy"])

    def test_rejects_permissive_recovery_key_policy_before_decrypting(self):
        self.recovery_policy["Statement"].pop(1)
        with self.assertRaisesRegex(ValueError, "installed recovery key policy"):
            self.wrap()
        self.assertEqual(self.calls, ["describe-key", "get-key-policy", "get-key-policy"])

    def test_rejects_a_recovery_key_sealed_for_another_epoch(self):
        self.recovery_policy = recovery_policy(self.custodians[0]["custodianRole"], self.custodians[0]["retirementRole"], "4")
        with self.assertRaisesRegex(ValueError, "installed recovery key policy"):
            self.wrap()
        self.assertNotIn("decrypt", self.calls)

    def test_rejects_imported_or_replicated_recovery_material_before_decrypting(self):
        expected = self.recovery_metadata
        for changes in ({"Origin": "EXTERNAL"}, {"MultiRegion": True}):
            self.recovery_metadata = {**expected, **changes}
            self.calls.clear()
            with self.assertRaisesRegex(ValueError, "generated by AWS KMS"):
                self.wrap()
            self.assertNotIn("decrypt", self.calls)

    def test_rechecks_expiration_across_kms_calls(self):
        deadline = self.manifest["expiresAt"]
        for times, last_call in (
            ([deadline], "get-public-key"),
            ([deadline - 1, deadline], "decrypt"),
            ([deadline - 1, deadline - 1, deadline], "encrypt"),
        ):
            with self.subTest(stage=last_call), patch("wrap_share.time", side_effect=times):
                self.calls.clear()
                with self.assertRaisesRegex(ValueError, "target approval has expired"):
                    self.wrap()
                self.assertEqual(self.calls[-1], last_call)

    def test_checks_roster_cutover_before_recovery_key_use(self):
        cutover = int(time.time()) + 100
        self.trust["approvalKeys"].append(schedule("6", 9, cutover))
        with patch("wrap_share.time", return_value=cutover):
            with self.assertRaisesRegex(ValueError, "current approval roster"):
                self.wrap()
        self.assertNotIn("decrypt", self.calls)

    def test_stops_when_retirement_races_share_recovery(self):
        self.active.side_effect = [None, ValueError("custody epoch is retired")]
        with self.assertRaisesRegex(ValueError, "custody epoch is retired"):
            self.wrap()
        self.assertEqual(self.calls[-1], "decrypt")

    def test_rejects_corrupt_share_before_wrapping(self):
        original = self.share
        for corrupt in [bytes(41), original[:-1], original[:-1] + b"\x12"]:
            self.share = corrupt
            self.calls.clear()
            with self.assertRaises(ValueError):
                self.wrap()
            self.assertEqual(self.calls[-1], "decrypt")

    def test_rejects_uncommitted_epoch_before_kms_operations(self):
        self.ledger.side_effect = ValueError("uncommitted epoch")
        with self.assertRaisesRegex(ValueError, "uncommitted"):
            self.wrap()
        self.assertEqual(self.calls, [])

    def test_unregistered_or_retired_target_cannot_decrypt(self):
        for detail in ("target not registered", "custody epoch is retired"):
            self.calls.clear()
            self.registry.side_effect = ValueError(detail)
            with self.assertRaisesRegex(ValueError, detail):
                self.wrap()
            self.assertNotIn("decrypt", self.calls)

    def test_rotation_binds_new_recovery_keys_and_rejects_reuse(self):
        self.manifest["mode"] = "rotate"
        roster = [{**member, "recoveryKeyArn": key(index, 4)} for index, member in enumerate(self.custodians, start=1)]
        self.manifest["nextCustodians"] = roster
        recipients = [f"{i:02x}" * 294 for i in range(1, 7)]
        path = self.build / "configuration.json"
        path.write_text(json.dumps({
            "releaseId": "release-a", "securityDomainId": DOMAIN, "deployment": {
                "mode": "rotate", "previous": self.receipt["custody"], "recipientPublicKeys": recipients,
            },
        }))
        self.manifest["configurationSha256"] = file_digest(path)
        _, _, keys = target(self.trust, self.approval, self.receipt, self.custodians, self.build)
        self.assertEqual(keys[0], hashlib.sha256(bytes.fromhex(recipients[0])).hexdigest())
        self.manifest["wrappingAlgorithm"] = "RSAES_OAEP_SHA_256"
        with self.assertRaisesRegex(ValueError, "does not match the epoch's pinned recovery path"):
            target(self.trust, self.approval, self.receipt, self.custodians, self.build)
        self.trust["recoveryRelays"] = {"5": {}}
        with self.assertRaisesRegex(ValueError, "cannot rotate a relay epoch to plaintext"):
            target(self.trust, self.approval, self.receipt, self.custodians, self.build)
        self.trust["recoveryRelays"]["6"] = {}
        roster[0]["recoveryKeyArn"] = key(1)
        with self.assertRaisesRegex(ValueError, "rotate recovery keys"):
            target(self.trust, self.approval, self.receipt, self.custodians, self.build)
