import base64
import hashlib
import json
import pathlib
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from approval import sha256, signature_args
from deployment import LABEL, file_digest, target
from kms_policy import recovery_policy
from wrap_share import wrap

DOMAIN = "ab" * 32
HOST = "arn:aws:iam::000000000007:role/host"
PINS = {f"PCR{index}": byte * 48 for index, byte in enumerate(("12", "23", "34"))}
DER_SIGNATURE = base64.b64encode(bytes.fromhex("3006020101020101")).decode()


def key(account, slot=1):
    return f"arn:aws:kms:eu-north-1:{account:012}:key/12345678-1234-1234-1234-{slot:012}"


class TargetApprovalTests(unittest.TestCase):
    def setUp(self):
        self.build = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.trust = {"network": "devnet", "securityDomainId": DOMAIN, "approvalKeys": [key(i) for i in (8, 9, 10)]}
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
        self.custodians = [{
            "recoveryKeyArn": key(i), "acknowledgementKeyArn": key(i, 3),
            "custodianRole": f"arn:aws:iam::{i:012}:role/custodian",
            "retirementRole": f"arn:aws:iam::{i:012}:role/retirement",
        } for i in range(1, 7)]
        self.manifest = {
            "network": "devnet", "securityDomainId": DOMAIN, "receiptSha256": sha256(self.receipt),
            "custodyEpoch": "5",
            "releaseId": "release-a", "mode": "serve", "expiresAt": int(time.time()) + 3600,
            "eifSha256": file_digest(self.build / "enclave.eif"),
            "configurationSha256": file_digest(self.build / "configuration.json"),
            "pcrs": PINS, "hostRole": HOST, "wrappingKeys": [key(i, 2) for i in range(1, 7)], "nextCustodians": None,
        }
        self.approval = {"manifest": self.manifest, "signatures": [
            {"keyArn": signer, "signature": DER_SIGNATURE} for signer in self.trust["approvalKeys"][:2]
        ]}
        _, policies, _ = target(self.trust, self.approval, self.receipt, self.custodians, self.build)
        self.policy = policies[0]
        self.recovery_policy = recovery_policy(self.custodians[0]["custodianRole"], self.custodians[0]["retirementRole"])
        self.signed = signature_args(LABEL, self.manifest)
        self.calls = []
        self.policy_key = key(1, 2)
        self.key_metadata = {"Arn": self.policy_key, "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT",
                             "Origin": "AWS_KMS", "MultiRegion": False, "KeyState": "Enabled"}
        self.enterContext(patch("approval.kms", side_effect=self.kms))
        self.enterContext(patch("custody_ledger.kms", side_effect=self.kms))
        self.enterContext(patch("wrap_share.kms", side_effect=self.kms))
        self.ledger = self.enterContext(patch("wrap_share.load_epoch", side_effect=self.load_epoch))

    def load_epoch(self, trust, epoch):
        self.assertEqual(trust, self.trust)
        self.assertEqual(epoch, "5")
        return {}, self.receipt, self.custodians

    def kms(self, arn, operation, args=(), body=None):
        self.calls.append(operation)
        if operation == "verify":
            return {"KeyId": arn, "SignatureValid": args == [*self.signed, "--signature", DER_SIGNATURE],
                    "SigningAlgorithm": "ECDSA_SHA_256"}
        if operation == "describe-key":
            return {"KeyMetadata": self.key_metadata}
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
        self.assertEqual(self.calls, ["verify", "verify", "describe-key", "get-key-policy", "get-key-policy",
                                      "get-public-key", "decrypt", "encrypt"])

    def test_no_decrypt_without_quorum_or_with_duplicate_signer(self):
        signers = self.approval["signatures"]
        for signatures in [signers[:1], [signers[0], signers[0]], [signers[0], {**signers[1], "keyArn": key(12)}]]:
            with self.subTest(signatures=signatures):
                self.approval["signatures"] = signatures
                with self.assertRaises(ValueError):
                    self.wrap()
        self.assertTrue(all(call == "verify" for call in self.calls))

    def test_replacement_wrapping_key_invalidates_approvals(self):
        self.manifest["wrappingKeys"][0] = key(1, 4)
        with self.assertRaisesRegex(ValueError, "signature"):
            self.wrap()
        self.assertEqual(self.calls, ["verify"])

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
        self.assertEqual(self.calls, ["verify", "verify", "describe-key", "get-key-policy"])

    def test_rejects_permissive_recovery_key_policy_before_decrypting(self):
        self.recovery_policy["Statement"].pop(1)
        with self.assertRaisesRegex(ValueError, "installed recovery key policy"):
            self.wrap()
        self.assertEqual(self.calls, ["verify", "verify", "describe-key", "get-key-policy", "get-key-policy"])

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
        self.assertEqual(keys[0], (key(1, 4), hashlib.sha256(bytes.fromhex(recipients[0])).hexdigest()))
        roster[0]["recoveryKeyArn"] = key(1)
        with self.assertRaisesRegex(ValueError, "rotate recovery keys"):
            target(self.trust, self.approval, self.receipt, self.custodians, self.build)
