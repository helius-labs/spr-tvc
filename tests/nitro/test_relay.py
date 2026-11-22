import base64
import hashlib
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from relay import prove_share, recover_to_relay
from relay_wrap import LABEL, release
from nitro_fixtures import DOMAIN, HOST, key, pin, sign

SCOPE = {"hostRole": HOST, "pcrs": {f"PCR{i}": f"{i+1:02x}" * 48 for i in range(3)}}
TRUST = {"network": "devnet", "recoveryRelays": {"1": SCOPE}}
CUSTODIAN = {"custodianRole": "arn:aws:iam::000000000001:role/custodian",
             "retirementRole": "arn:aws:iam::000000000001:role/retirement", "recoveryKeyArn": key(1)}
PUBLIC = b"fixture SPKI for an immutable recovery key"
RECEIPT = {"securityDomainId": DOMAIN, "custody": {"epoch": "1", "shareCommitments": ["ab" * 32]},
           "packages": [{"recipientSha256": hashlib.sha256(PUBLIC).hexdigest(), "ciphertext": "de" * 256}]}
KEYS = [pin(key(i, 9)) for i in (10, 11, 12)]


class RelayTests(unittest.TestCase):
    @patch("relay.sealed_rsa_key", return_value=PUBLIC)
    @patch("relay.key_result")
    def test_source_requests_only_attested_ciphertext_for_the_committed_recovery_key(self, kms, sealed):
        checks = []
        attested = b"attested relay recipient"
        result = {"CiphertextForRecipient": base64.b64encode(b"ciphertext").decode()}
        kms.return_value = {**result, "Plaintext": "YQ=="}
        with self.assertRaisesRegex(ValueError, "unexpected plaintext"):
            recover_to_relay(TRUST, RECEIPT, CUSTODIAN, 1, attested, lambda: checks.append(1))
        kms.return_value = result
        self.assertEqual(recover_to_relay(TRUST, RECEIPT, CUSTODIAN, 1, attested, lambda: checks.append(1)), b"ciphertext")
        args = kms.call_args.args
        self.assertEqual(args[:2], (key(1), "decrypt"))
        self.assertIn(base64.b64encode(attested).decode(), args[2][-1])
        self.assertEqual(checks, [1, 1])
        self.assertIn("DenyWrongPCR0", {rule["Sid"] for rule in sealed.call_args.args[1]["Statement"]})
        sealed.return_value = b"incorrect key"
        kms.reset_mock()
        with self.assertRaisesRegex(ValueError, "does not match its RSA KMS key"):
            recover_to_relay(TRUST, RECEIPT, CUSTODIAN, 1, attested, lambda: checks.append(1))
        kms.assert_not_called()

    @patch("relay.verify_evidence")
    @patch("relay.relay_request", return_value=b"attested share proof")
    @patch("relay.recover_to_relay", return_value=b"envelope")
    @patch("relay.live_recipient", return_value=("12" * 32, b"evidence"))
    def test_acknowledgement_verifies_fresh_evidence_for_the_exact_slot(self, _recipient, _decrypt, request, verify):
        prove_share(TRUST, RECEIPT, CUSTODIAN, 1, 7443, lambda: None)
        self.assertEqual(request.call_args.args[:2], (7443, "/prove"))
        self.assertEqual(verify.call_args.args[1:], (b"attested share proof", SCOPE))
        expected = hashlib.sha256(b"SPR/native-nitro/relay-share-proof/v1devnet" + bytes.fromhex(DOMAIN) +
                                  (1).to_bytes(8, "big") + b"\x01" + bytes.fromhex("ab" * 32)).hexdigest()
        self.assertEqual(verify.call_args.kwargs["binding"], expected)

    @patch("relay_wrap.require_active_epoch")
    @patch("relay_wrap.verify_target_approval")
    @patch("relay_wrap.relay_request", return_value=b"x" * 256)
    @patch("relay_wrap.recover_to_relay", return_value=b"envelope")
    @patch("relay_wrap.prepare")
    def test_release_checks_the_live_boot_and_exact_quorum_before_any_recovery(self, prepare, recover, request, _verify, active):
        statement = {"custodyEpoch": "1", "relayKeyId": "ab" * 32, "destinationPublicKey": "cd" * 32}
        prepare.return_value = (statement, KEYS, RECEIPT, CUSTODIAN, b"evidence")
        signatures = [sign(LABEL, statement, pin["keyArn"]) for pin in KEYS[:2]]
        approved = {"manifest": statement, "signatures": signatures}
        source = (TRUST, {}, pathlib.Path("build"), 1, 7443)
        for edited in [
            {**approved, "manifest": {**statement, "relayKeyId": "ef" * 32}},
            {**approved, "signatures": signatures[:1]},
            {**approved, "signatures": [signatures[0], signatures[0]]},
        ]:
            with self.assertRaises(ValueError):
                release(*source, edited)
        recover.assert_not_called()
        request.assert_not_called()
        self.assertEqual(release(*source, approved), b"x" * 256)
        self.assertEqual(request.call_args.args[:2], (7443, "/rewrap"))
        payload = request.call_args.args[2]
        self.assertIn(b'"envelope":"656e76656c6f7065"', payload)
        self.assertEqual(active.call_count, 2)

if __name__ == "__main__":
    unittest.main()
