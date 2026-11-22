import base64
import hashlib
import json
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from approval import aws
from deployment import host_policy
from kms_policy import RSA_OAEP, key_policy, recovery_policy, validate_scope
from provision import provision, read_target, recipient_for
from relay import decrypt_recipient

HOST = "arn:aws:iam::111111111111:role/host"
CUSTODIAN = "arn:aws:iam::222222222222:role/custodian"
RETIREMENT = "arn:aws:iam::222222222222:role/retirement"
PINS = {f"PCR{index}": byte * 48 for index, byte in enumerate(("12", "23", "34"))}
DOMAIN = "ab" * 32
KEY_1 = "arn:aws:kms:eu-north-1:222222222222:key/12345678-1234-1234-1234-123456789abc"
KEYS = [KEY_1.replace("222222222222", f"{index:012d}") for index in range(1, 7)]
TARGET = {"network": "mainnet", "securityDomainId": DOMAIN, "releaseId": "release-a", "custodyEpoch": "5",
          "hostRole": HOST, "pcrs": PINS, "wrappingKeys": KEYS, "mode": "serve", "expiresAt": 2_000_000_000,
          "nextCustodians": None, "nextRelay": None, "approvalFromEpoch": "1", "receiptSha256": "11" * 32,
          "eifSha256": "22" * 32, "configurationSha256": "33" * 32, "executableSha256": "44" * 32}
SHARES = pathlib.Path("shares")


class KeyPolicyTests(unittest.TestCase):
    def test_only_the_approved_principal_with_all_pcrs_can_decrypt(self):
        for policy, principal in (
            (recovery_policy(CUSTODIAN, RETIREMENT, HOST, PINS, "5"), CUSTODIAN),
            (key_policy(HOST, CUSTODIAN, RETIREMENT, PINS), HOST),
        ):
            statements = policy["Statement"]
            grant, = [rule for rule in statements if rule["Effect"] == "Allow" and rule["Action"] == "kms:Decrypt"]
            self.assertEqual(grant["Principal"], {"AWS": principal})
            expected = {**PINS, "PCR3": hashlib.sha384(bytes(48) + HOST.encode()).hexdigest()}
            self.assertEqual(grant["Condition"], {
                "StringEqualsIgnoreCase": {f"kms:RecipientAttestation:{pcr}": pin for pcr, pin in expected.items()},
                "StringEquals": {"kms:EncryptionAlgorithm": RSA_OAEP},
            })
            denied = {rule["Sid"]: rule for rule in statements if rule["Effect"] == "Deny"}
            self.assertEqual(denied["DenyOtherPrincipal"]["Condition"], {"StringNotEquals": {"aws:PrincipalArn": principal}})
            self.assertEqual(denied["DenyOtherAlgorithm"]["Condition"],
                             {"StringNotEquals": {"kms:EncryptionAlgorithm": RSA_OAEP}})
            for pcr, pin in expected.items():
                self.assertEqual(denied[f"DenyWrong{pcr}"]["Condition"], {
                    "StringNotEqualsIgnoreCase": {f"kms:RecipientAttestation:{pcr}": pin},
                })
                self.assertEqual(denied[f"DenyWrong{pcr}"]["Principal"], "*")
            self.assertTrue({"kms:CreateGrant", "kms:PutKeyPolicy", "kms:ReEncryptFrom"} <= set(denied["SealKey"]["Action"]))
            self.assertFalse(any(rule["Action"] == "kms:Encrypt" for rule in statements))

    def test_rejects_debug_pins_shared_roles_and_invalid_custody_scope(self):
        for host, measurements in [(CUSTODIAN, PINS), (HOST, {**PINS, "PCR1": "00" * 48})]:
            with self.assertRaises(ValueError):
                recovery_policy(CUSTODIAN, RETIREMENT, host, measurements, "5")
            with self.assertRaises(ValueError):
                key_policy(host, CUSTODIAN, RETIREMENT, measurements)
        for fields in [
            ("localnet", DOMAIN, "release-a", "1"), ("mainnet", "0" * 64, "release-a", "1"),
            ("mainnet", DOMAIN, "../release-a", "1"), ("mainnet", DOMAIN, "release-a", "0"),
            ("mainnet", DOMAIN, "release-a", "01"), ("mainnet", DOMAIN, "release-a", str(2**64)),
        ]:
            with self.assertRaises(ValueError):
                validate_scope(*fields)

    def test_host_identity_policy_can_only_unwrap_its_exact_approved_slots(self):
        statement, = host_policy(TARGET)["Statement"]
        policy = key_policy(HOST, CUSTODIAN, RETIREMENT, PINS)
        decrypt = next(rule for rule in policy["Statement"] if rule["Sid"] == "ProvisionAttestedEnclave")
        self.assertEqual(statement, {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": KEYS,
                                     "Condition": decrypt["Condition"]})

    @patch("provision.decrypt_recipient")
    @patch("provision.request", side_effect=[(200, b"evidence"), (200, bytes([2, 4, 6]))])
    def test_three_available_accounts_are_enough(self, request, decrypt):
        def wrapped(key, _blob, _evidence):
            slot = KEYS.index(key) + 1
            if slot % 2 == 0:
                return str(slot).encode()
            raise ValueError("unavailable custodian")

        decrypt.side_effect = wrapped
        self.assertEqual(provision(16, TARGET, SHARES), [2, 4, 6])
        self.assertCountEqual([call.args for call in decrypt.call_args_list],
                              [(key, f"fileb://{SHARES / f'{slot}.kms'}", b"evidence")
                               for slot, key in enumerate(KEYS, start=1)])
        request.assert_called_with(16, "POST", "/shares",
                                   b"".join(struct.pack(">BH", slot, 1) + str(slot).encode() for slot in (2, 4, 6)), limit=3)

    @patch("provision.decrypt_recipient")
    @patch("provision.request", return_value=(200, b"evidence"))
    def test_does_not_forward_fewer_than_three_shares(self, request, decrypt):
        decrypt.side_effect = [b"one", b"two", *[ValueError("unavailable")] * 4]
        with self.assertRaisesRegex(ValueError, "fewer than three"):
            provision(16, TARGET, SHARES)
        request.assert_called_once_with(16, "GET", "/recipient")

    @patch("provision.decrypt_recipient", return_value=b"envelope")
    @patch("provision.request", side_effect=[(200, b"evidence"), (200, bytes([2, 4, 6]))])
    def test_rehearsal_uses_exactly_the_requested_slots_without_fallback(self, request, decrypt):
        self.assertEqual(provision(16, TARGET, SHARES, [6, 2, 4]), [2, 4, 6])
        self.assertEqual({call.args[0] for call in decrypt.call_args_list}, {KEYS[1], KEYS[3], KEYS[5]})
        request.assert_called_with(16, "POST", "/shares",
                                   b"".join(struct.pack(">BH", slot, 8) + b"envelope" for slot in (2, 4, 6)), limit=3)
        request.reset_mock(side_effect=True)
        request.return_value = (200, b"evidence")
        decrypt.reset_mock(side_effect=True)
        decrypt.side_effect = [b"one", b"two", ValueError("custodian key denied")]
        with self.assertRaisesRegex(ValueError, "fewer than three"):
            provision(16, TARGET, SHARES, [2, 4, 6])
        self.assertEqual(decrypt.call_count, 3)
        request.assert_called_once_with(16, "GET", "/recipient")

    @patch("provision.decrypt_recipient", return_value=b"envelope")
    @patch("provision.request")
    def test_reports_the_restored_slots_and_rejects_an_invalid_or_missing_acknowledgement(self, request, _):
        request.side_effect = [(200, b"evidence"), (200, bytes([2, 4, 6]))]
        self.assertEqual(provision(16, TARGET, SHARES), [2, 4, 6])
        for ack in (b"", bytes([2, 4]), bytes([2, 2, 6]), bytes([2, 4, 5]), bytes([2, 4, 6, 7])):
            request.side_effect = [(200, b"evidence"), (200, ack)]
            with self.subTest(ack=ack), self.assertRaisesRegex(ValueError, "invalid enclave acknowledgement"):
                provision(16, TARGET, SHARES, [2, 4, 6])
        request.side_effect = [(200, b"evidence"), (400, b"")]
        with self.assertRaisesRegex(ValueError, "refused the shares with HTTP 400"):
            provision(16, TARGET, SHARES, [2, 4, 6])
        request.side_effect = [(200, b"evidence"), TimeoutError("lost response")]
        with self.assertRaisesRegex(ValueError, "could not confirm seed restoration"):
            provision(16, TARGET, SHARES, [2, 4, 6])

    @patch("provision.request")
    def test_refuses_keys_or_slot_selections_outside_the_approved_custody_set(self, request):
        host_key = KEY_1.replace("222222222222", "111111111111")
        for key in [KEYS[0], KEYS[0][:-1] + "d", "alias/other", host_key]:
            with self.assertRaises(ValueError):
                provision(16, {**TARGET, "wrappingKeys": [*KEYS[:5], key]}, SHARES)
        for slots in ([1, 1, 3], [1, 2, 8], [1, 2], [1, 2, 3, 4]):
            with self.assertRaisesRegex(ValueError, "exactly three distinct"):
                provision(16, TARGET, SHARES, slots)
        request.assert_not_called()

    def test_provisioning_requires_the_exact_pinned_target_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "target.json"
            body = json.dumps({"manifest": TARGET, "signatures": []}).encode()
            path.write_bytes(body)
            pin = hashlib.sha256(body).hexdigest()
            self.assertEqual(read_target(path, pin), TARGET)
            old = json.dumps({"manifest": {**TARGET, "wrappingAlgorithm": "SYMMETRIC_DEFAULT"}, "signatures": []}).encode()
            path.write_bytes(old)
            with self.assertRaisesRegex(ValueError, "expected document fields"):
                read_target(path, hashlib.sha256(old).hexdigest())
            path.write_bytes(body.replace(b"release-a", b"release-b"))
            with self.assertRaisesRegex(ValueError, "independently pinned digest"):
                read_target(path, pin)

    @patch("provision.sleep")
    @patch("provision.request", side_effect=[ConnectionRefusedError(), (503, b""), (429, b""), (200, b"evidence")])
    def test_waits_for_recipient_readiness(self, request, sleep):
        self.assertEqual(recipient_for(16), b"evidence")
        self.assertEqual(request.call_count, 4)
        self.assertEqual(sleep.call_count, 3)

    @patch("provision.monotonic", side_effect=[0, 21])
    @patch("provision.request", side_effect=ConnectionRefusedError)
    def test_recipient_startup_has_a_deadline(self, request, _):
        with self.assertRaisesRegex(ValueError, "did not become ready"):
            recipient_for(16)
        request.assert_called_once_with(16, "GET", "/recipient")

    @patch("provision.request", return_value=(200, b""))
    def test_refuses_invalid_recipient_evidence(self, request):
        with self.assertRaisesRegex(ValueError, "invalid recipient evidence"):
            recipient_for(16)
        request.assert_called_once_with(16, "GET", "/recipient")

    @patch("approval.subprocess.run")
    def test_decrypt_accepts_only_ciphertext_for_the_requested_recipient(self, run):
        result = {"KeyId": KEY_1, "CiphertextForRecipient": base64.b64encode(b"wrapped").decode()}
        for expected, reply in [(b"wrapped", result), (b"wrapped", {**result, "Plaintext": ""}),
                                (b"wrapped", {**result, "Plaintext": None}), (None, {**result, "Plaintext": "YQ=="}),
                                (None, {**result, "KeyId": KEYS[0]}), (None, {**result, "CiphertextForRecipient": ""})]:
            run.return_value = subprocess.CompletedProcess([], 0, json.dumps(reply), "")
            args = (KEY_1, "fileb://shares/1.kms", b"evidence")
            if expected is None:
                with self.assertRaises(ValueError):
                    decrypt_recipient(*args)
            else:
                self.assertEqual(decrypt_recipient(*args), expected)
        call = run.call_args.args[0]
        self.assertEqual(call[call.index("--encryption-algorithm") + 1], RSA_OAEP)
        self.assertEqual(json.loads(call[call.index("--recipient") + 1])["AttestationDocument"], "ZXZpZGVuY2U=")
        self.assertNotIn("--encryption-context", call)
        self.assertEqual(run.call_args.kwargs["env"]["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"], "true")

    @patch("approval.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"{}", b""))
    def test_custody_commands_ignore_configured_aws_endpoint_overrides(self, run):
        with patch.dict(os.environ, {"AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "false"}):
            self.assertEqual(aws("eu-north-1", "s3api", "list-objects-v2", []), {})
        self.assertEqual(run.call_args.kwargs["env"]["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"], "true")

if __name__ == "__main__":
    unittest.main()
