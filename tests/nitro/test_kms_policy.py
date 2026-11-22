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
from kms_policy import context, key_policy
from provision import decrypt_share, provision, read_target, recipient_for

HOST = "arn:aws:iam::111111111111:role/host"
CUSTODIAN = "arn:aws:iam::222222222222:role/custodian"
RETIREMENT = "arn:aws:iam::222222222222:role/retirement"
PINS = {f"PCR{index}": byte * 48 for index, byte in enumerate(("12", "23", "34"))}
DOMAIN = "ab" * 32
KEY_1 = "arn:aws:kms:eu-north-1:222222222222:key/12345678-1234-1234-1234-123456789abc"
KEYS = [KEY_1.replace("222222222222", f"{index:012d}") for index in range(1, 7)]
TARGET = {"network": "mainnet", "securityDomainId": DOMAIN, "releaseId": "release-a", "custodyEpoch": "5",
          "hostRole": HOST, "pcrs": PINS, "wrappingKeys": KEYS}
SHARES = pathlib.Path("shares")


class KeyPolicyTests(unittest.TestCase):
    def test_only_host_role_with_recipient_pcrs_and_exact_context_can_unwrap(self):
        ctx = context("mainnet", DOMAIN, "release-a", "5", 1)
        statements = key_policy(HOST, CUSTODIAN, RETIREMENT, PINS, ctx)["Statement"]
        decrypt, = [rule for rule in statements if rule["Sid"] == "ProvisionAttestedEnclave"]
        self.assertEqual(decrypt["Principal"], {"AWS": HOST})
        expected = {**PINS, "PCR3": hashlib.sha384(bytes(48) + HOST.encode()).hexdigest()}
        conditions = decrypt["Condition"]
        self.assertEqual(conditions["StringEqualsIgnoreCase"], {
            "kms:RecipientAttestation:" + key: value for key, value in expected.items()
        })
        self.assertEqual(conditions["StringEquals"], {"kms:EncryptionContext:" + key: value for key, value in ctx.items()})
        self.assertEqual(conditions["ForAllValues:StringEquals"]["kms:EncryptionContextKeys"], list(ctx))
        wrapper, = [rule for rule in statements if rule["Action"] == "kms:Encrypt"]
        self.assertEqual(wrapper["Principal"], {"AWS": CUSTODIAN})
        self.assertNotIn("StringEqualsIgnoreCase", wrapper["Condition"])
        seal, = [rule for rule in statements if rule["Sid"] == "SealKey"]
        self.assertEqual(seal["Principal"], "*")
        self.assertTrue({"kms:CreateGrant", "kms:PutKeyPolicy", "kms:ReEncryptFrom"} <= set(seal["Action"]))
        denials = {rule["Sid"]: rule["Condition"] for rule in statements if rule["Action"] == "kms:Decrypt"
                   and rule["Effect"] == "Deny" and rule["Principal"] == "*"}
        self.assertEqual(denials["DenyOtherHost"], {"StringNotEquals": {"aws:PrincipalArn": HOST}})
        for pcr, pin in expected.items():
            self.assertEqual(denials[f"DenyWrong{pcr}"], {
                "StringNotEqualsIgnoreCase": {f"kms:RecipientAttestation:{pcr}": pin},
            })
        for index, (field, value) in enumerate(ctx.items()):
            self.assertEqual(denials[f"DenyWrongContext{index}"], {
                "StringNotEquals": {f"kms:EncryptionContext:{field}": value},
            })
        self.assertEqual(denials["DenyExtraContext"], {"ForAnyValue:StringNotEquals": {"kms:EncryptionContextKeys": list(ctx)}})

    def test_rejects_debug_pins_shared_roles_and_ambiguous_contexts(self):
        ctx = context("mainnet", DOMAIN, "release-a", "5", 1)
        with self.assertRaises(ValueError):
            key_policy(HOST, HOST, RETIREMENT, PINS, ctx)
        with self.assertRaises(ValueError):
            key_policy(HOST, CUSTODIAN, RETIREMENT, {**PINS, "PCR0": "00" * 48}, ctx)
        for fields in [
            ("localnet", DOMAIN, "release-a", "1", 1), ("mainnet", "0" * 64, "release-a", "1", 1),
            ("mainnet", DOMAIN, "../release-a", "1", 1), ("mainnet", DOMAIN, "release-a", "1", 0),
            ("mainnet", DOMAIN, "release-a", "0", 1), ("mainnet", DOMAIN, "release-a", "01", 1),
            ("mainnet", DOMAIN, "release-a", "1", 7), ("mainnet", DOMAIN, "release-a", str(2**64), 1),
        ]:
            with self.assertRaises(ValueError):
                context(*fields)

    def test_host_identity_policy_can_only_unwrap_its_exact_approved_slots(self):
        statements = host_policy(TARGET)["Statement"]
        self.assertEqual([rule["Resource"] for rule in statements], KEYS)
        for index, rule in enumerate(statements, start=1):
            resource_policy = key_policy(HOST, CUSTODIAN, RETIREMENT, PINS,
                                         context("mainnet", DOMAIN, "release-a", "5", index))
            decrypt = next(rule for rule in resource_policy["Statement"] if rule["Sid"] == "ProvisionAttestedEnclave")
            self.assertEqual(rule, {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": KEYS[index - 1],
                                    "Condition": decrypt["Condition"]})

    @patch("provision.decrypt_share")
    @patch("provision.request", side_effect=[(200, b"evidence"), (200, bytes([2, 4, 6]))])
    def test_three_available_accounts_are_enough(self, request, decrypt):
        def wrapped(_, __, ___, ctx):
            if int(ctx["share"]) % 2 == 0:
                return ctx["share"].encode()
            raise ValueError("unavailable custodian")

        decrypt.side_effect = wrapped
        self.assertEqual(provision(16, TARGET, SHARES), [2, 4, 6])
        args = sorted((call.args for call in decrypt.call_args_list), key=lambda arg: arg[3]["share"])
        self.assertEqual([arg[0] for arg in args], KEYS)
        self.assertEqual([arg[1] for arg in args], [SHARES / f"{index}.kms" for index in range(1, 7)])
        self.assertEqual([arg[3]["share"] for arg in args], list("123456"))
        self.assertTrue(all(arg[3]["custody-epoch"] == "5" for arg in args))
        self.assertEqual({arg[2] for arg in args}, {args[0][2]})
        request.assert_called_with(16, "POST", "/shares",
                                   b"".join(struct.pack(">BH", slot, 1) + str(slot).encode() for slot in (2, 4, 6)), limit=3)

    @patch("provision.decrypt_share")
    @patch("provision.request", return_value=(200, b"evidence"))
    def test_does_not_forward_fewer_than_three_shares(self, request, decrypt):
        decrypt.side_effect = [b"one", b"two", *[ValueError("unavailable")] * 4]
        with self.assertRaisesRegex(ValueError, "fewer than three"):
            provision(16, TARGET, SHARES)
        request.assert_called_once_with(16, "GET", "/recipient")

    @patch("provision.decrypt_share", return_value=b"envelope")
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

    @patch("provision.decrypt_share", return_value=b"envelope")
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
            path.write_bytes(body.replace(b"release-a", b"release-b"))
            with self.assertRaisesRegex(ValueError, "independently pinned digest"):
                read_target(path, pin)

    @patch("provision.sleep")
    @patch("provision.request", side_effect=[ConnectionRefusedError(), (503, b""), (429, b""), (200, b"evidence")])
    def test_waits_for_recipient_readiness(self, request, sleep):
        recipient = json.loads(recipient_for(16))
        self.assertEqual(recipient["AttestationDocument"], base64.b64encode(b"evidence").decode())
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

    @patch("provision.subprocess.run")
    def test_decrypt_accepts_only_ciphertext_for_the_requested_recipient(self, run):
        result = {"KeyId": KEY_1, "CiphertextForRecipient": base64.b64encode(b"wrapped").decode()}
        for expected, reply in [(b"wrapped", result), (b"wrapped", {**result, "Plaintext": ""}),
                                (b"wrapped", {**result, "Plaintext": None}), (None, {**result, "Plaintext": "YQ=="}),
                                (None, {**result, "KeyId": KEYS[0]}), (None, {**result, "CiphertextForRecipient": ""})]:
            run.return_value = subprocess.CompletedProcess([], 0, json.dumps(reply), "")
            args = (KEY_1, SHARES / "1.kms", "recipient", context("mainnet", DOMAIN, "release-a", "5", 1))
            if expected is None:
                with self.assertRaises(ValueError):
                    decrypt_share(*args)
            else:
                self.assertEqual(decrypt_share(*args), expected)
        self.assertEqual(run.call_args.kwargs["env"]["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"], "true")

    @patch("approval.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"{}", b""))
    def test_custody_commands_ignore_configured_aws_endpoint_overrides(self, run):
        with patch.dict(os.environ, {"AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "false"}):
            self.assertEqual(aws("eu-north-1", "s3api", "list-objects-v2", []), {})
        self.assertEqual(run.call_args.kwargs["env"]["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"], "true")

if __name__ == "__main__":
    unittest.main()
