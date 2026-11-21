import hashlib
import pathlib
import sys
import struct
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from kms_policy import context, key_policy
from provision import provision

HOST = "arn:aws:iam::111111111111:role/host"
CUSTODIAN = "arn:aws:iam::222222222222:role/custodian"
RETIREMENT = "arn:aws:iam::222222222222:role/retirement"
PINS = {f"PCR{index}": byte * 48 for index, byte in enumerate(("12", "23", "34"))}
DOMAIN = "ab" * 32
KEY_1 = "arn:aws:kms:eu-north-1:222222222222:key/12345678-1234-1234-1234-123456789abc"
KEYS = [(KEY_1.replace("222222222222", f"{index:012d}"), str(index)) for index in range(1, 7)]


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

    @patch("provision.decrypt_share")
    @patch("provision.request", side_effect=[(200, b"evidence"), (204, b"")])
    def test_three_available_accounts_are_enough(self, request, decrypt):
        def wrapped(_, __, ___, ctx):
            if int(ctx["share"]) % 2 == 0:
                return ctx["share"].encode()
            raise ValueError("unavailable custodian")

        decrypt.side_effect = wrapped
        provision(16, "mainnet", DOMAIN, "release-a", "5", KEYS)
        args = sorted((call.args for call in decrypt.call_args_list), key=lambda arg: arg[3]["share"])
        self.assertEqual([arg[0] for arg in args], [key for key, _ in KEYS])
        self.assertEqual([arg[3]["share"] for arg in args], list("123456"))
        self.assertTrue(all(arg[3]["custody-epoch"] == "5" for arg in args))
        self.assertEqual({arg[2] for arg in args}, {args[0][2]})
        request.assert_called_with(16, "POST", "/shares",
                                   b"".join(struct.pack(">H", 1) + share for share in [b"2", b"4", b"6"]))

    @patch("provision.decrypt_share")
    @patch("provision.request", return_value=(200, b"evidence"))
    def test_does_not_forward_fewer_than_three_shares(self, request, decrypt):
        decrypt.side_effect = [b"one", b"two", *[ValueError("unavailable")] * 4]
        with self.assertRaisesRegex(ValueError, "fewer than three"):
            provision(16, "mainnet", DOMAIN, "release-a", "5", KEYS)
        request.assert_called_once_with(16, "GET", "/recipient")

    @patch("provision.request")
    def test_rejects_aliases_and_keys_from_the_same_account_before_fetching_evidence(self, request):
        for key in [KEYS[0][0], KEYS[0][0][:-1] + "d", "alias/other"]:
            with self.assertRaises(ValueError):
                provision(16, "mainnet", DOMAIN, "release-a", "5", [*KEYS[:5], (key, "old")])
        request.assert_not_called()

if __name__ == "__main__":
    unittest.main()
