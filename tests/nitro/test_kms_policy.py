import hashlib
import json
import pathlib
import sys
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
KEY_2 = KEY_1.replace("222222222222", "333333333333")


class KeyPolicyTests(unittest.TestCase):
    def test_only_host_role_with_recipient_pcrs_and_exact_context_can_unwrap(self):
        ctx = context("mainnet", DOMAIN, "release-a", 1)
        statements = key_policy(HOST, CUSTODIAN, RETIREMENT, PINS, ctx)["Statement"]
        decrypt, = [rule for rule in statements if rule["Action"] == "kms:Decrypt"]
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
        seal, = [rule for rule in statements if rule["Effect"] == "Deny"]
        self.assertEqual(seal["Principal"], "*")
        self.assertTrue({"kms:CreateGrant", "kms:PutKeyPolicy", "kms:ReEncryptFrom"} <= set(seal["Action"]))

    def test_rejects_debug_pins_shared_roles_and_ambiguous_contexts(self):
        ctx = context("mainnet", DOMAIN, "release-a", 1)
        with self.assertRaises(ValueError):
            key_policy(HOST, HOST, RETIREMENT, PINS, ctx)
        with self.assertRaises(ValueError):
            key_policy(HOST, CUSTODIAN, RETIREMENT, {**PINS, "PCR0": "00" * 48}, ctx)
        for fields in [
            ("localnet", DOMAIN, "release-a", 1), ("mainnet", "0" * 64, "release-a", 1),
            ("mainnet", DOMAIN, "../release-a", 1), ("mainnet", DOMAIN, "release-a", 0),
        ]:
            with self.assertRaises(ValueError):
                context(*fields)

    @patch("provision.decrypt_share", side_effect=[b"one", b"two"])
    @patch("provision.request", side_effect=[(200, b"evidence"), (204, b"")])
    def test_combines_only_wrapped_shares_from_distinct_accounts(self, request, decrypt):
        provision(16, "mainnet", DOMAIN, "release-a", [(KEY_1, "first"), (KEY_2, "second")])
        args = [call.args for call in decrypt.call_args_list]
        self.assertEqual([arg[0] for arg in args], [KEY_1, KEY_2])
        self.assertEqual([arg[3]["share"] for arg in args], ["1", "2"])
        self.assertEqual(json.loads(args[0][2]), json.loads(args[1][2]))
        request.assert_called_with(16, "POST", "/shares", b"\x00\x03onetwo")

    @patch("provision.request")
    def test_rejects_aliases_and_two_keys_from_the_same_account_before_fetching_evidence(self, request):
        for second in [KEY_1, KEY_1[:-1] + "d", "alias/other"]:
            with self.assertRaises(ValueError):
                provision(16, "mainnet", DOMAIN, "release-a", [(KEY_1, "first"), (second, "second")])
        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
