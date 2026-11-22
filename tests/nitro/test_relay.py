import base64
import hashlib
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from approval import canonical, signing_sec1
from provenance import describe
from relay import prove_share, recover_to_relay, verify_relay_build
from relay_wrap import LABEL, prepare, release, sign_release
from nitro_fixtures import DOMAIN, HOST, key, pin, sign

SCOPE = {"hostRole": HOST, "pcrs": {f"PCR{i}": f"{i+1:02x}" * 48 for i in range(3)}}
TRUST = {"network": "devnet", "recoveryRelays": {"1": SCOPE}}
CUSTODIAN = {"custodianRole": "arn:aws:iam::000000000001:role/custodian",
             "retirementRole": "arn:aws:iam::000000000001:role/retirement", "recoveryKeyArn": key(1)}
PUBLIC = b"fixture SPKI for an immutable recovery key"
RECEIPT = {"securityDomainId": DOMAIN, "custody": {"epoch": "1", "shareCommitments": ["ab" * 32]},
           "packages": [{"recipientSha256": hashlib.sha256(PUBLIC).hexdigest(), "ciphertext": "de" * 256}]}
KEYS = [pin(key(i, 9)) for i in (10, 11, 12)]
NEXT_KEYS = [pin(key(i, 9)) for i in (13, 14, 15)]


class RelayTests(unittest.TestCase):
    @patch("provenance.verify_eif")
    @patch("provenance.subprocess.run")
    def test_relay_must_match_the_reviewed_build_and_ordered_epoch_roster(self, github, _eif):
        build = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        commit, ref = "ad" * 20, "refs/heads/native"
        trust = {**TRUST, "securityDomainId": DOMAIN,
                 "approvalKeys": [{"fromEpoch": "1", "activeFrom": 0, "keys": KEYS}]}
        deployment = {"mode": "relay", "custodyEpoch": "1", "approvalKeys": [signing_sec1(key) for key in KEYS]}
        config = {"releaseId": "recovery", "securityDomainId": DOMAIN, "deployment": deployment}
        (build / "tvc_app").write_bytes(b"executable")
        (build / "enclave.eif").write_bytes(b"EIF")
        (build / "measurements.json").write_bytes(canonical({"Measurements": SCOPE["pcrs"]}))

        def write_config(candidate):
            (build / "configuration.json").write_bytes(canonical(candidate))
            (build / "provenance.json").write_bytes(canonical(describe(build, "devnet", commit)))

        write_config(config)
        review = build / "review.json"
        pins = {"sourceCommit": commit, "sourceRef": ref,
                "provenanceSha256": hashlib.sha256((build / "provenance.json").read_bytes()).hexdigest()}
        review.write_bytes(canonical(pins))
        verify_relay_build(trust, "1", build, review)
        github.assert_called_once()
        github.reset_mock()
        for invalid in (
            {**config, "securityDomainId": "42" * 32},
            {**config, "deployment": {**deployment, "custodyEpoch": "2"}},
            {**config, "deployment": {**deployment, "mode": "serve"}},
            {**config, "deployment": {**deployment, "approvalKeys": list(reversed(deployment["approvalKeys"]))}},
        ):
            write_config(invalid)
            with self.assertRaisesRegex(ValueError, "pinned custody domain, epoch and approval roster"):
                verify_relay_build(trust, "1", build, review)
        github.assert_not_called()

        write_config(config)
        review.write_bytes(canonical({**pins, "sourceCommit": "ef" * 20}))
        with self.assertRaisesRegex(ValueError, "reviewed build attestation"):
            verify_relay_build(trust, "1", build, review)
        review.write_bytes(canonical(pins))
        wrong_pins = {**SCOPE, "pcrs": {**SCOPE["pcrs"], "PCR2": "aa" * 48}}
        with self.assertRaisesRegex(ValueError, "relay pins or configuration"):
            verify_relay_build({**trust, "recoveryRelays": {"1": wrong_pins}}, "1", build, review)

    @patch("relay_wrap.time", return_value=10)
    @patch("relay_wrap.live_recipient", return_value=("ab" * 32, b"evidence"))
    @patch("relay_wrap.sealed_rsa_key", return_value=PUBLIC)
    @patch("relay_wrap.require_registered_target")
    @patch("relay_wrap.target", return_value=(KEYS, [{}], None))
    @patch("relay_wrap.load_epoch", return_value=(None, RECEIPT, [CUSTODIAN]))
    @patch("relay_wrap.relay_pins")
    @patch("relay_wrap.verify_target_approval")
    def test_successor_can_wrap_before_cutover_and_old_roster_cannot_wrap_after(
        self, verify, _pins, _epoch, _target, _registered, _sealed, _recipient, now,
    ):
        schedule = [
            {"fromEpoch": "1", "activeFrom": 0, "keys": KEYS},
            {"fromEpoch": "2", "activeFrom": 20, "keys": NEXT_KEYS},
        ]
        trust = {**TRUST, "approvalKeys": schedule}
        verify.return_value = {
            "network": "devnet", "securityDomainId": DOMAIN, "custodyEpoch": "2", "approvalFromEpoch": "1",
            "wrappingKeys": [key(1)], "expiresAt": 30,
        }
        source = (trust, {}, pathlib.Path("build"), 1, 7443)
        statement, release_keys, *_ = prepare(*source)
        self.assertEqual(statement["expiresAt"], 20)
        self.assertEqual(release_keys, NEXT_KEYS)
        verify.assert_called_with(trust, {}, at=10)

        _sealed.reset_mock()
        _recipient.reset_mock()
        with patch("relay_wrap.require_profile_account") as identity:
            identity.side_effect = ValueError("slot profile is in the wrong account")
            with self.assertRaisesRegex(ValueError, "profile is in the wrong account"):
                prepare(*source, inspection_profile="slot-reader")
            _sealed.assert_not_called()
            _recipient.assert_not_called()
            identity.side_effect = None
            statement, *_ = prepare(*source, inspection_profile="slot-reader")
            self.assertEqual(statement["expiresAt"], 20)
            identity.assert_called_with("slot-reader", "eu-north-1", "000000000001")
            _sealed.assert_called_once_with(key(1), {}, profile="slot-reader")

        verify.return_value["expiresAt"] = 15
        statement, *_ = prepare(*source)
        self.assertEqual(statement["expiresAt"], 15)

        def late_recipient(*_args):
            now.return_value = 15
            return "ab" * 32, b"evidence"

        _recipient.side_effect = late_recipient
        with self.assertRaisesRegex(ValueError, "relay authorization has expired"):
            prepare(*source)
        _recipient.side_effect = None

        now.return_value = 20
        verify.return_value.update(custodyEpoch="1", approvalFromEpoch="2", expiresAt=30)
        _sealed.reset_mock()
        _recipient.reset_mock()
        with self.assertRaisesRegex(ValueError, "approval roster has retired"):
            prepare(*source)
        _sealed.assert_not_called()
        _recipient.assert_not_called()

        verify.return_value["custodyEpoch"] = "2"
        statement, release_keys, *_ = prepare(*source)
        self.assertEqual(statement["expiresAt"], 30)
        self.assertEqual(release_keys, NEXT_KEYS)

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
    @patch("relay_wrap.require_reviewed_target")
    @patch("relay_wrap.time", return_value=10)
    def test_release_checks_the_live_boot_and_exact_quorum_before_any_recovery(
        self, now, reviewed, prepare, recover, request, _verify, active,
    ):
        statement = {"custodyEpoch": "1", "relayKeyId": "ab" * 32, "destinationPublicKey": "cd" * 32, "expiresAt": 20}
        prepare.return_value = (statement, KEYS, RECEIPT, CUSTODIAN, b"evidence")
        signatures = [sign(LABEL, statement, pin["keyArn"]) for pin in KEYS[:2]]
        approved = {"manifest": statement, "signatures": signatures}
        source = (TRUST, {"manifest": {}}, pathlib.Path("build"), 1, 7443)
        review = {"review": pathlib.Path("review.json")}
        for edited in [
            {**approved, "manifest": {**statement, "relayKeyId": "ef" * 32}},
            {**approved, "signatures": signatures[:1]},
            {**approved, "signatures": [signatures[0], signatures[0]]},
        ]:
            with self.assertRaises(ValueError):
                release(*source, edited, **review)
        recover.assert_not_called()
        request.assert_not_called()
        reviewed.assert_not_called()
        self.assertEqual(release(*source, approved, **review), b"x" * 256)
        self.assertEqual(request.call_args.args[:2], (7443, "/rewrap"))
        payload = request.call_args.args[2]
        self.assertIn(b'"envelope":"656e76656c6f7065"', payload)
        self.assertEqual(active.call_count, 2)
        request.reset_mock()
        now.return_value = 20
        with self.assertRaisesRegex(ValueError, "relay authorization has expired"):
            release(*source, approved, **review)
        request.assert_not_called()

    @patch("relay_wrap.time", return_value=10)
    @patch("relay_wrap.verify_target_approval")
    @patch("relay_wrap.require_active_epoch")
    @patch("relay_wrap.add_approval")
    def test_signing_rechecks_the_ledger_and_cutoff_before_returning_the_signature(self, sign, active, _verify, now):
        statement = {"custodyEpoch": "1", "expiresAt": 20}
        draft = {"manifest": statement, "signatures": []}
        args = (TRUST, {}, statement, KEYS, draft, KEYS[0]["keyArn"])
        self.assertEqual(sign_release(*args), sign.return_value)
        self.assertEqual(active.call_count, 2)

        sign.reset_mock()
        now.return_value = 20
        with self.assertRaisesRegex(ValueError, "relay authorization has expired"):
            sign_release(*args)
        sign.assert_not_called()

        now.return_value = 10
        active.side_effect = [None, ValueError("custody epoch is retired")]
        with self.assertRaisesRegex(ValueError, "custody epoch is retired"):
            sign_release(*args)
        sign.assert_called_once()

        def late_signature(*_args):
            now.return_value = 20
            return draft

        active.side_effect = None
        sign.side_effect = late_signature
        with self.assertRaisesRegex(ValueError, "relay authorization has expired"):
            sign_release(*args)

if __name__ == "__main__":
    unittest.main()
