import base64
import hashlib
import io
import json
import pathlib
import sys
import tempfile
import time
import unittest
from unittest.mock import call, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from approval import sha256
from custody_ledger import TARGET_APPROVAL
from deployment import HostUnobserved, file_digest, main, require_host_state, target
from kms_policy import recovery_policy
from nitro_fixtures import DOMAIN, HOST, INSTANCE, REGION, key, pin, schedule, sign
from provenance import describe
from relay_wrap import LABEL, release
from retirement import require_terminated_parent

PINS = {f"PCR{index}": byte * 48 for index, byte in enumerate(("12", "23", "34"))}
RELAY_HOST = "arn:aws:iam::000000000009:role/relay"
SOURCE = b"r" * 294
DESTINATION = b"t" * 294
BOOT = "ab" * 32


class TargetApprovalTests(unittest.TestCase):
    def setUp(self):
        self.build = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.trust = {"network": "devnet", "securityDomainId": DOMAIN, "approvalKeys": [schedule()],
                      "recoveryRelays": {str(epoch): {"hostRole": RELAY_HOST, "pcrs": PINS} for epoch in (5, 6)}}
        commitment = "44" * 32
        spki = hashlib.sha256(SOURCE).hexdigest()
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
            "pcrs": PINS, "hostRole": HOST, "hostRegion": REGION, "instanceId": INSTANCE, "wrappingKeys": [key(i, 2) for i in range(1, 7)],
            "nextCustodians": None, "nextRelay": None,
        }
        self.approval = {"manifest": self.manifest, "signatures": [
            sign(TARGET_APPROVAL, self.manifest, signer["keyArn"]) for signer in self.trust["approvalKeys"][0]["keys"][:2]
        ]}
        _, policies, _ = target(self.trust, self.approval, self.receipt, self.custodians, self.build)
        self.policy = policies[0]
        self.recovery_policy = recovery_policy(self.custodians[0]["custodianRole"], self.custodians[0]["retirementRole"],
                                               RELAY_HOST, PINS, "5")
        self.calls = []
        self.policy_key = key(1, 2)
        self.key_metadata = {"Arn": self.policy_key, "KeySpec": "RSA_2048", "KeyUsage": "ENCRYPT_DECRYPT",
                             "Origin": "AWS_KMS", "MultiRegion": False, "KeyState": "Enabled"}
        self.recovery_metadata = {**self.key_metadata, "Arn": key(1), "KeySpec": "RSA_2048"}
        self.enterContext(patch("approval.kms", side_effect=self.kms))
        self.enterContext(patch("relay.kms", side_effect=self.kms))
        self.ledger = self.enterContext(patch("relay_wrap.load_epoch", side_effect=self.load_epoch))
        self.reviewed = self.enterContext(patch("relay_wrap.require_reviewed_target"))
        self.registry = self.enterContext(patch("relay_wrap.require_registered_target"))
        self.active = self.enterContext(patch("relay_wrap.require_active_epoch"))
        self.enterContext(patch("relay_wrap.live_recipient", return_value=(BOOT, b"evidence")))
        self.relay = self.enterContext(patch("relay_wrap.relay_request", return_value=b"c" * 256))
        self.decrypt_reply = {"KeyId": key(1), "CiphertextForRecipient": "ZW52ZWxvcGU="}
        statement = {
            "network": "devnet", "securityDomainId": DOMAIN, "custodyEpoch": "5", "slot": 1,
            "shareCommitment": commitment, "relayKeyId": BOOT, "targetDigest": sha256(self.manifest),
            "destinationPublicKey": DESTINATION.hex(), "expiresAt": self.manifest["expiresAt"],
        }
        self.authorization = {"manifest": statement, "signatures": [
            sign(LABEL, statement, member["keyArn"]) for member in self.trust["approvalKeys"][0]["keys"][:2]
        ]}

    def load_epoch(self, trust, epoch):
        self.assertEqual(trust, self.trust)
        self.assertEqual(epoch, "5")
        return {}, self.receipt, self.custodians

    def kms(self, arn, operation, args=(), _body=None, **_options):
        self.calls.append(operation)
        if operation == "describe-key":
            return {"KeyMetadata": self.key_metadata if arn == self.policy_key else self.recovery_metadata}
        if operation == "get-key-policy":
            return {"Policy": json.dumps(self.policy if arn == self.policy_key else self.recovery_policy)}
        if operation == "get-public-key":
            return {"KeyId": arn, "PublicKey": base64.b64encode(DESTINATION if arn == self.policy_key else SOURCE).decode(), "KeyUsage": "ENCRYPT_DECRYPT",
                    "KeySpec": "RSA_2048", "EncryptionAlgorithms": ["RSAES_OAEP_SHA_256"]}
        if operation == "decrypt":
            self.assertEqual(json.loads(args[-1])["AttestationDocument"], "ZXZpZGVuY2U=")
            return self.decrypt_reply
        self.fail(operation)

    def wrap(self):
        return release(self.trust, self.approval, self.build, 1, 7443, self.authorization,
                       review=self.build / "review.json")

    def test_quorum_and_installed_policy_checked_before_opening_one_share(self):
        self.assertEqual(self.wrap(), b"c" * 256)
        self.registry.assert_called_once_with(self.trust, self.manifest)
        self.assertEqual(self.active.call_count, 3)
        self.assertEqual(self.calls, ["describe-key", "get-key-policy", "get-public-key",
                                      "describe-key", "get-key-policy", "get-public-key", "decrypt"])

    def test_custodian_requires_an_independently_reviewed_target_before_opening_a_share(self):
        self.reviewed.side_effect = ValueError("target does not match the verified build provenance")
        with self.assertRaisesRegex(ValueError, "verified build provenance"):
            self.wrap()
        self.reviewed.assert_called_once_with(self.build, self.manifest, self.build / "review.json")
        self.assertNotIn("decrypt", self.calls)
        self.relay.assert_not_called()

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
        profiles = [f"slot-{index}-reader" for index in range(1, 7)]
        argv = ["deployment.py", str(trust_path), str(self.build), "sign", str(target_path),
                signing_key, str(output), "--review", str(self.build / "review.json"), "--host-inspection-profile", "host-reader",
                "--inspection-profiles", *profiles]
        reviewed = describe(self.build, "devnet", commit)
        with (patch("sys.argv", argv), patch("deployment.load_epoch", side_effect=self.load_epoch),
              patch("deployment.require_active_epoch") as active, patch("deployment.verify_build") as verify_build,
              patch("deployment.require_host_state") as inspect, patch("deployment.sealed_rsa_key") as inspect_key,
              patch("deployment.add_approval", return_value=self.approval) as sign_target):
            for field in ("configurationSha256", "eifSha256", "executableSha256", "pcrs"):
                value = {**PINS, "PCR0": "aa" * 48} if field == "pcrs" else "aa" * 32
                verify_build.return_value = {**reviewed, field: value}
                with self.subTest(field=field), self.assertRaisesRegex(SystemExit, "verified build provenance"):
                    main()
            sign_target.assert_not_called()
            self.assertFalse(output.exists())
            inspect_key.assert_not_called()
            verify_build.return_value = reviewed
            inspect_key.side_effect = [DESTINATION] * 5 + [ValueError("unsealed wrapping key")]
            with self.assertRaisesRegex(SystemExit, "unsealed wrapping key"):
                main()
            sign_target.assert_not_called()
            self.assertFalse(output.exists())

            inspect_key.side_effect = None
            active.side_effect = [None, ValueError("epoch retired during inspection")]
            with self.assertRaisesRegex(SystemExit, "epoch retired during inspection"):
                main()
            sign_target.assert_not_called()
            self.assertFalse(output.exists())

            active.side_effect = None
            inspect.side_effect = ValueError("target instance profile does not contain the approved host role")
            with self.assertRaisesRegex(SystemExit, "approved host role"):
                main()
            sign_target.assert_not_called()
            self.assertFalse(output.exists())

            inspect.side_effect = None
            inspect.reset_mock()
            inspect_key.reset_mock()
            main()
            self.assertEqual(json.loads(output.read_bytes()), self.approval)
            inspect.assert_called_once_with(self.manifest, "running", "host-reader")
            _, policies, _ = target(self.trust, self.approval, self.receipt, self.custodians, self.build)
            self.assertEqual(inspect_key.call_args_list, [
                call(key, policy, profile=profile)
                for key, policy, profile in zip(self.manifest["wrappingKeys"], policies, profiles, strict=True)
            ])
            sign_target.assert_called_once()

    @patch("deployment.aws")
    def test_host_state_requires_exact_account_id_and_expected_state(self, describe):
        instance = {"InstanceId": INSTANCE, "State": {"Name": "terminated"}}
        reservation = {"OwnerId": "000000000007", "Instances": [instance]}
        describe.return_value = {"Reservations": [reservation]}
        self.assertEqual(require_host_state(self.manifest, "terminated", "host-reader")["instanceId"], INSTANCE)
        describe.assert_called_once_with(REGION, "ec2", "describe-instances", ["--instance-ids", INSTANCE],
                                        profile="host-reader")
        for state in ("running", "stopped", "shutting-down"):
            instance["State"]["Name"] = state
            with self.subTest(state=state), self.assertRaises(ValueError):
                require_host_state(self.manifest, "terminated", "host-reader")
        instance["State"]["Name"] = "running"
        with self.assertRaisesRegex(ValueError, "running"):
            require_host_state(self.manifest, "running", "host-reader")
        instance["EnclaveOptions"] = {"Enabled": True}
        for changed in ([], [{**reservation, "OwnerId": "000000000006"}],
                        [{**reservation, "Instances": [{**instance, "InstanceId": "i-1234567890abcdef1"}]}]):
            describe.return_value = {"Reservations": changed}
            with self.assertRaises(ValueError):
                require_host_state(self.manifest, "running", "host-reader")

    @patch("deployment.aws")
    def test_running_parent_must_have_the_approved_architecture_and_role(self, aws):
        account = "000000000007"
        attachment = {"Arn": f"arn:aws:iam::{account}:instance-profile/nitro/serving-parent", "Id": "AIPAEXAMPLE"}
        parent = {"InstanceId": INSTANCE, "State": {"Name": "running"}, "EnclaveOptions": {"Enabled": True},
                  "Architecture": "x86_64", "IamInstanceProfile": attachment}
        profile = {"Arn": attachment["Arn"], "InstanceProfileId": attachment["Id"], "Roles": [{"Arn": HOST}]}
        responses = {
            "describe-instances": {"Reservations": [{"OwnerId": account, "Instances": [parent]}]},
            "get-instance-profile": {"InstanceProfile": profile},
        }
        aws.side_effect = lambda _region, _service, operation, _args, **_options: responses[operation]
        self.assertEqual(require_host_state(self.manifest, "running", "host-reader")["instanceId"], INSTANCE)
        self.assertEqual(aws.call_args_list, [
            call(REGION, "ec2", "describe-instances", ["--instance-ids", INSTANCE], profile="host-reader"),
            call(REGION, "iam", "get-instance-profile", ["--instance-profile-name", "serving-parent"], profile="host-reader"),
        ])
        for changed, error in (
            ({"Architecture": "arm64"}, "x86-64 EIF"),
            ({"IamInstanceProfile": None}, "no instance profile"),
            ({"IamInstanceProfile": {**attachment, "Arn": attachment["Arn"].replace(account, "000000000006")}},
             "approved account"),
            ({"IamInstanceProfile": {**attachment, "Id": ""}}, "approved account"),
        ):
            aws.reset_mock()
            with self.subTest(parent=changed), patch.dict(parent, changed):
                with self.assertRaisesRegex(ValueError, error):
                    require_host_state(self.manifest, "running", "host-reader")
            aws.assert_called_once()
        for changed in (
            {"Arn": attachment["Arn"] + "-other"},
            {"InstanceProfileId": "AIPAOTHER"},
            {"Roles": []},
            {"Roles": [{"Arn": HOST + "-other"}]},
        ):
            with self.subTest(iam=changed), patch.dict(profile, changed):
                with self.assertRaisesRegex(ValueError, "approved host role"):
                    require_host_state(self.manifest, "running", "host-reader")

    @patch("retirement.aws")
    @patch("retirement.require_host_state")
    def test_retirement_uses_a_positive_config_deletion_for_an_unlisted_host(self, describe, config):
        capture = "2026-11-22T06:00:00+00:00"
        deletion = {"accountId": "000000000007", "awsRegion": REGION, "resourceId": INSTANCE,
                    "resourceType": "AWS::EC2::Instance", "configurationItemStatus": "ResourceDeleted",
                    "configurationItemCaptureTime": capture}
        config.return_value = {"configurationItems": [deletion]}
        describe.side_effect = ValueError("parent remains running")
        with self.assertRaisesRegex(ValueError, "parent remains running"):
            require_terminated_parent(self.manifest, "host-reader")
        config.assert_not_called()
        describe.side_effect = HostUnobserved("instance is no longer listed")
        self.assertEqual(require_terminated_parent(self.manifest, "host-reader"), {
            "account": "000000000007", "region": REGION, "instanceId": INSTANCE,
            "state": "terminated", "source": "aws-config", "capturedAt": capture,
        })
        config.assert_called_once_with(REGION, "configservice", "get-resource-config-history", [
            "--resource-type", "AWS::EC2::Instance", "--resource-id", INSTANCE,
            "--chronological-order", "Reverse", "--limit", "1", "--no-paginate",
        ], profile="host-reader")
        for changed in ([], [{**deletion, "accountId": "000000000008"}], [{**deletion, "awsRegion": "us-east-1"}],
                        [{**deletion, "resourceId": "i-1234567890abcdef1"}], [{**deletion, "resourceType": "Example::Custom::Host"}],
                        [{**deletion, "configurationItemStatus": "ResourceDeletedNotRecorded"}],
                        [{**deletion, "configurationItemStatus": "OK"}, deletion]):
            config.return_value = {"configurationItems": changed}
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                require_terminated_parent(self.manifest, "host-reader")

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
            self.assertEqual(json.loads(output.getvalue())["Statement"][0]["Resource"], self.manifest["wrappingKeys"])

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
        with self.assertRaisesRegex(ValueError, "installed RSA key policy"):
            self.wrap()
        self.assertEqual(self.calls, ["describe-key", "get-key-policy"])

    def test_rejects_permissive_recovery_key_policy_before_decrypting(self):
        self.recovery_policy["Statement"].pop(1)
        with self.assertRaisesRegex(ValueError, "installed RSA key policy"):
            self.wrap()
        self.assertEqual(self.calls, ["describe-key", "get-key-policy", "get-public-key", "describe-key", "get-key-policy"])

    def test_rejects_a_recovery_key_sealed_for_another_epoch(self):
        self.recovery_policy = recovery_policy(self.custodians[0]["custodianRole"], self.custodians[0]["retirementRole"], RELAY_HOST, PINS, "4")
        with self.assertRaisesRegex(ValueError, "installed RSA key policy"):
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
        for boundary, crossed, decrypts, wraps in (
            ("ledger read", lambda: self.active.called, 0, 0),
            ("KMS unwrap", lambda: "decrypt" in self.calls, 1, 0),
            ("relay wrap", lambda: self.relay.called, 1, 1),
        ):
            with (self.subTest(boundary=boundary),
                  patch("relay_wrap.time", side_effect=lambda: deadline if crossed() else deadline - 1)):
                self.calls.clear()
                self.relay.reset_mock()
                self.active.reset_mock()
                with self.assertRaisesRegex(ValueError, "relay authorization has expired"):
                    self.wrap()
                self.assertEqual(self.calls.count("decrypt"), decrypts)
                self.assertEqual(self.relay.call_count, wraps)

    def test_checks_roster_cutover_before_recovery_key_use(self):
        cutover = int(time.time()) + 100
        self.trust["approvalKeys"].append(schedule("6", 9, cutover))
        with patch("relay_wrap.time", return_value=cutover):
            with self.assertRaisesRegex(ValueError, "target approval roster"):
                self.wrap()
        self.assertNotIn("decrypt", self.calls)

    def test_stops_when_retirement_races_share_recovery(self):
        self.active.side_effect = [None, ValueError("custody epoch is retired")]
        with self.assertRaisesRegex(ValueError, "custody epoch is retired"):
            self.wrap()
        self.assertEqual(self.calls[-1], "decrypt")

    def test_rejects_plaintext_or_a_reply_for_another_kms_key_before_rewrapping(self):
        original = self.decrypt_reply
        for invalid in ({"Plaintext": "YQ=="}, {"KeyId": key(2)}, {"CiphertextForRecipient": ""}):
            self.decrypt_reply = {**original, **invalid}
            with self.assertRaises(ValueError):
                self.wrap()
            self.relay.assert_not_called()

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
        self.manifest["nextRelay"] = self.trust["recoveryRelays"]["6"]
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
        scope = self.trust["recoveryRelays"].pop("6")
        with self.assertRaisesRegex(ValueError, "requires a pinned recovery relay"):
            target(self.trust, self.approval, self.receipt, self.custodians, self.build)
        self.trust["recoveryRelays"]["6"] = {**scope, "hostRole": HOST}
        with self.assertRaisesRegex(ValueError, "successor's pinned recovery relay"):
            target(self.trust, self.approval, self.receipt, self.custodians, self.build)
        self.trust["recoveryRelays"]["6"] = scope
        roster[0]["recoveryKeyArn"] = key(1)
        with self.assertRaisesRegex(ValueError, "rotate recovery keys"):
            target(self.trust, self.approval, self.receipt, self.custodians, self.build)
