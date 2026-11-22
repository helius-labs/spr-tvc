import copy
import json
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from custody_archive import ledger_checkpoint
from custody_ledger import (
    check_installed_ledger, check_recovery_bucket, ledger_policy, ledger_replica_plan, require_frozen_ledger, write_once,
)
from nitro_fixtures import DOMAIN

SOURCE_ACCOUNT = "000000000008"
DESTINATION_ACCOUNT = "000000000010"
SOURCE_BUCKET = "custody-journal"
DESTINATION_BUCKET = "custody-recovery"
ROLE = f"arn:aws:iam::{SOURCE_ACCOUNT}:role/replication"
PREFIX = f"spr-custody/devnet/{DOMAIN}/"
SOURCE_ROLES = (f"arn:aws:iam::{SOURCE_ACCOUNT}:role/admin", f"arn:aws:iam::{SOURCE_ACCOUNT}:role/publisher", [])
DESTINATION_ROLES = (f"arn:aws:iam::{DESTINATION_ACCOUNT}:role/admin",
                     f"arn:aws:iam::{DESTINATION_ACCOUNT}:role/publisher", [])
REPLICA = {"bucket": DESTINATION_BUCKET, "region": "eu-west-1", "account": DESTINATION_ACCOUNT, "role": ROLE}
TRUST = {"network": "devnet", "securityDomainId": DOMAIN, "ledgerReplica": REPLICA,
         "ledger": {"bucket": SOURCE_BUCKET, "region": "eu-north-1", "account": SOURCE_ACCOUNT}}
BUCKET_CONTROLS = {
    "get-bucket-versioning": {"Status": "Enabled"},
    "get-bucket-ownership-controls": {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}},
    "get-public-access-block": {"PublicAccessBlockConfiguration": {
        flag: True for flag in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    }},
    "get-bucket-lifecycle-configuration": None,
}


class LedgerReplicationTests(unittest.TestCase):
    def test_replica_can_receive_only_the_pinned_source_role_and_prefix(self):
        plan = ledger_replica_plan(TRUST, *DESTINATION_ROLES)
        replication = plan["replication"]
        self.assertEqual(replication["Role"], ROLE)
        rule, = replication["Rules"]
        self.assertEqual(rule["Filter"], {"Prefix": PREFIX})
        self.assertEqual(rule["Destination"], {"Bucket": f"arn:aws:s3:::{DESTINATION_BUCKET}", "StorageClass": "STANDARD"})
        self.assertEqual(rule["DeleteMarkerReplication"], {"Status": "Disabled"})
        self.assertEqual(plan["roleTrust"]["Statement"], [
            {"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sts:AssumeRole"},
        ])
        source_config, source_records, replica_records = plan["rolePermissions"]["Statement"]
        self.assertEqual(source_config["Resource"], f"arn:aws:s3:::{SOURCE_BUCKET}")
        self.assertEqual(source_records["Resource"], f"arn:aws:s3:::{SOURCE_BUCKET}/{PREFIX}*")
        self.assertEqual(source_records["Action"], ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl"])
        self.assertEqual(source_records["Condition"], {"StringEquals": {"s3:ResourceAccount": SOURCE_ACCOUNT}})
        self.assertEqual(replica_records, {"Effect": "Allow", "Action": "s3:ReplicateObject",
                                          "Resource": f"arn:aws:s3:::{DESTINATION_BUCKET}/{PREFIX}*",
                                          "Condition": {"StringEquals": {"s3:ResourceAccount": DESTINATION_ACCOUNT}}})
        by_sid = {rule["Sid"]: rule for rule in plan["destinationPolicy"]["Statement"]}
        self.assertEqual(by_sid["AllowReplication"]["Principal"], {"AWS": ROLE})
        self.assertEqual(by_sid["RestrictReplication"]["Condition"], {"StringNotEquals": {"aws:PrincipalArn": ROLE}})
        self.assertEqual(by_sid["PreserveCustodyHistory"]["Action"], [
            "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:ReplicateDelete", "s3:PutObject",
        ])

        source_policy = {rule["Sid"]: rule for rule in ledger_policy(TRUST, *SOURCE_ROLES)["Statement"]}
        self.assertIn(ROLE, source_policy["RestrictRecordReads"]["Condition"]["StringNotEquals"]["aws:PrincipalArn"])
        self.assertNotIn(ROLE, source_policy["ReadCustodyRecords"]["Principal"]["AWS"])
        self.assertEqual(source_policy["RequireSseS3"]["Condition"], {
            "StringNotEquals": {"s3:x-amz-server-side-encryption": "AES256"},
        })
        with patch("custody_ledger.storage") as storage:
            write_once(TRUST, "1.json", {"fixture": True}, lambda value: value)
            args = storage.call_args.args[2]
            self.assertEqual(args[args.index("--if-none-match") + 1], "*")
            self.assertEqual(args[args.index("--server-side-encryption") + 1], "AES256")

        replica_trust = {key: TRUST[key] for key in ("network", "securityDomainId")}
        replica_trust["ledger"] = {key: REPLICA[key] for key in TRUST["ledger"]}
        with patch("custody_ledger.installed_ledger_policy", return_value=plan["destinationPolicy"]):
            with self.assertRaisesRegex(ValueError, "requires the frozen bucket policy"):
                require_frozen_ledger(replica_trust)

    def test_replication_needs_a_separate_bucket_account_region_and_role(self):
        for field in ("bucket", "account", "region"):
            invalid = {**TRUST, "ledgerReplica": {**REPLICA, field: TRUST["ledger"][field]}}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "separate bucket, account and region"):
                ledger_policy(invalid, *SOURCE_ROLES)
        for role in (SOURCE_ROLES[0], SOURCE_ROLES[1]):
            invalid = {**TRUST, "ledgerReplica": {**REPLICA, "role": role}}
            with self.subTest(role=role), self.assertRaisesRegex(ValueError, "requires its own role"):
                ledger_policy(invalid, *SOURCE_ROLES)
        invalid = {**TRUST, "ledgerReplica": {**REPLICA, "role": DESTINATION_ROLES[0]}}
        with self.assertRaisesRegex(ValueError, "requires a source role"):
            ledger_replica_plan(invalid, *DESTINATION_ROLES)

    def test_installed_replication_must_match_the_pinned_rule(self):
        expected = ledger_policy(TRUST, *SOURCE_ROLES)
        replication = ledger_replica_plan(TRUST, *DESTINATION_ROLES)["replication"]
        responses = {
            **BUCKET_CONTROLS,
            "get-bucket-policy": {"Policy": json.dumps(expected)},
            "get-bucket-replication": {"ReplicationConfiguration": replication},
        }
        with patch("custody_ledger.storage", side_effect=lambda _trust, operation, **_options: responses[operation]):
            check_installed_ledger(TRUST, expected)
            with patch.dict(responses, {"get-bucket-replication": None}):
                with self.assertRaisesRegex(ValueError, "does not match the pinned ledger replica"):
                    check_installed_ledger(TRUST, expected)
            for field, value in (
                ("Filter", {"Prefix": ""}), ("DeleteMarkerReplication", {"Status": "Enabled"}),
                ("Destination", {"Bucket": "arn:aws:s3:::unrelated-bucket"}),
            ):
                wrong = copy.deepcopy(replication)
                wrong["Rules"][0][field] = value
                with self.subTest(field=field), patch.dict(responses, {"get-bucket-replication": {"ReplicationConfiguration": wrong}}):
                    with self.assertRaisesRegex(ValueError, "does not match the pinned ledger replica"):
                        check_installed_ledger(TRUST, expected)

    def test_recovery_bucket_must_preserve_replicated_versions(self):
        policy = ledger_replica_plan(TRUST, *DESTINATION_ROLES)["destinationPolicy"]
        responses = {**BUCKET_CONTROLS, "get-bucket-policy": {"Policy": json.dumps(policy)}}

        def aws(region, service, operation, args, **options):
            self.assertEqual((region, service, options["profile"]), (REPLICA["region"], "s3api", "recovery-read"))
            self.assertEqual(args, ["--bucket", DESTINATION_BUCKET, "--expected-bucket-owner", DESTINATION_ACCOUNT])
            return responses[operation]

        with (patch("custody_ledger.require_profile_account") as account,
              patch("custody_ledger.aws", side_effect=aws) as inspect):
            check_recovery_bucket(TRUST, REPLICA, "recovery-read")
            account.assert_called_once_with("recovery-read", REPLICA["region"], DESTINATION_ACCOUNT)
            self.assertEqual(inspect.call_count, len(responses))
            for operation, value, message in (
                ("get-bucket-lifecycle-configuration", {"Rules": [{"Expiration": {"Days": 1}}]}, "no lifecycle"),
                ("get-bucket-versioning", {"Status": "Suspended"}, "requires versioning"),
                ("get-bucket-ownership-controls", {}, "bucket-owner-enforced"),
                ("get-public-access-block", {}, "public access blocks"),
            ):
                with self.subTest(operation=operation), patch.dict(responses, {operation: value}):
                    with self.assertRaisesRegex(ValueError, message):
                        check_recovery_bucket(TRUST, REPLICA, "recovery-read")
            for sid in ("PreserveCustodyHistory", "RestrictReplication"):
                changed = {**policy, "Statement": [rule for rule in policy["Statement"] if rule["Sid"] != sid]}
                with self.subTest(sid=sid), patch.dict(responses, {"get-bucket-policy": {"Policy": json.dumps(changed)}}):
                    with self.assertRaisesRegex(ValueError, "pinned replica write and delete protections"):
                        check_recovery_bucket(TRUST, REPLICA, "recovery-read")
            inspect.reset_mock()
            account.side_effect = ValueError("wrong AWS account")
            with self.assertRaisesRegex(ValueError, "wrong AWS account"):
                check_recovery_bucket(TRUST, REPLICA, "recovery-read")
            inspect.assert_not_called()

    def test_checkpoint_requires_the_pinned_replica_before_and_after_promotion(self):
        names = ["1.json", "retired/1.json"]
        new_replica = {"bucket": "custody-replacement", "account": "000000000011", "region": "eu-west-2",
                       "role": f"arn:aws:iam::{DESTINATION_ACCOUNT}:role/replication"}
        promoted = {key: TRUST[key] for key in ("network", "securityDomainId")}
        promoted["ledger"] = {key: REPLICA[key] for key in TRUST["ledger"]}
        records = {}
        for bucket, status in ((SOURCE_BUCKET, "COMPLETED"), (DESTINATION_BUCKET, "REPLICA")):
            records[bucket] = {
                name: (name.encode(), {"LastModified": "2026-11-01T00:00:00Z", "VersionId": f"version-{name}",
                                       "ReplicationStatus": status})
                for name in names
            }

        def read(trust, name):
            try:
                return records[trust["ledger"]["bucket"]][name]
            except KeyError as error:
                raise ValueError("missing S3 record") from error

        def list_names(trust, _name):
            return sorted(records[trust["ledger"]["bucket"]])

        with (patch("custody_archive.require_frozen_ledger"), patch("custody_archive.list_objects", side_effect=list_names),
              patch("custody_archive.read_stored_payload", side_effect=read),
              patch("custody_ledger.read_stored_payload", side_effect=read)):
            pin = ledger_checkpoint(TRUST)
            self.assertEqual(ledger_checkpoint(promoted, pin), pin)
            for status in (None, "PENDING", "FAILED"):
                with self.subTest(status=status), patch.dict(records[SOURCE_BUCKET][names[-1]][1], {"ReplicationStatus": status}):
                    with self.assertRaisesRegex(ValueError, "retired/1.json has not completed"):
                        ledger_checkpoint(TRUST)

            promoted["ledgerReplica"] = new_replica
            with self.assertRaisesRegex(ValueError, "1.json from the pinned replica"):
                ledger_checkpoint(promoted)
            records[new_replica["bucket"]] = copy.deepcopy(records[DESTINATION_BUCKET])
            body, metadata = records[new_replica["bucket"]][names[-1]]
            for change in ({"VersionId": "wrong-version"}, {"LastModified": "2026-11-01T00:00:01Z"},
                           {"ReplicationStatus": "COMPLETED"}):
                with self.subTest(change=change), patch.dict(metadata, change):
                    with self.assertRaisesRegex(ValueError, "retired/1.json differs from the pinned replica"):
                        ledger_checkpoint(promoted)
            with patch.dict(records[new_replica["bucket"]], {names[-1]: (body + b"x", metadata)}):
                with self.assertRaisesRegex(ValueError, "retired/1.json differs from the pinned replica"):
                    ledger_checkpoint(promoted)
            with patch.dict(records[new_replica["bucket"]], {"retired/2.json": (body, metadata)}):
                with self.assertRaisesRegex(ValueError, "pinned replica namespace differs"):
                    ledger_checkpoint(promoted)
            self.assertEqual(ledger_checkpoint(promoted, pin), pin)


if __name__ == "__main__":
    unittest.main()
