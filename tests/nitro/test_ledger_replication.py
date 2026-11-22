import copy
import hashlib
import json
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from custody_archive import ledger_checkpoint, verify_promotion
from custody_ledger import (
    check_installed_ledger, check_recovery_bucket, custody_history_statement, ledger_policy, ledger_replica_plan,
    list_ledger_versions, replica_trust, replication_configuration, require_frozen_ledger, write_once,
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
        self.assertIn("s3:ListBucketVersions", source_policy["ListCustodyRecords"]["Action"])
        self.assertEqual(source_policy["RequireSseS3"]["Condition"], {
            "StringNotEquals": {"s3:x-amz-server-side-encryption": "AES256"},
        })
        with patch("custody_ledger.storage") as storage:
            write_once(TRUST, "1.json", {"fixture": True}, lambda: None)
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

    def test_version_inventory_rejects_old_versions_and_delete_markers_across_pages(self):
        start = {"Name": SOURCE_BUCKET, "Prefix": PREFIX, "IsTruncated": False}
        first = {"Key": PREFIX + "1.json", "VersionId": "one", "IsLatest": True, "LastModified": "2026-11-01T00:00:00Z"}
        second = {**first, "Key": PREFIX + "2.json", "VersionId": "two"}
        page_one = {**start, "Versions": [first], "IsTruncated": True,
                    "NextKeyMarker": first["Key"], "NextVersionIdMarker": first["VersionId"]}
        page_two = {**start, "Versions": [second]}
        with patch("custody_ledger.storage", side_effect=[page_one, page_two]) as storage:
            self.assertEqual(list_ledger_versions(TRUST, profile="reader"), {"1.json": "one", "2.json": "two"})
            args = ["--prefix", PREFIX, "--max-keys", "32", "--no-paginate"]
            storage.assert_called_with(TRUST, "list-object-versions",
                                       [*args, "--key-marker", first["Key"], "--version-id-marker", "one"], profile="reader")

        for bad, message in (
            ({**page_two, "Versions": [{**first, "IsLatest": False}, second]}, "one current version"),
            ({**page_two, "Versions": [first, second]}, "one current version"),
            ({**page_two, "DeleteMarkers": [{**first, "Key": PREFIX + "hidden.json"}]}, "delete markers"),
            ({**page_two, "Versions": [{**second, "VersionId": "null"}]}, "requires an original S3 version"),
            ({**page_two, "Versions": [{**second, "Key": "another-prefix/2.json"}]}, "one current version"),
            ({**page_two, "Prefix": "another-prefix/"}, "invalid custody ledger version listing"),
            ({**page_one, "Versions": [second], "NextKeyMarker": second["Key"], "NextVersionIdMarker": None},
             "invalid custody ledger version continuation"),
            ({**page_one, "Versions": [second]}, "invalid custody ledger version continuation"),
        ):
            with self.subTest(bad=bad), patch("custody_ledger.storage", side_effect=[page_one, bad]):
                with self.assertRaisesRegex(ValueError, message):
                    list_ledger_versions(TRUST)

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

        def versions(trust):
            return {name: record[1]["VersionId"] for name, record in records[trust["ledger"]["bucket"]].items()}

        with (patch("custody_archive.require_frozen_ledger"), patch("custody_archive.list_ledger_versions", side_effect=versions),
              patch("custody_archive.verify_ledger_records"),
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
                with self.assertRaisesRegex(ValueError, "pinned replica versions differ"):
                    ledger_checkpoint(promoted)
            with patch("custody_archive.list_ledger_versions", return_value={
                **versions(promoted), "1.json": "changed-after-list",
            }):
                with self.assertRaisesRegex(ValueError, "differs from its listed version"):
                    ledger_checkpoint(promoted)
            self.assertEqual(ledger_checkpoint(promoted, pin), pin)

    def test_promotion_requires_the_original_fence_and_final_history(self):
        trust = {**TRUST, "network": "mainnet", "walletTrustSha256": "a1" * 32}
        new_replica = {"bucket": "custody-replacement", "account": "000000000011", "region": "eu-west-2",
                       "role": f"arn:aws:iam::{DESTINATION_ACCOUNT}:role/replication"}
        promoted = {**trust, "ledger": replica_trust(trust, REPLICA)["ledger"], "ledgerReplica": new_replica}
        source_scope = {name: value for name, value in trust.items() if name != "ledgerReplica"}
        policies = {
            ledger["ledger"]["bucket"]: {"Statement": [custody_history_statement(ledger, frozen=True)]}
            for ledger in (source_scope, promoted)
        }
        names = {bucket: ["1.json", "retired/1.json"] for bucket in (SOURCE_BUCKET, DESTINATION_BUCKET, new_replica["bucket"])}
        profiles = {SOURCE_BUCKET: "source-read", DESTINATION_BUCKET: "recovery-read", new_replica["bucket"]: "recovery-read"}
        replication = replication_configuration(promoted, new_replica)
        replica_policy = ledger_replica_plan(
            promoted, f"arn:aws:iam::{new_replica['account']}:role/admin",
            f"arn:aws:iam::{new_replica['account']}:role/publisher", [],
        )["destinationPolicy"]
        replica_controls = BUCKET_CONTROLS.copy()
        freeze_controls = {bucket: BUCKET_CONTROLS.copy() for bucket in policies}

        def policy(ledger, *, profile):
            bucket = ledger["ledger"]["bucket"]
            if bucket == new_replica["bucket"]:
                self.assertEqual(profile, "new-replica-read")
                return replica_policy
            self.assertEqual(profile, profiles[bucket])
            return policies[bucket]

        def bucket_controls(ledger, operation, **options):
            if operation == "get-bucket-replication":
                self.assertEqual(ledger, promoted)
                self.assertEqual(options["profile"], "recovery-read")
                return {"ReplicationConfiguration": replication}
            bucket = ledger["ledger"]["bucket"]
            if bucket in policies:
                self.assertEqual(options["profile"], profiles[bucket])
                return freeze_controls[bucket][operation]
            self.assertEqual(ledger, replica_trust(promoted, new_replica))
            self.assertEqual(options["profile"], "new-replica-read")
            return replica_controls[operation]

        def versions(ledger, *, profile):
            bucket = ledger["ledger"]["bucket"]
            self.assertEqual(profile, profiles[bucket])
            return {name: f"version-{name}" for name in names[bucket]}

        def read(ledger, name, *, profile):
            bucket = ledger["ledger"]["bucket"]
            self.assertEqual(profile, profiles[bucket])
            self.assertIn(name, names[bucket])
            return name.encode(), {"LastModified": "2026-11-01T00:00:00Z", "VersionId": f"version-{name}",
                                   "ReplicationStatus": "COMPLETED" if bucket == SOURCE_BUCKET else "REPLICA"}

        with (patch("custody_ledger.installed_ledger_policy", side_effect=policy),
              patch("custody_ledger.storage", side_effect=bucket_controls),
              patch("custody_archive.list_ledger_versions", side_effect=versions),
              patch("custody_archive.read_stored_payload", side_effect=read),
              patch("custody_ledger.read_stored_payload", side_effect=read),
              patch("custody_archive.verify_ledger_records") as verify_records,
              patch("custody_archive.require_profile_account") as account,
              patch("custody_ledger.require_profile_account", account)):
            pin = ledger_checkpoint(source_scope, profile="source-read")

            def verify(candidate=promoted):
                return verify_promotion(trust, candidate, pin, "source-read", "recovery-read", replica_profile="new-replica-read")

            self.assertEqual(verify(), pin)
            self.assertEqual(verify_records.call_count, 3)
            verify_records.assert_any_call(
                promoted, tuple(names[DESTINATION_BUCKET]), profile="recovery-read",
                checkpoint_records={
                    name: (f"version-{name}", "2026-11-01T00:00:00+00:00", hashlib.sha256(name.encode()).hexdigest())
                    for name in names[DESTINATION_BUCKET]
                },
            )
            self.assertEqual([call.args for call in account.call_args_list], [
                ("source-read", TRUST["ledger"]["region"], SOURCE_ACCOUNT),
                ("recovery-read", REPLICA["region"], DESTINATION_ACCOUNT),
                ("new-replica-read", new_replica["region"], new_replica["account"]),
            ])
            with patch.dict(replica_controls, {"get-bucket-lifecycle-configuration": {"Rules": [{"Expiration": {"Days": 1}}]}}):
                with self.assertRaisesRegex(ValueError, "no lifecycle"):
                    verify()
            with patch.dict(replica_policy, {"Statement": []}):
                with self.assertRaisesRegex(ValueError, "pinned replica write and delete protections"):
                    verify()
            for ledger in (trust, promoted):
                bucket = ledger["ledger"]["bucket"]
                with self.subTest(writable=bucket), patch.dict(policies, {bucket: {"Statement": []}}):
                    with self.assertRaisesRegex(ValueError, "requires the frozen bucket policy"):
                        verify()
                for operation, message in (
                    ("get-bucket-versioning", "requires versioning"),
                    ("get-bucket-ownership-controls", "requires bucket-owner-enforced"),
                    ("get-public-access-block", "requires all four public access blocks"),
                ):
                    with self.subTest(bucket=bucket, operation=operation), patch.dict(freeze_controls[bucket], {operation: {}}):
                        with self.assertRaisesRegex(ValueError, message):
                            verify()
            with patch.dict(names, {SOURCE_BUCKET: ["1.json", "retired/1.json", "retired/2.json"]}):
                with self.assertRaisesRegex(ValueError, "differs from the independently pinned checkpoint"):
                    verify()
            with patch("custody_ledger.installed_ledger_policy", side_effect=[
                policies[SOURCE_BUCKET], policies[DESTINATION_BUCKET], policies[DESTINATION_BUCKET], {"Statement": []},
            ]):
                with self.assertRaisesRegex(ValueError, "requires the frozen bucket policy"):
                    verify()
            with patch.dict(replication, {}, clear=True):
                with self.assertRaisesRegex(ValueError, "does not match the pinned ledger replica"):
                    verify()
            with patch("custody_ledger.installed_ledger_policy", side_effect=OSError("original bucket unreachable")):
                with self.assertRaisesRegex(OSError, "original bucket unreachable"):
                    verify()
            with self.assertRaisesRegex(ValueError, "original ledger's pinned replica"):
                verify({**promoted, "ledger": {**promoted["ledger"], "account": "000000000012"}})
            with self.assertRaisesRegex(ValueError, "preserve the custody trust"):
                verify({**promoted, "walletTrustSha256": "b2" * 32})
            with self.assertRaisesRegex(ValueError, "requires a new pinned replica"):
                verify({name: value for name, value in promoted.items() if name != "ledgerReplica"})
            with self.assertRaisesRegex(ValueError, "keep the original ledger frozen"):
                verify({**promoted, "ledgerReplica": {**trust["ledger"], "role": new_replica["role"]}})
            with self.assertRaisesRegex(ValueError, "provide --replica-profile"):
                verify_promotion(trust, promoted, pin, "source-read", "recovery-read")


if __name__ == "__main__":
    unittest.main()
