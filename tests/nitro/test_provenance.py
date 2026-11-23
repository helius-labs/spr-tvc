import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from approval import MAX_DOCUMENT_BYTES, canonical
from provenance import WORKFLOW, check_artifact, describe, require_available_reviewer, require_independent_review, verify

COMMIT = "ab" * 20
ENVIRONMENT_ID = 73
REVIEWER_SNAPSHOT = {"environmentId": ENVIRONMENT_ID, "reviewerIds": [2]}
PROVENANCE_SHA256 = "cd" * 32


class IndependentReleaseReviewTests(unittest.TestCase):
    review = {"state": "approved", "comment": PROVENANCE_SHA256, "user": {"id": 2, "type": "User"},
              "environments": [{"name": "image-publish", "id": ENVIRONMENT_ID}]}

    def test_requires_a_configured_reviewer_before_building_mainnet(self):
        def environment(*reviewers):
            return {"name": "image-publish", "id": ENVIRONMENT_ID, "can_admins_bypass": False, "protection_rules": [
                {"type": "branch_policy"}, {"type": "required_reviewers", "reviewers": reviewers},
            ]}

        dispatcher = {"type": "User", "reviewer": {"id": 1, "type": "User"}}
        other = {"type": "User", "reviewer": {"id": 2, "type": "User"}}
        team = {"type": "Team", "reviewer": {"id": 1}}
        for reviewers in ((other,), (dispatcher, other), (team, other)):
            self.assertEqual(require_available_reviewer(environment(*reviewers), "1", "1"), REVIEWER_SNAPSHOT)
        third = {"type": "User", "reviewer": {"id": 3, "type": "User"}}
        self.assertEqual(require_available_reviewer(environment(third, other), "1", "1"),
                         {"environmentId": ENVIRONMENT_ID, "reviewerIds": [2, 3]})
        self.assertNotEqual(require_available_reviewer(environment(third), "1", "1"), REVIEWER_SNAPSHOT)
        bot = {"type": "User", "reviewer": {"id": 2, "type": "Bot"}}
        invalid_id = {"type": "User", "reviewer": {"id": True, "type": "User"}}
        for reviewers in ((), (dispatcher,), (bot,), (invalid_id,), (team,)):
            with self.subTest(reviewers=reviewers), self.assertRaisesRegex(ValueError, "no required reviewer"):
                require_available_reviewer(environment(*reviewers), "1", "1")
        with self.assertRaisesRegex(ValueError, "no required reviewer"):
            require_available_reviewer({**environment(), "protection_rules": []}, "1", "1")
        with self.assertRaisesRegex(ValueError, "expected the image-publish"):
            require_available_reviewer({**environment(other), "name": "native-eif-devnet"}, "1", "1")
        with self.assertRaisesRegex(ValueError, "expected the image-publish"):
            require_available_reviewer({**environment(other), "id": True}, "1", "1")
        for bypass in (True, 0, None):
            with self.subTest(bypass=bypass), self.assertRaisesRegex(ValueError, "disable administrator bypass"):
                require_available_reviewer({**environment(other), "can_admins_bypass": bypass}, "1", "1")
        with self.assertRaisesRegex(ValueError, "dispatch a new mainnet build"):
            require_available_reviewer(environment(other), "1", "2")

    def test_requires_an_independent_approval_of_the_production_environment(self):
        require_independent_review([self.review], "1", "1", REVIEWER_SNAPSHOT, PROVENANCE_SHA256)
        for reviews in ([], [{**self.review, "state": "rejected"}],
                        [{**self.review, "environments": [{"name": "native-eif-devnet", "id": ENVIRONMENT_ID}]}],
                        [{**self.review, "environments": [{"name": "image-publish", "id": ENVIRONMENT_ID + 1}]}],
                        [{**self.review, "environments": [{"name": "image-publish"}]}],
                        [{**self.review, "user": {"id": 1, "type": "User"}}],
                        [{**self.review, "user": {"id": 2, "type": "Bot"}}],
                        [{**self.review, "user": {"id": True, "type": "User"}}]):
            with self.subTest(reviews=reviews), self.assertRaisesRegex(ValueError, "configured reviewer"):
                require_independent_review(reviews, "1", "1", REVIEWER_SNAPSHOT, PROVENANCE_SHA256)

    def test_rejects_old_run_attempts_and_missing_dispatch_identity(self):
        with self.assertRaisesRegex(ValueError, "dispatch a new mainnet build"):
            require_independent_review([self.review], "1", "2", REVIEWER_SNAPSHOT, PROVENANCE_SHA256)
        for actor in ("", "0", "invalid"):
            with self.subTest(actor=actor), self.assertRaisesRegex(ValueError, "invalid GitHub release review evidence"):
                require_independent_review([self.review], actor, "1", REVIEWER_SNAPSHOT, PROVENANCE_SHA256)

    def test_approval_must_name_the_exact_provenance_digest(self):
        for comment in (None, "", "Approved", "de" * 32, PROVENANCE_SHA256.upper(),
                        PROVENANCE_SHA256 + " another artifact"):
            review = {**self.review, "comment": comment}
            with self.subTest(comment=comment), self.assertRaisesRegex(ValueError, "provenance digest"):
                require_independent_review([review], "1", "1", REVIEWER_SNAPSHOT, PROVENANCE_SHA256)

    def test_approval_cannot_be_reused_for_another_build(self):
        with self.assertRaisesRegex(ValueError, "provenance digest"):
            require_independent_review([self.review], "1", "1", REVIEWER_SNAPSHOT, "de" * 32)

    def test_rejects_approval_from_a_user_absent_when_the_build_started(self):
        environment = {
            "name": "image-publish", "id": ENVIRONMENT_ID, "can_admins_bypass": False,
            "protection_rules": [{"type": "required_reviewers", "reviewers": [
                {"type": "User", "reviewer": {"id": 2, "type": "User"}},
            ]}],
        }
        snapshot = require_available_reviewer(environment, "1", "1")
        substitute = {**self.review, "user": {"id": 3, "type": "User"}}
        with self.assertRaisesRegex(ValueError, "configured reviewer"):
            require_independent_review([substitute], "1", "1", snapshot, PROVENANCE_SHA256)

    def test_rejects_malformed_reviewer_snapshots(self):
        for reviewers in ([], [1, 2], [True, 2], [2, 2], ["2"], [3, 2], {"2": True}):
            snapshot = {**REVIEWER_SNAPSHOT, "reviewerIds": reviewers}
            with self.subTest(reviewers=reviewers), self.assertRaisesRegex(ValueError, "release review evidence"):
                require_independent_review([self.review], "1", "1", snapshot, PROVENANCE_SHA256)


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.build = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        for file in ("tvc_app", "configuration.json", "enclave.eif"):
            (self.build / file).write_text(file)
        (self.build / "measurements.json").write_bytes(canonical({
            "CheckCRC": True,
            "Measurements": {f"PCR{index}": f"{index + 7:02x}" * 48 for index in range(3)},
        }))
        self.manifest = self.build / "provenance.json"
        self.manifest.write_bytes(canonical(describe(self.build, "mainnet", COMMIT)))
        self.bundle = self.build / "provenance.intoto.jsonl"
        self.bundle.write_bytes(b'{"bundle":"signed"}\n')
        self.review = self.build / "review.json"
        self.pin_review()
        self.check_eif = self.enterContext(patch("provenance.verify_eif"))

    def pin_review(self, ref="refs/heads/main"):
        self.review.write_bytes(canonical({"sourceCommit": COMMIT, "sourceRef": ref,
                                           "provenanceSha256": hashlib.sha256(self.manifest.read_bytes()).hexdigest()}))

    def test_release_tool_rejects_named_pipes_before_reading_or_hashing(self):
        tool = pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro/provenance.py"
        for name in ("measurements.json", "tvc_app"):
            path = self.build / name
            original = path.read_bytes()
            path.unlink()
            os.mkfifo(path)
            try:
                result = subprocess.run([sys.executable, "-B", str(tool), "describe", str(self.build), "mainnet", COMMIT],
                                        capture_output=True, text=True, timeout=3, check=False)
                self.assertEqual(result.returncode, 1)
                self.assertIn(f"expected a regular file: {path}", result.stderr)
            finally:
                path.unlink()
                path.write_bytes(original)

    @patch("provenance.subprocess.run")
    def test_matches_the_exact_source_network_and_artifacts_before_github_verification(self, run):
        contents = self.manifest.read_bytes() + b"\n"
        bundle = self.bundle.read_bytes()
        self.manifest.write_bytes(contents)
        self.pin_review()

        def verify_subject(args, **_options):
            subject = pathlib.Path(args[3])
            verification_bundle = pathlib.Path(args[args.index("--bundle") + 1])
            self.assertNotEqual(subject, self.manifest)
            self.assertNotEqual(verification_bundle, self.bundle)
            self.assertEqual(subject.read_bytes(), contents)
            self.assertEqual(verification_bundle.read_bytes(), bundle)

        run.side_effect = verify_subject
        self.assertEqual(verify(self.build, "mainnet", self.review), describe(self.build, "mainnet", COMMIT))
        self.check_eif.assert_called_once_with(self.build / "enclave.eif", describe(self.build, "mainnet", COMMIT))
        run.assert_called_once()
        args = run.call_args.args[0]
        self.assertEqual(args[args.index("--cert-identity") + 1], f"https://github.com/{WORKFLOW}@refs/heads/main")
        self.assertNotIn("--signer-workflow", args)
        self.assertEqual(args[args.index("--source-ref") + 1], "refs/heads/main")
        self.assertEqual(args[args.index("--source-digest") + 1], COMMIT)
        self.assertEqual(args[args.index("--signer-digest") + 1], COMMIT)
        self.assertIn("--deny-self-hosted-runners", args)

    @patch("provenance.subprocess.run")
    def test_rejects_missing_empty_or_oversized_bundles_before_gh(self, run):
        self.bundle.unlink()
        with self.assertRaises(FileNotFoundError):
            verify(self.build, "mainnet", self.review)
        for payload in (b"", b"a" * (MAX_DOCUMENT_BYTES + 1)):
            self.bundle.write_bytes(payload)
            with self.subTest(length=len(payload)), self.assertRaisesRegex(ValueError, "of at most 64 KiB"):
                verify(self.build, "mainnet", self.review)
        run.assert_not_called()

    def test_checks_downloaded_artifacts_against_the_previewed_digest_before_signing(self):
        contents = self.manifest.read_bytes()
        digest = hashlib.sha256(contents).hexdigest()
        manifest, verified = check_artifact(self.build, "mainnet", COMMIT, digest)
        self.assertEqual(manifest, describe(self.build, "mainnet", COMMIT))
        self.assertEqual(verified, contents)
        self.manifest.write_bytes(contents + b"\n")
        with self.assertRaisesRegex(ValueError, "independently reviewed digest"):
            check_artifact(self.build, "mainnet", COMMIT, digest)
        self.manifest.write_bytes(contents)
        (self.build / "tvc_app").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "does not match the reviewed build"):
            check_artifact(self.build, "mainnet", COMMIT, digest)

    @patch("provenance.subprocess.run")
    def test_attestation_cannot_substitute_for_a_valid_eif(self, run):
        self.check_eif.side_effect = ValueError("invalid EIF contents")
        with self.assertRaisesRegex(ValueError, "invalid EIF contents"):
            verify(self.build, "mainnet", self.review)
        run.assert_not_called()

    @patch("provenance.subprocess.run")
    def test_devnet_accepts_an_explicit_reviewed_branch_and_mainnet_rejects_it(self, run):
        branch = "refs/heads/review/nitro-devnet"
        self.pin_review(branch)
        with self.assertRaisesRegex(ValueError, "mainnet requires"):
            verify(self.build, "mainnet", self.review)
        run.assert_not_called()
        self.manifest.write_bytes(canonical(describe(self.build, "devnet", COMMIT)))
        self.pin_review(branch)
        verify(self.build, "devnet", self.review)
        args = run.call_args.args[0]
        self.assertEqual(args[args.index("--source-ref") + 1], branch)
        self.assertEqual(args[args.index("--cert-identity") + 1], f"https://github.com/{WORKFLOW}@{branch}")

    @patch("provenance.subprocess.run")
    def test_rejects_pr_merge_refs_and_tags_for_devnet_commissioning(self, run):
        self.manifest.write_bytes(canonical(describe(self.build, "devnet", COMMIT)))
        for ref in ("refs/pull/61/merge", "refs/tags/v1", "main", "https://example.com/ref"):
            self.pin_review(ref)
            with self.subTest(ref=ref), self.assertRaisesRegex(ValueError, "reviewed branch ref"):
                verify(self.build, "devnet", self.review)
        run.assert_not_called()

    @patch("provenance.subprocess.run")
    def test_substituted_code_config_measurement_eif_or_network_never_qualifies(self, run):
        for file in ("tvc_app", "configuration.json", "enclave.eif", "measurements.json"):
            artifact = self.build / file
            original = artifact.read_bytes()
            artifact.write_bytes(original.replace(b"07", b"ee") if file == "measurements.json" else b"unreviewed")
            with self.subTest(file=file), self.assertRaisesRegex(ValueError, "reviewed build"):
                verify(self.build, "mainnet", self.review)
            artifact.write_bytes(original)
        with self.assertRaisesRegex(ValueError, "reviewed build"):
            verify(self.build, "devnet", self.review)
        self.review.write_bytes(self.review.read_bytes().replace(COMMIT.encode(), b"cd" * 20))
        with self.assertRaisesRegex(ValueError, "reviewed build"):
            verify(self.build, "mainnet", self.review)
        run.assert_not_called()

    @patch("provenance.subprocess.run")
    def test_rejects_a_different_build_from_the_same_commit_before_accepting_its_attestation(self, run):
        (self.build / "configuration.json").write_bytes(b'{"releaseId":"different"}')
        self.manifest.write_bytes(canonical(describe(self.build, "mainnet", COMMIT)))
        with self.assertRaisesRegex(ValueError, "independently reviewed digest"):
            verify(self.build, "mainnet", self.review)
        run.assert_not_called()
        self.pin_review()
        verify(self.build, "mainnet", self.review)
        run.assert_called_once()

    def test_packaging_requires_valid_checksum_and_matching_build_measurements(self):
        command_dir = self.build / "bin"
        command_dir.mkdir()
        binary = self.build / "tvc_app"
        binary.write_text(
            '#!/bin/sh\n'
            'test "$1" = --check-configuration && test "$2" = "${0%/*}/configuration.json" && '
            'test "$CHECK_CONFIGURATION" = ready\n'
        )
        docker = command_dir / "docker"
        docker.write_text('#!/bin/sh\ntouch "$DOCKER_CALLED"\n')
        cli = command_dir / "nitro-cli"
        cli.write_text(
            '#!/bin/sh\n'
            'case "$1" in\n'
            '  build-enclave) printf EIF > "$5"; cat "$BUILD_PINS" ;;\n'
            '  describe-eif) cat "$EIF_PINS" ;;\n'
            '  --version) printf "nitro-cli fixture\\n" ;;\n'
            'esac\n'
        )
        docker.chmod(0o700)
        cli.chmod(0o700)
        measurements = (self.build / "measurements.json").read_bytes()
        script = pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro/build-eif.sh"
        command = ["bash", str(script), str(self.build / "tvc_app"), str(self.build / "configuration.json")]
        docker_called = self.build / "docker-called"
        env = {**os.environ, "PATH": f"{command_dir}:{os.environ['PATH']}", "BUILD_PINS": str(self.build / "measurements.json"),
               "CHECK_CONFIGURATION": "ready", "DOCKER_CALLED": str(docker_called)}
        invalid = subprocess.run([*command, str(self.build / "invalid")], cwd=self.build,
                                 env={**env, "CHECK_CONFIGURATION": "invalid"}, capture_output=True, timeout=10)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertFalse(docker_called.exists())
        good = subprocess.run([*command, str(self.build / "good")], cwd=self.build,
                              env={**env, "EIF_PINS": env["BUILD_PINS"]}, capture_output=True, timeout=10)
        self.assertEqual(good.returncode, 0, good.stderr.decode())
        for case, observed, failure in (
            ("wrong-pcr", measurements.replace(b"07", b"ef"), b"EIF PCR verification failed"),
            ("bad-checksum", measurements.replace(b'"CheckCRC":true', b'"CheckCRC":false'), b"EIF checksum verification failed"),
            ("missing-checksum", measurements.replace(b'"CheckCRC":true,', b''), b"EIF checksum verification failed"),
        ):
            with self.subTest(case=case):
                evidence = self.build / f"{case}.json"
                evidence.write_bytes(observed)
                output = self.build / case
                rejected = subprocess.run([*command, str(output)], cwd=self.build,
                                          env={**env, "EIF_PINS": str(evidence)}, capture_output=True, timeout=10)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(failure, rejected.stderr)
                self.assertFalse((output / "SHA256SUMS").exists())
