import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from approval import canonical
from provenance import WORKFLOW, describe, require_independent_review, verify

COMMIT = "ab" * 20


class IndependentReleaseReviewTests(unittest.TestCase):
    review = {"state": "approved", "user": {"id": 2, "type": "User"},
              "environments": [{"name": "image-publish"}]}

    def test_requires_an_independent_approval_of_the_production_environment(self):
        require_independent_review([self.review], "1", "1")
        for reviews in ([], [{**self.review, "state": "rejected"}],
                        [{**self.review, "environments": [{"name": "native-eif-devnet"}]}],
                        [{**self.review, "user": {"id": 1, "type": "User"}}],
                        [{**self.review, "user": {"id": 2, "type": "Bot"}}],
                        [{**self.review, "user": {"id": True, "type": "User"}}]):
            with self.subTest(reviews=reviews), self.assertRaisesRegex(ValueError, "from another GitHub user"):
                require_independent_review(reviews, "1", "1")

    def test_rejects_old_run_attempts_and_missing_dispatch_identity(self):
        with self.assertRaisesRegex(ValueError, "dispatch a new mainnet build"):
            require_independent_review([self.review], "1", "2")
        for actor in ("", "0", "invalid"):
            with self.subTest(actor=actor), self.assertRaisesRegex(ValueError, "invalid GitHub release review evidence"):
                require_independent_review([self.review], actor, "1")


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
        self.review = self.build / "review.json"
        self.pin_review()

    def pin_review(self, ref="refs/heads/main"):
        self.review.write_bytes(canonical({"sourceCommit": COMMIT, "sourceRef": ref,
                                           "provenanceSha256": hashlib.sha256(self.manifest.read_bytes()).hexdigest()}))

    @patch("provenance.subprocess.run")
    def test_matches_the_exact_source_network_and_artifacts_before_github_verification(self, run):
        contents = self.manifest.read_bytes() + b"\n"
        self.manifest.write_bytes(contents)
        self.pin_review()

        def verify_subject(args, **_options):
            subject = pathlib.Path(args[3])
            self.assertNotEqual(subject, self.manifest)
            self.assertEqual(subject.read_bytes(), contents)

        run.side_effect = verify_subject
        self.assertEqual(verify(self.build, "mainnet", self.review), describe(self.build, "mainnet", COMMIT))
        run.assert_called_once()
        args = run.call_args.args[0]
        self.assertIn(str(self.build / "provenance.intoto.jsonl"), args)
        self.assertEqual(args[args.index("--signer-workflow") + 1], WORKFLOW)
        self.assertEqual(args[args.index("--source-ref") + 1], "refs/heads/main")
        self.assertEqual(args[args.index("--source-digest") + 1], COMMIT)
        self.assertEqual(args[args.index("--signer-digest") + 1], COMMIT)
        self.assertIn("--deny-self-hosted-runners", args)

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
