import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from approval import canonical
from provenance import WORKFLOW, describe, verify

COMMIT = "ab" * 20


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.build = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        for file in ("tvc_app", "configuration.json", "enclave.eif"):
            (self.build / file).write_text(file)
        (self.build / "measurements.json").write_bytes(canonical({
            "Measurements": {f"PCR{index}": f"{index + 7:02x}" * 48 for index in range(3)},
        }))
        self.manifest = self.build / "provenance.json"
        self.manifest.write_bytes(canonical(describe(self.build, "mainnet", COMMIT)))

    @patch("provenance.subprocess.run")
    def test_matches_the_exact_source_network_and_artifacts_before_github_verification(self, run):
        verify(self.build, "mainnet", COMMIT)
        args = run.call_args.args[0]
        self.assertIn(str(self.manifest), args)
        self.assertIn(str(self.build / "provenance.intoto.jsonl"), args)
        self.assertEqual(args[args.index("--signer-workflow") + 1], WORKFLOW)
        self.assertEqual(args[args.index("--source-ref") + 1], "refs/heads/main")
        self.assertEqual(args[args.index("--source-digest") + 1], COMMIT)
        self.assertEqual(args[args.index("--signer-digest") + 1], COMMIT)
        self.assertIn("--deny-self-hosted-runners", args)

    @patch("provenance.subprocess.run")
    def test_devnet_accepts_an_explicit_reviewed_branch_and_mainnet_rejects_it(self, run):
        branch = "refs/heads/review/nitro-devnet"
        with self.assertRaisesRegex(ValueError, "mainnet requires"):
            verify(self.build, "mainnet", COMMIT, branch)
        run.assert_not_called()
        self.manifest.write_bytes(canonical(describe(self.build, "devnet", COMMIT)))
        verify(self.build, "devnet", COMMIT, branch)
        args = run.call_args.args[0]
        self.assertEqual(args[args.index("--source-ref") + 1], branch)

    @patch("provenance.subprocess.run")
    def test_rejects_pr_merge_refs_and_tags_for_devnet_commissioning(self, run):
        self.manifest.write_bytes(canonical(describe(self.build, "devnet", COMMIT)))
        for ref in ("refs/pull/61/merge", "refs/tags/v1", "main", "https://example.com/ref"):
            with self.subTest(ref=ref), self.assertRaisesRegex(ValueError, "reviewed branch ref"):
                verify(self.build, "devnet", COMMIT, ref)
        run.assert_not_called()

    @patch("provenance.subprocess.run")
    def test_substituted_code_config_measurement_eif_or_network_never_qualifies(self, run):
        for file in ("tvc_app", "configuration.json", "enclave.eif", "measurements.json"):
            artifact = self.build / file
            original = artifact.read_bytes()
            artifact.write_bytes(original.replace(b"07", b"ee") if file == "measurements.json" else b"unreviewed")
            with self.subTest(file=file), self.assertRaisesRegex(ValueError, "reviewed build"):
                verify(self.build, "mainnet", COMMIT)
            artifact.write_bytes(original)
        for network, commit in [("devnet", COMMIT), ("mainnet", "cd" * 20)]:
            with self.assertRaisesRegex(ValueError, "reviewed build"):
                verify(self.build, network, commit)
        run.assert_not_called()

    def test_packaging_requires_the_written_eif_to_match_build_measurements(self):
        command_dir = self.build / "bin"
        command_dir.mkdir()
        docker = command_dir / "docker"
        docker.write_text("#!/bin/sh\nexit 0\n")
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
        mismatched = self.build / "mismatched.json"
        mismatched.write_bytes((self.build / "measurements.json").read_bytes().replace(b"07", b"ef"))
        script = pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro/build-eif.sh"
        command = ["bash", str(script), str(self.build / "tvc_app"), str(self.build / "configuration.json")]
        env = {**os.environ, "PATH": f"{command_dir}:{os.environ['PATH']}", "BUILD_PINS": str(self.build / "measurements.json")}
        good = subprocess.run([*command, str(self.build / "good")], cwd=self.build,
                              env={**env, "EIF_PINS": env["BUILD_PINS"]}, capture_output=True, timeout=10)
        self.assertEqual(good.returncode, 0, good.stderr.decode())
        rejected = subprocess.run([*command, str(self.build / "rejected")], cwd=self.build,
                                  env={**env, "EIF_PINS": str(mismatched)}, capture_output=True, timeout=10)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertFalse((self.build / "rejected/SHA256SUMS").exists())
