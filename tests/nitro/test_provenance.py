import pathlib
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
        self.assertIn("--deny-self-hosted-runners", args)

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
