import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from audit_openssl import check_source, required_patches


def advisory(cve, fixed, commit=None):
    page = f'<h2 id="{cve}">{cve}</h2><li>from 3.5.0 before 3.5.{fixed}</li>'
    if commit is not None:
        page += f'<a href="https://github.com/openssl/openssl/commit/{commit}">3.5.{fixed} git commit</a>'
    return page


class OpenSslAuditTests(unittest.TestCase):
    def test_missing_or_invalid_advisory_cannot_pass(self):
        published = advisory("CVE-2026-1", 9)
        self.assertEqual(list(required_patches(published, 9)), [])
        for page, message in (
            ("<html>Unexpected response</html>", "expected an OpenSSL 3.5 advisory listing"),
            (published * 2, "expected an OpenSSL 3.5 advisory listing"),
            ('<h2 id="CVE-2026-1">CVE-2026-1</h2>', "missing its OpenSSL 3.5 affected range"),
            (published + advisory("CVE-2026-2", 10), "missing an OpenSSL 3.5.10 fix reference"),
        ):
            with self.subTest(page=page), self.assertRaisesRegex(ValueError, message):
                list(required_patches(page, 9))

    def test_released_fixes_and_backports_must_be_in_the_selected_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = pathlib.Path(directory)

            def git(*args):
                return subprocess.run(["git", "-C", directory, "-c", "user.name=Test", "-c", "user.email=test@example.com",
                                       "-c", "commit.gpgsign=false", "-c", "tag.gpgSign=false", *args],
                                      capture_output=True, text=True, check=True).stdout.strip()

            git("init", "--initial-branch", "openssl-3.5")
            git("commit", "--allow-empty", "-m", "3.5.9")
            baseline = git("rev-parse", "HEAD")
            git("tag", "openssl-3.5.9")
            git("commit", "--allow-empty", "-m", "fix")
            fix = git("rev-parse", "HEAD")
            git("commit", "--allow-empty", "-m", "subsequent unrelated change")
            pin = git("rev-parse", "HEAD")
            page = advisory("CVE-2026-1", 9) + advisory("CVE-2026-2", 10, fix)
            self.assertEqual(check_source(repo, pin, page), (9, 1))
            with self.assertRaisesRegex(ValueError, "lacks the published fix for CVE-2026-2"):
                check_source(repo, baseline, page)
            with self.assertRaisesRegex(ValueError, "outside the upstream OpenSSL 3.5 branch"):
                check_source(repo, "a" * 40, page)
            git("tag", "openssl-3.5.10")
            self.assertEqual(check_source(repo, pin, page), (10, 0))


if __name__ == "__main__":
    unittest.main()
