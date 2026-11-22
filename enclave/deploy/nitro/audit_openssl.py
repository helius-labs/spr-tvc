"""Check the pinned OpenSSL 3.5 source against OpenSSL's published fixes."""

import re
import subprocess
import sys
from pathlib import Path

REPOSITORY = "https://github.com/openssl/openssl"
REVISION = r"[0-9a-f]{40}"
ADVISORY_HEADING = re.compile(r'<h2\b[^>]*\bid="(CVE-[0-9]{4}-[0-9]+)"[^>]*>')
FIXED_IN = re.compile(r"<li>\s*from 3\.5\.[0-9]+ before 3\.5\.([0-9]+)\s*</li>")


def required_patches(page, released_patch):
    sections = ADVISORY_HEADING.split(page)
    advisories = list(zip(sections[1::2], sections[2::2], strict=True))
    if not advisories or len({name for name, _ in advisories}) != len(advisories):
        raise ValueError("expected an OpenSSL 3.5 advisory listing")
    for name, section in advisories:
        fixed = FIXED_IN.findall(section)
        if not fixed:
            raise ValueError(f"{name} is missing its OpenSSL 3.5 affected range")
        for patch in sorted({int(value) for value in fixed if int(value) > released_patch}):
            reference = rf'<a\s+href="{re.escape(REPOSITORY)}/commit/({REVISION})"[^>]*>\s*3\.5(?:\.{patch}| branch) git commit\s*</a>'
            commits = re.findall(reference, section)
            if not commits:
                raise ValueError(f"{name} is missing an OpenSSL 3.5.{patch} fix reference")
            for commit in commits:
                yield name, commit


def check_source(repo, revision, page):
    def git(*args):
        return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True, timeout=30).stdout

    if not re.fullmatch(REVISION, revision):
        raise ValueError("expected an exact OpenSSL source revision")
    try:
        git("merge-base", "--is-ancestor", revision, "HEAD")
    except subprocess.CalledProcessError as error:
        raise ValueError("the pinned revision is outside the upstream OpenSSL 3.5 branch") from error
    tags = git("tag", "--merged", revision, "--list", "openssl-3.5.*").splitlines()
    releases = [int(match[1]) for tag in tags if (match := re.fullmatch(r"openssl-3\.5\.([0-9]+)", tag))]
    if not releases:
        raise ValueError("the OpenSSL revision must descend from a 3.5 release")
    baseline = max(releases)
    patches = list(required_patches(page, baseline))
    for name, commit in patches:
        try:
            git("merge-base", "--is-ancestor", commit, revision)
        except subprocess.CalledProcessError as error:
            raise ValueError(f"OpenSSL revision lacks the published fix for {name} ({commit})") from error
    return baseline, len(patches)


def main():
    revision, checkout, advisory_file = sys.argv[1:]
    subprocess.run(["git", "clone", "--bare", "--filter=blob:none", "--single-branch",
                    "--branch", "openssl-3.5", REPOSITORY + ".git", checkout], check=True, timeout=120)
    baseline, count = check_source(Path(checkout), revision, Path(advisory_file).read_text(encoding="utf-8"))
    print(f"OpenSSL {revision} contains release 3.5.{baseline} and {count} later published fixes")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None
