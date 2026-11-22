import binascii
import hashlib
import pathlib
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "enclave/deploy/nitro"))
from eif import verify_eif

KERNEL = b"kernel fixture"
CMDLINE = b"command line fixture"
BOOTSTRAP = b"bootstrap fixture"
APP = b"application fixture"
CONFIGURATION = b'{"fixture":true}'


def extend(data):
    return hashlib.sha384(bytes(48) + hashlib.sha384(data).digest()).hexdigest()


def entry(name, mode, body=b"", *, links=1):
    def aligned(part):
        return part + bytes(-len(part) % 4)

    fields = (1, mode, 0, 0, links, 0, len(body), 0, 0, 0, 0, len(name) + 1, 0)
    return aligned(b"070701" + b"".join(f"{field:08x}".encode() for field in fields) + name + b"\0") + aligned(body)


def enclosed(parts):
    payloads = ((1, KERNEL), (2, CMDLINE), (5, b"{}"), (3, BOOTSTRAP), (3, parts))
    offsets, sizes, region = [], [], bytearray()
    for kind, payload in payloads:
        offsets.append(548 + len(region))
        sizes.append(len(payload))
        region.extend(struct.pack(">HHQ", kind, 0, len(payload)) + payload)
    table = offsets + [0] * 27 + sizes + [0] * 27
    header = struct.pack(">4sHHQQHH64QI", b".eif", 4, 0, 0, 0, 0, 5, *table, 0)
    checksum = binascii.crc32(header + region)
    return header + struct.pack(">I", checksum) + region


class EifTests(unittest.TestCase):
    def setUp(self):
        directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = directory / "enclave.eif"
        self.enterContext(patch("eif.BOOTSTRAP_PCR", extend(KERNEL + CMDLINE + BOOTSTRAP)))
        self.payload = {
            b"rootfs": entry(b"rootfs", 0o040755, links=2),
            b"rootfs/configuration.json": entry(b"rootfs/configuration.json", 0o100644, CONFIGURATION),
            b"rootfs/tvc_app": entry(b"rootfs/tvc_app", 0o100755, APP),
            b"cmd": entry(b"cmd", 0o100644, b"/tvc_app\n"),
            b"env": entry(b"env", 0o100644, b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"),
        }
        self.trailer = entry(b"TRAILER!!!", 0)

    def image(self, archive):
        data = enclosed(archive)
        self.path.write_bytes(data)
        return {
            "eifSha256": hashlib.sha256(data).hexdigest(),
            "executableSha256": hashlib.sha256(APP).hexdigest(),
            "configurationSha256": hashlib.sha256(CONFIGURATION).hexdigest(),
            "pcrs": {"PCR0": extend(KERNEL + CMDLINE + BOOTSTRAP + archive),
                     "PCR1": extend(KERNEL + CMDLINE + BOOTSTRAP),
                     "PCR2": extend(archive)},
        }

    def test_checks_the_image_digest_checksum_and_independently_measured_pcrs(self):
        manifest = self.image(b"".join(self.payload.values()) + self.trailer)
        verify_eif(self.path, manifest)
        with self.assertRaisesRegex(ValueError, "EIF bytes do not match"):
            verify_eif(self.path, {**manifest, "eifSha256": "ff" * 32})
        with self.assertRaisesRegex(ValueError, "EIF PCRs do not match"):
            verify_eif(self.path, {**manifest, "pcrs": {**manifest["pcrs"], "PCR2": "ff" * 48}})
        with patch("eif.BOOTSTRAP_PCR", "ff" * 48):
            with self.assertRaisesRegex(ValueError, "bootstrap does not match"):
                verify_eif(self.path, manifest)
        corrupt = self.path.read_bytes()[:-1] + b"x"
        self.path.write_bytes(corrupt)
        with self.assertRaisesRegex(ValueError, "EIF checksum verification failed"):
            verify_eif(self.path, {**manifest, "eifSha256": hashlib.sha256(corrupt).hexdigest()})

    def test_rejects_a_different_embedded_app_config_or_launch(self):
        for name, mode, body, links, message in (
            (b"rootfs/tvc_app", 0o100755, b"other executable", 1, "does not match provenance"),
            (b"rootfs/configuration.json", 0o100644, b"{}", 1, "does not match provenance"),
            (b"rootfs/tvc_app", 0o100644, APP, 1, "does not match provenance"),
            (b"rootfs/tvc_app", 0o100755, APP, 2, "hard link"),
            (b"cmd", 0o100644, b"/tvc_app\n--fixture\n", 1, "command or environment"),
            (b"env", 0o100644, b"CHANGED=yes\n", 1, "command or environment"),
        ):
            changed = {**self.payload, name: entry(name, mode, body, links=links)}
            manifest = self.image(b"".join(changed.values()) + self.trailer)
            with self.subTest(name=name, body=body), self.assertRaisesRegex(ValueError, message):
                verify_eif(self.path, manifest)

    def test_checks_section_offsets_and_rejects_unsupported_layouts(self):
        manifest = self.image(b"".join(self.payload.values()) + self.trailer)
        original = self.path.read_bytes()
        for offset, replacement, message in (
            (4, b"\x00\x03", "expected an unsigned x86-64 EIF v4"),
            (28, (549).to_bytes(8, "big"), "invalid EIF section bounds"),
            (548, b"\x00\x03", "unexpected EIF section type"),
        ):
            changed = bytearray(original)
            changed[offset:offset + len(replacement)] = replacement
            checksum = binascii.crc32(changed[:544] + changed[548:])
            changed[544:548] = checksum.to_bytes(4, "big")
            self.path.write_bytes(changed)
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, message):
                verify_eif(self.path, {**manifest, "eifSha256": hashlib.sha256(changed).hexdigest()})
        self.path.write_bytes(original)
        with patch("eif.MAX_EIF_BYTES", len(original) - 1):
            with self.assertRaisesRegex(ValueError, "exceed 64 MiB"):
                verify_eif(self.path, manifest)

    def test_rejects_ambiguous_or_incomplete_application_archives(self):
        valid = b"".join(self.payload.values())
        for archive, message in (
            (valid + self.payload[b"rootfs/tvc_app"] + self.trailer, "duplicate file"),
            (valid + entry(b"rootfs/../cmd", 0o100644, b"other") + self.trailer, "unexpected file"),
            (valid + self.trailer + b"other archive bytes", "unexpected data"),
            (valid + self.trailer[:-4], "invalid application archive"),
            (valid + b"\x00", "missing application archive trailer"),
            (valid.removesuffix(self.payload[b"env"]) + self.trailer, "missing the measured application"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                verify_eif(self.path, self.image(archive))


if __name__ == "__main__":
    unittest.main()
