"""Check the unsigned x86-64 EIF layout emitted by our pinned Nitro CLI."""

import binascii
import hashlib
import re
import stat
import struct

from approval import open_regular

MAX_EIF_BYTES = 64 * 1024 * 1024
EIF_HEADER = struct.Struct(">4sHHQQHH32Q32QII")
SECTION_HEADER = struct.Struct(">HHQ")
SECTION_TYPES = (1, 2, 5, 3, 3)  # Kernel, cmdline, metadata, bootstrap, application.

# Kernel, cmdline and bootstrap initramfs from Nitro CLI v1.5.3 (536dca3).
BOOTSTRAP_PCR = "0343b056cd8485ca7890ddd833476d78460aed2aa161548e4e26bedf321726696257d623e8805f3f605946b3d8b0c6aa"
APP_FILES = {b"rootfs/tvc_app": (0o100755, "executableSha256"),
             b"rootfs/configuration.json": (0o100644, "configurationSha256")}
LAUNCH_FILES = {
    b"cmd": b"/tvc_app\n",
    b"env": b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n",
}
LINUXKIT_DIRECTORIES = {b"rootfs", b"rootfs/dev", b"rootfs/dev/pts", b"rootfs/dev/shm", b"rootfs/etc",
                        b"rootfs/proc", b"rootfs/sys", b"rootfs/run", b"rootfs/var", b"rootfs/tmp"}
LINUXKIT_LINKS = {b"rootfs/etc/mtab": b"/proc/mounts", b"rootfs/etc/resolv.conf": b"/run/resolvconf/resolv.conf"}
HOSTS_PATH = b"rootfs/etc/hosts"
HOSTS_SHA256 = "43037ff87af87fda11c4377e963593a0f55e513702779db721c6ce574c06e88e"


def measured_sections(image):
    if len(image) < EIF_HEADER.size:
        raise ValueError("truncated EIF header")
    magic, version, flags, _, _, reserved, count, *table = EIF_HEADER.unpack_from(image)
    if (magic, version, flags, reserved, count) != (b".eif", 4, 0, 0, len(SECTION_TYPES)):
        raise ValueError("expected an unsigned x86-64 EIF v4 with two ramdisks")
    offsets, sizes = table[:32], table[32:64]
    reserved, checksum = table[64:]
    if reserved or any(offsets[count:]) or any(sizes[count:]):
        raise ValueError("invalid EIF section table")
    calculated = binascii.crc32(image[EIF_HEADER.size:], binascii.crc32(image[:EIF_HEADER.size - 4]))
    if checksum != calculated:
        raise ValueError("EIF checksum verification failed")

    position = EIF_HEADER.size
    sections = []
    for kind, offset, size in zip(SECTION_TYPES, offsets[:count], sizes[:count], strict=True):
        start = offset + SECTION_HEADER.size
        end = start + size
        if offset != position or not size or end > len(image):
            raise ValueError("invalid EIF section bounds")
        if SECTION_HEADER.unpack_from(image, offset) != (kind, 0, size):
            raise ValueError("unexpected EIF section type, flags or length")
        sections.append(image[start:end])
        position = end
    if position != len(image):
        raise ValueError("unexpected data after the EIF sections")
    kernel, cmdline, _, bootstrap, app = sections
    return kernel, cmdline, bootstrap, app


def pcr(*sections):
    digest = hashlib.sha384()
    for section in sections:
        digest.update(section)
    return hashlib.sha384(bytes(48) + digest.digest()).hexdigest()


def application_entries(archive):
    position = 0
    while position + 110 <= len(archive):
        header = bytes(archive[position:position + 110])
        if not re.fullmatch(b"070701[0-9A-Fa-f]{104}", header):
            raise ValueError("expected an uncompressed newc application archive")
        _, mode, uid, gid, links, _, size, _, _, _, _, name_size, checksum = (
            int(header[index:index + 8], 16) for index in range(6, 110, 8)
        )
        name_start = position + 110
        name_end = name_start + name_size
        data_start = (name_end + 3) & ~3
        data_end = data_start + size
        position = (data_end + 3) & ~3
        if not 2 <= name_size <= 4096 or position > len(archive) or checksum:
            raise ValueError("invalid application archive entry length or checksum")
        if any(archive[name_end:data_start]) or any(archive[data_end:position]):
            raise ValueError("invalid application archive padding")
        name = bytes(archive[name_start:name_end])
        if not name.endswith(b"\0") or b"\0" in name[:-1]:
            raise ValueError("invalid application archive path")
        name = name[:-1]
        if name == b"TRAILER!!!":
            if size or any(archive[position:]):
                raise ValueError("unexpected data after the application archive")
            return
        if uid or gid or (not stat.S_ISDIR(mode) and links != 1):
            raise ValueError("unexpected application archive ownership or hard link")
        yield name, mode, archive[data_start:data_end]
    raise ValueError("missing application archive trailer")


def verify_application(archive, manifest):
    seen = set()
    for name, mode, body in application_entries(archive):
        directory = name.removesuffix(b"/")
        if directory in LINUXKIT_DIRECTORIES:
            if mode != 0o040755 or body:
                raise ValueError("unexpected LinuxKit directory mode or contents")
            seen.add(directory)
            continue
        if name in seen:
            raise ValueError("duplicate file in EIF application archive")
        seen.add(name)
        if name in APP_FILES:
            expected_mode, field = APP_FILES[name]
            if mode != expected_mode or hashlib.sha256(body).hexdigest() != manifest[field]:
                raise ValueError("embedded application or configuration does not match provenance")
        elif name in LAUNCH_FILES:
            if mode != 0o100644 or body != LAUNCH_FILES[name]:
                raise ValueError("unexpected EIF application command or environment")
        elif name in LINUXKIT_LINKS:
            if not stat.S_ISLNK(mode) or body != LINUXKIT_LINKS[name]:
                raise ValueError("unexpected LinuxKit symlink")
        elif name == HOSTS_PATH:
            if mode != 0o100755 or hashlib.sha256(body).hexdigest() != HOSTS_SHA256:
                raise ValueError("unexpected LinuxKit hosts file mode or contents")
        else:
            raise ValueError("unexpected file in EIF application archive")
    if ({b"rootfs", HOSTS_PATH} | APP_FILES.keys() | LAUNCH_FILES.keys()) - seen:
        raise ValueError("EIF is missing the measured application, configuration or runtime files")


def verify_eif(path, manifest):
    with open_regular(path) as source:
        image = memoryview(source.read(MAX_EIF_BYTES + 1))
    if len(image) > MAX_EIF_BYTES or hashlib.sha256(image).hexdigest() != manifest["eifSha256"]:
        raise ValueError("EIF bytes do not match the reviewed digest or exceed 64 MiB")
    kernel, cmdline, bootstrap, app = measured_sections(image)
    bootstrap_pcr = pcr(kernel, cmdline, bootstrap)
    if bootstrap_pcr != BOOTSTRAP_PCR:
        raise ValueError("EIF bootstrap does not match the pinned Nitro CLI")
    if manifest["pcrs"] != {"PCR0": pcr(kernel, cmdline, bootstrap, app), "PCR1": bootstrap_pcr, "PCR2": pcr(app)}:
        raise ValueError("EIF PCRs do not match provenance")
    verify_application(app, manifest)
