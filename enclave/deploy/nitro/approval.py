"""Canonical operator documents and KMS-backed custody approvals."""

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

KEY_ARN = re.compile(r"arn:aws:kms:([a-z0-9-]+):([0-9]{12}):key/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
ROLE_ARN = re.compile(r"arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+")
SIGNING_ALGORITHM = "ECDSA_SHA_256"
MAX_DOCUMENT_BYTES = 64 * 1024
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


def fields(value, *expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError(f"expected document fields: {', '.join(expected)}")


def unique_object(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate JSON field")
    return value


def parse_json(data):
    if len(data) > MAX_DOCUMENT_BYTES:
        raise ValueError("operator document exceeds 64 KiB")
    return json.loads(data, object_pairs_hook=unique_object)


@contextmanager
def open_regular(path):
    with open(path, "rb", opener=lambda name, flags: os.open(name, flags | os.O_NONBLOCK)) as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError(f"expected a regular file: {path}")
        yield source


def read_document(path):
    with open_regular(path) as source:
        return source.read(MAX_DOCUMENT_BYTES + 1)


def read_json(path):
    return parse_json(read_document(path))


def publish_new_file(path, payload, *, before_publish=None):
    with tempfile.TemporaryDirectory(dir=path.parent) as directory:
        staged = Path(directory) / path.name
        staged.write_bytes(payload)
        if before_publish is not None:
            before_publish()
        path.hardlink_to(staged)


def canonical(value):
    # Custody signatures and hashes use sorted keys and ASCII JSON escapes.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def sha256(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_digest(path):
    with open_regular(path) as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def hex_digest(value, length=32):
    if not isinstance(value, str) or not re.fullmatch(fr"[0-9a-f]{{{2 * length}}}", value) or not int(value, 16):
        raise ValueError(f"expected a nonzero {length}-byte hex digest")
    return value


def arn(pattern, value):
    match = pattern.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("expected an immutable KMS key ARN or exact IAM role ARN")
    return match


def aws_environment():
    return {**os.environ, "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "true"}


class InvalidAwsResponse(ValueError):
    """An AWS CLI call succeeded but returned an invalid response."""


def aws(region, service, operation, arguments, body=None, *, profile=None, absent=None):
    credentials = ["--profile", profile] if profile is not None else []
    error_format = ["--cli-error-format", "json"] if absent is not None else []
    reply = subprocess.run([
        "aws", *credentials, "--region", region, "--no-cli-pager", "--output", "json", *error_format,
        service, operation, *arguments,
    ], input=body, capture_output=True, timeout=25, check=False, env=aws_environment())
    if reply.returncode:
        if absent is not None:
            try:
                error = parse_json(reply.stderr)
            except ValueError:
                error = None
            if isinstance(error, dict) and error.get("Code") == absent:
                return None
        raise ValueError(f"AWS {service} {operation} failed")
    try:
        result = parse_json(reply.stdout)
    except (ValueError, RecursionError) as error:
        raise InvalidAwsResponse(f"unexpected AWS {service} {operation} response") from error
    if not isinstance(result, dict):
        raise InvalidAwsResponse(f"unexpected AWS {service} {operation} response")
    return result


def kms(key, operation, arguments=(), body=None, **options):
    return aws(arn(KEY_ARN, key)[1], "kms", operation,
               ["--key-id", key, "--cli-binary-format", "base64", *arguments], body, **options)


def key_result(key, operation, arguments=(), body=None, **options):
    result = kms(key, operation, arguments, body, **options)
    if not isinstance(result, dict) or result.get("KeyId") != key:
        raise ValueError(f"unexpected KMS key for {operation}")
    return result


def require_kms_key(metadata, key, specs, usage):
    if (metadata.get("Arn") != key or metadata.get("KeySpec") not in specs or metadata.get("KeyUsage") != usage or
            metadata.get("Origin") != "AWS_KMS" or metadata.get("MultiRegion") is not False or
            metadata.get("KeyState") != "Enabled"):
        raise ValueError("expected an enabled, single-region key generated by AWS KMS")


def epoch_number(epoch):
    if not isinstance(epoch, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", epoch) or int(epoch) > 2**64 - 1:
        raise ValueError("invalid custody epoch")
    return int(epoch)


def signing_key(key):
    fields(key, "keyArn", "publicKey")
    arn(KEY_ARN, key["keyArn"])
    public = key["publicKey"]
    if not isinstance(public, str) or len(public) != 124:
        raise ValueError("expected a canonical P-256 public key")
    der = base64.b64decode(public, validate=True)
    if (len(der) != 91 or not der.startswith(P256_SPKI_PREFIX) or
            base64.b64encode(der).decode() != public):
        raise ValueError("expected a canonical P-256 public key")
    return public


def signing_sec1(key):
    return base64.b64decode(signing_key(key))[len(P256_SPKI_PREFIX) - 1:].hex()


def approval_roster(trust, *, epoch=None, at=None):
    schedule = trust["approvalKeys"]
    if not isinstance(schedule, list) or not schedule:
        raise ValueError("expected a custody approval key schedule")
    upto = epoch_number(epoch) if epoch is not None else (time.time() if at is None else at)
    selected, previous, previous_time = None, 0, -1
    known_keys, known_arns = {}, {}
    for entry in schedule:
        fields(entry, "fromEpoch", "activeFrom", "keys")
        start = epoch_number(entry["fromEpoch"])
        active_from = entry["activeFrom"]
        if (previous == 0 and start != 1) or start <= previous:
            raise ValueError("approval key schedule must start at 1 and increase")
        if (type(active_from) is not int or not previous_time < active_from < 2**53 or
                (previous == 0 and active_from != 0)):
            raise ValueError("approval key activation times must start at 0 and increase")
        previous = start
        previous_time = active_from
        keys = entry["keys"]
        if not isinstance(keys, list) or len(keys) != 3:
            raise ValueError("expected three approval keys in independent AWS accounts")
        accounts = set()
        for key in keys:
            public = signing_key(key)
            identity = key["keyArn"]
            accounts.add(arn(KEY_ARN, identity)[2])
            if known_keys.setdefault(identity, public) != public or known_arns.setdefault(public, identity) != identity:
                raise ValueError("a signing key must have one stable public key and ARN")
        if len(accounts) != 3:
            raise ValueError("expected three approval keys in independent AWS accounts")
        if (start if epoch is not None else active_from) <= upto:
            selected = entry
    if selected is None:
        raise ValueError("no active custody approval roster")
    return selected


def approval_keys(trust, epoch=None):
    return approval_roster(trust, epoch=epoch)["keys"]


def approval_message(label, manifest):
    return f"SPR/native-nitro/{label}/v1\0".encode() + canonical(manifest)


def signature_args(label, manifest):
    digest = hashlib.sha256(approval_message(label, manifest)).digest()
    return ["--signing-algorithm", SIGNING_ALGORITHM, "--message-type", "DIGEST",
            "--message", base64.b64encode(digest).decode()]


class ApprovalVerificationUnavailable(ValueError):
    """The verifier could not determine whether the signature is valid."""


def is_p256_der_signature(signature):
    if not 8 <= len(signature) <= 72 or signature[:2] != bytes((0x30, len(signature) - 2)):
        return False
    offset = 2
    for _ in range(2):
        if offset + 2 >= len(signature) or signature[offset] != 0x02:
            return False
        size = signature[offset + 1]
        start, offset = offset + 2, offset + 2 + size
        if not 1 <= size <= 33 or offset > len(signature):
            return False
        scalar = signature[start:offset]
        if (scalar[0] >= 0x80 or (size > 1 and scalar[0] == 0 and scalar[1] < 0x80) or
                not 0 < int.from_bytes(scalar, "big") < P256_ORDER):
            return False
    return offset == len(signature)


def check_approvals(keys, label, document, minimum=2):
    fields(document, "manifest", "signatures")
    signatures = document["signatures"]
    if not isinstance(signatures, list) or not minimum <= len(signatures) <= len(keys):
        raise ValueError("expected approvals from the pinned signing quorum")
    pins = {key["keyArn"]: signing_key(key) for key in keys}
    if len(pins) != len(keys) or len(set(pins.values())) != len(keys):
        raise ValueError("signing quorum contains duplicate keys")
    message = approval_message(label, document["manifest"])
    seen = set()
    with tempfile.TemporaryDirectory() as directory:
        public_path, signature_path = Path(directory) / "public.pem", Path(directory) / "signature.der"
        for approval in signatures:
            fields(approval, "keyArn", "signature")
            key, encoded = approval["keyArn"], approval["signature"]
            if key not in pins or key in seen or not isinstance(encoded, str) or len(encoded) > 96:
                raise ValueError("invalid or duplicate approval")
            signature = base64.b64decode(encoded, validate=True)
            if not is_p256_der_signature(signature) or base64.b64encode(signature).decode() != encoded:
                raise ValueError("invalid custody approval signature encoding")
            public = pins[key]
            public_path.write_text(f"-----BEGIN PUBLIC KEY-----\n{public[:64]}\n{public[64:]}\n-----END PUBLIC KEY-----\n")
            signature_path.write_bytes(signature)
            result = subprocess.run([
                "openssl", "dgst", "-sha256", "-verify", str(public_path), "-signature", str(signature_path),
            ], input=message, capture_output=True, timeout=10, check=False)
            # dgst uses exit 1 for both a mismatch and verifier errors.
            if result.returncode == 1 and result.stdout == b"Verification failure\n":
                raise ValueError("invalid custody approval signature")
            if result.returncode != 0 or result.stdout != b"Verified OK\n":
                raise ApprovalVerificationUnavailable("could not verify custody approval signature")
            seen.add(key)


def add_approval(keys, label, document, key):
    selected = next((pin for pin in keys if pin["keyArn"] == key), None)
    if selected is None or any(signature["keyArn"] == key for signature in document["signatures"]):
        raise ValueError("signing key is not pinned or already approved this document")
    check_approvals(keys, label, document, minimum=0)
    signature = key_result(key, "sign", signature_args(label, document["manifest"]))
    if signature.get("SigningAlgorithm") != SIGNING_ALGORITHM:
        raise ValueError("unexpected KMS signing algorithm")
    signed = {"keyArn": key, "signature": signature["Signature"]}
    check_approvals([selected], label, {"manifest": document["manifest"], "signatures": [signed]}, minimum=1)
    return {"manifest": document["manifest"], "signatures": [*document["signatures"], signed]}


def require_inspection_profiles(profiles):
    if profiles is None or len(profiles) != 6 or len(set(profiles)) != 6 or not all(profiles):
        raise ValueError("provide six distinct read-only inspection profiles in custody slot order")


def require_custody_key_profiles(profiles):
    if (not isinstance(profiles, dict) or len(profiles) < 3 or
            any(not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
                or not isinstance(profile, str) or not profile.strip()
                for account, profile in profiles.items()) or len(set(profiles.values())) != len(profiles)):
        raise ValueError("provide --custody-key-profiles with distinct AWS profiles keyed by account")


def require_profile_account(profile, region, account):
    try:
        identity = aws(region, "sts", "get-caller-identity", [], profile=profile)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"cannot identify AWS inspection profile {profile}") from error
    if not isinstance(identity, dict) or identity.get("Account") != account:
        raise ValueError(f"AWS inspection profile {profile} must belong to account {account}")


def get_signing_key(key, **options):
    require_kms_key(kms(key, "describe-key", **options)["KeyMetadata"], key, {"ECC_NIST_P256"}, "SIGN_VERIFY")
    result = key_result(key, "get-public-key", **options)
    if (result.get("KeySpec") != "ECC_NIST_P256" or result.get("KeyUsage") != "SIGN_VERIFY" or
            SIGNING_ALGORITHM not in result.get("SigningAlgorithms", [])):
        raise ValueError("expected a P-256 KMS signing key")
    pin = {"keyArn": key, "publicKey": result["PublicKey"]}
    signing_key(pin)
    return pin


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export the public key of an immutable P-256 KMS signing key.")
    parser.add_argument("key_arn")
    parser.add_argument("--sec1", action="store_true", help="output the uncompressed public key as lowercase hex")
    args = parser.parse_args()
    try:
        key = get_signing_key(args.key_arn)
        print(signing_sec1(key) if args.sec1 else canonical(key).decode())
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error)) from None
