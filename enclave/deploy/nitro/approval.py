"""Canonical operator documents and KMS-backed custody approvals."""

import base64
import hashlib
import json
import re
import subprocess

KEY_ARN = re.compile(r"arn:aws:kms:([a-z0-9-]+):([0-9]{12}):key/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
ROLE_ARN = re.compile(r"arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+")
SIGNING_ALGORITHM = "ECDSA_SHA_256"
MAX_DOCUMENT_BYTES = 64 * 1024


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


def read_json(path):
    with path.open("rb") as source:
        return parse_json(source.read(MAX_DOCUMENT_BYTES + 1))


def canonical(value):
    # Operator documents use ASCII field names and strings. No floating point fields.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def sha256(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_digest(path):
    with path.open("rb") as source:
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


def aws(region, service, operation, arguments, body=None):
    reply = subprocess.run([
        "aws", "--region", region, "--no-cli-pager", "--output", "json", service, operation, *arguments,
    ], input=body, capture_output=True, timeout=25, check=False)
    if reply.returncode:
        raise ValueError(f"AWS {service} {operation} failed")
    return parse_json(reply.stdout)


def kms(key, operation, arguments=(), body=None):
    return aws(arn(KEY_ARN, key)[1], "kms", operation,
               ["--key-id", key, "--cli-binary-format", "base64", *arguments], body)


def key_result(key, operation, arguments=(), body=None):
    result = kms(key, operation, arguments, body)
    if result.get("KeyId") != key:
        raise ValueError(f"unexpected KMS key for {operation}")
    return result


def approval_keys(trust):
    keys = trust["approvalKeys"]
    if not isinstance(keys, list) or len(keys) != 3 or len({arn(KEY_ARN, key)[2] for key in keys}) != 3:
        raise ValueError("expected three approval keys in independent AWS accounts")
    return keys


def signature_args(label, manifest):
    digest = hashlib.sha256(f"SPR/native-nitro/{label}/v1\0".encode() + canonical(manifest)).digest()
    return ["--signing-algorithm", SIGNING_ALGORITHM, "--message-type", "DIGEST",
            "--message", base64.b64encode(digest).decode()]


def check_approvals(keys, label, document, minimum=2):
    fields(document, "manifest", "signatures")
    signatures = document["signatures"]
    if not isinstance(signatures, list) or not minimum <= len(signatures) <= len(keys):
        raise ValueError("expected approvals from the pinned signing quorum")
    seen = set()
    args = signature_args(label, document["manifest"])
    for approval in signatures:
        fields(approval, "keyArn", "signature")
        key, signature = approval["keyArn"], approval["signature"]
        if key not in keys or key in seen or not isinstance(signature, str) or not 8 <= len(base64.b64decode(signature, validate=True)) <= 72:
            raise ValueError("invalid or duplicate approval")
        result = key_result(key, "verify", [*args, "--signature", signature])
        if result.get("SignatureValid") is not True or result.get("SigningAlgorithm") != SIGNING_ALGORITHM:
            raise ValueError("invalid custody approval signature")
        seen.add(key)


def add_approval(keys, label, document, key):
    if key not in keys or any(signature["keyArn"] == key for signature in document["signatures"]):
        raise ValueError("signing key is not pinned or already approved this document")
    check_approvals(keys, label, document, minimum=0)
    signature = key_result(key, "sign", signature_args(label, document["manifest"]))
    if signature.get("SigningAlgorithm") != SIGNING_ALGORITHM:
        raise ValueError("unexpected KMS signing algorithm")
    return {"manifest": document["manifest"], "signatures": [
        *document["signatures"], {"keyArn": key, "signature": signature["Signature"]},
    ]}
