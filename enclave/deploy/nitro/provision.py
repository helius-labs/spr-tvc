"""Forward KMS recipient ciphertexts from a 3-of-6 custody set into a measured SPR Nitro enclave."""

import argparse
import base64
import errno
import hashlib
import http.client
import json
import socket
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from time import monotonic, sleep

from approval import KEY_ARN, MAX_DOCUMENT_BYTES, ROLE_ARN, arn, fields, hex_digest, parse_json
from kms_policy import target_context

MAX_ENVELOPE = 6144
MAX_EVIDENCE = 16384
THRESHOLD = 3
SHARE_COUNT = 6
RECIPIENT_WAIT_SECONDS = 20


class BootstrapConnection(http.client.HTTPConnection):
    def __init__(self, cid):
        super().__init__("localhost", timeout=8)
        self.cid = cid

    def connect(self):
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.cid, 44031))


def request(cid, method, path, body=None, limit=MAX_EVIDENCE):
    conn = BootstrapConnection(cid)
    try:
        conn.request(method, path, body)
        with conn.getresponse() as response:
            return response.status, response.read(limit + 1)
    finally:
        conn.close()


def recipient_for(cid):
    deadline = monotonic() + RECIPIENT_WAIT_SECONDS
    while True:
        try:
            status, evidence = request(cid, "GET", "/recipient")
        except OSError as error:
            if not isinstance(error, (ConnectionError, TimeoutError)) and error.errno not in {errno.ENODEV, errno.ENOTCONN}:
                raise
        else:
            if status == 200 and 1 <= len(evidence) <= MAX_EVIDENCE:
                return json.dumps({
                    "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
                    "AttestationDocument": base64.b64encode(evidence).decode("ascii"),
                })
            if status not in {429, 503}:
                raise ValueError(f"invalid recipient evidence from HTTP {status}")
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise ValueError("enclave recipient did not become ready")
        sleep(min(0.25, remaining))


def decrypt_share(arn, wrapped_share, recipient, ctx):
    key = KEY_ARN.fullmatch(arn)
    if key is None:
        raise ValueError("expected immutable KMS key ARN")
    result = subprocess.run([
        "aws", "--region", key[1], "kms", "decrypt", "--key-id", arn,
        "--ciphertext-blob", f"fileb://{wrapped_share}",
        "--encryption-context", json.dumps(ctx), "--recipient", recipient,
        "--cli-binary-format", "base64", "--output", "json", "--no-cli-pager",
    ], capture_output=True, text=True, timeout=25)
    if result.returncode:
        if "AccessDeniedException" in result.stderr:
            raise ValueError("KMS denied the attested recipient")
        raise ValueError("attested KMS decrypt failed")
    envelope = parse_json(result.stdout)
    if not isinstance(envelope, dict) or envelope.get("Plaintext") not in (None, "") or envelope.get("KeyId") != arn:
        raise ValueError("unexpected KMS decrypt response")
    ciphertext = base64.b64decode(envelope["CiphertextForRecipient"], validate=True)
    if not 1 <= len(ciphertext) <= MAX_ENVELOPE:
        raise ValueError("invalid KMS recipient envelope length")
    return ciphertext


def read_target(path, expected_digest):
    with path.open("rb") as source:
        payload = source.read(MAX_DOCUMENT_BYTES + 1)
    if hashlib.sha256(payload).hexdigest() != hex_digest(expected_digest):
        raise ValueError("target file does not match the independently pinned digest")
    document = parse_json(payload)
    fields(document, "manifest", "signatures")
    return document["manifest"]


def provision(cid, manifest, directory, slots=None):
    keys = manifest["wrappingKeys"]
    if not isinstance(keys, list) or len(keys) != SHARE_COUNT:
        raise ValueError("expected six custody key ARNs in the approved target")
    accounts = {arn(KEY_ARN, key)[2] for key in keys}
    if len(accounts) != SHARE_COUNT or arn(ROLE_ARN, manifest["hostRole"])[1] in accounts:
        raise ValueError("expected six custody accounts separate from the enclave host")
    available_slots = range(1, SHARE_COUNT + 1)
    if slots is not None and (len(slots) != THRESHOLD or len(set(slots)) != THRESHOLD or
                              any(slot not in available_slots for slot in slots)):
        raise ValueError("select exactly three distinct custody slots")
    selected = [(slot, keys[slot - 1], directory / f"{slot}.kms", target_context(manifest, slot))
                for slot in (available_slots if slots is None else sorted(slots))]
    recipient = recipient_for(cid)

    def unwrap(entry):
        _, key, blob, ctx = entry
        try:
            return decrypt_share(key, blob, recipient, ctx)
        except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
            return None

    with ThreadPoolExecutor(max_workers=len(selected)) as workers:
        shares = [(entry[0], share) for entry, share in zip(selected, workers.map(unwrap, selected), strict=True)
                  if share is not None]
    submitted = [slot for slot, _ in shares]
    if len(shares) < THRESHOLD:
        raise ValueError(f"KMS returned fewer than three share envelopes; successful slots: {submitted}")
    frame = b"".join(struct.pack(">H", len(share)) + share for _, share in shares)
    status, _ = request(cid, "POST", "/shares", frame)
    if status != 204:
        raise ValueError(f"enclave refused the shares with HTTP {status}")
    return submitted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cid", type=int)
    parser.add_argument("target", type=Path)
    parser.add_argument("--target-sha256", required=True)
    parser.add_argument("--slots", type=int, nargs=THRESHOLD, choices=range(1, SHARE_COUNT + 1))
    args = parser.parse_args()
    try:
        target = read_target(args.target, args.target_sha256)
        slots = provision(args.cid, target, args.target.parent / "shares", args.slots)
        print(f"enclave accepted the batch from custody slots {slots}")
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
