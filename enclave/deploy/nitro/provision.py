"""Forward KMS recipient ciphertexts from a 3-of-6 custody set into a measured SPR Nitro enclave."""

import argparse
import base64
import http.client
import json
import re
import socket
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from kms_policy import context

MAX_ENVELOPE = 6144
MAX_EVIDENCE = 16384
KEY_ARN = re.compile(r"arn:aws:kms:([a-z0-9-]+):([0-9]{12}):key/[0-9a-f-]{36}")


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
    envelope = json.loads(result.stdout)
    if envelope.get("Plaintext") or envelope.get("KeyId") != arn:
        raise ValueError("unexpected KMS decrypt response")
    ciphertext = base64.b64decode(envelope["CiphertextForRecipient"], validate=True)
    if not 1 <= len(ciphertext) <= MAX_ENVELOPE:
        raise ValueError("invalid KMS recipient envelope length")
    return ciphertext


def provision(cid, network, domain, release, epoch, keys):
    matches = [KEY_ARN.fullmatch(arn) for arn, _ in keys]
    if len(matches) != 6 or any(match is None for match in matches) or len({match[2] for match in matches}) != 6:
        raise ValueError("expected six immutable KMS key ARNs in six different AWS accounts")
    contexts = [context(network, domain, release, epoch, index) for index in range(1, 7)]
    status, evidence = request(cid, "GET", "/recipient")
    if status != 200 or not 1 <= len(evidence) <= MAX_EVIDENCE:
        raise ValueError(f"recipient evidence failed with HTTP {status}")
    recipient = json.dumps({
        "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
        "AttestationDocument": base64.b64encode(evidence).decode("ascii"),
    })

    def unwrap(entry):
        (arn, blob), ctx = entry
        try:
            return decrypt_share(arn, blob, recipient, ctx)
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
            return None

    with ThreadPoolExecutor(max_workers=6) as workers:
        shares = tuple(share for share in workers.map(unwrap, zip(keys, contexts)) if share is not None)
    if len(shares) < 3:
        raise ValueError("KMS returned fewer than three share envelopes")
    frame = b"".join(struct.pack(">H", len(share)) + share for share in shares)
    status, _ = request(cid, "POST", "/shares", frame)
    if status != 204:
        raise ValueError(f"enclave refused the shares with HTTP {status}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cid", type=int)
    parser.add_argument("network", choices=["devnet", "mainnet"])
    parser.add_argument("security_domain")
    parser.add_argument("release")
    parser.add_argument("keys", type=Path)
    args = parser.parse_args()
    try:
        plan = json.loads(args.keys.read_text())
        keys = [(entry["keyArn"], args.keys.parent / entry["ciphertext"]) for entry in plan["keys"]]
        provision(args.cid, args.network, args.security_domain, args.release, plan["epoch"], keys)
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
