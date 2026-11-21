import subprocess
import tempfile
from base64 import b64encode
from functools import cache
from pathlib import Path

from approval import approval_message

DOMAIN = "ab" * 32
HOST = "arn:aws:iam::000000000007:role/host"


def key(account, slot=1):
    return f"arn:aws:kms:eu-north-1:{account:012}:key/12345678-1234-1234-1234-{slot:012}"


def openssl(*args, body=None):
    return subprocess.run(["openssl", *args], input=body, capture_output=True, timeout=10, check=True).stdout


@cache
def keypair(identity):
    private = openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1")
    public = openssl("pkey", "-pubout", "-outform", "DER", body=private)
    return private, b64encode(public).decode()


def pin(identity):
    return {"keyArn": identity, "publicKey": keypair(identity)[1]}


def sign(label, manifest, identity):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "fixture.pem"
        path.write_bytes(keypair(identity)[0])
        signature = openssl("dgst", "-sha256", "-sign", str(path), body=approval_message(label, manifest))
    return {"keyArn": identity, "signature": b64encode(signature).decode()}


def schedule(epoch="1", slot=7):
    return {"fromEpoch": epoch, "keys": [pin(key(account, slot)) for account in (8, 9, 10)]}
