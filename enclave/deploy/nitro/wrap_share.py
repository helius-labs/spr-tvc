"""Rewrap one share from an independently verified custody receipt."""

import argparse
import base64
import hashlib
import json
import subprocess
from pathlib import Path

from kms_policy import context
from provision import KEY_ARN


def kms(key, operation, arguments=(), plaintext=None):
    region = KEY_ARN.fullmatch(key)[1]
    reply = subprocess.run([
        "aws", "--region", region, "--no-cli-pager", "--output", "json", "kms", operation,
        "--key-id", key, "--cli-binary-format", "base64", *arguments,
    ], input=plaintext, capture_output=True, timeout=25, check=False)
    if reply.returncode:
        raise ValueError(f"KMS {operation} failed")
    result = json.loads(reply.stdout)
    if result.get("KeyId") != key:
        raise ValueError(f"unexpected KMS key for {operation}")
    return result


def wrap(receipt, index, recovery_key, wrapping_key, release):
    recovery = KEY_ARN.fullmatch(recovery_key)
    wrapper = KEY_ARN.fullmatch(wrapping_key)
    if not recovery or not wrapper or recovery[2] != wrapper[2] or recovery_key == wrapping_key:
        raise ValueError("use two immutable KMS keys in the same custodian account")
    custody = receipt["custody"]
    domain = receipt["securityDomainId"]
    epoch = custody["epoch"]
    ctx = context(receipt["network"], domain, release, epoch, index)
    package = receipt["packages"][index - 1]
    public = base64.b64decode(kms(recovery_key, "get-public-key")["PublicKey"], validate=True)
    if hashlib.sha256(public).hexdigest() != package["recipientSha256"]:
        raise ValueError("custodian key does not match the verified receipt")

    capsule = base64.b64encode(bytes.fromhex(package["ciphertext"])).decode()
    plaintext = base64.b64decode(kms(recovery_key, "decrypt", [
        "--encryption-algorithm", "RSAES_OAEP_SHA_256", "--ciphertext-blob", capsule,
    ])["Plaintext"], validate=True)
    if len(plaintext) != 41 or int.from_bytes(plaintext[:8], "big") != int(epoch) or plaintext[8] != index:
        raise ValueError("share identity does not match the custody epoch and slot")
    committed = hashlib.sha256(b"SPR/native-nitro/custody-share/v1" + bytes.fromhex(domain) + plaintext)
    if committed.hexdigest() != custody["shareCommitments"][index - 1]:
        raise ValueError("decrypted share does not match the verified receipt")
    return base64.b64decode(kms(wrapping_key, "encrypt", [
        "--plaintext", "fileb:///dev/stdin", "--encryption-context", json.dumps(ctx),
    ], plaintext)["CiphertextBlob"], validate=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("verified_receipt", type=Path)
    parser.add_argument("share", type=int, choices=range(1, 7))
    parser.add_argument("recovery_key")
    parser.add_argument("wrapping_key")
    parser.add_argument("release")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        receipt = json.loads(args.verified_receipt.read_text())
        ciphertext = wrap(receipt, args.share, args.recovery_key, args.wrapping_key, args.release)
        with args.output.open("xb") as output:
            output.write(ciphertext)
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
