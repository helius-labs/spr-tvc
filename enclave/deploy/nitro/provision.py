"""Forward KMS recipient ciphertexts from a 3-of-6 custody set into a measured SPR Nitro enclave."""

import argparse
import base64
import errno
import hashlib
import http.client
import socket
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from time import monotonic, sleep

from approval import KEY_ARN, ROLE_ARN, InvalidAwsResponse, arn, aws, fields, hex_digest, open_regular, parse_json, read_document
from custody_ledger import target_fields
from kms_policy import RSA_CIPHERTEXT_BYTES
from operator_http import HTTP_TIMEOUT, request_bytes
from relay import MAX_EVIDENCE, InvalidRecipientResponse, decrypt_recipient

THRESHOLD = 3
SHARE_COUNT = 6
RECIPIENT_WAIT_SECONDS = 20


def request(cid, method, path, body=None, limit=MAX_EVIDENCE, *, deadline=None):
    return request_bytes(socket.AF_VSOCK, (cid, 44031), method, path, body, limit, deadline=deadline)


def recipient_for(cid):
    deadline = monotonic() + RECIPIENT_WAIT_SECONDS
    while (now := monotonic()) < deadline:
        try:
            status, evidence = request(cid, "GET", "/recipient", deadline=min(deadline, now + HTTP_TIMEOUT))
        except OSError as error:
            if not isinstance(error, (ConnectionError, TimeoutError)) and error.errno not in {errno.ENODEV, errno.ENOTCONN}:
                raise
        except http.client.HTTPException as error:
            raise ValueError("invalid HTTP response from the enclave recipient") from error
        else:
            if monotonic() >= deadline:
                break
            if status == 200 and 1 <= len(evidence) <= MAX_EVIDENCE:
                return evidence
            if status not in {429, 503}:
                raise ValueError(f"invalid recipient evidence from HTTP {status}")
        remaining = deadline - monotonic()
        if remaining > 0:
            sleep(min(0.25, remaining))
    raise ValueError("enclave recipient did not become ready within its deadline")


def read_target(path, expected_digest):
    payload = read_document(path)
    if hashlib.sha256(payload).hexdigest() != hex_digest(expected_digest):
        raise ValueError("target file does not match the independently pinned digest")
    document = parse_json(payload)
    fields(document, "manifest", "signatures")
    target_fields(document["manifest"])
    return document["manifest"]


def require_host_identity(manifest):
    role = manifest["hostRole"]
    account = arn(ROLE_ARN, role)[1]
    role_name = role.rsplit("/", 1)[-1]
    identity = aws(manifest["hostRegion"], "sts", "get-caller-identity", [])
    caller = identity.get("Arn")
    if (identity.get("Account") != account or not isinstance(caller, str) or
            not caller.startswith(f"arn:aws:sts::{account}:assumed-role/{role_name}/") or
            caller.count("/") != 2 or caller.endswith("/")):
        raise ValueError("parent AWS credentials must use the approved host role")


class UnconfirmedBootstrap(ValueError):
    def __init__(self, reason):
        super().__init__(f"could not confirm seed restoration ({reason}). "
                         "Verify serving attestation or the rotation receipt before restarting")


class InsufficientShares(ValueError):
    """Fewer than three KMS envelopes are available."""


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
    selected = [(slot, keys[slot - 1], directory / f"{slot}.kms")
                for slot in (available_slots if slots is None else sorted(slots))]
    recipient = recipient_for(cid)

    def unwrap(entry):
        slot, key, blob = entry
        try:
            with open_regular(blob) as source:
                ciphertext = source.read(max(RSA_CIPHERTEXT_BYTES) + 1)
            if len(ciphertext) not in RSA_CIPHERTEXT_BYTES:
                return None
            return decrypt_recipient(key, base64.b64encode(ciphertext).decode(), recipient)
        except (InvalidAwsResponse, InvalidRecipientResponse) as error:
            raise InvalidRecipientResponse(f"invalid recipient reply for custody slot {slot}: {error}") from error
        except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
            return None

    with ThreadPoolExecutor(max_workers=len(selected)) as workers:
        shares = [(entry[0], share) for entry, share in zip(selected, workers.map(unwrap, selected), strict=True)
                  if share is not None]
    submitted = [slot for slot, _ in shares]
    if len(shares) < THRESHOLD:
        raise InsufficientShares(f"KMS returned fewer than three share envelopes; successful slots: {submitted}")
    frame = b"".join(struct.pack(">BH", slot, len(share)) + share for slot, share in shares)
    deadline = monotonic() + HTTP_TIMEOUT
    try:
        while monotonic() < deadline:
            status, body = request(cid, "POST", "/shares", frame, limit=THRESHOLD, deadline=deadline)
            if status != 429:
                break
            # The enclave returns 429 before it processes any shares.
            remaining = deadline - monotonic()
            if remaining > 0:
                sleep(min(0.25, remaining))
        else:
            raise ValueError("enclave remained busy until the share submission deadline")
    except (OSError, http.client.HTTPException) as error:
        raise UnconfirmedBootstrap("no complete acknowledgement") from error
    if status == 400:
        raise ValueError("enclave refused the shares with HTTP 400")
    if status != 200:
        raise UnconfirmedBootstrap(f"HTTP {status}")
    accepted = set(body)
    if len(body) != THRESHOLD or len(accepted) != THRESHOLD or not accepted.issubset(submitted):
        raise UnconfirmedBootstrap("invalid enclave acknowledgement of custody slots")
    return list(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cid", type=int)
    parser.add_argument("target", type=Path)
    parser.add_argument("--target-sha256", required=True)
    parser.add_argument("--slots", type=int, nargs=THRESHOLD, choices=range(1, SHARE_COUNT + 1))
    args = parser.parse_args()
    try:
        target = read_target(args.target, args.target_sha256)
        try:
            slots = provision(args.cid, target, args.target.parent / "shares", args.slots)
        except InsufficientShares as unavailable:
            try:
                require_host_identity(target)
            except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as identity:
                raise ValueError(f"{unavailable}. {identity}") from identity
            raise
        print(f"enclave acknowledged custody slots {slots}")
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
