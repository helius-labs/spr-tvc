"""Exchange ciphertext and Nitro evidence with the pinned custody relay."""

import base64
import hashlib
import http.client
import json
import secrets
import socket
import subprocess
from pathlib import Path

from approval import (
    ROLE_ARN, approval_keys, arn, canonical, epoch_number, fields, hex_digest, key_result, kms, parse_json, read_document,
    require_kms_key, signing_sec1,
)
from kms_policy import RSA_KEYS, RSA_OAEP, boot_pins, recovery_policy
from operator_http import request_bytes
from provenance import verify as verify_build

MAX_EVIDENCE = 16_384
MAX_CMS = 6_144


def relay_pins(trust, epoch):
    epoch_number(epoch)
    scope = trust.get("recoveryRelays", {}).get(epoch)
    if scope is None:
        raise ValueError("custody epoch requires a pinned recovery relay")
    fields(scope, "hostRole", "pcrs")
    arn(ROLE_ARN, scope["hostRole"])
    fields(scope["pcrs"], "PCR0", "PCR1", "PCR2")
    for pin in scope["pcrs"].values():
        hex_digest(pin, 48)
    return scope


def verify_relay_build(trust, epoch, build, review):
    scope = relay_pins(trust, epoch)
    build = Path(build)
    configuration = read_document(build / "configuration.json")
    config = parse_json(configuration)
    fields(config, "releaseId", "securityDomainId", "deployment")
    expected = {
        "mode": "relay", "custodyEpoch": epoch,
        "approvalKeys": [signing_sec1(key) for key in approval_keys(trust, epoch)],
    }
    if config["securityDomainId"] != trust["securityDomainId"] or config["deployment"] != expected:
        raise ValueError("relay configuration does not match the pinned custody domain, epoch and approval roster")
    reviewed = verify_build(build, trust["network"], review)
    if (reviewed["pcrs"] != scope["pcrs"] or
            reviewed["configurationSha256"] != hashlib.sha256(configuration).hexdigest()):
        raise ValueError("relay pins or configuration do not match the reviewed build provenance")


def relay_request(port, path, body, limit):
    if not 1 <= port <= 65535:
        raise ValueError("invalid local relay port")
    try:
        status, data = request_bytes(socket.AF_INET, ("127.0.0.1", port), "POST", path, body, limit)
    except http.client.HTTPException as error:
        raise ValueError(f"invalid HTTP response from relay {path}") from error
    if status != 200 or not 1 <= len(data) <= limit:
        raise ValueError(f"relay refused {path} or returned an invalid body (HTTP {status})")
    return data


def verify_evidence(nonce, evidence, scope, binding=None):
    pcrs = {name.removeprefix("PCR"): pin for name, pin in boot_pins(scope["hostRole"], scope["pcrs"]).items()}
    root = Path(__file__).resolve().parents[3]
    request = {"nonce": nonce.hex(), "evidence": evidence.hex(), "pcrs": pcrs}
    mode = "recipient"
    if binding is not None:
        request["binding"] = binding
        mode = "proof"
    result = subprocess.run([
        "pnpm", "--dir", str(root / "example"), "exec", "tsx", str(root / "xtask/nitro-relay.ts"), mode,
    ], input=canonical(request), stdout=subprocess.PIPE, timeout=25, check=True)
    if mode == "recipient":
        return hex_digest(result.stdout.decode())



def live_recipient(port, scope):
    nonce = secrets.token_bytes(32)
    evidence = relay_request(port, "/recipient", nonce, MAX_EVIDENCE)
    return verify_evidence(nonce, evidence, scope), evidence


def inspect_rsa_key(arn, **options):
    metadata = kms(arn, "describe-key", **options)["KeyMetadata"]
    require_kms_key(metadata, arn, RSA_KEYS, "ENCRYPT_DECRYPT")
    policy = parse_json(kms(arn, "get-key-policy", ["--policy-name", "default"], **options)["Policy"])
    return metadata, policy


def sealed_rsa_key(arn, expected, **options):
    metadata, policy = inspect_rsa_key(arn, **options)
    if policy != expected:
        raise ValueError("installed RSA key policy does not match its pinned recipient")
    result = key_result(arn, "get-public-key", **options)
    if (result.get("KeySpec") != metadata["KeySpec"] or result.get("KeyUsage") != "ENCRYPT_DECRYPT" or
            RSA_OAEP not in result.get("EncryptionAlgorithms", [])):
        raise ValueError("unexpected RSA key usage or algorithm")
    spki = base64.b64decode(result["PublicKey"], validate=True)
    if not 256 <= len(spki) <= 600:
        raise ValueError("unexpected RSA public key length")
    return spki


def custody_recovery_policy(trust, custodian, epoch):
    scope = relay_pins(trust, epoch)
    return recovery_policy(custodian["custodianRole"], custodian["retirementRole"], scope["hostRole"], scope["pcrs"], epoch)


class InvalidRecipientResponse(ValueError):
    """KMS returned a response outside the attested decryption contract."""


def decrypt_recipient(key, ciphertext, evidence):
    result = kms(key, "decrypt", [
        "--encryption-algorithm", RSA_OAEP, "--ciphertext-blob", ciphertext,
        "--recipient", json.dumps({"KeyEncryptionAlgorithm": RSA_OAEP,
                                   "AttestationDocument": base64.b64encode(evidence).decode()}),
    ])
    if result.get("KeyId") != key or result.get("EncryptionAlgorithm") != RSA_OAEP:
        raise InvalidRecipientResponse("unexpected KMS recipient key or decryption algorithm")
    if result.get("Plaintext") not in (None, ""):
        raise InvalidRecipientResponse("unexpected plaintext in attested KMS response")
    try:
        envelope = base64.b64decode(result["CiphertextForRecipient"], validate=True)
    except (KeyError, TypeError, ValueError) as error:
        raise InvalidRecipientResponse("invalid KMS recipient envelope encoding") from error
    if not 1 <= len(envelope) <= MAX_CMS:
        raise InvalidRecipientResponse("invalid KMS recipient envelope length")
    return envelope


def recover_to_relay(trust, receipt, custodian, index, evidence, before_decrypt):
    epoch = receipt["custody"]["epoch"]
    expected = custody_recovery_policy(trust, custodian, epoch)
    key = custodian["recoveryKeyArn"]
    spki = sealed_rsa_key(key, expected)
    package = receipt["packages"][index - 1]
    if hashlib.sha256(spki).hexdigest() != package["recipientSha256"]:
        raise ValueError("recovery package does not match its RSA KMS key")
    before_decrypt()
    return decrypt_recipient(key, base64.b64encode(bytes.fromhex(package["ciphertext"])).decode(), evidence)


def prove_share(trust, receipt, custodian, index, port, require_authorized):
    epoch = receipt["custody"]["epoch"]
    scope = relay_pins(trust, epoch)
    key_id, evidence = live_recipient(port, scope)
    envelope = recover_to_relay(trust, receipt, custodian, index, evidence, require_authorized)
    require_authorized()
    nonce = secrets.token_bytes(32)
    commitment = receipt["custody"]["shareCommitments"][index - 1]
    binding = hashlib.sha256(b"SPR/native-nitro/relay-share-proof/v1" + trust["network"].encode() +
                             bytes.fromhex(receipt["securityDomainId"]) + int(epoch).to_bytes(8, "big") +
                             bytes([index]) + bytes.fromhex(commitment) + bytes.fromhex(key_id) +
                             hashlib.sha256(envelope).digest()).hexdigest()
    proof = relay_request(port, "/prove", canonical({"slot": index, "shareCommitment": commitment,
                                                     "envelope": envelope.hex(), "nonce": nonce.hex()}), MAX_EVIDENCE)
    verify_evidence(nonce, proof, scope, binding=binding)
