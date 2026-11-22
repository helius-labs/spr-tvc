"""Exchange ciphertext and Nitro evidence with the pinned devnet custody relay."""

import base64
import hashlib
import http.client
import json
import secrets
import subprocess
from pathlib import Path

from approval import canonical, fields, hex_digest, key_result, kms, parse_json, require_kms_key
from kms_policy import RSA_OAEP, boot_pins, recovery_policy, relay_recovery_policy

MAX_EVIDENCE = 16_384
MAX_CMS = 6_144
RSA_KEYS = {"RSA_2048", "RSA_3072", "RSA_4096"}


def relay_pins(trust, epoch):
    if trust["network"] != "devnet":
        raise ValueError("the recovery relay trial requires devnet")
    scope = trust["recoveryRelays"][epoch]
    fields(scope, "hostRole", "pcrs")
    return scope


def relay_request(port, path, body, limit):
    if not 1 <= port <= 65535:
        raise ValueError("invalid local relay port")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    try:
        connection.request("POST", path, body, headers={"Content-Type": "application/octet-stream"})
        with connection.getresponse() as response:
            data = response.read(limit + 1)
            if response.status != 200 or not 1 <= len(data) <= limit:
                raise ValueError(f"relay refused {path} or returned an invalid body (HTTP {response.status})")
            return data
    finally:
        connection.close()


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


def sealed_rsa_key(arn, expected, **options):
    metadata = kms(arn, "describe-key", **options)["KeyMetadata"]
    require_kms_key(metadata, arn, RSA_KEYS, "ENCRYPT_DECRYPT")
    if parse_json(kms(arn, "get-key-policy", ["--policy-name", "default"], **options)["Policy"]) != expected:
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
    role, admin = custodian["custodianRole"], custodian["retirementRole"]
    if epoch not in trust.get("recoveryRelays", {}):
        return recovery_policy(role, admin, epoch)
    scope = relay_pins(trust, epoch)
    return relay_recovery_policy(role, admin, scope["hostRole"], scope["pcrs"], epoch)


def recover_to_relay(trust, receipt, custodian, index, evidence, before_decrypt):
    epoch = receipt["custody"]["epoch"]
    relay_pins(trust, epoch)  # Require a pinned relay. This path has no plaintext fallback.
    expected = custody_recovery_policy(trust, custodian, epoch)
    key = custodian["recoveryKeyArn"]
    spki = sealed_rsa_key(key, expected)
    package = receipt["packages"][index - 1]
    if hashlib.sha256(spki).hexdigest() != package["recipientSha256"]:
        raise ValueError("recovery package does not match its RSA KMS key")
    before_decrypt()
    result = key_result(key, "decrypt", [
        "--encryption-algorithm", RSA_OAEP,
        "--ciphertext-blob", base64.b64encode(bytes.fromhex(package["ciphertext"])).decode(),
        "--recipient", json.dumps({"KeyEncryptionAlgorithm": RSA_OAEP,
                                   "AttestationDocument": base64.b64encode(evidence).decode()}),
    ])
    if result.get("Plaintext") not in (None, ""):
        raise ValueError("unexpected plaintext in attested KMS response")
    ciphertext = base64.b64decode(result["CiphertextForRecipient"], validate=True)
    if not 1 <= len(ciphertext) <= MAX_CMS:
        raise ValueError("invalid KMS recipient envelope length")
    return ciphertext


def prove_share(trust, receipt, custodian, index, port, before_decrypt):
    epoch = receipt["custody"]["epoch"]
    scope = relay_pins(trust, epoch)
    _, evidence = live_recipient(port, scope)
    envelope = recover_to_relay(trust, receipt, custodian, index, evidence, before_decrypt)
    nonce = secrets.token_bytes(32)
    commitment = receipt["custody"]["shareCommitments"][index - 1]
    binding = hashlib.sha256(b"SPR/native-nitro/relay-share-proof/v1" + trust["network"].encode() +
                             bytes.fromhex(receipt["securityDomainId"]) + int(epoch).to_bytes(8, "big") +
                             bytes([index]) + bytes.fromhex(commitment)).hexdigest()
    proof = relay_request(port, "/prove", canonical({"slot": index, "shareCommitment": commitment,
                                                     "envelope": envelope.hex(), "nonce": nonce.hex()}), MAX_EVIDENCE)
    verify_evidence(nonce, proof, scope, binding=binding)
