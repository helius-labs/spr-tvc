"""Sign, publish and read one authenticated custody receipt per epoch."""

import argparse
import base64
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path

from approval import (
    KEY_ARN, ROLE_ARN, MAX_DOCUMENT_BYTES, add_approval, approval_keys, arn, aws, canonical, check_approvals,
    fields, file_digest, hex_digest, key_result, kms, parse_json, read_json, sha256,
)
from kms_policy import acknowledgement_policy, context, recovery_policy, validate_custodian_roles
from provenance import verify as verify_build

LABEL = "custody-epoch"
ACKNOWLEDGEMENT = "custodian-acknowledgement"


def record(trust, document):
    fields(document, "authorization", "acknowledgements")
    authorization = document["authorization"]
    fields(authorization, "manifest", "signatures")
    manifest = authorization["manifest"]
    fields(manifest, "capture", "ceremonyEifSha256", "ceremonyHostRole", "custodians", "previousReceiptSha256")
    hex_digest(manifest["ceremonyEifSha256"])
    capture = manifest["capture"]
    fields(capture, "receipt", "evidence", "nonce", "verifiedAtMs", "configuration", "pcrs")
    receipt = capture["receipt"]
    fields(receipt, "network", "securityDomainId", "releaseId", "custody", "packages")
    network, domain, release = receipt["network"], receipt["securityDomainId"], receipt["releaseId"]
    if (network, domain) != (trust["network"], trust["securityDomainId"]):
        raise ValueError("custody receipt is outside the pinned security domain")
    custody = receipt["custody"]
    fields(custody, "epoch", "noteSeedCommitment", "shareCommitments")
    epoch = custody["epoch"]
    context(network, domain, release, epoch, 1)
    previous = manifest["previousReceiptSha256"]
    if epoch == "1":
        if previous is not None:
            raise ValueError("genesis cannot name a predecessor")
    else:
        hex_digest(previous)
    custodians = manifest["custodians"]
    validate_roster(custodians, manifest["ceremonyHostRole"])
    if not isinstance(receipt["packages"], list) or len(receipt["packages"]) != 6:
        raise ValueError("custody requires six recovery packages")
    return receipt, custodians


def validate_roster(custodians, host):
    accounts = {arn(ROLE_ARN, host)[1]}
    if not isinstance(custodians, list) or len(custodians) != 6:
        raise ValueError("custody requires six recovery accounts")
    for custodian in custodians:
        fields(custodian, "recoveryKeyArn", "acknowledgementKeyArn", "custodianRole", "retirementRole")
        recovery, acknowledgement = custodian["recoveryKeyArn"], custodian["acknowledgementKeyArn"]
        account = arn(KEY_ARN, recovery)[2]
        if (account in accounts or recovery == acknowledgement or arn(KEY_ARN, acknowledgement)[2] != account or
                arn(ROLE_ARN, custodian["custodianRole"])[1] != account):
            raise ValueError("custody requires distinct accounts and a separate acknowledgment key per custodian")
        validate_custodian_roles(custodian["custodianRole"], custodian["retirementRole"])
        accounts.add(account)


def ledger_prefix(trust):
    ledger = trust["ledger"]
    fields(ledger, "bucket", "account", "region")
    if not (re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", ledger["bucket"]) and
            re.fullmatch(r"[0-9]{12}", ledger["account"]) and re.fullmatch(r"[a-z0-9-]+", ledger["region"])):
        raise ValueError("expected pinned custody bucket, AWS account and region")
    network, domain = trust["network"], trust["securityDomainId"]
    context(network, domain, "custody", "1", 1)
    return ledger, f"spr-custody/{network}/{domain}/"


def ledger_object(trust, epoch):
    ledger, prefix = ledger_prefix(trust)
    context(trust["network"], trust["securityDomainId"], "custody", epoch, 1)
    return ledger["region"], ["--bucket", ledger["bucket"], "--expected-bucket-owner", ledger["account"],
                               "--key", f"{prefix}{epoch}.json"]


def ledger_policy(trust, publisher, readers):
    ledger, prefix = ledger_prefix(trust)
    if arn(ROLE_ARN, publisher)[1] != ledger["account"]:
        raise ValueError("publisher must be a dedicated role in the custody ledger account")
    for reader in readers:
        arn(ROLE_ARN, reader)
    resource = f"arn:aws:s3:::{ledger['bucket']}/{prefix}*"
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "RequireWriteOnce", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
         "Resource": resource, "Condition": {"StringNotEquals": {"s3:if-none-match": "*"}}},
        {"Sid": "RestrictPublisher", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
         "Resource": resource, "Condition": {"StringNotEquals": {"aws:PrincipalArn": publisher}}},
        {"Sid": "PreserveCustodyHistory", "Effect": "Deny", "Principal": "*", "Resource": resource,
         "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:ReplicateObject", "s3:ReplicateDelete"]},
        {"Sid": "AllowPublisher", "Effect": "Allow", "Principal": {"AWS": publisher},
         "Action": "s3:PutObject", "Resource": resource},
        {"Sid": "AllowReaders", "Effect": "Allow", "Principal": {"AWS": sorted(set([publisher, *readers]))},
         "Action": "s3:GetObject", "Resource": resource},
    ]}


def load_epoch(trust, epoch):
    region, args = ledger_object(trust, epoch)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "custody.json"
        aws(region, "s3api", "get-object", [*args, "--range", f"bytes=0-{MAX_DOCUMENT_BYTES}", str(path)])
        document = read_json(path)
    receipt, custodians = record(trust, document)
    if receipt["custody"]["epoch"] != epoch:
        raise ValueError("canonical custody receipt belongs to another epoch")
    check_commit(trust, document, custodians)
    return document, receipt, custodians


def acknowledgements(document):
    return {"manifest": document["authorization"]["manifest"], "signatures": document["acknowledgements"]}


def check_commit(trust, document, custodians):
    check_approvals(approval_keys(trust), LABEL, document["authorization"])
    check_approvals([custodian["acknowledgementKeyArn"] for custodian in custodians],
                    ACKNOWLEDGEMENT, acknowledgements(document), minimum=6)


def draft(trust, capture, build, host, roster):
    epoch = int(capture["receipt"]["custody"]["epoch"])
    previous = None if epoch == 1 else sha256(load_epoch(trust, str(epoch - 1))[1])
    document = {"authorization": {"manifest": {
        "capture": capture, "ceremonyEifSha256": file_digest(build / "enclave.eif"), "ceremonyHostRole": host,
        "custodians": roster, "previousReceiptSha256": previous,
    }, "signatures": []}, "acknowledgements": []}
    record(trust, document)
    return document


def check_previous(trust, document, receipt):
    epoch = int(receipt["custody"]["epoch"])
    if epoch == 1:
        return
    _, predecessor, previous_roster = load_epoch(trust, str(epoch - 1))
    manifest = document["authorization"]["manifest"]
    if (sha256(predecessor) != manifest["previousReceiptSha256"] or
            predecessor["custody"]["noteSeedCommitment"] != receipt["custody"]["noteSeedCommitment"] or
            predecessor["custody"] != manifest["capture"]["configuration"]["deployment"]["previous"]):
        raise ValueError("custody rotation does not descend from the canonical previous receipt")
    previous_keys = {custodian["recoveryKeyArn"] for custodian in previous_roster}
    if previous_keys & {custodian["recoveryKeyArn"] for custodian in manifest["custodians"]}:
        raise ValueError("custody rotation requires fresh recovery keys")


def check_recovery_key(key, expected_fingerprint):
    public = key_result(key, "get-public-key")
    fingerprint = hashlib.sha256(base64.b64decode(public["PublicKey"], validate=True)).hexdigest()
    if (public.get("KeyUsage") != "ENCRYPT_DECRYPT" or public.get("KeySpec") not in {"RSA_2048", "RSA_3072", "RSA_4096"} or
            "RSAES_OAEP_SHA_256" not in public.get("EncryptionAlgorithms", []) or fingerprint != expected_fingerprint):
        raise ValueError("recovery key does not match its recovery package")


def open_share(custodian, receipt, index):
    key = custodian["recoveryKeyArn"]
    package = receipt["packages"][index - 1]
    custody = receipt["custody"]
    expected = recovery_policy(custodian["custodianRole"], custodian["retirementRole"], custody["epoch"])
    installed = parse_json(kms(key, "get-key-policy", ["--policy-name", "default"])["Policy"])
    if installed != expected:
        raise ValueError("installed recovery key policy does not match the custodian role")
    check_recovery_key(key, package["recipientSha256"])
    capsule = base64.b64encode(bytes.fromhex(package["ciphertext"])).decode()
    share = base64.b64decode(key_result(key, "decrypt", [
        "--encryption-algorithm", "RSAES_OAEP_SHA_256", "--ciphertext-blob", capsule,
    ])["Plaintext"], validate=True)
    if len(share) != 41 or int.from_bytes(share[:8], "big") != int(custody["epoch"]) or share[8] != index:
        raise ValueError("share identity does not match the custody epoch and slot")
    commitment = hashlib.sha256(
        b"SPR/native-nitro/custody-share/v1" + bytes.fromhex(receipt["securityDomainId"]) + share,
    ).hexdigest()
    if commitment != custody["shareCommitments"][index - 1]:
        raise ValueError("decrypted share does not match the verified receipt")
    return share


def sign_epoch(trust, document, key, build, source_commit):
    receipt, custodians = record(trust, document)
    check_previous(trust, document, receipt)
    authorization = document["authorization"]
    manifest = authorization["manifest"]
    capture = manifest["capture"]
    build_pins = read_json(build / "measurements.json")["Measurements"]
    pins = {str(index): build_pins[f"PCR{index}"] for index in range(3)}
    pins["3"] = hashlib.sha384(bytes(48) + manifest["ceremonyHostRole"].encode()).hexdigest()
    if (capture["configuration"] != read_json(build / "configuration.json") or capture["pcrs"] != pins or
            manifest["ceremonyEifSha256"] != file_digest(build / "enclave.eif")):
        raise ValueError("captured ceremony does not match the reviewed build")
    verify_build(build, receipt["network"], source_commit)
    root = Path(__file__).resolve().parents[3]
    subprocess.run(["pnpm", "--dir", str(root / "example"), "exec", "tsx",
                    str(root / "xtask/nitro-ceremony.ts"), "verify"],
                   input=canonical(capture), timeout=25, check=True)
    for custodian, package in zip(custodians, receipt["packages"], strict=True):
        check_recovery_key(custodian["recoveryKeyArn"], package["recipientSha256"])
    return {**document, "authorization": add_approval(approval_keys(trust), LABEL, authorization, key)}


def acknowledge(trust, document, index):
    receipt, custodians = record(trust, document)
    check_approvals(approval_keys(trust), LABEL, document["authorization"])
    check_previous(trust, document, receipt)
    if index not in range(1, 7):
        raise ValueError("invalid custody slot")
    custodian = custodians[index - 1]
    key = custodian["acknowledgementKeyArn"]
    expected = acknowledgement_policy(custodian["custodianRole"], custodian["retirementRole"])
    if parse_json(kms(key, "get-key-policy", ["--policy-name", "default"])["Policy"]) != expected:
        raise ValueError("installed acknowledgement policy does not match the custodian role")
    open_share(custodian, receipt, index)
    keys = [member["acknowledgementKeyArn"] for member in custodians]
    approved = add_approval(keys, ACKNOWLEDGEMENT, acknowledgements(document), key)
    return {**document, "acknowledgements": approved["signatures"]}


def publish(trust, document):
    receipt, custodians = record(trust, document)
    check_commit(trust, document, custodians)
    check_previous(trust, document, receipt)
    epoch = receipt["custody"]["epoch"]
    region, args = ledger_object(trust, epoch)
    payload = canonical(document) + b"\n"
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise ValueError("custody receipt exceeds the ledger size limit")
    try:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custody.json"
            path.write_bytes(payload)
            aws(region, "s3api", "put-object", [*args, "--if-none-match", "*", "--body", str(path)])
    except (ValueError, subprocess.TimeoutExpired):
        # Resolve concurrent publication and ambiguous network failures by reading the winner.
        committed, _, _ = load_epoch(trust, epoch)
        if committed["authorization"]["manifest"] != document["authorization"]["manifest"]:
            raise ValueError("a different custody receipt is already committed for this epoch") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trust", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("draft")
    prepare.add_argument("capture", type=Path)
    prepare.add_argument("build", type=Path)
    prepare.add_argument("host_role")
    prepare.add_argument("roster", type=Path)
    sign = commands.add_parser("sign")
    sign.add_argument("candidate", type=Path)
    sign.add_argument("build", type=Path)
    sign.add_argument("key")
    sign.add_argument("output", type=Path)
    sign.add_argument("--source-commit", required=True)
    ack = commands.add_parser("acknowledge")
    ack.add_argument("candidate", type=Path)
    ack.add_argument("share", type=int, choices=range(1, 7))
    ack.add_argument("output", type=Path)
    post = commands.add_parser("publish")
    post.add_argument("candidate", type=Path)
    get = commands.add_parser("read")
    get.add_argument("epoch")
    policy = commands.add_parser("policy")
    policy.add_argument("publisher")
    policy.add_argument("readers", nargs="+")
    recovery = commands.add_parser("recovery-policy")
    recovery.add_argument("custodian_role")
    recovery.add_argument("retirement_role")
    recovery.add_argument("epoch")
    acknowledgement = commands.add_parser("acknowledgement-policy")
    acknowledgement.add_argument("custodian_role")
    acknowledgement.add_argument("retirement_role")
    args = parser.parse_args()
    try:
        trust = read_json(args.trust)
        if args.command == "policy":
            print(canonical(ledger_policy(trust, args.publisher, args.readers)).decode())
            return
        if args.command == "recovery-policy":
            print(canonical(recovery_policy(args.custodian_role, args.retirement_role, args.epoch)).decode())
            return
        if args.command == "acknowledgement-policy":
            print(canonical(acknowledgement_policy(args.custodian_role, args.retirement_role)).decode())
            return
        if args.command == "draft":
            document = draft(trust, read_json(args.capture), args.build, args.host_role, read_json(args.roster))
            print(canonical(document).decode())
            return
        if args.command == "read":
            _, receipt, _ = load_epoch(trust, args.epoch)
            print(canonical(receipt).decode())
            return
        document = read_json(args.candidate)
        if args.command == "publish":
            publish(trust, document)
            return
        signed = (sign_epoch(trust, document, args.key, args.build, args.source_commit) if args.command == "sign"
                  else acknowledge(trust, document, args.share))
        with args.output.open("xb") as output:
            output.write(canonical(signed) + b"\n")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
