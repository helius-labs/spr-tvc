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
    epoch_number, fields, file_digest, get_signing_key, hex_digest, key_result, kms, parse_json, read_json, require_kms_key,
    sha256, signing_key,
)
from kms_policy import acknowledgement_policy, context, recovery_policy, validate_custodian_roles
from provenance import MAIN_REF, verify as verify_build

LABEL = "custody-epoch"
ACKNOWLEDGEMENT = "custodian-acknowledgement"
RETIREMENT = "custody-retirement"
RECOVERY_SPECS = {"RSA_2048", "RSA_3072", "RSA_4096"}


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
    public_keys = set()
    if not isinstance(custodians, list) or len(custodians) != 6:
        raise ValueError("custody requires six recovery accounts")
    for custodian in custodians:
        fields(custodian, "recoveryKeyArn", "acknowledgementKey", "custodianRole", "retirementRole")
        ack = custodian["acknowledgementKey"]
        public = signing_key(ack)
        recovery, acknowledgement = custodian["recoveryKeyArn"], ack["keyArn"]
        account = arn(KEY_ARN, recovery)[2]
        if (public in public_keys or account in accounts or recovery == acknowledgement or arn(KEY_ARN, acknowledgement)[2] != account or
                arn(ROLE_ARN, custodian["custodianRole"])[1] != account):
            raise ValueError("custody requires distinct accounts and a separate acknowledgment key per custodian")
        validate_custodian_roles(custodian["custodianRole"], custodian["retirementRole"])
        accounts.add(account)
        public_keys.add(public)


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
    context(trust["network"], trust["securityDomainId"], "custody", epoch, 1)
    return f"{epoch}.json"


def retirement_object_name(epoch):
    epoch_number(epoch)
    return f"retired/{epoch}.json"


def storage(trust, operation, args):
    ledger, _ = ledger_prefix(trust)
    return aws(ledger["region"], "s3api", operation, [
        "--bucket", ledger["bucket"], "--expected-bucket-owner", ledger["account"], *args,
    ])


def read_object(trust, name):
    _, prefix = ledger_prefix(trust)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "record.json"
        storage(trust, "get-object", ["--key", prefix + name, "--range", f"bytes=0-{MAX_DOCUMENT_BYTES}", str(path)])
        return read_json(path)


def write_once(trust, name, document, subject):
    _, prefix = ledger_prefix(trust)
    payload = canonical(document) + b"\n"
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise ValueError("record exceeds the ledger size limit")
    try:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            path.write_bytes(payload)
            storage(trust, "put-object", ["--key", prefix + name, "--if-none-match", "*", "--body", str(path)])
    except (ValueError, subprocess.TimeoutExpired):
        # Resolve ambiguous writes by reading the authenticated immutable subject.
        if subject(read_object(trust, name)) != subject(document):
            raise ValueError("a different record is already committed") from None


def list_objects(trust, name):
    _, prefix = ledger_prefix(trust)
    args = ["--prefix", prefix + name, "--max-keys", "100", "--no-paginate"]
    while True:
        page = storage(trust, "list-objects-v2", args)
        for entry in page.get("Contents", []):
            object_key = entry["Key"]
            if not object_key.startswith(prefix + name):
                raise ValueError("ledger listed an object outside its prefix")
            yield object_key[len(prefix):]
        if not page.get("IsTruncated"):
            return
        args = [*args[:5], "--continuation-token", page["NextContinuationToken"]]


def ledger_reader_policy(trust):
    ledger, prefix = ledger_prefix(trust)
    bucket = f"arn:aws:s3:::{ledger['bucket']}"
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "ReadCustodyRecords", "Effect": "Allow", "Action": "s3:GetObject", "Resource": f"{bucket}/{prefix}*"},
        {"Sid": "ListCustodyTargetsAndRetirement", "Effect": "Allow", "Action": "s3:ListBucket", "Resource": bucket,
         "Condition": {"StringLike": {"s3:prefix": [f"{prefix}targets/*", f"{prefix}retired/*"]}}},
    ]}


def ledger_policy(trust, administrator, publisher, readers):
    read, listing = ledger_reader_policy(trust)["Statement"]
    ledger = trust["ledger"]
    if arn(ROLE_ARN, publisher)[1] != ledger["account"]:
        raise ValueError("publisher must be a dedicated role in the custody ledger account")
    if arn(ROLE_ARN, administrator)[1] != ledger["account"] or administrator in {publisher, *readers}:
        raise ValueError("bucket administrator must be a separate role in the custody ledger account")
    for reader in readers:
        arn(ROLE_ARN, reader)
    resource = read["Resource"]
    principals = {"AWS": sorted(set([publisher, *readers]))}
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "RestrictBucketAdministration", "Effect": "Deny", "Principal": "*",
         "Action": ["s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:PutBucketPolicy", "s3:PutBucketVersioning",
                    "s3:PutLifecycleConfiguration", "s3:PutReplicationConfiguration", "s3:PutBucketOwnershipControls",
                    "s3:PutBucketAcl", "s3:PutBucketPublicAccessBlock", "s3:PutEncryptionConfiguration",
                    "s3:PutBucketObjectLockConfiguration"],
         "Resource": listing["Resource"], "Condition": {"StringNotEquals": {"aws:PrincipalArn": administrator}}},
        {"Sid": "RestrictRecordReads", "Effect": "Deny", "Principal": "*", "Action": "s3:GetObject*", "Resource": resource,
         "Condition": {"StringNotEquals": {"aws:PrincipalArn": [administrator, *principals["AWS"]]}}},
        {"Sid": "RestrictBucketListing", "Effect": "Deny", "Principal": "*", "Action": "s3:ListBucket*",
         "Resource": listing["Resource"], "Condition": {"StringNotEquals": {"aws:PrincipalArn": [administrator, *principals["AWS"]]}}},
        {"Sid": "RequireWriteOnce", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
         "Resource": resource, "Condition": {"StringNotEquals": {"s3:if-none-match": "*"}}},
        {"Sid": "RestrictPublisher", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
         "Resource": resource, "Condition": {"StringNotEquals": {"aws:PrincipalArn": publisher}}},
        {"Sid": "PreserveCustodyHistory", "Effect": "Deny", "Principal": "*", "Resource": resource,
         "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:ReplicateObject", "s3:ReplicateDelete"]},
        {"Sid": "AllowPublisher", "Effect": "Allow", "Principal": {"AWS": publisher},
         "Action": "s3:PutObject", "Resource": resource},
        {**read, "Principal": principals},
        {**listing, "Principal": principals},
    ]}


def load_epoch(trust, epoch):
    document = read_object(trust, ledger_object(trust, epoch))
    receipt, custodians = record(trust, document)
    if receipt["custody"]["epoch"] != epoch:
        raise ValueError("canonical custody receipt belongs to another epoch")
    check_commit(trust, document, receipt, custodians)
    return document, receipt, custodians


def acknowledgements(document):
    return {"manifest": document["authorization"]["manifest"], "signatures": document["acknowledgements"]}


def check_commit(trust, document, receipt, custodians):
    check_approvals(approval_keys(trust, receipt["custody"]["epoch"]), LABEL, document["authorization"])
    check_approvals([custodian["acknowledgementKey"] for custodian in custodians],
                    ACKNOWLEDGEMENT, acknowledgements(document), minimum=6)


def verify_retirement(trust, document, epoch):
    fields(document, "manifest", "signatures")
    manifest = document["manifest"]
    fields(manifest, "network", "securityDomainId", "epoch", "receiptSha256", "replacementEpoch",
           "replacementReceiptSha256", "replacementCustodyDigest", "approvalFromEpoch", "walletPolicyDigest")
    if ((manifest["network"], manifest["securityDomainId"], manifest["epoch"]) !=
            (trust["network"], trust["securityDomainId"], epoch) or
            epoch_number(manifest["replacementEpoch"]) <= epoch_number(epoch)):
        raise ValueError("retirement record does not match the requested epoch")
    for field in ("receiptSha256", "replacementReceiptSha256", "replacementCustodyDigest", "walletPolicyDigest"):
        hex_digest(manifest[field])
    start = manifest["approvalFromEpoch"]
    if not any(entry["fromEpoch"] == start for entry in trust["approvalKeys"]):
        raise ValueError("unknown retirement approval roster")
    check_approvals(approval_keys(trust, start), RETIREMENT, document)
    return manifest


def load_retirement(trust, epoch):
    marker = verify_retirement(trust, read_object(trust, retirement_object_name(epoch)), epoch)
    _, previous, custodians = load_epoch(trust, epoch)
    _, replacement, _ = load_epoch(trust, marker["replacementEpoch"])
    if (marker["receiptSha256"] != sha256(previous) or marker["replacementReceiptSha256"] != sha256(replacement) or
            marker["replacementCustodyDigest"] != sha256(replacement["custody"]) or
            previous["custody"]["noteSeedCommitment"] != replacement["custody"]["noteSeedCommitment"]):
        raise ValueError("retirement receipts do not match the ledger")
    return marker, custodians


def verify_archive(trust, document, expected_digest):
    if sha256(document) != hex_digest(expected_digest):
        raise ValueError("archive does not match the pinned custody document digest")
    receipt, custodians = record(trust, document)
    check_commit(trust, document, receipt, custodians)
    return receipt


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
    require_kms_key(kms(key, "describe-key")["KeyMetadata"], key, RECOVERY_SPECS, "ENCRYPT_DECRYPT")
    public = key_result(key, "get-public-key")
    fingerprint = hashlib.sha256(base64.b64decode(public["PublicKey"], validate=True)).hexdigest()
    if (public.get("KeyUsage") != "ENCRYPT_DECRYPT" or public.get("KeySpec") not in RECOVERY_SPECS or
            "RSAES_OAEP_SHA_256" not in public.get("EncryptionAlgorithms", []) or fingerprint != expected_fingerprint):
        raise ValueError("recovery key does not match its recovery package")


def check_acknowledgement_key(custodian):
    key = custodian["acknowledgementKey"]
    if get_signing_key(key["keyArn"]) != key:
        raise ValueError("acknowledgement public key does not match the custodian KMS key")


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


def sign_epoch(trust, document, key, build, source_commit, source_ref):
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
    verify_build(build, receipt["network"], source_commit, source_ref)
    root = Path(__file__).resolve().parents[3]
    subprocess.run(["pnpm", "--dir", str(root / "example"), "exec", "tsx",
                    str(root / "xtask/nitro-ceremony.ts"), "verify"],
                   input=canonical(capture), timeout=25, check=True)
    for custodian, package in zip(custodians, receipt["packages"], strict=True):
        check_recovery_key(custodian["recoveryKeyArn"], package["recipientSha256"])
        check_acknowledgement_key(custodian)
    keys = approval_keys(trust, receipt["custody"]["epoch"])
    return {**document, "authorization": add_approval(keys, LABEL, authorization, key)}


def acknowledge(trust, document, index):
    receipt, custodians = record(trust, document)
    check_approvals(approval_keys(trust, receipt["custody"]["epoch"]), LABEL, document["authorization"])
    check_previous(trust, document, receipt)
    if index not in range(1, 7):
        raise ValueError("invalid custody slot")
    custodian = custodians[index - 1]
    key = custodian["acknowledgementKey"]["keyArn"]
    expected = acknowledgement_policy(custodian["custodianRole"], custodian["retirementRole"])
    if parse_json(kms(key, "get-key-policy", ["--policy-name", "default"])["Policy"]) != expected:
        raise ValueError("installed acknowledgement policy does not match the custodian role")
    open_share(custodian, receipt, index)
    keys = [member["acknowledgementKey"] for member in custodians]
    approved = add_approval(keys, ACKNOWLEDGEMENT, acknowledgements(document), key)
    return {**document, "acknowledgements": approved["signatures"]}


def publish(trust, document):
    receipt, custodians = record(trust, document)
    check_commit(trust, document, receipt, custodians)
    check_previous(trust, document, receipt)
    epoch = receipt["custody"]["epoch"]
    def subject(committed):
        stored_receipt, roster = record(trust, committed)
        if stored_receipt["custody"]["epoch"] != epoch:
            raise ValueError("canonical custody receipt belongs to another epoch")
        check_commit(trust, committed, stored_receipt, roster)
        return committed["authorization"]["manifest"]
    write_once(trust, ledger_object(trust, epoch), document, subject)


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
    sign.add_argument("--source-ref", default=MAIN_REF)
    ack = commands.add_parser("acknowledge")
    ack.add_argument("candidate", type=Path)
    ack.add_argument("share", type=int, choices=range(1, 7))
    ack.add_argument("output", type=Path)
    post = commands.add_parser("publish")
    post.add_argument("candidate", type=Path)
    get = commands.add_parser("read")
    get.add_argument("epoch")
    get.add_argument("--custody-digest", action="store_true")
    archive = commands.add_parser("archive")
    archive.add_argument("epoch")
    verify = commands.add_parser("verify-archive")
    verify.add_argument("archive", type=Path)
    verify.add_argument("sha256")
    policy = commands.add_parser("policy")
    policy.add_argument("administrator")
    policy.add_argument("publisher")
    policy.add_argument("readers", nargs="+")
    commands.add_parser("reader-policy")
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
            print(canonical(ledger_policy(trust, args.administrator, args.publisher, args.readers)).decode())
            return
        if args.command == "reader-policy":
            print(canonical(ledger_reader_policy(trust)).decode())
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
        if args.command in {"read", "archive"}:
            document, receipt, _ = load_epoch(trust, args.epoch)
            if args.command == "read" and args.custody_digest:
                print(sha256(receipt["custody"]))
            else:
                print(canonical(receipt if args.command == "read" else document).decode())
            return
        if args.command == "verify-archive":
            print(canonical(verify_archive(trust, read_json(args.archive), args.sha256)).decode())
            return
        document = read_json(args.candidate)
        if args.command == "publish":
            publish(trust, document)
            return
        signed = (sign_epoch(trust, document, args.key, args.build, args.source_commit, args.source_ref) if args.command == "sign"
                  else acknowledge(trust, document, args.share))
        with args.output.open("xb") as output:
            output.write(canonical(signed) + b"\n")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
