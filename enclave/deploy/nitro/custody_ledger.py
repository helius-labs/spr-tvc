"""Sign, publish and read one authenticated custody receipt per epoch."""

import argparse
import base64
import hashlib
import re
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from approval import (
    KEY_ARN, ROLE_ARN, MAX_DOCUMENT_BYTES, add_approval, approval_keys, approval_roster, arn, aws, canonical, check_approvals,
    epoch_number, fields, file_digest, get_signing_key, hex_digest, key_result, kms, parse_json, read_document,
    read_json, require_kms_key, sha256, signing_key, signing_sec1,
)
from kms_policy import RSA_OAEP, acknowledgement_policy, boot_pins, context, recovery_policy, target_algorithm, validate_custodian_roles
from provenance import MAIN_REF, verify as verify_build
from relay import custody_recovery_policy, prove_share, relay_pins, sealed_rsa_key, verify_relay_build

LABEL = "custody-epoch"
ACKNOWLEDGEMENT = "custodian-acknowledgement"
TARGET_APPROVAL = "target-approval"
RETIREMENT = "custody-retirement"
RETIREMENT_RECOVERY = "retirement-recovery"
RECOVERY_WINDOW_SECONDS = 24 * 60 * 60
LEDGER_WRITE_MARGIN_SECONDS = 30
RECOVERY_SPECS = {"RSA_2048", "RSA_3072", "RSA_4096"}


def record(trust, document):
    fields(document, "authorization", "acknowledgements")
    authorization = document["authorization"]
    fields(authorization, "manifest", "signatures")
    manifest = authorization["manifest"]
    fields(manifest, "capture", "ceremonyEifSha256", "ceremonyHostRole", "custodians", "previousReceiptSha256",
           "rotationTargetSha256")
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
    rotation = manifest["rotationTargetSha256"]
    mode = capture["configuration"]["deployment"]["mode"]
    if epoch == "1":
        if mode != "initialize" or previous is not None or rotation is not None:
            raise ValueError("genesis requires initialization without a predecessor or rotation target")
    else:
        if mode != "rotate":
            raise ValueError("a successor receipt requires a rotation ceremony")
        hex_digest(previous)
        hex_digest(rotation)
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


def target_path(epoch, identity):
    epoch_number(epoch)
    return f"targets/{epoch}/{hex_digest(identity)}.json"


def target_attestation(manifest):
    pins = boot_pins(manifest["hostRole"], manifest["pcrs"])
    return {"releaseId": manifest["releaseId"], "pcrs": {key.removeprefix("PCR"): value for key, value in pins.items()}}


def target_object_name(manifest):
    return target_path(manifest["custodyEpoch"], sha256(target_attestation(manifest)))


def storage(trust, operation, args):
    ledger, _ = ledger_prefix(trust)
    return aws(ledger["region"], "s3api", operation, [
        "--bucket", ledger["bucket"], "--expected-bucket-owner", ledger["account"], *args,
    ])


def read_object(trust, name):
    return read_stored_object(trust, name)[0]


def read_stored_object(trust, name):
    _, prefix = ledger_prefix(trust)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "record.json"
        metadata = storage(trust, "get-object", ["--key", prefix + name, "--range", f"bytes=0-{MAX_DOCUMENT_BYTES}", str(path)])
        return read_json(path), metadata


def publication_time(metadata):
    committed = datetime.fromisoformat(metadata["LastModified"])
    if committed.tzinfo is None:
        raise ValueError("custody ledger publication time requires a timezone")
    return committed.timestamp()


def require_publication_roster(trust, start):
    # Leave room for the AWS CLI's 25-second request deadline.
    now = time.time()
    if any(approval_roster(trust, at=instant)["fromEpoch"] != start
           for instant in (now, now + LEDGER_WRITE_MARGIN_SECONDS)):
        raise ValueError("custody approval cutover is too close for a ledger write")


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
    except (ValueError, subprocess.TimeoutExpired) as write_error:
        # Resolve ambiguous writes by reading the authenticated immutable subject.
        try:
            stored = read_object(trust, name)
        except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as read_error:
            raise ValueError(f"could not confirm ledger write ({write_error}). Readback failed ({read_error})") from None
        if subject(stored) != subject(document):
            raise ValueError("a different record is already committed") from None


def list_objects(trust, name):
    ledger, prefix = ledger_prefix(trust)
    scope = prefix + name
    args = ["--prefix", scope, "--max-keys", "100", "--no-paginate"]
    continuation = []
    last_key = ""
    seen_tokens = set()
    while True:
        page = storage(trust, "list-objects-v2", [*args, *continuation])
        if not isinstance(page, dict):
            raise ValueError("invalid custody ledger listing")
        entries = page.get("Contents", [])
        truncated = page.get("IsTruncated")
        if (page.get("Name") != ledger["bucket"] or page.get("Prefix") != scope or
                type(truncated) is not bool or type(page.get("KeyCount")) is not int or
                not isinstance(entries, list) or page["KeyCount"] != len(entries) or len(entries) > 100):
            raise ValueError("invalid custody ledger listing")
        keys = []
        for entry in entries:
            object_key = entry.get("Key") if isinstance(entry, dict) else None
            if not isinstance(object_key, str) or not object_key.startswith(scope) or object_key <= last_key:
                raise ValueError("invalid or out-of-order custody ledger key")
            last_key = object_key
            keys.append(object_key[len(prefix):])
        if truncated:
            token = page.get("NextContinuationToken")
            if not keys or not isinstance(token, str) or not token or token in seen_tokens:
                raise ValueError("invalid custody ledger continuation token")
            seen_tokens.add(token)
            continuation = ["--continuation-token", token]
        elif "NextContinuationToken" in page:
            raise ValueError("invalid custody ledger continuation token")
        yield from keys
        if not truncated:
            return


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


def read_epoch_record(trust, epoch):
    document = read_object(trust, ledger_object(trust, epoch))
    receipt, custodians = record(trust, document)
    if receipt["custody"]["epoch"] != epoch:
        raise ValueError("canonical custody receipt belongs to another epoch")
    check_commit(trust, document, receipt, custodians)
    return document, receipt, custodians


def load_epoch(trust, epoch):
    document, receipt, custodians = read_epoch_record(trust, epoch)
    check_previous(trust, document, receipt)
    return document, receipt, custodians


def acknowledgements(document):
    return {"manifest": document["authorization"]["manifest"], "signatures": document["acknowledgements"]}


def check_commit(trust, document, receipt, custodians):
    check_approvals(approval_keys(trust, receipt["custody"]["epoch"]), LABEL, document["authorization"])
    check_approvals([custodian["acknowledgementKey"] for custodian in custodians],
                    ACKNOWLEDGEMENT, acknowledgements(document), minimum=6)


def require_target_approval_window(manifest, at, *, remaining=0):
    expires = manifest["expiresAt"]
    if type(expires) is not int or not 0 < expires < 2**53:
        raise ValueError("invalid target approval deadline")
    if at >= expires:
        raise ValueError("target approval has expired")
    if expires - at <= remaining:
        raise ValueError("target approval deadline is too close for a ledger write")


def verify_target_approval(trust, document, *, at=None):
    manifest = document["manifest"]
    rsa_target = target_algorithm(manifest) == RSA_OAEP
    if rsa_target != (manifest["custodyEpoch"] in trust.get("recoveryRelays", {})):
        raise ValueError("target wrapping algorithm does not match the epoch's pinned recovery path")
    at = time.time() if at is None else at
    require_target_approval_window(manifest, at)
    roster = approval_roster(trust, at=at)
    if roster["fromEpoch"] != manifest["approvalFromEpoch"]:
        raise ValueError("target approval roster does not match its publication time")
    check_approvals(roster["keys"], TARGET_APPROVAL, document)
    return manifest


def read_registered_target(trust, name, epoch, receipt_digest):
    document, metadata = read_stored_object(trust, name)
    target = verify_target_approval(trust, document, at=publication_time(metadata))
    if (name != target_object_name(target) or
            (target["network"], target["securityDomainId"], target["custodyEpoch"], target["receiptSha256"]) !=
            (trust["network"], trust["securityDomainId"], epoch, receipt_digest)):
        raise ValueError("registered target does not match the committed custody receipt")
    return target


def retirement_approval(document):
    fields(document, "manifest", "signatures", "recoveryProofs")
    return {"manifest": document["manifest"], "signatures": document["signatures"]}


def retirement_bootstrap(bootstrap):
    fields(bootstrap, "bootKeyId", "slots")
    hex_digest(bootstrap["bootKeyId"])
    slots = bootstrap["slots"]
    if (not isinstance(slots, list) or len(slots) != 3 or
            any(type(slot) is not int or slot not in range(1, 7) for slot in slots) or slots != sorted(set(slots))):
        raise ValueError("expected three distinct attested bootstrap slots in order")
    return slots


def retirement_recovery(document, custodians):
    manifest = document["manifest"]
    proofs = {"manifest": manifest, "signatures": document["recoveryProofs"]}
    members = [custodians[slot - 1] for slot in retirement_bootstrap(manifest["replacementBootstrap"])]
    check_approvals([member["acknowledgementKey"] for member in members], RETIREMENT_RECOVERY, proofs, minimum=3)
    return members


def recovery_deadline(manifest):
    deadline = manifest["recoveryDeadline"]
    if type(deadline) is not int or not RECOVERY_WINDOW_SECONDS < deadline < 2**53:
        raise ValueError("invalid retirement recovery deadline")
    return deadline


def verify_retirement(trust, document, epoch, published_at):
    approval = retirement_approval(document)
    manifest = document["manifest"]
    fields(manifest, "network", "securityDomainId", "epoch", "receiptSha256", "replacementEpoch",
           "replacementReceiptSha256", "replacementCustodyDigest", "replacementTargetIdentity", "replacementTargetSha256",
           "approvalFromEpoch", "walletPolicyDigest", "recoveryDeadline", "replacementBootstrap")
    retirement_bootstrap(manifest["replacementBootstrap"])
    deadline = recovery_deadline(manifest)
    if not deadline - RECOVERY_WINDOW_SECONDS <= published_at < deadline:
        raise ValueError("retirement was published outside the recovery window")
    if ((manifest["network"], manifest["securityDomainId"], manifest["epoch"]) !=
            (trust["network"], trust["securityDomainId"], epoch) or
            epoch_number(manifest["replacementEpoch"]) <= epoch_number(epoch)):
        raise ValueError("retirement record does not match the requested epoch")
    for field in ("receiptSha256", "replacementReceiptSha256", "replacementCustodyDigest", "replacementTargetIdentity",
                  "replacementTargetSha256", "walletPolicyDigest"):
        hex_digest(manifest[field])
    roster = approval_roster(trust, at=published_at)
    if roster["fromEpoch"] != manifest["approvalFromEpoch"]:
        raise ValueError("retirement approval roster does not match its publication time")
    check_approvals(roster["keys"], RETIREMENT, approval)
    return manifest


def load_retirement(trust, epoch):
    document, metadata = read_stored_object(trust, retirement_object_name(epoch))
    marker = verify_retirement(trust, document, epoch, publication_time(metadata))
    _, previous, custodians = load_epoch(trust, epoch)
    replacement_epoch = marker["replacementEpoch"]
    _, replacement, replacement_custodians = load_epoch(trust, replacement_epoch)
    if (marker["receiptSha256"] != sha256(previous) or marker["replacementReceiptSha256"] != sha256(replacement) or
            marker["replacementCustodyDigest"] != sha256(replacement["custody"]) or
            previous["custody"]["noteSeedCommitment"] != replacement["custody"]["noteSeedCommitment"]):
        raise ValueError("retirement receipts do not match the ledger")
    retirement_recovery(document, replacement_custodians)
    name = target_path(replacement_epoch, marker["replacementTargetIdentity"])
    target = read_registered_target(trust, name, replacement_epoch, marker["replacementReceiptSha256"])
    if target["mode"] != "serve" or sha256(target) != marker["replacementTargetSha256"]:
        raise ValueError("replacement target does not match the registered serving enclave")
    return document, custodians


def find_retirement(trust, epoch):
    name = retirement_object_name(epoch)
    if name not in list_objects(trust, name):
        return None
    try:
        return load_retirement(trust, epoch)
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        raise ValueError(f"cannot verify retirement record for epoch {epoch}: {error}") from error


def require_active_epoch(trust, epoch):
    if find_retirement(trust, epoch) is not None:
        raise ValueError("custody epoch is retired")


def check_serving_policy(trust, document, custody_signer=None):
    fields(document, "policy", "signatures", "custodySignatures")
    policy = document["policy"]
    targets = policy["targets"]
    if type(policy["recoveryOnly"]) is not bool:
        raise ValueError("expected a recoveryOnly boolean")
    if policy["action"] != "activate" or not isinstance(targets, list) or not 1 <= len(targets) <= 8:
        raise ValueError("expected an activation with one to eight serving targets")
    if (policy["network"], policy["securityDomainId"]) != (trust["network"], trust["securityDomainId"]):
        raise ValueError("wallet policy does not match the pinned custody domain")
    by_epoch = {}
    floor = epoch_number(policy["minimumCustodyEpoch"])
    for target in targets:
        epoch = target["custodyEpoch"]
        if epoch_number(epoch) < floor:
            raise ValueError("serving target is below the wallet custody floor")
        by_epoch.setdefault(epoch, []).append(target)

    def check_epoch(item):
        epoch, replicas = item
        require_active_epoch(trust, epoch)
        _, receipt, _ = load_epoch(trust, epoch)
        custody = receipt["custody"]
        if policy["noteSeedCommitment"] != custody["noteSeedCommitment"]:
            raise ValueError("wallet policy does not match the committed note seed")
        custody_digest, receipt_digest = sha256(custody), sha256(receipt)
        for replica in replicas:
            if replica["custodyDigest"] != custody_digest:
                raise ValueError("serving target does not match the committed custody record")
            identity = {"releaseId": replica["releaseId"], "pcrs": replica["pcrs"]}
            registered = read_registered_target(trust, target_path(epoch, sha256(identity)), epoch, receipt_digest)
            if (registered["mode"] != "serve" or
                    hex_digest(registered["executableSha256"]) != replica["executableSha256"]):
                raise ValueError("serving executable does not match the custody-approved target")

    with ThreadPoolExecutor(max_workers=len(by_epoch)) as workers:
        list(workers.map(check_epoch, by_epoch.items()))
    if custody_signer is not None:
        key_arn, public = custody_signer
        if not any(pin["keyArn"] == key_arn and signing_sec1(pin) == public for pin in approval_roster(trust)["keys"]):
            raise ValueError("custody policy signer must match a key in the active custody approval roster")


def verify_archive(trust, document, expected_digest):
    if sha256(document) != hex_digest(expected_digest):
        raise ValueError("archive does not match the pinned custody document digest")
    receipt, custodians = record(trust, document)
    check_commit(trust, document, receipt, custodians)
    return receipt


def draft(trust, capture, build, host, roster):
    epoch = int(capture["receipt"]["custody"]["epoch"])
    previous = None if epoch == 1 else sha256(load_epoch(trust, str(epoch - 1))[1])
    manifest = {
        "capture": capture, "ceremonyEifSha256": file_digest(build / "enclave.eif"), "ceremonyHostRole": host,
        "custodians": roster, "previousReceiptSha256": previous, "rotationTargetSha256": None,
    }
    if epoch != 1:
        target = rotation_target(trust, manifest, str(epoch - 1))
        if target["configurationSha256"] != file_digest(build / "configuration.json"):
            raise ValueError("ceremony build configuration does not match the registered rotation target")
        manifest["rotationTargetSha256"] = sha256(target)
    document = {"authorization": {"manifest": manifest, "signatures": []}, "acknowledgements": []}
    record(trust, document)
    return document


def rotation_target(trust, manifest, previous_epoch):
    capture = manifest["capture"]
    pcrs = capture["pcrs"]
    fields(pcrs, "0", "1", "2", "3")
    identity = {
        "releaseId": capture["receipt"]["releaseId"], "hostRole": manifest["ceremonyHostRole"],
        "pcrs": {f"PCR{i}": pcrs[str(i)] for i in range(3)}, "custodyEpoch": previous_epoch,
    }
    target = read_registered_target(trust, target_object_name(identity), previous_epoch, manifest["previousReceiptSha256"])
    if (target["mode"] != "rotate" or target["hostRole"] != manifest["ceremonyHostRole"] or
            pcrs != target_attestation(target)["pcrs"] or target["eifSha256"] != manifest["ceremonyEifSha256"] or
            target["nextCustodians"] != manifest["custodians"]):
        raise ValueError("ceremony image or successor roster does not match the registered rotation target")
    return target


def check_previous(trust, document, receipt):
    epoch = int(receipt["custody"]["epoch"])
    if epoch == 1:
        return
    previous_epoch = str(epoch - 1)
    _, predecessor, previous_roster = read_epoch_record(trust, previous_epoch)
    manifest = document["authorization"]["manifest"]
    if (sha256(predecessor) != manifest["previousReceiptSha256"] or
            predecessor["custody"]["noteSeedCommitment"] != receipt["custody"]["noteSeedCommitment"] or
            predecessor["custody"] != manifest["capture"]["configuration"]["deployment"]["previous"]):
        raise ValueError("custody rotation does not descend from the canonical previous receipt")
    previous_keys = {custodian["recoveryKeyArn"] for custodian in previous_roster}
    if previous_keys & {custodian["recoveryKeyArn"] for custodian in manifest["custodians"]}:
        raise ValueError("custody rotation requires fresh recovery keys")
    target = rotation_target(trust, manifest, previous_epoch)
    if manifest["rotationTargetSha256"] != sha256(target):
        raise ValueError("custody record does not pin the registered rotation target")
    return target


def check_recovery_key(key, expected_fingerprint):
    require_kms_key(kms(key, "describe-key")["KeyMetadata"], key, RECOVERY_SPECS, "ENCRYPT_DECRYPT")
    public = key_result(key, "get-public-key")
    fingerprint = hashlib.sha256(base64.b64decode(public["PublicKey"], validate=True)).hexdigest()
    if (public.get("KeyUsage") != "ENCRYPT_DECRYPT" or public.get("KeySpec") not in RECOVERY_SPECS or
            "RSAES_OAEP_SHA_256" not in public.get("EncryptionAlgorithms", []) or fingerprint != expected_fingerprint):
        raise ValueError("recovery key does not match its recovery package")


def check_recovery_roster(trust, epoch, custodians, fingerprints, inspection_profiles, relay_build=None):
    if epoch not in trust.get("recoveryRelays", {}):
        if relay_build is not None:
            raise ValueError("no recovery relay is pinned for this custody epoch")
        for custodian, fingerprint in zip(custodians, fingerprints, strict=True):
            check_recovery_key(custodian["recoveryKeyArn"], fingerprint)
        return
    if inspection_profiles is None or len(inspection_profiles) != 6 or len(set(inspection_profiles)) != 6:
        raise ValueError("provide six distinct read-only inspection profiles in custody slot order")
    if relay_build is None:
        raise ValueError("provide the independently reviewed recovery relay build, commit and ref")
    verify_relay_build(trust, epoch, *relay_build)
    for custodian, fingerprint, profile in zip(custodians, fingerprints, inspection_profiles, strict=True):
        expected = custody_recovery_policy(trust, custodian, epoch)
        public = sealed_rsa_key(custodian["recoveryKeyArn"], expected, profile=profile)
        if hashlib.sha256(public).hexdigest() != fingerprint:
            raise ValueError("inspected recovery key does not match its recovery package")


def check_acknowledgement_key(custodian):
    key = custodian["acknowledgementKey"]
    if get_signing_key(key["keyArn"]) != key:
        raise ValueError("acknowledgement public key does not match the custodian KMS key")


def open_share(custodian, receipt, index, *, before_decrypt=None):
    key = custodian["recoveryKeyArn"]
    package = receipt["packages"][index - 1]
    custody = receipt["custody"]
    expected = recovery_policy(custodian["custodianRole"], custodian["retirementRole"], custody["epoch"])
    installed = parse_json(kms(key, "get-key-policy", ["--policy-name", "default"])["Policy"])
    if installed != expected:
        raise ValueError("installed recovery key policy does not match the custodian role")
    check_recovery_key(key, package["recipientSha256"])
    capsule = base64.b64encode(bytes.fromhex(package["ciphertext"])).decode()
    if before_decrypt is not None:
        before_decrypt()
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


def sign_epoch(trust, document, key, build, source_commit, source_ref, inspection_profiles=None, relay_build=None):
    receipt, custodians = record(trust, document)
    target = check_previous(trust, document, receipt)
    authorization = document["authorization"]
    manifest = authorization["manifest"]
    capture = manifest["capture"]
    configuration = read_document(build / "configuration.json")
    config = parse_json(configuration)
    configuration_digest = hashlib.sha256(configuration).hexdigest()
    if target is not None and target["configurationSha256"] != configuration_digest:
        raise ValueError("ceremony build configuration does not match the registered rotation target")
    reviewed = verify_build(build, receipt["network"], source_commit, source_ref)
    pins = {name.removeprefix("PCR"): pin for name, pin in boot_pins(manifest["ceremonyHostRole"], reviewed["pcrs"]).items()}
    if (capture["configuration"] != config or configuration_digest != reviewed["configurationSha256"] or
            capture["pcrs"] != pins or manifest["ceremonyEifSha256"] != reviewed["eifSha256"] or
            (target is not None and target["executableSha256"] != reviewed["executableSha256"])):
        raise ValueError("captured ceremony does not match the verified build provenance")
    root = Path(__file__).resolve().parents[3]
    subprocess.run(["pnpm", "--dir", str(root / "example"), "exec", "tsx",
                    str(root / "xtask/nitro-ceremony.ts"), "verify"],
                   input=canonical(capture), timeout=25, check=True)
    epoch = receipt["custody"]["epoch"]
    check_recovery_roster(trust, epoch, custodians, [package["recipientSha256"] for package in receipt["packages"]],
                          inspection_profiles, relay_build)
    for custodian in custodians:
        check_acknowledgement_key(custodian)
    keys = approval_keys(trust, epoch)
    return {**document, "authorization": add_approval(keys, LABEL, authorization, key)}


def sign_share_recovery(trust, custodians, receipt, index, label, approval, relay_port=None):
    if index not in range(1, 7):
        raise ValueError("invalid custody slot")
    epoch = receipt["custody"]["epoch"]

    def require_open_epoch():
        require_active_epoch(trust, epoch)

    require_open_epoch()
    custodian = custodians[index - 1]
    key = custodian["acknowledgementKey"]["keyArn"]
    expected = acknowledgement_policy(custodian["custodianRole"], custodian["retirementRole"])
    if parse_json(kms(key, "get-key-policy", ["--policy-name", "default"])["Policy"]) != expected:
        raise ValueError("installed acknowledgement policy does not match the custodian role")
    if epoch in trust.get("recoveryRelays", {}):
        if relay_port is None:
            raise ValueError("this custody epoch requires an attested recovery relay")
        prove_share(trust, receipt, custodian, index, relay_port, require_open_epoch)
    else:
        if relay_port is not None:
            raise ValueError("no recovery relay is pinned for this custody epoch")
        open_share(custodian, receipt, index, before_decrypt=require_open_epoch)
    require_open_epoch()
    keys = [member["acknowledgementKey"] for member in custodians]
    return add_approval(keys, label, approval, key)["signatures"]


def acknowledge(trust, document, index, relay_port=None):
    receipt, custodians = record(trust, document)
    check_approvals(approval_keys(trust, receipt["custody"]["epoch"]), LABEL, document["authorization"])
    check_previous(trust, document, receipt)
    signatures = sign_share_recovery(trust, custodians, receipt, index, ACKNOWLEDGEMENT, acknowledgements(document), relay_port)
    return {**document, "acknowledgements": signatures}


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
    sign.add_argument("--inspection-profiles", nargs=6)
    sign.add_argument("--relay-build", nargs=3, metavar=("BUILD", "COMMIT", "REF"))
    ack = commands.add_parser("acknowledge")
    ack.add_argument("candidate", type=Path)
    ack.add_argument("share", type=int, choices=range(1, 7))
    ack.add_argument("output", type=Path)
    ack.add_argument("--relay-port", type=int)
    post = commands.add_parser("publish")
    post.add_argument("candidate", type=Path)
    check = commands.add_parser("check-serving-policy")
    check.add_argument("candidate", type=Path)
    check.add_argument("--custody-signer", nargs=2, metavar=("KEY_ARN", "SEC1_HEX"))
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
    relay = commands.add_parser("relay-recovery-policy", help="render a recovery key policy for the devnet relay trial")
    relay.add_argument("custodian_role")
    relay.add_argument("retirement_role")
    relay.add_argument("epoch")
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
        if args.command == "relay-recovery-policy":
            relay_pins(trust, args.epoch)
            custodian = {"custodianRole": args.custodian_role, "retirementRole": args.retirement_role}
            print(canonical(custody_recovery_policy(trust, custodian, args.epoch)).decode())
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
        if args.command == "check-serving-policy":
            check_serving_policy(trust, document, args.custody_signer)
            return
        signed = (sign_epoch(trust, document, args.key, args.build, args.source_commit, args.source_ref,
                             args.inspection_profiles, args.relay_build)
                  if args.command == "sign"
                  else acknowledge(trust, document, args.share, args.relay_port))
        with args.output.open("xb") as output:
            output.write(canonical(signed) + b"\n")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
