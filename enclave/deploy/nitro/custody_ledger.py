"""Sign, publish and read one authenticated custody receipt per epoch."""

import argparse
import hashlib
import re
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from approval import (
    KEY_ARN, ROLE_ARN, MAX_DOCUMENT_BYTES, add_approval, approval_keys, approval_roster, arn, aws, canonical, check_approvals,
    epoch_number, fields, file_digest, get_signing_key, hex_digest, kms, parse_json, publish_new_file, read_document,
    read_json, require_custody_key_profiles, require_inspection_profiles, require_kms_key, require_profile_account,
    sha256, signing_key, signing_sec1,
)
from host import require_bootstrap_access
from kms_policy import acknowledgement_policy, boot_pins, key_policy, target_boot_pins, validate_custodian_roles, validate_scope
from provenance import verify as verify_build
from relay import custody_recovery_policy, inspect_rsa_key, prove_share, relay_pins, sealed_rsa_key, verify_relay_build

LABEL = "custody-epoch"
ACKNOWLEDGEMENT = "custodian-acknowledgement"
TARGET_APPROVAL = "target-approval"
RETIREMENT = "custody-retirement"
RETIREMENT_RECOVERY = "retirement-recovery"
RECOVERY_WINDOW_SECONDS = 24 * 60 * 60
LEDGER_WRITE_MARGIN_SECONDS = 30


def note_identity(custody):
    return hex_digest(custody["noteSeedCommitment"]), hex_digest(custody["canaryDigest"])


def record(trust, document):
    fields(document, "authorization", "acknowledgements")
    authorization = document["authorization"]
    fields(authorization, "manifest", "signatures")
    manifest = authorization["manifest"]
    fields(manifest, "capture", "ceremonyEifSha256", "ceremonyHostRole", "custodians", "relay", "previousReceiptSha256",
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
    fields(custody, "epoch", "noteSeedCommitment", "canaryDigest", "shareCommitments")
    if "00" * 32 in note_identity(custody):
        raise ValueError("custody requires nonzero seed and canary commitments")
    epoch = custody["epoch"]
    validate_scope(network, domain, release, epoch)
    if manifest["relay"] != relay_pins(trust, epoch):
        raise ValueError("custody record does not match the pinned recovery relay")
    previous = manifest["previousReceiptSha256"]
    rotation = manifest["rotationTargetSha256"]
    mode = capture["configuration"]["deployment"]["mode"]
    if epoch == "1":
        if mode != "initialize" or previous is not None or rotation is not None:
            raise ValueError("genesis requires initialization without a predecessor or rotation target")
        pcrs = capture["pcrs"]
        fields(pcrs, "0", "1", "2", "3")
        expected = boot_pins(manifest["ceremonyHostRole"], {f"PCR{pcr}": pcrs[pcr] for pcr in ("0", "1", "2")})
        if pcrs["3"] != expected["PCR3"]:
            raise ValueError("genesis capture does not match the ceremony host role")
    else:
        if mode != "rotate":
            raise ValueError("a successor receipt requires a rotation ceremony")
        hex_digest(previous)
        hex_digest(rotation)
    custodians = manifest["custodians"]
    validate_roster(trust, custodians, manifest["ceremonyHostRole"])
    if not isinstance(receipt["packages"], list) or len(receipt["packages"]) != 6:
        raise ValueError("custody requires six recovery packages")
    return receipt, custodians


def validate_roster(trust, custodians, host):
    accounts = {arn(ROLE_ARN, host)[1]}
    authorities = [key for entry in trust["approvalKeys"] for key in entry["keys"]]
    approval_arns = {key["keyArn"] for key in authorities}
    approval_public_keys = {key["publicKey"] for key in authorities}
    public_keys = set()
    if not isinstance(custodians, list) or len(custodians) != 6:
        raise ValueError("custody requires six recovery accounts")
    for custodian in custodians:
        fields(custodian, "recoveryKeyArn", "acknowledgementKey", "custodianRole", "retirementRole")
        ack = custodian["acknowledgementKey"]
        public = signing_key(ack)
        recovery, acknowledgement = custodian["recoveryKeyArn"], ack["keyArn"]
        if acknowledgement in approval_arns or public in approval_public_keys:
            raise ValueError("custody approvals and share acknowledgements require separate signing keys")
        account = arn(KEY_ARN, recovery)[2]
        if (public in public_keys or account in accounts or recovery == acknowledgement or arn(KEY_ARN, acknowledgement)[2] != account or
                arn(ROLE_ARN, custodian["custodianRole"])[1] != account):
            raise ValueError("custody requires distinct accounts and a separate acknowledgment key per custodian")
        validate_custodian_roles(custodian["custodianRole"], custodian["retirementRole"])
        accounts.add(account)
        public_keys.add(public)


LEDGER_FIELDS = ("bucket", "account", "region", "administratorRole", "publisherRole", "readerRoles")


def ledger_prefix(trust):
    ledger = trust["ledger"]
    fields(ledger, *LEDGER_FIELDS)
    if not (re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", ledger["bucket"]) and
            re.fullmatch(r"[0-9]{12}", ledger["account"]) and re.fullmatch(r"[a-z0-9-]+", ledger["region"])):
        raise ValueError("expected pinned custody bucket, AWS account and region")
    administrator, publisher, readers = (ledger[name] for name in ("administratorRole", "publisherRole", "readerRoles"))
    if arn(ROLE_ARN, administrator)[1] != ledger["account"]:
        raise ValueError("bucket administrator must be in the custody ledger account")
    if arn(ROLE_ARN, publisher)[1] != ledger["account"]:
        raise ValueError("publisher must be a dedicated role in the custody ledger account")
    if not isinstance(readers, list):
        raise ValueError("expected a list of pinned custody ledger reader roles")
    for reader in readers:
        arn(ROLE_ARN, reader)
    if len(readers) != len(set(readers)) or publisher in readers:
        raise ValueError("custody ledger reader roles must be distinct from each other and the publisher")
    if administrator in {publisher, *readers}:
        raise ValueError("bucket administrator must be a separate role in the custody ledger account")
    network, domain = trust["network"], trust["securityDomainId"]
    validate_scope(network, domain, "custody", "1")
    return ledger, f"spr-custody/{network}/{domain}/"


def ledger_object(trust, epoch):
    validate_scope(trust["network"], trust["securityDomainId"], "custody", epoch)
    return f"{epoch}.json"


def retirement_object_name(epoch):
    epoch_number(epoch)
    return f"retired/{epoch}.json"


def target_path(epoch, identity):
    epoch_number(epoch)
    return f"targets/{epoch}/{hex_digest(identity)}.json"


def target_attestation(manifest):
    pins = target_boot_pins(manifest["hostRole"], manifest["pcrs"], manifest["instanceId"])
    return {"releaseId": manifest["releaseId"], "pcrs": {key.removeprefix("PCR"): value for key, value in pins.items()}}


def target_object_name(manifest):
    return target_path(manifest["custodyEpoch"], sha256(target_attestation(manifest)))


def storage(trust, operation, args=(), **options):
    ledger, _ = ledger_prefix(trust)
    return aws(ledger["region"], "s3api", operation, [
        "--bucket", ledger["bucket"], "--expected-bucket-owner", ledger["account"], *args,
    ], **options)


def read_stored_object(trust, name, *, expected_version=None, observed_records=None, **options):
    payload, metadata = read_stored_payload(trust, name, **options)
    version = ledger_record_version(name, metadata)
    if expected_version is not None and version != expected_version:
        raise ValueError(f"custody ledger record {name} differs from its listed version")
    if observed_records is not None:
        observe_record(observed_records, name, ledger_record_fingerprint(name, payload, metadata))
    return parse_json(payload), metadata


def read_stored_payload(trust, name, *, checkpoint_records=None, **options):
    _, prefix = ledger_prefix(trust)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "record.json"
        metadata = storage(trust, "get-object",
                           ["--key", prefix + name, "--range", f"bytes=0-{MAX_DOCUMENT_BYTES}", str(path)], **options)
        payload = read_document(path)
        if checkpoint_records is not None and checkpoint_records.get(name) != ledger_record_fingerprint(name, payload, metadata):
            raise ValueError(f"custody ledger record {name} changed after checkpoint")
        return payload, metadata


def publication_datetime(metadata):
    committed = datetime.fromisoformat(metadata["LastModified"])
    if committed.tzinfo is None:
        raise ValueError("custody ledger publication time requires a timezone")
    return committed


def publication_time(metadata):
    return publication_datetime(metadata).timestamp()


def ledger_record_version(name, metadata):
    version = metadata.get("VersionId")
    if not isinstance(version, str) or not version or version == "null":
        raise ValueError(f"custody ledger record {name} requires an original S3 version")
    return version


def ledger_record_fingerprint(name, payload, metadata):
    if not 0 < len(payload) <= MAX_DOCUMENT_BYTES:
        raise ValueError(f"invalid custody ledger record size for {name}")
    version = ledger_record_version(name, metadata)
    published_at = publication_datetime(metadata).astimezone(timezone.utc).isoformat()
    return version, published_at, hashlib.sha256(payload).hexdigest()


def observe_record(records, name, fingerprint):
    if records.setdefault(name, fingerprint) != fingerprint:
        raise ValueError(f"custody ledger record {name} changed during verification")


def read_replicated_record(trust, destination, name, **options):
    original, source_metadata = read_stored_payload(trust, name, **options)
    # Records inherited during promotion can still be marked REPLICA at the source.
    if source_metadata.get("ReplicationStatus") not in ("COMPLETED", "REPLICA"):
        raise ValueError(f"custody ledger record {name} has not completed S3 replication")
    fingerprint = ledger_record_fingerprint(name, original, source_metadata)
    try:
        copied, replica_metadata = read_stored_payload(destination, name, **options)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise ValueError(f"could not read custody ledger record {name} from the pinned replica") from error
    if (replica_metadata.get("ReplicationStatus") != "REPLICA" or
            fingerprint != ledger_record_fingerprint(name, copied, replica_metadata)):
        raise ValueError(f"custody ledger record {name} differs from the pinned replica")
    return original, fingerprint


def require_replicated_custody(trust, replica, epoch, observed_records):
    destination = replica_trust(trust, replica)

    def read(name):
        payload, fingerprint = read_replicated_record(trust, destination, name)
        if name in observed_records and observed_records[name] != fingerprint:
            raise ValueError(f"custody ledger record {name} changed during verification")
        return parse_json(payload), fingerprint[1]

    def read_entry(number):
        names = [ledger_object(trust, str(number))]
        document, receipt_time = read(names[0])
        rotation = None
        if number > 1:
            manifest = document["authorization"]["manifest"]
            names.append(rotation_target_name(manifest, str(number - 1)))
            approval, published_at = read(names[1])
            rotation = {"approval": approval, "publishedAt": published_at}
        return {"document": document, "publishedAt": receipt_time, "rotation": rotation}, names

    # Schedule bounded batches even when a signed epoch number is very large.
    last = epoch_number(epoch)
    batch_size = 8
    previous = None
    remaining = set(observed_records)
    with ThreadPoolExecutor(max_workers=batch_size) as workers:
        for start in range(1, last + 1, batch_size):
            batch = range(start, min(start + batch_size, last + 1))
            for number, (entry, names) in zip(batch, workers.map(read_entry, batch), strict=True):
                previous = check_custody_history_entry(trust, str(number), entry, previous)
                remaining.difference_update(names)
        list(workers.map(read, sorted(remaining)))


def require_publication_roster(trust, start):
    # Leave room for the AWS CLI's 25-second request deadline.
    now = time.time()
    if any(approval_roster(trust, at=instant)["fromEpoch"] != start
           for instant in (now, now + LEDGER_WRITE_MARGIN_SECONDS)):
        raise ValueError("custody approval cutover is too close for a ledger write")


def ledger_slot_version(trust, name):
    replica = ledger_replica(trust)
    destination = replica_trust(trust, replica) if replica is not None else None
    copied_version = list_ledger_versions(destination, exact=name).get(name) if destination is not None else None
    version = list_ledger_versions(trust, exact=name).get(name)
    if copied_version is not None:
        try:
            if version != copied_version:
                raise ValueError("source and replica list different current versions")
            _, fingerprint = read_replicated_record(trust, destination, name)
            if fingerprint[0] != version:
                raise ValueError("record differs from its listed version")
        except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
            raise ValueError(f"custody ledger slot {name} exists in the pinned replica: {error}") from error
    return version


def write_once(trust, name, document, confirm, *, before_write=None):
    _, prefix = ledger_prefix(trust)
    payload = canonical(document) + b"\n"
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise ValueError("record exceeds the ledger size limit")
    version = ledger_slot_version(trust, name)
    if version is not None:
        confirm(version)
        return
    encryption = ["--server-side-encryption", "AES256"] if "ledgerReplica" in trust else []
    write_error = None
    acknowledged_version = None
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "record.json"
        path.write_bytes(payload)
        if before_write is not None:
            before_write()
        try:
            response = storage(trust, "put-object",
                               ["--key", prefix + name, "--if-none-match", "*", "--body", str(path), *encryption])
            acknowledged_version = ledger_record_version(name, response)
        except (ValueError, subprocess.TimeoutExpired) as error:
            write_error = error
    try:
        version = ledger_slot_version(trust, name)
        if version is None:
            raise ValueError(f"custody ledger object missing after write: {name}")
        if acknowledged_version is not None and version != acknowledged_version:
            raise ValueError(f"custody ledger record {name} differs from its acknowledged version")
        confirm(version)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as read_error:
        if write_error is None:
            raise
        raise ValueError(f"could not confirm ledger write ({write_error}). Readback failed ({read_error})") from None


def list_objects(trust, name, **options):
    ledger, prefix = ledger_prefix(trust)
    scope = prefix + name
    args = ["--prefix", scope, "--max-keys", "100", "--no-paginate"]
    continuation = []
    last_key = ""
    seen_tokens = set()
    while True:
        page = storage(trust, "list-objects-v2", [*args, *continuation], **options)
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


def list_ledger_versions(trust, *, exact=None, **options):
    ledger, prefix = ledger_prefix(trust)
    scope = prefix if exact is None else prefix + exact
    page_size = 32
    args = ["--prefix", scope, "--max-keys", str(page_size), "--no-paginate"]
    continuation = []
    seen_markers = set()
    versions = {}
    while True:
        page = storage(trust, "list-object-versions", [*args, *continuation], **options)
        if not isinstance(page, dict):
            raise ValueError("invalid custody ledger version listing")
        entries = page.get("Versions", [])
        deletes = page.get("DeleteMarkers", [])
        truncated = page.get("IsTruncated")
        if (page.get("Name") != ledger["bucket"] or page.get("Prefix") != scope or
                type(truncated) is not bool or not isinstance(entries, list) or not isinstance(deletes, list) or
                len(entries) + len(deletes) > page_size or page.get("CommonPrefixes", []) != []):
            raise ValueError("invalid custody ledger version listing")
        for entry in deletes:
            key = entry.get("Key") if isinstance(entry, dict) else None
            if not isinstance(key, str) or not key.startswith(scope):
                raise ValueError("invalid custody ledger delete marker")
            if exact is None or key == scope:
                raise ValueError("custody ledger contains delete markers")
        for entry in entries:
            key = entry.get("Key") if isinstance(entry, dict) else None
            if not isinstance(key, str) or not key.startswith(scope):
                raise ValueError("custody ledger requires one current version per record")
            if exact is not None and key != scope:
                continue
            if entry.get("IsLatest") is not True:
                raise ValueError("custody ledger requires one current version per record")
            name = key[len(prefix):]
            if name in versions:
                raise ValueError("custody ledger requires one current version per record")
            versions[name] = ledger_record_version(name, entry)
        if not truncated:
            if "NextKeyMarker" in page or "NextVersionIdMarker" in page:
                raise ValueError("invalid custody ledger version continuation")
            return versions
        key, version = page.get("NextKeyMarker"), page.get("NextVersionIdMarker")
        if (not (entries or deletes) or not isinstance(key, str) or not key.startswith(scope) or
                not isinstance(version, str) or not version or version == "null" or (key, version) in seen_markers):
            raise ValueError("invalid custody ledger version continuation")
        seen_markers.add((key, version))
        continuation = ["--cli-input-json", canonical({"KeyMarker": key, "VersionIdMarker": version}).decode()]


def ledger_reader_policy(trust):
    ledger, prefix = ledger_prefix(trust)
    bucket = f"arn:aws:s3:::{ledger['bucket']}"
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "ReadCustodyRecords", "Effect": "Allow", "Action": "s3:GetObject", "Resource": f"{bucket}/{prefix}*"},
        {"Sid": "ListCustodyRecords", "Effect": "Allow", "Action": ["s3:ListBucket", "s3:ListBucketVersions"], "Resource": bucket,
         "Condition": {"StringLike": {"s3:prefix": f"{prefix}*"}}},
    ]}


def custody_history_statement(trust, *, frozen=False):
    ledger, prefix = ledger_prefix(trust)
    actions = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:ReplicateObject", "s3:ReplicateDelete"]
    if frozen:
        actions.append("s3:PutObject")
    return {"Sid": "PreserveCustodyHistory", "Effect": "Deny", "Principal": "*",
            "Resource": f"arn:aws:s3:::{ledger['bucket']}/{prefix}*", "Action": actions}


def replica_history_statements(destination, role):
    history = custody_history_statement(destination, frozen=True)
    history["Action"].remove("s3:ReplicateObject")
    restriction = {"Sid": "RestrictReplication", "Effect": "Deny", "Principal": "*", "Action": "s3:ReplicateObject",
                   "Resource": history["Resource"], "Condition": {"StringNotEquals": {"aws:PrincipalArn": role}}}
    return history, restriction


def ledger_replica(trust):
    if "ledgerReplica" not in trust:
        return None
    replica = trust["ledgerReplica"]
    fields(replica, *LEDGER_FIELDS, "role")
    source, _ = ledger_prefix(trust)
    destination, _ = ledger_prefix(replica_trust(trust, replica))
    if (any(source[field] == destination[field] for field in ("bucket", "account", "region")) or
            arn(ROLE_ARN, replica["role"])[1] != source["account"]):
        raise ValueError("ledger replication requires a source role and a separate bucket, account and region")
    if replica["role"] in {source["administratorRole"], source["publisherRole"], *source["readerRoles"]}:
        raise ValueError("ledger replication requires its own role")
    return replica


def replica_trust(trust, replica):
    return {"network": trust["network"], "securityDomainId": trust["securityDomainId"],
            "ledger": {name: replica[name] for name in LEDGER_FIELDS}}


def replica_with_record(trust, replica, name):
    destination = replica_trust(trust, replica)
    return destination if name in list_ledger_versions(destination, exact=name) else None


def replication_configuration(trust, replica):
    _, prefix = ledger_prefix(trust)
    return {"Role": replica["role"], "Rules": [{
        "ID": "spr-custody", "Priority": 1, "Status": "Enabled", "Filter": {"Prefix": prefix},
        "DeleteMarkerReplication": {"Status": "Disabled"},
        "Destination": {"Bucket": f"arn:aws:s3:::{replica['bucket']}", "StorageClass": "STANDARD"},
    }]}


def ledger_administration_statement(trust):
    ledger, _ = ledger_prefix(trust)
    return {
        "Sid": "RestrictBucketAdministration", "Effect": "Deny", "Principal": "*",
        "Action": ["s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:PutBucketPolicy", "s3:PutBucketVersioning",
                   "s3:PutLifecycleConfiguration", "s3:PutReplicationConfiguration", "s3:PutBucketOwnershipControls",
                   "s3:PutBucketAcl", "s3:PutBucketPublicAccessBlock", "s3:PutEncryptionConfiguration",
                   "s3:PutBucketObjectLockConfiguration"],
        "Resource": f"arn:aws:s3:::{ledger['bucket']}",
        "Condition": {"StringNotEquals": {"aws:PrincipalArn": ledger["administratorRole"]}},
    }


def ledger_policy(trust, *, frozen=False):
    read, listing = ledger_reader_policy(trust)["Statement"]
    ledger = trust["ledger"]
    administrator, publisher, readers = (ledger[name] for name in ("administratorRole", "publisherRole", "readerRoles"))
    resource = read["Resource"]
    data_roles = {publisher, *readers}
    replica = ledger_replica(trust)
    replica_role = {replica["role"]} if replica is not None else set()
    principals = {"AWS": sorted(data_roles)}
    allowed_to_read = [administrator, *sorted(data_roles | replica_role)]
    policy = {"Version": "2012-10-17", "Statement": [
        ledger_administration_statement(trust),
        {"Sid": "RestrictRecordReads", "Effect": "Deny", "Principal": "*", "Action": "s3:GetObject*", "Resource": resource,
         "Condition": {"StringNotEquals": {"aws:PrincipalArn": allowed_to_read}}},
        {"Sid": "RestrictBucketListing", "Effect": "Deny", "Principal": "*", "Action": "s3:ListBucket*",
         "Resource": listing["Resource"], "Condition": {"StringNotEquals": {"aws:PrincipalArn": allowed_to_read}}},
        {"Sid": "RequireWriteOnce", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
         "Resource": resource, "Condition": {"StringNotEquals": {"s3:if-none-match": "*"}}},
        {"Sid": "RestrictPublisher", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
         "Resource": resource, "Condition": {"StringNotEquals": {"aws:PrincipalArn": publisher}}},
        custody_history_statement(trust, frozen=frozen),
        {"Sid": "AllowPublisher", "Effect": "Allow", "Principal": {"AWS": publisher},
         "Action": "s3:PutObject", "Resource": resource},
        {**read, "Principal": principals},
        {**listing, "Principal": principals},
    ]}
    if replica is not None:
        policy["Statement"].append(
            {"Sid": "RequireSseS3", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject", "Resource": resource,
             "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption": "AES256"}}},
        )
    return policy


def recovery_bucket_policy(trust, replica):
    destination = replica_trust(trust, replica)
    policy = ledger_policy(destination, frozen=True)
    history, restriction = replica_history_statements(destination, replica["role"])
    policy["Statement"] = [history if rule["Sid"] == history["Sid"] else rule for rule in policy["Statement"]]
    policy["Statement"].extend([
        restriction,
        {"Sid": "AllowReplication", "Effect": "Allow", "Principal": {"AWS": replica["role"]},
         "Action": "s3:ReplicateObject", "Resource": history["Resource"]},
    ])
    return policy


def ledger_replica_plan(trust):
    replica = ledger_replica(trust)
    if replica is None:
        raise ValueError("pin ledgerReplica before configuring replication")
    source, prefix = ledger_prefix(trust)
    role = replica["role"]
    destination_policy = recovery_bucket_policy(trust, replica)
    resource = f"arn:aws:s3:::{replica['bucket']}/{prefix}*"
    source_bucket = f"arn:aws:s3:::{source['bucket']}"
    return {
        "replication": replication_configuration(trust, replica),
        "roleTrust": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sts:AssumeRole",
        }]},
        "rolePermissions": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetReplicationConfiguration", "s3:ListBucket"], "Resource": source_bucket,
             "Condition": {"StringEquals": {"s3:ResourceAccount": source["account"]}}},
            {"Effect": "Allow", "Action": ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl"],
             "Resource": f"{source_bucket}/{prefix}*", "Condition": {"StringEquals": {"s3:ResourceAccount": source["account"]}}},
            {"Effect": "Allow", "Action": "s3:ReplicateObject", "Resource": resource,
             "Condition": {"StringEquals": {"s3:ResourceAccount": replica["account"]}}},
        ]},
        "destinationPolicy": destination_policy,
    }


def installed_ledger_policy(trust, **options):
    policy = storage(trust, "get-bucket-policy", **options).get("Policy")
    if not isinstance(policy, str):
        raise ValueError("custody ledger bucket did not return a policy")
    return parse_json(policy)


def require_no_ledger_lifecycle(trust, **options):
    if storage(trust, "get-bucket-lifecycle-configuration", absent="NoSuchLifecycleConfiguration", **options) is not None:
        raise ValueError("custody ledger bucket must have no lifecycle configuration")


def require_frozen_ledger(trust, **options):
    policy = installed_ledger_policy(trust, **options)
    statements = policy.get("Statement") if isinstance(policy, dict) else None
    if not isinstance(statements, list) or custody_history_statement(trust, frozen=True) not in statements:
        raise ValueError("custody ledger checkpoint requires the frozen bucket policy")
    if ledger_administration_statement(trust) not in statements:
        raise ValueError("custody ledger is missing the pinned bucket administration policy")
    check_ledger_bucket_controls(trust, **options)


def check_ledger_bucket_controls(trust, **options):
    if storage(trust, "get-bucket-versioning", **options).get("Status") != "Enabled":
        raise ValueError("custody ledger bucket requires versioning")
    ownership = storage(trust, "get-bucket-ownership-controls", **options).get("OwnershipControls")
    if ownership != {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}:
        raise ValueError("custody ledger bucket requires bucket-owner-enforced ownership")
    public_access = storage(trust, "get-public-access-block", **options).get("PublicAccessBlockConfiguration")
    if not isinstance(public_access, dict) or any(public_access.get(flag) is not True for flag in (
        "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets",
    )):
        raise ValueError("custody ledger bucket requires all four public access blocks")
    require_no_ledger_lifecycle(trust, **options)


def check_installed_ledger(trust, expected_policy, **options):
    if installed_ledger_policy(trust, **options) != expected_policy:
        raise ValueError("custody ledger bucket policy differs from the pinned policy")
    check_ledger_bucket_controls(trust, **options)
    require_pinned_replication(trust, **options)


def check_source_ledger(trust, profile):
    source, _ = ledger_prefix(trust)
    require_profile_account(profile, source["region"], source["account"])
    check_installed_ledger(trust, ledger_policy(trust), profile=profile)


def require_replication_role(trust, replica, *, profile=None):
    source, _ = ledger_prefix(trust)
    name = replica["role"].rsplit("/", 1)[-1]
    plan = ledger_replica_plan(trust)

    def inspect(operation, *args):
        return aws(source["region"], "iam", operation, ["--role-name", name, *args], profile=profile)

    role = inspect("get-role").get("Role")
    if not isinstance(role, dict) or role.get("Arn") != replica["role"]:
        raise ValueError("installed replication role is not the pinned ARN")
    if role.get("AssumeRolePolicyDocument") != plan["roleTrust"]:
        raise ValueError("installed replication role trust policy differs from the pinned policy")
    policies = inspect("list-role-policies").get("PolicyNames")
    if not isinstance(policies, list) or len(policies) != 1 or not isinstance(policies[0], str) or not policies[0]:
        raise ValueError("installed replication role requires one inline policy")
    if inspect("list-attached-role-policies").get("AttachedPolicies") != []:
        raise ValueError("installed replication role has managed policies or an invalid policy listing")
    if inspect("get-role-policy", "--policy-name", policies[0]).get("PolicyDocument") != plan["rolePermissions"]:
        raise ValueError("installed replication role permissions differ from the pinned policy")


def require_pinned_replication(trust, **options):
    replication = storage(trust, "get-bucket-replication", absent="ReplicationConfigurationNotFoundError", **options)
    replica = ledger_replica(trust)
    if replica is None:
        if replication is not None:
            raise ValueError("custody ledger bucket must have no replication configuration")
        return
    if replication is None or replication.get("ReplicationConfiguration") != replication_configuration(trust, replica):
        raise ValueError("installed S3 replication does not match the pinned ledger replica")
    require_replication_role(trust, replica, **options)


def check_recovery_bucket(trust, replica, profile):
    destination = replica_trust(trust, replica)
    require_profile_account(profile, replica["region"], replica["account"])
    check_ledger_bucket_controls(destination, profile=profile)
    if installed_ledger_policy(destination, profile=profile) != recovery_bucket_policy(trust, replica):
        raise ValueError("custody recovery bucket policy differs from the pinned policy")


def read_epoch_record(trust, epoch, **options):
    document, metadata = read_stored_object(trust, ledger_object(trust, epoch), **options)
    receipt, custodians = record(trust, document)
    if receipt["custody"]["epoch"] != epoch:
        raise ValueError("canonical custody receipt belongs to another epoch")
    check_commit(trust, document, receipt, custodians)
    return document, receipt, custodians, publication_time(metadata)


def load_epoch_with_time(trust, epoch, *, expected_version=None, **options):
    document, receipt, custodians, published_at = read_epoch_record(trust, epoch, expected_version=expected_version, **options)
    check_previous(trust, document, receipt, published_at=published_at, **options)
    return document, receipt, custodians, published_at


def load_epoch(trust, epoch, **options):
    document, receipt, custodians, _ = load_epoch_with_time(trust, epoch, **options)
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


def target_fields(manifest):
    fields(manifest, "network", "securityDomainId", "custodyEpoch", "receiptSha256", "releaseId", "mode", "expiresAt",
           "eifSha256", "configurationSha256", "executableSha256", "pcrs", "hostRole", "hostRegion", "instanceId", "wrappingKeys",
           "nextCustodians", "nextRelay", "approvalFromEpoch")


def validate_target(trust, manifest):
    target_fields(manifest)
    epoch = manifest["custodyEpoch"]
    network, domain = manifest["network"], manifest["securityDomainId"]
    validate_scope(network, domain, manifest["releaseId"], epoch)
    if (network, domain) != (trust["network"], trust["securityDomainId"]):
        raise ValueError("target is outside the pinned custody domain")
    if not isinstance(manifest["hostRegion"], str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+", manifest["hostRegion"]):
        raise ValueError("expected an EC2 region")
    arn(ROLE_ARN, manifest["hostRole"])
    fields(manifest["pcrs"], "PCR0", "PCR1", "PCR2")
    target_attestation(manifest)
    relay_pins(trust, epoch)
    if manifest["mode"] == "rotate":
        if manifest["nextRelay"] != relay_pins(trust, str(int(epoch) + 1)):
            raise ValueError("rotation does not match the successor's pinned recovery relay")
        validate_roster(trust, manifest["nextCustodians"], manifest["hostRole"])
    elif manifest["mode"] != "serve" or manifest["nextRelay"] is not None or manifest["nextCustodians"] is not None:
        raise ValueError("expected a serving target with no successor or a rotation target")


def verify_target_approval(trust, document, *, at=None):
    fields(document, "manifest", "signatures")
    manifest = document["manifest"]
    validate_target(trust, manifest)
    at = time.time() if at is None else at
    require_target_approval_window(manifest, at)
    roster = approval_roster(trust, at=at)
    if roster["fromEpoch"] != manifest["approvalFromEpoch"]:
        raise ValueError("target approval roster does not match its publication time")
    check_approvals(roster["keys"], TARGET_APPROVAL, document)
    return manifest


def read_registered_target_record(trust, name, epoch, receipt_digest, *, receipt_at=None, **options):
    document, metadata = read_stored_object(trust, name, **options)
    published_at = publication_time(metadata)
    target = check_registered_target(trust, name, epoch, receipt_digest, document, published_at)
    if receipt_at is not None and published_at < receipt_at:
        raise ValueError("target registration precedes its custody receipt")
    return target, published_at


def read_registered_target(trust, name, epoch, receipt_digest, **options):
    target, _ = read_registered_target_record(trust, name, epoch, receipt_digest, **options)
    return target


def check_registered_target(trust, name, epoch, receipt_digest, document, published_at):
    target = verify_target_approval(trust, document, at=published_at)
    if (name != target_object_name(target) or
            (target["network"], target["securityDomainId"], target["custodyEpoch"], target["receiptSha256"]) !=
            (trust["network"], trust["securityDomainId"], epoch, receipt_digest)):
        raise ValueError("registered target does not match the committed custody receipt")
    return target


def retirement_approval(document):
    fields(document, "manifest", "signatures", "recoveryProofs")
    return {"manifest": document["manifest"], "signatures": document["signatures"]}


def retirement_bootstrap(bootstrap):
    fields(bootstrap, "bootKeyId", "bootedAtMs", "slots")
    hex_digest(bootstrap["bootKeyId"])
    if epoch_number(bootstrap["bootedAtMs"]) >= 2**53:
        raise ValueError("invalid replacement boot time")
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
    booted_at = epoch_number(manifest["replacementBootstrap"]["bootedAtMs"]) // 1000
    if type(deadline) is not int or deadline != booted_at + RECOVERY_WINDOW_SECONDS:
        raise ValueError("retirement deadline must be measured from the replacement boot")
    return deadline


def verify_retirement(trust, document, epoch, verified_at, *, requalification=False):
    approval = retirement_approval(document)
    manifest = document["manifest"]
    extra_fields = ("priorRetirementSha256",) if requalification else ()
    fields(manifest, "network", "securityDomainId", "epoch", "receiptSha256", "replacementEpoch",
           "replacementReceiptSha256", "replacementCustodyDigest", "replacementTargetIdentity", "replacementTargetSha256",
           "approvalFromEpoch", "walletPolicyDigest", "recoveryDeadline", "replacementBootstrap", *extra_fields)
    retirement_bootstrap(manifest["replacementBootstrap"])
    deadline = recovery_deadline(manifest)
    if not deadline - RECOVERY_WINDOW_SECONDS <= verified_at < deadline:
        raise ValueError("retirement record is outside the recovery window")
    if ((manifest["network"], manifest["securityDomainId"], manifest["epoch"]) !=
            (trust["network"], trust["securityDomainId"], epoch) or
            epoch_number(manifest["replacementEpoch"]) <= epoch_number(epoch)):
        raise ValueError("retirement record does not match the requested epoch")
    for field in ("receiptSha256", "replacementReceiptSha256", "replacementCustodyDigest", "replacementTargetIdentity",
                  "replacementTargetSha256", "walletPolicyDigest"):
        hex_digest(manifest[field])
    roster = approval_roster(trust, at=verified_at)
    if roster["fromEpoch"] != manifest["approvalFromEpoch"]:
        reference = "the verification time" if requalification else "its publication time"
        raise ValueError(f"retirement approval roster does not match {reference}")
    check_approvals(roster["keys"], RETIREMENT, approval)
    return manifest


def retirement_target(trust, marker, *, receipt_at=None, retired_at=None, **options):
    replacement = marker["replacementEpoch"]
    name = target_path(replacement, marker["replacementTargetIdentity"])
    target, registered_at = read_registered_target_record(trust, name, replacement, marker["replacementReceiptSha256"],
                                                          receipt_at=receipt_at, **options)
    if retired_at is not None and retired_at < registered_at:
        raise ValueError("retirement precedes its replacement target registration")
    if target["mode"] != "serve" or sha256(target) != marker["replacementTargetSha256"]:
        raise ValueError("replacement target does not match the registered serving enclave")
    return target


def load_retirement(trust, epoch, *, expected_version=None, **options):
    document, metadata = read_stored_object(trust, retirement_object_name(epoch), expected_version=expected_version, **options)
    published_at = publication_time(metadata)
    marker = verify_retirement(trust, document, epoch, published_at)
    _, previous, custodians, previous_at = load_epoch_with_time(trust, epoch, **options)
    replacement_epoch = marker["replacementEpoch"]
    _, replacement, replacement_custodians, replacement_at = load_epoch_with_time(trust, replacement_epoch, **options)
    if published_at < max(previous_at, replacement_at):
        raise ValueError("retirement precedes a custody receipt it depends on")
    if (marker["receiptSha256"] != sha256(previous) or marker["replacementReceiptSha256"] != sha256(replacement) or
            marker["replacementCustodyDigest"] != sha256(replacement["custody"]) or
            note_identity(previous["custody"]) != note_identity(replacement["custody"])):
        raise ValueError("retirement receipts do not match the ledger")
    retirement_recovery(document, replacement_custodians)
    retirement_target(trust, marker, receipt_at=replacement_at, retired_at=published_at, **options)
    return document, custodians, published_at


def find_retirement(trust, epoch):
    name = retirement_object_name(epoch)
    version = list_ledger_versions(trust, exact=name).get(name)
    if version is None:
        return None
    try:
        document, _, _ = load_retirement(trust, epoch, expected_version=version)
        return document, version
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        raise ValueError(f"cannot verify retirement record for epoch {epoch}: {error}") from error


def require_active_epoch(trust, epoch):
    # Read the source last so a closure still replicating can block admission.
    replica = ledger_replica(trust)
    if replica is not None and replica_with_record(trust, replica, retirement_object_name(epoch)) is not None:
        raise ValueError("custody epoch has a retirement record in the pinned replica")
    if find_retirement(trust, epoch) is not None:
        raise ValueError("custody epoch is retired")


def require_pinned_publications(trust, publications):
    pinned = trust.get("publications")
    if not isinstance(pinned, list) or len(pinned) != 2 or pinned != publications:
        raise ValueError("wallet policy publications must match the pinned primary and mirror")
    for publication in pinned:
        fields(publication, "bucket", "region", "account")
        for field, pattern in (
            ("bucket", r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]"),
            ("region", r"[a-z]{2}-[a-z]+-[1-9][0-9]*"),
            ("account", r"[0-9]{12}"),
        ):
            if not isinstance(publication[field], str) or not re.fullmatch(pattern, publication[field]):
                raise ValueError(f"invalid publication {field}")
    if any(pinned[0][field] == pinned[1][field] for field in ("bucket", "account")):
        raise ValueError("wallet publications require separate buckets and accounts")


def wrapping_pairs(target, custodians):
    wrapping_keys = target["wrappingKeys"]
    if not isinstance(wrapping_keys, list) or len(wrapping_keys) != 6:
        raise ValueError("target requires six custody slots")
    accounts = {arn(ROLE_ARN, target["hostRole"])[1]}
    pairs = []
    for member, wrapping in zip(custodians, wrapping_keys, strict=True):
        recovery = member["recoveryKeyArn"]
        account = arn(KEY_ARN, recovery)[2]
        if (account in accounts or recovery == wrapping or arn(KEY_ARN, wrapping)[2] != account or
                arn(ROLE_ARN, member["custodianRole"])[1] != account or
                arn(ROLE_ARN, member["retirementRole"])[1] != account):
            raise ValueError("each custody slot requires separate keys and roles in its own account")
        accounts.add(account)
        pairs.append((recovery, wrapping))
    return pairs


def require_payment_recovery_quorums(trust, target_slots, profiles):
    expected = {}
    accounts = {}
    for epoch, target, custodians, pairs, _ in target_slots:
        for (recovery, wrapping), member in zip(pairs, custodians, strict=True):
            custodian, admin = member["custodianRole"], member["retirementRole"]
            for key, policy in (
                (recovery, custody_recovery_policy(trust, member, epoch)),
                (wrapping, key_policy(target["hostRole"], custodian, admin, target["pcrs"], target["instanceId"])),
            ):
                if expected.setdefault(key, policy) != policy:
                    raise ValueError("custody targets require different sealed policies for the same key")
                region, account = arn(KEY_ARN, key).groups()
                if account in profiles:
                    accounts.setdefault(account, region)

    def verify_account(account):
        try:
            require_profile_account(profiles[account], accounts[account], account)
        except ValueError:
            return False
        return True

    def qualified(key):
        account = arn(KEY_ARN, key)[2]
        if account not in verified_accounts:
            return False
        try:
            _, policy = inspect_rsa_key(key, profile=profiles[account])
            return policy == expected[key]
        except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired):
            return False

    def verify_target(entry):
        epoch, target, _, pairs, bootstrapped = entry
        release = target["releaseId"]
        ready = {slot for slot, (recovery, wrapping) in enumerate(pairs, 1)
                 if recovery in available and wrapping in available}
        if len(ready) < 3:
            raise ValueError(f"custody epoch {epoch} target {release} requires three enabled recovery and wrapping pairs with approved policies")
        if bootstrapped is not None and not ready.issuperset(bootstrapped):
            raise ValueError(f"custody epoch {epoch} target {release} has an unavailable attested bootstrap slot")
        require_bootstrap_access(target, profiles.get(arn(ROLE_ARN, target["hostRole"])[1]))

    with ThreadPoolExecutor(max_workers=min(len(expected), 24)) as workers:
        verified_accounts = {account for account, valid in zip(accounts, workers.map(verify_account, accounts), strict=True)
                             if valid}
        available = {key for key, valid in zip(expected, workers.map(qualified, expected), strict=True) if valid}
        list(workers.map(verify_target, target_slots))


def check_release_policy(trust, document, custody_signer=None, *, source_profile=None, replica_profile=None,
                         key_profiles=None, bootstrap_slots=None):
    fields(document, "policy", "signatures", "custodySignatures")
    policy = document["policy"]
    targets = policy["targets"]
    if type(policy["recoveryOnly"]) is not bool:
        raise ValueError("expected a recoveryOnly boolean")
    if (policy["network"], policy["securityDomainId"]) != (trust["network"], trust["securityDomainId"]):
        raise ValueError("wallet policy does not match the pinned custody domain")
    require_pinned_publications(trust, policy.get("publications"))
    if policy["action"] == "revoke" and targets == []:
        return None
    if policy["action"] != "activate" or not isinstance(targets, list) or not 1 <= len(targets) <= 8:
        raise ValueError("expected an activation with one to eight serving targets")
    ledger_backup = ledger_replica(trust)
    mainnet = trust["network"] == "mainnet"
    if ledger_backup is None and mainnet:
        raise ValueError("mainnet activation requires a pinned custody ledger replica")
    verify_payment_recovery = not policy["recoveryOnly"] and (
        mainnet or source_profile is not None or replica_profile is not None or key_profiles is not None
    )
    if verify_payment_recovery and (not source_profile or not replica_profile):
        raise ValueError("payment activation requires both --source-profile and --replica-profile")
    if verify_payment_recovery:
        require_custody_key_profiles(key_profiles)
    if verify_payment_recovery and ledger_backup is None:
        raise ValueError("payment recovery verification requires a pinned custody ledger replica")
    if bootstrap_slots is not None and (
            not verify_payment_recovery or not isinstance(bootstrap_slots, list) or len(bootstrap_slots) != len(targets) or
            any(not isinstance(slots, list) or len(slots) != 3 or
                any(type(slot) is not int or slot not in range(1, 7) for slot in slots) or len(set(slots)) != 3
                for slots in bootstrap_slots)):
        raise ValueError("expected three distinct attested bootstrap slots in policy target order")
    by_epoch = {}
    floor = epoch_number(policy["minimumCustodyEpoch"])
    for index, target in enumerate(targets):
        epoch = target["custodyEpoch"]
        if epoch_number(epoch) < floor:
            raise ValueError("serving target is below the wallet custody floor")
        slots = None if bootstrap_slots is None else bootstrap_slots[index]
        by_epoch.setdefault(epoch, []).append((target, slots))

    def check_epoch(item):
        epoch, replicas = item
        observed = {}
        _, receipt, custodians, receipt_at = load_epoch_with_time(trust, epoch, observed_records=observed)
        custody = receipt["custody"]
        if policy["noteSeedCommitment"] != custody["noteSeedCommitment"]:
            raise ValueError("wallet policy does not match the committed note seed")
        custody_digest, receipt_digest = sha256(custody), sha256(receipt)
        target_slots = []
        for replica, slots in replicas:
            if replica["custodyDigest"] != custody_digest:
                raise ValueError("serving target does not match the committed custody record")
            identity = {"releaseId": replica["releaseId"], "pcrs": replica["pcrs"]}
            name = target_path(epoch, sha256(identity))
            registered = read_registered_target(trust, name, epoch, receipt_digest, receipt_at=receipt_at,
                                                observed_records=observed)
            if (registered["mode"] != "serve" or
                    hex_digest(registered["executableSha256"]) != replica["executableSha256"]):
                raise ValueError("serving executable does not match the custody-approved target")
            pairs = wrapping_pairs(registered, custodians)
            target_slots.append((epoch, registered, custodians, pairs, slots))
        return observed, target_slots, custody["canaryDigest"]

    with ThreadPoolExecutor(max_workers=len(by_epoch)) as workers:
        readiness = list(workers.map(check_epoch, by_epoch.items()))
        canary_digests = {digest for _, _, digest in readiness}
        if len(canary_digests) != 1:
            raise ValueError("serving targets must match the same custody canary")
        observed_records = {}
        for observed, _, _ in readiness:
            for name, fingerprint in observed.items():
                observe_record(observed_records, name, fingerprint)
        if verify_payment_recovery:
            require_payment_recovery_quorums(trust, [target for _, targets, _ in readiness for target in targets], key_profiles)
            check_source_ledger(trust, source_profile)
            check_recovery_bucket(trust, ledger_backup, replica_profile)
        if ledger_backup is not None:
            require_replicated_custody(trust, ledger_backup, max(by_epoch, key=epoch_number), observed_records)
        # Check retirement after reading receipts, targets and key state.
        list(workers.map(lambda epoch: require_active_epoch(trust, epoch), by_epoch))
    now = time.time()
    roster = approval_roster(trust, at=now)
    keys = [(pin["keyArn"], signing_sec1(pin)) for pin in roster["keys"]]
    if custody_signer is not None and tuple(custody_signer) not in keys:
        raise ValueError("custody policy signer must match a key in the active custody approval roster")
    next_cutover = next((str(entry["activeFrom"]) for entry in trust["approvalKeys"] if entry["activeFrom"] > now), None)
    return {"custodyKeys": [public for _, public in keys], "nextCutover": next_cutover,
            "canaryDigest": canary_digests.pop(), "ledgerDigest": sha256(observed_records)}


def draft(trust, capture, build, host, roster):
    epoch = int(capture["receipt"]["custody"]["epoch"])
    previous = None if epoch == 1 else sha256(load_epoch(trust, str(epoch - 1))[1])
    manifest = {
        "capture": capture, "ceremonyEifSha256": file_digest(build / "enclave.eif"), "ceremonyHostRole": host,
        "custodians": roster, "relay": relay_pins(trust, str(epoch)),
        "previousReceiptSha256": previous, "rotationTargetSha256": None,
    }
    if epoch != 1:
        target, _ = read_rotation_target(trust, manifest, str(epoch - 1))
        if target["configurationSha256"] != file_digest(build / "configuration.json"):
            raise ValueError("ceremony build configuration does not match the registered rotation target")
        manifest["rotationTargetSha256"] = sha256(target)
    document = {"authorization": {"manifest": manifest, "signatures": []}, "acknowledgements": []}
    record(trust, document)
    return document


def rotation_target_name(manifest, previous_epoch):
    capture = manifest["capture"]
    pcrs = capture["pcrs"]
    fields(pcrs, "0", "1", "2", "3", "4")
    identity = {"releaseId": capture["receipt"]["releaseId"], "pcrs": pcrs}
    return target_path(previous_epoch, sha256(identity))


def read_rotation_target(trust, manifest, previous_epoch, **options):
    name = rotation_target_name(manifest, previous_epoch)
    target, published_at = read_registered_target_record(trust, name, previous_epoch, manifest["previousReceiptSha256"], **options)
    check_rotation_target(manifest, target)
    return target, published_at


def check_rotation_target(manifest, target):
    pcrs = manifest["capture"]["pcrs"]
    if (target["mode"] != "rotate" or target["hostRole"] != manifest["ceremonyHostRole"] or
            pcrs != target_attestation(target)["pcrs"] or target["eifSha256"] != manifest["ceremonyEifSha256"] or
            target["nextCustodians"] != manifest["custodians"] or target["nextRelay"] != manifest["relay"]):
        raise ValueError("ceremony image or successor roster does not match the registered rotation target")


def check_predecessor(document, receipt, predecessor, previous_roster):
    manifest = document["authorization"]["manifest"]
    if (sha256(predecessor) != manifest["previousReceiptSha256"] or
            note_identity(predecessor["custody"]) != note_identity(receipt["custody"]) or
            predecessor["custody"] != manifest["capture"]["configuration"]["deployment"]["previous"]):
        raise ValueError("custody rotation does not descend from the canonical previous receipt")
    previous_keys = {custodian["recoveryKeyArn"] for custodian in previous_roster}
    if previous_keys & {custodian["recoveryKeyArn"] for custodian in manifest["custodians"]}:
        raise ValueError("custody rotation requires fresh recovery keys")


def require_rotation_order(previous_at, rotation_at, successor_at=None):
    if rotation_at < previous_at or (successor_at is not None and successor_at < rotation_at):
        raise ValueError("rotation registration must be recorded between the predecessor and successor receipts")


def check_previous(trust, document, receipt, *, published_at=None, **options):
    epoch = int(receipt["custody"]["epoch"])
    if epoch == 1:
        return
    previous_epoch = str(epoch - 1)
    _, predecessor, previous_roster, previous_at = read_epoch_record(trust, previous_epoch, **options)
    check_predecessor(document, receipt, predecessor, previous_roster)
    manifest = document["authorization"]["manifest"]
    target, rotation_at = read_rotation_target(trust, manifest, previous_epoch, **options)
    require_rotation_order(previous_at, rotation_at, published_at)
    if manifest["rotationTargetSha256"] != sha256(target):
        raise ValueError("custody record does not pin the registered rotation target")
    return target


def check_custody_history_entry(trust, epoch, entry, previous):
    fields(entry, "document", "publishedAt", "rotation")
    document, rotation = entry["document"], entry["rotation"]
    published_at = publication_time({"LastModified": entry["publishedAt"]})
    receipt, custodians = record(trust, document)
    if receipt["custody"]["epoch"] != epoch:
        raise ValueError("custody history epochs must be consecutive from genesis")
    check_commit(trust, document, receipt, custodians)
    manifest = document["authorization"]["manifest"]
    if previous is None:
        if rotation is not None:
            raise ValueError("genesis history cannot include a rotation")
    else:
        predecessor, previous_roster, previous_at = previous
        check_predecessor(document, receipt, predecessor, previous_roster)
        fields(rotation, "approval", "publishedAt")
        prior_epoch = predecessor["custody"]["epoch"]
        rotation_at = publication_time({"LastModified": rotation["publishedAt"]})
        target = check_registered_target(
            trust, rotation_target_name(manifest, prior_epoch), prior_epoch, sha256(predecessor),
            rotation["approval"], rotation_at,
        )
        require_rotation_order(previous_at, rotation_at, published_at)
        check_rotation_target(manifest, target)
        if manifest["rotationTargetSha256"] != sha256(target):
            raise ValueError("custody record does not pin the registered rotation target")
    return receipt, custodians, published_at


def check_custody_roster(trust, epoch, custodians, fingerprints, inspection_profiles, relay_build=None):
    require_inspection_profiles(inspection_profiles)
    if relay_build is None:
        raise ValueError("provide the recovery relay build and independent review")
    verify_relay_build(trust, epoch, *relay_build)
    for custodian, fingerprint, profile in zip(custodians, fingerprints, inspection_profiles, strict=True):
        recovery_key = custodian["recoveryKeyArn"]
        key = arn(KEY_ARN, recovery_key)
        require_profile_account(profile, key[1], key[2])
        expected = custody_recovery_policy(trust, custodian, epoch)
        public = sealed_rsa_key(recovery_key, expected, profile=profile)
        if hashlib.sha256(public).hexdigest() != fingerprint:
            raise ValueError("inspected recovery key does not match its recovery package")
        ack = custodian["acknowledgementKey"]
        if get_signing_key(ack["keyArn"], profile=profile) != ack:
            raise ValueError("acknowledgement public key does not match the custodian KMS key")
        check_acknowledgement_policy(custodian, profile=profile)


def check_acknowledgement_policy(custodian, **options):
    key = custodian["acknowledgementKey"]["keyArn"]
    expected = acknowledgement_policy(custodian["custodianRole"], custodian["retirementRole"])
    if parse_json(kms(key, "get-key-policy", ["--policy-name", "default"], **options)["Policy"]) != expected:
        raise ValueError("installed acknowledgement policy does not match the custodian role")


def require_receipt_keys(trust, epoch, custodians, key_profiles):
    require_custody_key_profiles(key_profiles)

    def check_slot(member):
        recovery = member["recoveryKeyArn"]
        acknowledgement = member["acknowledgementKey"]["keyArn"]
        region, account = arn(KEY_ARN, recovery).groups()
        profile = key_profiles.get(account)
        if profile is None:
            raise ValueError(f"missing read-only inspection profile for custody account {account}")
        require_profile_account(profile, region, account)
        try:
            _, installed = inspect_rsa_key(recovery, profile=profile)
            if installed != custody_recovery_policy(trust, member, epoch):
                raise ValueError("installed recovery key policy does not match the approved relay")
            metadata = kms(acknowledgement, "describe-key", profile=profile)["KeyMetadata"]
            require_kms_key(metadata, acknowledgement, {"ECC_NIST_P256"}, "SIGN_VERIFY")
            check_acknowledgement_policy(member, profile=profile)
        except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
            raise ValueError(f"custody account {account} has an unavailable key: {error}") from error

    with ThreadPoolExecutor(max_workers=6) as workers:
        list(workers.map(check_slot, custodians))


def verify_ceremony_capture(capture):
    root = Path(__file__).resolve().parents[3]
    subprocess.run(["pnpm", "--dir", str(root / "example"), "exec", "tsx",
                    str(root / "xtask/nitro-ceremony.ts"), "verify"],
                   input=canonical(capture), timeout=25, check=True)


def verify_reviewed_ceremony(manifest, target, build, review):
    capture = manifest["capture"]
    configuration = read_document(build / "configuration.json")
    config = parse_json(configuration)
    configuration_digest = hashlib.sha256(configuration).hexdigest()
    if target is not None and target["configurationSha256"] != configuration_digest:
        raise ValueError("ceremony build configuration does not match the registered rotation target")
    reviewed = verify_build(build, capture["receipt"]["network"], review)
    pins = target_attestation(target)["pcrs"] if target is not None else {
        name.removeprefix("PCR"): pin for name, pin in boot_pins(manifest["ceremonyHostRole"], reviewed["pcrs"]).items()
    }
    if (capture["configuration"] != config or configuration_digest != reviewed["configurationSha256"] or
            capture["pcrs"] != pins or manifest["ceremonyEifSha256"] != reviewed["eifSha256"] or
            (target is not None and (target["executableSha256"], target["pcrs"]) !=
             (reviewed["executableSha256"], reviewed["pcrs"]))):
        raise ValueError("captured ceremony does not match the verified build provenance")
    verify_ceremony_capture(capture)


def sign_epoch(trust, document, key, build, review, inspection_profiles=None, relay_build=None):
    receipt, custodians = record(trust, document)
    target = check_previous(trust, document, receipt)
    authorization = document["authorization"]
    verify_reviewed_ceremony(authorization["manifest"], target, build, review)
    epoch = receipt["custody"]["epoch"]
    check_custody_roster(trust, epoch, custodians, [package["recipientSha256"] for package in receipt["packages"]],
                         inspection_profiles, relay_build)
    keys = approval_keys(trust, epoch)
    return {**document, "authorization": add_approval(keys, LABEL, authorization, key)}


def sign_share_recovery(trust, custodians, receipt, index, label, approval, relay_port, *, require_window=None):
    if index not in range(1, 7):
        raise ValueError("invalid custody slot")
    epoch = receipt["custody"]["epoch"]

    def require_open_epoch():
        if require_window is not None:
            require_window()
        require_active_epoch(trust, epoch)
        if require_window is not None:
            require_window()

    require_open_epoch()
    custodian = custodians[index - 1]
    key = custodian["acknowledgementKey"]["keyArn"]
    check_acknowledgement_policy(custodian)
    prove_share(trust, receipt, custodian, index, relay_port, require_open_epoch)
    require_open_epoch()
    keys = [member["acknowledgementKey"] for member in custodians]
    signed = add_approval(keys, label, approval, key)
    require_open_epoch()
    return signed["signatures"]


def acknowledge(trust, document, index, relay_port, build, review):
    receipt, custodians = record(trust, document)
    authorization = document["authorization"]
    check_approvals(approval_keys(trust, receipt["custody"]["epoch"]), LABEL, authorization)
    target = check_previous(trust, document, receipt)
    verify_reviewed_ceremony(authorization["manifest"], target, build, review)
    signatures = sign_share_recovery(trust, custodians, receipt, index, ACKNOWLEDGEMENT, acknowledgements(document), relay_port)
    return {**document, "acknowledgements": signatures}


def publish(trust, document, *, key_profiles=None):
    receipt, custodians = record(trust, document)
    check_commit(trust, document, receipt, custodians)
    observed_records = {}
    check_previous(trust, document, receipt, observed_records=observed_records)
    authorization = document["authorization"]["manifest"]
    verify_ceremony_capture(authorization["capture"])
    epoch = receipt["custody"]["epoch"]

    def confirm(version):
        stored, _, _ = load_epoch(trust, epoch, expected_version=version, observed_records=observed_records)
        if canonical(stored["authorization"]["manifest"]) != canonical(authorization):
            raise ValueError("a different custody receipt is already committed")

    def before_write():
        require_receipt_keys(trust, epoch, custodians, key_profiles)
        check_previous(trust, document, receipt, observed_records=observed_records)
        require_active_epoch(trust, epoch)
        if epoch != "1":
            require_active_epoch(trust, str(epoch_number(epoch) - 1))

    write_once(trust, ledger_object(trust, epoch), document, confirm, before_write=before_write)


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
    sign.add_argument("--review", type=Path, required=True)
    sign.add_argument("--inspection-profiles", nargs=6, required=True)
    sign.add_argument("--relay-build", nargs=2, type=Path, metavar=("BUILD", "REVIEW"), required=True)
    ack = commands.add_parser("acknowledge")
    ack.add_argument("candidate", type=Path)
    ack.add_argument("build", type=Path)
    ack.add_argument("share", type=int, choices=range(1, 7))
    ack.add_argument("output", type=Path)
    ack.add_argument("--relay-port", type=int, required=True)
    ack.add_argument("--review", type=Path, required=True)
    post = commands.add_parser("publish")
    post.add_argument("candidate", type=Path)
    post.add_argument("--custody-key-profiles", type=Path, help="JSON map from custody AWS account to read-only profile")
    check = commands.add_parser("check-release-policy")
    check.add_argument("--source-profile")
    check.add_argument("--replica-profile")
    check.add_argument("--custody-key-profiles", type=Path, help="JSON map from custody and host accounts to read-only profiles")
    check.add_argument("--bootstrap-slots", help="JSON array of attested slot triples in policy target order")
    check.add_argument("candidate", type=Path)
    check.add_argument("--custody-signer", nargs=2, metavar=("KEY_ARN", "SEC1_HEX"))
    get = commands.add_parser("read")
    get.add_argument("epoch")
    get.add_argument("--custody-digest", action="store_true")
    policy = commands.add_parser("policy")
    policy.add_argument("--check-installed", action="store_true")
    policy.add_argument("--frozen", action="store_true", help="deny all object writes on this custody prefix")
    commands.add_parser("replica-plan")
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
            expected = ledger_policy(trust, frozen=args.frozen)
            if args.check_installed:
                check_installed_ledger(trust, expected)
                print("Custody ledger bucket controls verified")
            else:
                print(canonical(expected).decode())
            return
        if args.command == "replica-plan":
            print(canonical(ledger_replica_plan(trust)).decode())
            return
        if args.command == "reader-policy":
            print(canonical(ledger_reader_policy(trust)).decode())
            return
        if args.command == "recovery-policy":
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
        if args.command == "read":
            _, receipt, _ = load_epoch(trust, args.epoch)
            print(sha256(receipt["custody"]) if args.custody_digest else canonical(receipt).decode())
            return
        document = read_json(args.candidate)
        if args.command == "publish":
            profiles = read_json(args.custody_key_profiles) if args.custody_key_profiles else None
            publish(trust, document, key_profiles=profiles)
            return
        if args.command == "check-release-policy":
            slots = parse_json(args.bootstrap_slots.encode()) if args.bootstrap_slots is not None else None
            profiles = None
            if args.custody_key_profiles and document["policy"]["action"] == "activate" and document["policy"]["recoveryOnly"] is False:
                profiles = read_json(args.custody_key_profiles)
                require_custody_key_profiles(profiles)
            print(canonical(check_release_policy(trust, document, args.custody_signer,
                                                 source_profile=args.source_profile, replica_profile=args.replica_profile,
                                                 key_profiles=profiles, bootstrap_slots=slots)).decode())
            return
        signed = (sign_epoch(trust, document, args.key, args.build, args.review,
                             args.inspection_profiles, args.relay_build)
                  if args.command == "sign"
                  else acknowledge(trust, document, args.share, args.relay_port, args.build, args.review))
        publish_new_file(args.output, canonical(signed) + b"\n")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
