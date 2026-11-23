"""Close an old custody epoch and inventory the KMS keys that must be retired."""

import argparse
import hashlib
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from subprocess import run as run_command
from time import sleep

from approval import (
    KEY_ARN, MAX_DOCUMENT_BYTES, ROLE_ARN, add_approval, approval_keys, approval_roster, arn, aws, canonical, check_approvals,
    epoch_number, fields, hex_digest, kms,
    parse_json, publish_new_file, read_document, read_json, require_custody_key_profiles, require_inspection_profiles,
    require_profile_account, sha256,
)
from custody_ledger import (
    LEDGER_WRITE_MARGIN_SECONDS, RECOVERY_WINDOW_SECONDS, RETIREMENT, RETIREMENT_RECOVERY,
    check_recovery_bucket, check_registered_target, find_retirement, ledger_object, ledger_replica, ledger_slot_version,
    list_objects, load_epoch, load_epoch_with_time, load_retirement, note_identity, observe_record, publication_time,
    read_registered_target, read_replicated_record,
    recovery_deadline, replica_trust,
    require_active_epoch, require_pinned_publications,
    require_publication_roster, require_replicated_custody, retirement_approval, retirement_bootstrap,
    retirement_object_name, retirement_recovery, retirement_target, sign_share_recovery,
    target_attestation, target_path, verify_retirement, write_once,
)
from host import HostUnobserved, require_bootstrap_access, require_host_state
from kms_policy import key_policy
from relay import custody_recovery_policy, inspect_rsa_key


def retirement_scope(trust, epoch, replacement, **options):
    if epoch_number(replacement) <= epoch_number(epoch):
        raise ValueError("retirement requires a newer custody epoch")
    _, old, _, old_at = load_epoch_with_time(trust, epoch, **options)
    _, new, custodians, new_at = load_epoch_with_time(trust, replacement, **options)
    if time.time() < max(old_at, new_at):
        raise ValueError("retirement cannot precede a committed custody receipt")
    if note_identity(old["custody"]) != note_identity(new["custody"]):
        raise ValueError("replacement epoch must preserve the note seed and canary")
    return {
        "network": trust["network"], "securityDomainId": trust["securityDomainId"],
        "epoch": epoch, "receiptSha256": sha256(old), "replacementEpoch": replacement,
        "replacementReceiptSha256": sha256(new), "replacementCustodyDigest": sha256(new["custody"]),
        "approvalFromEpoch": approval_roster(trust)["fromEpoch"],
    }, new, custodians, new_at


def require_recovery_quorum(trust, manifest, custodians, replacement_profiles, *, receipt_at=None, **options):
    require_custody_key_profiles(replacement_profiles)
    target = retirement_target(trust, manifest, receipt_at=receipt_at, retired_at=time.time(), **options)
    slots = retirement_bootstrap(manifest["replacementBootstrap"])
    epoch = manifest["replacementEpoch"]

    def check_slot(slot, member):
        region, account = arn(KEY_ARN, member["recoveryKeyArn"]).groups()
        profile = replacement_profiles.get(account)
        if profile is None:
            raise ValueError(f"missing read-only inspection profile for custody account {account}")
        require_profile_account(profile, region, account)
        _, policies = slot_inventory(trust, epoch, member, [target], slot)
        for key, expected in policies.items():
            try:
                _, installed = inspect_rsa_key(key, profile=profile)
                if installed != expected:
                    raise ValueError("installed KMS policy does not match the approved recovery path")
            except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as error:
                raise ValueError(f"proven replacement key is unavailable: {key}: {error}") from error

    with ThreadPoolExecutor(max_workers=len(slots)) as workers:
        list(workers.map(lambda pair: check_slot(*pair), zip(slots, custodians, strict=True)))
    require_bootstrap_access(target, replacement_profiles.get(arn(ROLE_ARN, target["hostRole"])[1]))


def registered_targets(trust, epoch, receipt_digest, **options):
    _, receipt, _, receipt_at = load_epoch_with_time(trust, epoch, **options)
    if sha256(receipt) != receipt_digest:
        raise ValueError("target inventory does not match the committed custody receipt")
    for name in list_objects(trust, f"targets/{epoch}/"):
        yield read_registered_target(trust, name, epoch, receipt_digest, receipt_at=receipt_at, **options)


class ReplacementNotReady(ValueError):
    pass


@dataclass(frozen=True)
class LiveBoot:
    evidence: dict
    valid_until_ms: int

    def require_current(self, *, remaining=0):
        if (time.time() + remaining) * 1000 >= self.valid_until_ms:
            raise ReplacementNotReady("replacement evidence expired or has insufficient time remaining")


def pinned_wallet_trust(trust, wallet_trust):
    pinned_trust = read_document(wallet_trust)
    if (len(pinned_trust) > MAX_DOCUMENT_BYTES or
            hashlib.sha256(pinned_trust).hexdigest() != hex_digest(trust["walletTrustSha256"])):
        raise ValueError("wallet trust file does not match the pinned digest")
    wallet = parse_json(pinned_trust)
    require_pinned_publications(trust, wallet.get("publications") if isinstance(wallet, dict) else None)
    return pinned_trust


def replacement_targets(trust, scope):
    epoch = scope["replacementEpoch"]
    require_active_epoch(trust, epoch)
    old_instances = {target["instanceId"] for target in registered_targets(trust, scope["epoch"], scope["receiptSha256"])}
    candidates = {
        sha256(target_attestation(target)): target
        for target in registered_targets(trust, epoch, scope["replacementReceiptSha256"])
        if target["mode"] == "serve" and target["instanceId"] not in old_instances
    }
    if not candidates:
        raise ValueError("no registered serving target on a separate replacement instance")
    return candidates


def retirement_command(scope):
    root = Path(__file__).resolve().parents[3]
    return [
        "pnpm", "--dir", str(root / "example"), "exec", "tsx", str(root / "xtask/nitro-retirement.ts"),
        scope["network"], scope["securityDomainId"], scope["replacementEpoch"], scope["replacementCustodyDigest"],
    ]


def attested_boots(pinned_trust, candidates, scope, custody, *, after_ms=0, deadline=None, expected=None, required_slots=None):
    timeout = 25 if deadline is None else min(25, deadline - time.monotonic())
    if timeout <= 0:
        raise ReplacementNotReady("replacement boot wait expired")
    seed, canary_digest = note_identity(custody)
    reply = run_command([*retirement_command(scope), "probe", seed, canary_digest],
                        input=pinned_trust, stdout=subprocess.PIPE, check=True, timeout=timeout)
    evidence = parse_json(reply.stdout)
    fields(evidence, "policyDigest", "targets")
    matches = []
    for observed in evidence["targets"]:
        fields(observed, "releaseId", "pcrs", "bootstrap", "validUntilMs")
        identity = sha256({"releaseId": observed["releaseId"], "pcrs": observed["pcrs"]})
        if identity in candidates:
            bootstrap = observed["bootstrap"]
            slots = retirement_bootstrap(bootstrap)
            if required_slots is not None and slots != required_slots:
                continue
            booted_at = epoch_number(bootstrap["bootedAtMs"])
            boot_deadline = (booted_at // 1000 + RECOVERY_WINDOW_SECONDS) * 1000
            valid_until_ms = min(boot_deadline, epoch_number(observed["validUntilMs"]))
            if booted_at <= after_ms or valid_until_ms <= time.time() * 1000:
                continue
            qualification = {"walletPolicyDigest": hex_digest(evidence["policyDigest"]),
                             "replacementTargetIdentity": identity, "replacementTargetSha256": sha256(candidates[identity]),
                             "replacementBootstrap": bootstrap}
            if expected is not None and any(expected[field] != value for field, value in qualification.items()):
                continue
            matches.append(LiveBoot(qualification, valid_until_ms))
    if deadline is not None and time.monotonic() >= deadline:
        raise ReplacementNotReady("replacement boot wait expired")
    if not matches:
        raise ReplacementNotReady("no fresh attested serving boot matches the registered replacement")
    return matches


def qualified_policy(trust, wallet_trust, scope, custody, *, after_ms=0, expected=None, custodians=None,
                     replacement_profiles=None):
    pinned_trust = pinned_wallet_trust(trust, wallet_trust)
    candidates = replacement_targets(trust, scope)
    boots = attested_boots(pinned_trust, candidates, scope, custody, after_ms=after_ms, expected=expected)
    if custodians is not None:
        return ready_boot(trust, scope, boots, custodians, replacement_profiles)
    return boots[0]


def after_write_ms(published_at):
    # S3 Last-Modified only resolves to a second.
    return (int(published_at) + 1) * 1000 - 1


def check_requalification_anchor(closure, published_at, manifest):
    marker = closure["manifest"]
    if (manifest["priorRetirementSha256"] != sha256(closure) or
            (manifest["epoch"], manifest["receiptSha256"]) != (marker["epoch"], marker["receiptSha256"])):
        raise ValueError("requalification does not match the committed retirement")
    if epoch_number(manifest["replacementEpoch"]) < epoch_number(marker["replacementEpoch"]):
        raise ValueError("requalification cannot lower the replacement custody epoch")
    if epoch_number(manifest["replacementBootstrap"]["bootedAtMs"]) <= after_write_ms(published_at):
        raise ValueError("requalification requires a boot after the committed retirement")


def qualified_manifest(trust, wallet_trust, epoch, replacement, *, requalify=False, replacement_profiles=None):
    scope, receipt, custodians, _ = retirement_scope(trust, epoch, replacement)
    custody = receipt["custody"]
    if requalify:
        closure, _, published_at = load_retirement(trust, epoch)
        scope["priorRetirementSha256"] = sha256(closure)
        boot = qualified_policy(trust, wallet_trust, scope, custody,
                                after_ms=after_write_ms(published_at), custodians=custodians,
                                replacement_profiles=replacement_profiles)
        check_requalification_anchor(closure, published_at, {**scope, **boot.evidence})
    else:
        boot = qualified_policy(trust, wallet_trust, scope, custody, custodians=custodians,
                                replacement_profiles=replacement_profiles)
    policy = boot.evidence
    booted_at = epoch_number(policy["replacementBootstrap"]["bootedAtMs"]) // 1000
    manifest = {**scope, **policy, "recoveryDeadline": booted_at + RECOVERY_WINDOW_SECONDS}
    require_recovery_window(manifest)
    boot.require_current()
    return manifest


def require_recovery_window(manifest, remaining=0):
    deadline = recovery_deadline(manifest)
    now = time.time()
    if not deadline - RECOVERY_WINDOW_SECONDS <= now < deadline - remaining:
        raise ValueError("retirement recovery window is closed or has insufficient time remaining")


def checked_scope(trust, manifest, *, committed=None, **options):
    require_recovery_window(manifest)
    scope, receipt, custodians, receipt_at = retirement_scope(trust, manifest["epoch"], manifest["replacementEpoch"], **options)
    if any(manifest.get(field) != value for field, value in scope.items()):
        raise ValueError("retirement no longer matches the committed receipts or approval roster")
    if "priorRetirementSha256" in manifest:
        if committed is None:
            closure, _, published_at = load_retirement(trust, manifest["epoch"], **options)
        else:
            closure, published_at = committed
        check_requalification_anchor(closure, published_at, manifest)
        scope["priorRetirementSha256"] = manifest["priorRetirementSha256"]
    return scope, receipt, custodians, receipt_at


def retirement_qualification(trust, closure, published_at, requalification, **options):
    if requalification is None:
        return closure["manifest"]
    manifest = verify_retirement(trust, requalification, closure["manifest"]["epoch"], time.time(), requalification=True)
    _, _, custodians, receipt_at = checked_scope(trust, manifest, committed=(closure, published_at), **options)
    retirement_recovery(requalification, custodians)
    retirement_target(trust, manifest, receipt_at=receipt_at, retired_at=time.time(), **options)
    return manifest


def require_current_requalification(trust, manifest):
    if "priorRetirementSha256" in manifest:
        require_recovery_window(manifest)
        if approval_roster(trust)["fromEpoch"] != manifest["approvalFromEpoch"]:
            raise ValueError("requalification requires the active approval roster")


def prove_recovery(trust, document, index, relay_port):
    manifest = retirement_approval(document)["manifest"]
    observed = {}
    _, receipt, custodians, receipt_at = checked_scope(trust, manifest, observed_records=observed)
    if index not in retirement_bootstrap(manifest["replacementBootstrap"]):
        raise ValueError("custodian did not supply an attested bootstrap slot")
    proof = {"manifest": manifest, "signatures": document["recoveryProofs"]}

    def require_current():
        checked_scope(trust, manifest, observed_records=observed)
        retirement_target(trust, manifest, receipt_at=receipt_at, retired_at=time.time(), observed_records=observed)
        require_active_epoch(trust, receipt["custody"]["epoch"])
        require_recovery_window(manifest)

    signatures = sign_share_recovery(trust, custodians, receipt, index, RETIREMENT_RECOVERY, proof, relay_port,
                                     require_current=require_current)
    return {**document, "recoveryProofs": signatures}


def verify_qualification(trust, wallet_trust, document, *, observed_records=None, replacement_profiles=None):
    manifest = document["manifest"]
    observed = {} if observed_records is None else observed_records
    scope, receipt, custodians, receipt_at = checked_scope(trust, manifest, observed_records=observed)
    proven = retirement_recovery(document, custodians)
    boot = qualified_policy(trust, wallet_trust, scope, receipt["custody"], expected=manifest)
    policy = boot.evidence
    if manifest != {**scope, **policy, "recoveryDeadline": manifest["recoveryDeadline"]}:
        raise ValueError("retirement no longer matches the qualified replacement and wallet policy")
    if ledger_replica(trust) is not None:
        # Record every old registration and the selected replacement.
        for _ in registered_targets(trust, scope["epoch"], scope["receiptSha256"], observed_records=observed):
            pass
        retirement_target(trust, manifest, receipt_at=receipt_at, retired_at=time.time(), observed_records=observed)
    require_retirement_replication(trust, manifest, observed)
    require_recovery_quorum(trust, manifest, proven, replacement_profiles, receipt_at=receipt_at, observed_records=observed)
    require_active_epoch(trust, scope["replacementEpoch"])
    boot.require_current()
    return boot


def sign_retirement(trust, wallet_trust, document, key, *, replacement_profiles=None):
    approval = retirement_approval(document)
    manifest = approval["manifest"]
    observed = {}
    boot = verify_qualification(trust, wallet_trust, document, observed_records=observed, replacement_profiles=replacement_profiles)
    require_recovery_window(manifest)
    roster = approval_roster(trust)
    if roster["fromEpoch"] != manifest["approvalFromEpoch"]:
        raise ValueError("retirement requires the active approval roster")
    signed = add_approval(roster["keys"], RETIREMENT, approval, key)
    boot.require_current()
    verify_qualification(trust, wallet_trust, document, observed_records=observed, replacement_profiles=replacement_profiles)
    require_recovery_window(manifest)
    return {**document, "signatures": signed["signatures"]}


def commit_retirement(trust, wallet_trust, document, *, replacement_profiles=None):
    approval = retirement_approval(document)
    manifest = approval["manifest"]
    if "priorRetirementSha256" in manifest:
        raise ValueError("pass the signed requalification to inspection; the retirement record is already committed")
    epoch = manifest["epoch"]

    def require_same_record(stored):
        if canonical(stored) != canonical(document):
            raise ValueError("a different retirement record is already committed")

    existing = find_retirement(trust, epoch)
    if existing is not None:
        stored, version = existing
        if ledger_slot_version(trust, retirement_object_name(epoch)) != version:
            raise ValueError("retirement record changed during retry")
        require_same_record(stored)
        return
    check_approvals(approval_keys(trust), RETIREMENT, approval)
    observed = {}
    boot = verify_qualification(trust, wallet_trust, document, observed_records=observed, replacement_profiles=replacement_profiles)

    def before_write():
        require_recovery_window(manifest, remaining=LEDGER_WRITE_MARGIN_SECONDS)
        boot.require_current(remaining=LEDGER_WRITE_MARGIN_SECONDS)
        _, receipt, custodians, receipt_at = load_epoch_with_time(trust, manifest["replacementEpoch"],
                                                                 observed_records=observed)
        if sha256(receipt) != manifest["replacementReceiptSha256"]:
            raise ValueError("replacement custody receipt changed before retirement")
        proven = retirement_recovery(document, custodians)
        require_recovery_quorum(trust, manifest, proven, replacement_profiles, receipt_at=receipt_at, observed_records=observed)
        checked_scope(trust, manifest, observed_records=observed)
        # The ledger and key checks can outlast a policy. Reattest the signed replacement after them.
        confirmed = qualified_policy(trust, wallet_trust, manifest, receipt["custody"], expected=boot.evidence)
        if confirmed.evidence != boot.evidence:
            raise ValueError("replacement boot or wallet policy changed before retirement")
        require_active_epoch(trust, manifest["replacementEpoch"])
        require_recovery_window(manifest, remaining=LEDGER_WRITE_MARGIN_SECONDS)
        require_publication_roster(trust, manifest["approvalFromEpoch"])
        confirmed.require_current(remaining=LEDGER_WRITE_MARGIN_SECONDS)

    def confirm(version):
        stored, _, _ = load_retirement(trust, epoch, expected_version=version, observed_records=observed)
        require_same_record(stored)

    write_once(trust, retirement_object_name(epoch), document, confirm, before_write=before_write)


def retirement_inventory(trust, epoch, index, *, requalification=None, observed_records=None):
    if index not in range(1, 7):
        raise ValueError("invalid custody slot")
    observed = {} if observed_records is None else observed_records
    document, custodians, published_at = load_retirement(trust, epoch, observed_records=observed)
    marker = document["manifest"]
    qualification = retirement_qualification(trust, document, published_at, requalification, observed_records=observed)
    targets = list(registered_targets(trust, epoch, marker["receiptSha256"], observed_records=observed))
    require_retirement_replication(trust, qualification, observed, committed=True)
    role, keys = slot_inventory(trust, epoch, custodians[index - 1], targets, index)
    return qualification, role, keys, published_at, targets


def require_retirement_replication(trust, qualification, observed_records, *, committed=False):
    replica = ledger_replica(trust)
    if replica is None:
        if not committed and trust["network"] == "mainnet":
            raise ValueError("mainnet retirement requires a pinned custody ledger replica")
        return
    require_replicated_custody(trust, replica, qualification["replacementEpoch"], observed_records)


def require_observed_target_replication(trust, qualification, evidence):
    replica = ledger_replica(trust)
    if evidence["replacementTargetIdentity"] == qualification.get("replacementTargetIdentity"):
        if evidence["replacementTargetSha256"] != qualification["replacementTargetSha256"]:
            raise ValueError("attested replacement registration changed during verification")
        return
    if replica is None:
        return
    epoch = qualification["replacementEpoch"]
    name = target_path(epoch, evidence["replacementTargetIdentity"])
    payload, fingerprint = read_replicated_record(trust, replica_trust(trust, replica), name)
    target = check_registered_target(trust, name, epoch, qualification["replacementReceiptSha256"], parse_json(payload),
                                     publication_time({"LastModified": fingerprint[1]}))
    if sha256(target) != evidence["replacementTargetSha256"]:
        raise ValueError("replicated target does not match the attested replacement")
    return fingerprint


def ready_boot(trust, scope, boots, custodians, replacement_profiles, *, confirm=None, observed_records=None):
    failures = []
    for boot in boots:
        evidence = boot.evidence
        try:
            fingerprint = require_observed_target_replication(trust, scope, evidence)
            slots = retirement_bootstrap(evidence["replacementBootstrap"])
            require_recovery_quorum(trust, {**scope, **evidence}, [custodians[slot - 1] for slot in slots], replacement_profiles)
            if confirm is not None:
                boot = confirm(evidence)
            boot.require_current()
            if observed_records is not None and fingerprint is not None:
                name = target_path(scope["replacementEpoch"], evidence["replacementTargetIdentity"])
                observe_record(observed_records, name, fingerprint)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            failures.append(f"Target {evidence['replacementTargetIdentity']} failed with {error}")
        else:
            return boot
    raise ReplacementNotReady("\n".join(["no attested replacement qualified", *failures]))


def slot_inventory(trust, epoch, member, targets, index):
    custodian, admin = member["custodianRole"], member["retirementRole"]
    keys = {member["recoveryKeyArn"]: custody_recovery_policy(trust, member, epoch)}
    for target in targets:
        key = target["wrappingKeys"][index - 1]
        expected = key_policy(target["hostRole"], custodian, admin, target["pcrs"], target["instanceId"])
        if keys.setdefault(key, expected) != expected:
            raise ValueError("one key appears with different retirement policies")
    return admin, keys


def qualify_key_retirement(trust, wallet_trust, qualification, published_at, *, observed_records=None, replacement_profiles=None):
    pinned_trust = pinned_wallet_trust(trust, wallet_trust)
    replacement = qualification["replacementEpoch"]
    _, receipt, custodians = load_epoch(trust, replacement, observed_records=observed_records)
    if sha256(receipt) != qualification["replacementReceiptSha256"]:
        raise ValueError("replacement custody receipt changed during verification")
    candidates = replacement_targets(trust, qualification)
    custody = receipt["custody"]
    bootstrap = qualification["replacementBootstrap"]
    slots = retirement_bootstrap(bootstrap)
    after_ms = max(after_write_ms(published_at), epoch_number(bootstrap["bootedAtMs"]) - 1)
    boots = attested_boots(pinned_trust, candidates, qualification, custody, after_ms=after_ms, required_slots=slots)

    def confirm(boot):
        return attested_boots(pinned_trust, candidates, qualification, custody, after_ms=after_ms, expected=boot)[0]

    return ready_boot(trust, qualification, boots, custodians, replacement_profiles,
                      confirm=confirm, observed_records=observed_records)


def retirement_replica(trust, profile):
    replica = ledger_replica(trust)
    if replica is None and trust["network"] == "mainnet":
        raise ValueError("mainnet key retirement requires a pinned custody ledger replica")
    if replica is not None and not profile:
        raise ValueError("provide --replica-profile to verify the custody ledger replica")
    return replica


def confirm_retirement_policy(trust, wallet_trust, qualification, boot, replica, replica_profile, *, observed_records):
    if replica is not None:
        check_recovery_bucket(trust, replica, replica_profile)
        boot.require_current()
        destination = replica_trust(trust, replica)
        epoch = qualification["replacementEpoch"]
        names = (ledger_object(trust, epoch), target_path(epoch, boot.evidence["replacementTargetIdentity"]))
        with ThreadPoolExecutor(max_workers=len(names)) as workers:
            list(workers.map(lambda name: read_replicated_record(trust, destination, name,
                                                                  checkpoint_records=observed_records), names))
    boot.require_current()
    try:
        run_command([*retirement_command(qualification), "policy", boot.evidence["walletPolicyDigest"]],
                    input=pinned_wallet_trust(trust, wallet_trust), check=True, timeout=10)
    except subprocess.SubprocessError as error:
        raise ReplacementNotReady("could not confirm the replacement wallet policy after AWS checks") from error
    require_active_epoch(trust, qualification["replacementEpoch"])
    require_current_requalification(trust, qualification)
    boot.require_current()


def inspect_keys(trust, epoch, index, check_inactive, *, wallet_trust=None, replica_profile=None, host_profiles=None,
                 requalification=None, replacement_profiles=None):
    if check_inactive and requalification is not None:
        raise ValueError("inactive-key inspection uses the committed retirement")
    replica = None
    if not check_inactive:
        if wallet_trust is None:
            raise ValueError("provide --wallet-trust before scheduling key deletion")
        replica = retirement_replica(trust, replica_profile)
    observed = {}
    qualification, role, keys, published_at, targets = retirement_inventory(
        trust, epoch, index, requalification=requalification, observed_records=observed,
    )
    result = inspect_inventory((role, keys), check_inactive)
    if not check_inactive:
        result["terminatedParents"] = inspect_old_parents(targets, host_profiles or {})
        boot = qualify_key_retirement(trust, wallet_trust, qualification, published_at, observed_records=observed,
                                     replacement_profiles=replacement_profiles)
        confirm_retirement_policy(trust, wallet_trust, qualification, boot, replica, replica_profile, observed_records=observed)
        result["replacement"] = boot.evidence
        result["validUntilMs"] = str(boot.valid_until_ms)
        if requalification is not None:
            result["requalificationSha256"] = sha256(requalification)
    return result


def deleted_keys(region, account, keys, **options):
    # CloudTrail indexes DeleteKey by event name. Its KMS ARN is inside the event.
    selector = {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "DeleteKey"}], "MaxResults": 20}
    missing = set(keys)
    tokens = set()
    while missing:
        page = aws(region, "cloudtrail", "lookup-events", [
            "--no-paginate", "--cli-input-json", canonical(selector).decode(),
        ], **options)
        for row in page["Events"]:
            event = parse_json(row["CloudTrailEvent"])
            event_id = event.get("eventID")
            if (event.get("eventSource") != "kms.amazonaws.com" or event.get("eventName") != "DeleteKey" or
                    event.get("eventType") != "AwsServiceEvent" or event.get("awsRegion") != region or
                    event.get("recipientAccountId") != account or
                    "errorCode" in event or not isinstance(event_id, str) or not event_id):
                continue
            for resource in event.get("resources", []):
                key = resource.get("ARN")
                if (key in missing and resource.get("type") == "AWS::KMS::Key" and
                        resource.get("accountId") == account):
                    missing.remove(key)
                    yield {"keyArn": key, "state": "Deleted", "deletionEventId": event_id}
        token = page.get("NextToken")
        if token is None or not missing:
            break
        if not isinstance(token, str) or not token or token in tokens:
            raise ValueError("invalid CloudTrail continuation token")
        tokens.add(token)
        selector["NextToken"] = token
    if missing:
        raise ValueError(f"retirement keys have no verified KMS deletion event: {', '.join(sorted(missing))}")


def inspect_inventory(inventory, check_inactive, **options):
    role, keys = inventory
    result = []
    missing = {}
    for key, expected in keys.items():
        try:
            policy = kms(key, "get-key-policy", ["--policy-name", "default"], **options)["Policy"]
            metadata = kms(key, "describe-key", **options)["KeyMetadata"]
        except (ValueError, subprocess.TimeoutExpired):
            if not check_inactive:
                raise
            region = arn(KEY_ARN, key)[1]
            missing.setdefault(region, []).append(key)
            continue
        installed = parse_json(policy)
        if installed != expected or metadata.get("Arn") != key:
            raise ValueError("retirement key does not match the recorded epoch policy")
        state = metadata["KeyState"]
        if check_inactive and state not in {"Disabled", "PendingDeletion"}:
            raise ValueError(f"retirement key {key} remains usable or unverified")
        result.append({"keyArn": key, "state": state})
    for region, absent_keys in missing.items():
        result.extend(deleted_keys(region, arn(ROLE_ARN, role)[1], absent_keys, **options))
    return {"retirementRole": role, "keys": sorted(result, key=lambda row: row["keyArn"])}


def require_terminated_parent(target, profile):
    try:
        return require_host_state(target, "terminated", profile)
    except HostUnobserved:
        # EC2 drops terminated instances from its inventory. Require a positive
        # deletion record for the exact managed resource from AWS Config.
        pass
    account = arn(ROLE_ARN, target["hostRole"])[1]
    region, instance = target["hostRegion"], target["instanceId"]
    resource_type = "AWS::EC2::Instance"
    rows = aws(region, "configservice", "get-resource-config-history", [
        "--resource-type", resource_type, "--resource-id", instance,
        "--chronological-order", "Reverse", "--limit", "1", "--no-paginate",
    ], profile=profile)["configurationItems"]
    if len(rows) != 1:
        raise ValueError(f"missing AWS Config termination evidence for {account}/{region}/{instance}")
    row = rows[0]
    capture_time = row.get("configurationItemCaptureTime")
    if (row.get("accountId") != account or row.get("awsRegion") != region or
            row.get("resourceId") != instance or row.get("resourceType") != resource_type or
            row.get("configurationItemStatus") != "ResourceDeleted" or
            not isinstance(capture_time, str) or not capture_time):
        raise ValueError(f"unverified AWS Config termination for {account}/{region}/{instance}")
    return {"account": account, "region": region, "instanceId": instance, "state": "terminated",
            "source": "aws-config", "capturedAt": capture_time}


def inspect_old_parents(targets, profiles, *, check_profiles=True):
    parents = {(arn(ROLE_ARN, target["hostRole"])[1], target["hostRegion"], target["instanceId"]): target
               for target in targets}
    if profiles.keys() != {account for account, _, _ in parents}:
        raise ValueError("provide one host inspection profile for each old parent account")
    if check_profiles:
        for account, region in sorted({(account, region) for account, region, _ in parents}):
            require_profile_account(profiles[account], region, account)
    return [require_terminated_parent(target, profiles[account])
            for (account, _, _), target in sorted(parents.items())]


def verify_retired(trust, wallet_trust, epoch, profiles, host_profiles, wait_seconds, *, replica_profile=None,
                   requalification=None, replacement_profiles=None):
    require_inspection_profiles(profiles)
    if wait_seconds <= 0:
        raise ValueError("provide a positive replacement boot wait time")
    replica = retirement_replica(trust, replica_profile)
    observed = {}
    document, custodians, published_at = load_retirement(trust, epoch, observed_records=observed)
    marker = document["manifest"]
    _, retired, _ = load_epoch(trust, epoch, observed_records=observed)
    if sha256(retired) != marker["receiptSha256"]:
        raise ValueError("retired custody receipt changed during verification")
    qualification = retirement_qualification(trust, document, published_at, requalification, observed_records=observed)
    _, replacement, replacement_custodians = load_epoch(trust, qualification["replacementEpoch"], observed_records=observed)

    def inspect_all(*, check_profiles=False):
        targets = list(registered_targets(trust, epoch, marker["receiptSha256"], observed_records=observed))
        require_retirement_replication(trust, qualification, observed, committed=True)
        with ThreadPoolExecutor(max_workers=6) as workers:
            if check_profiles:
                accounts = [arn(KEY_ARN, member["recoveryKeyArn"]) for member in custodians]
                checks = [(profile, key[1], key[2]) for profile, key in zip(profiles, accounts, strict=True)]
                list(workers.map(lambda check: require_profile_account(*check), checks))
            slots = list(workers.map(
                lambda index, member, profile: inspect_inventory(
                    slot_inventory(trust, epoch, member, targets, index), True, profile=profile),
                range(1, 7), custodians, profiles,
            ))
        return slots, inspect_old_parents(targets, host_profiles, check_profiles=check_profiles)

    inspect_all(check_profiles=True)
    pinned_trust = pinned_wallet_trust(trust, wallet_trust)
    candidates = replacement_targets(trust, qualification)
    after_ms = int(time.time() * 1000)
    deadline = time.monotonic() + wait_seconds
    custody = replacement["custody"]
    proven_slots = retirement_bootstrap(qualification["replacementBootstrap"])
    print("All old keys are inactive and registered parents terminated. Waiting for a newer replacement boot.", file=sys.stderr, flush=True)
    while True:
        try:
            require_current_requalification(trust, qualification)
            boots = attested_boots(pinned_trust, candidates, qualification, custody, after_ms=after_ms,
                                   deadline=deadline, required_slots=proven_slots)
            slots, parents = inspect_all()
            current_candidates = replacement_targets(trust, qualification)

            def confirm(boot):
                return attested_boots(pinned_trust, current_candidates, qualification, custody, after_ms=after_ms,
                                      deadline=deadline, expected=boot)[0]

            boot = ready_boot(trust, qualification, boots, replacement_custodians, replacement_profiles,
                              confirm=confirm, observed_records=observed)
            break
        except (ReplacementNotReady, subprocess.SubprocessError) as error:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                sleep(min(2, remaining))
                if time.monotonic() < deadline:
                    candidates = replacement_targets(trust, qualification)
                    if time.monotonic() < deadline:
                        continue
            raise ValueError(f"no replacement boot observed after verifying the old keys: {error}") from error

    confirm_retirement_policy(trust, wallet_trust, qualification, boot, replica, replica_profile, observed_records=observed)
    report = {
        "retirementSha256": sha256(document), "retirementObservedAtMs": str(after_ms),
        "retired": {
            "network": marker["network"], "securityDomainId": marker["securityDomainId"],
            "custodyEpoch": epoch, "custodyDigest": sha256(retired["custody"]),
            "publishedAtMs": str(int(published_at * 1000)),
        },
        "replacement": {
            **boot.evidence, "custodyEpoch": qualification["replacementEpoch"],
            "custodyDigest": qualification["replacementCustodyDigest"],
        },
        "slots": slots, "terminatedParents": parents,
    }
    if requalification is not None:
        report["requalificationSha256"] = sha256(requalification)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trust", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    draft = commands.add_parser("draft")
    draft.add_argument("wallet_trust", type=Path)
    draft.add_argument("epoch")
    draft.add_argument("replacement")
    draft.add_argument("--requalify", action="store_true", help="prove a new quorum for an already closed epoch")
    prove = commands.add_parser("prove-recovery")
    prove.add_argument("candidate", type=Path)
    prove.add_argument("share", type=int, choices=range(1, 7))
    prove.add_argument("--relay-port", type=int, required=True)
    sign = commands.add_parser("sign")
    sign.add_argument("wallet_trust", type=Path)
    sign.add_argument("candidate", type=Path)
    sign.add_argument("key")
    publish = commands.add_parser("publish")
    publish.add_argument("wallet_trust", type=Path)
    publish.add_argument("candidate", type=Path)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("epoch")
    inspect.add_argument("share", type=int, choices=range(1, 7))
    inspect.add_argument("--check-inactive", action="store_true")
    inspect.add_argument("--wallet-trust", type=Path, help="verify the post-commit cold boot before scheduling deletion")
    inspect.add_argument("--replica-profile", help="inspect the custody recovery bucket in its owner's AWS account")
    verify = commands.add_parser("verify-retired")
    verify.add_argument("wallet_trust", type=Path)
    verify.add_argument("epoch")
    verify.add_argument("--inspection-profiles", nargs=6, required=True)
    for command in (draft, sign, publish, inspect, verify):
        command.add_argument("--custody-key-profiles", type=Path, required=command is not inspect,
                             help="JSON map from replacement custody and host accounts to read-only profiles")
    for command in (inspect, verify):
        command.add_argument("--host-inspection-profile", metavar="ACCOUNT=PROFILE", action="append", default=[])
        command.add_argument("--requalification", type=Path, help="signed proof of a new quorum for the closed epoch")
    verify.add_argument("--replica-profile", help="inspect the custody recovery bucket in its owner's AWS account")
    verify.add_argument("--wait-seconds", type=int, default=300)
    verify.add_argument("--output", type=Path, help="publish the report atomically at a new path")
    args = parser.parse_args()
    try:
        trust = read_json(args.trust)
        replacement_profiles = None
        if args.command != "prove-recovery" and not (args.command == "inspect" and args.check_inactive):
            if args.custody_key_profiles is not None:
                replacement_profiles = read_json(args.custody_key_profiles)
            require_custody_key_profiles(replacement_profiles)
        requalification_file = getattr(args, "requalification", None)
        requalification = read_json(requalification_file) if requalification_file is not None else None
        if requalification_file is not None and not isinstance(requalification, dict):
            raise ValueError("expected a signed requalification document")
        host_profiles = {}
        for mapping in getattr(args, "host_inspection_profile", ()):
            account, _, profile = mapping.partition("=")
            if not re.fullmatch(r"[0-9]{12}", account) or not profile or account in host_profiles:
                raise ValueError("provide distinct host inspection profiles as ACCOUNT=PROFILE")
            host_profiles[account] = profile
        if args.command == "inspect":
            result = inspect_keys(trust, args.epoch, args.share, args.check_inactive, wallet_trust=args.wallet_trust,
                                  replica_profile=args.replica_profile, host_profiles=host_profiles,
                                  requalification=requalification, replacement_profiles=replacement_profiles)
        elif args.command == "verify-retired":
            if args.output is not None and args.output.exists():
                raise ValueError("retirement report already exists")
            result = verify_retired(trust, args.wallet_trust, args.epoch, args.inspection_profiles, host_profiles,
                                    args.wait_seconds, replica_profile=args.replica_profile, requalification=requalification,
                                    replacement_profiles=replacement_profiles)
            if args.output is not None:
                publish_new_file(args.output, canonical(result) + b"\n")
                return
        elif args.command == "draft":
            result = {"manifest": qualified_manifest(trust, args.wallet_trust, args.epoch, args.replacement,
                                                     requalify=args.requalify, replacement_profiles=replacement_profiles),
                      "signatures": [], "recoveryProofs": []}
        else:
            document = read_json(args.candidate)
            if args.command == "publish":
                commit_retirement(trust, args.wallet_trust, document, replacement_profiles=replacement_profiles)
                return
            result = (prove_recovery(trust, document, args.share, args.relay_port) if args.command == "prove-recovery" else
                      sign_retirement(trust, args.wallet_trust, document, args.key, replacement_profiles=replacement_profiles))
        print(canonical(result).decode())
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
