"""Approve the exact EIF, configuration and KMS destinations for a release."""

import argparse
import hashlib
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from approval import (
    KEY_ARN, ROLE_ARN, add_approval, approval_roster, arn, canonical, fields, file_digest, hex_digest,
    parse_json, publish_new_file, read_document, read_json, require_custody_key_profiles, require_inspection_profiles,
    require_profile_account, sha256,
)
from custody_ledger import (
    LEDGER_WRITE_MARGIN_SECONDS, TARGET_APPROVAL, check_custody_roster, ledger_slot_version, list_objects, load_epoch_with_time,
    publication_time, read_registered_target, read_stored_object, require_active_epoch, require_publication_roster,
    require_target_approval_window, target_attestation, target_object_name, validate_target, verify_target_approval,
    wrapping_pairs, write_once,
)
from host import host_policy, require_bootstrap_access, require_host_state
from kms_policy import key_policy
from provenance import verify as verify_build
from relay import inspect_rsa_key, relay_pins, sealed_rsa_key


def target_binding(manifest):
    """The registered destination remains the same when its approval is renewed."""
    return {name: value for name, value in manifest.items() if name not in {"expiresAt", "approvalFromEpoch"}}


def wrapping_policies(manifest, custodians):
    wrapping_pairs(manifest, custodians)
    return [key_policy(manifest["hostRole"], member["custodianRole"], member["retirementRole"],
                       manifest["pcrs"], manifest["instanceId"]) for member in custodians]


def require_live_registration(manifest, custodians, key_profiles):
    require_custody_key_profiles(key_profiles)
    policies = wrapping_policies(manifest, custodians)

    def check_key(key, expected):
        region, account = arn(KEY_ARN, key).groups()
        profile = key_profiles.get(account)
        if profile is None:
            raise ValueError(f"missing read-only inspection profile for custody account {account}")
        require_profile_account(profile, region, account)
        try:
            _, installed = inspect_rsa_key(key, profile=profile)
            if installed != expected:
                raise ValueError("installed wrapping key policy does not match the approved target")
        except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
            raise ValueError(f"cannot verify target wrapping key {key}: {error}") from error

    with ThreadPoolExecutor(max_workers=len(policies)) as workers:
        list(workers.map(lambda pair: check_key(*pair), zip(manifest["wrappingKeys"], policies, strict=True)))
    require_bootstrap_access(manifest, key_profiles.get(arn(ROLE_ARN, manifest["hostRole"])[1]))


def register_target(trust, document, *, build=None, key_profiles=None):
    fields(document, "manifest", "signatures")
    manifest = document["manifest"]
    validate_target(trust, manifest)
    epoch = manifest["custodyEpoch"]
    observed_records = {}
    _, receipt, custodians, receipt_at = load_epoch_with_time(trust, epoch, observed_records=observed_records)
    if manifest["receiptSha256"] != sha256(receipt):
        raise ValueError("target does not match the committed custody receipt")
    name = target_object_name(manifest)
    published_at = None
    version = None
    if name in list_objects(trust, name):
        stored, metadata = read_stored_object(trust, name)
        if canonical(stored) == canonical(document):
            published_at = publication_time(metadata)
            version = metadata["VersionId"]
    verify_target_approval(trust, document, at=published_at)
    if build is not None:
        target(trust, document, receipt, custodians, build, at=published_at)
    if published_at is not None:
        if ledger_slot_version(trust, name) != version:
            raise ValueError("target registration changed during retry")
        load_epoch_with_time(trust, epoch, observed_records=observed_records)
        require_active_epoch(trust, epoch)
        if published_at < receipt_at:
            raise ValueError("target registration precedes its custody receipt")
        return

    def before_write():
        require_live_registration(manifest, custodians, key_profiles)
        load_epoch_with_time(trust, epoch, observed_records=observed_records)
        require_active_epoch(trust, epoch)
        require_target_approval_window(manifest, time.time(), remaining=LEDGER_WRITE_MARGIN_SECONDS)
        require_publication_roster(trust, manifest["approvalFromEpoch"])

    def confirm(version):
        load_epoch_with_time(trust, epoch, observed_records=observed_records)
        require_registered_target(trust, manifest, receipt_at=receipt_at, expected_version=version)

    write_once(trust, name, document, confirm, before_write=before_write)


def require_registered_target(trust, manifest, *, receipt_at=None, expected_version=None):
    # Registration precedes the retirement check. Every wrap admitted before
    # the marker will appear in the subsequent inventory, even if it ends later.
    name = target_object_name(manifest)
    version = ledger_slot_version(trust, name) if expected_version is None else expected_version
    if version is None:
        raise ValueError(f"registered target object missing: {name}")
    recorded = read_registered_target(trust, name, manifest["custodyEpoch"], manifest["receiptSha256"],
                                      receipt_at=receipt_at, expected_version=version)
    if target_binding(recorded) != target_binding(manifest):
        raise ValueError("target does not match the immutable deployment register")
    require_active_epoch(trust, manifest["custodyEpoch"])
    return version


def target(trust, document, receipt, custodians, build, *, at=None):
    at = time.time() if at is None else at
    roster = approval_roster(trust, at=at)
    fields(document, "manifest", "signatures")
    manifest = document["manifest"]
    validate_target(trust, manifest)
    if manifest["approvalFromEpoch"] != roster["fromEpoch"]:
        raise ValueError("target requires the current approval roster")
    network, domain, release = manifest["network"], manifest["securityDomainId"], manifest["releaseId"]
    if (network, domain) != (trust["network"], trust["securityDomainId"]) or (
        network, domain
    ) != (receipt["network"], receipt["securityDomainId"]) or (manifest["custodyEpoch"], manifest["receiptSha256"]) != (
        receipt["custody"]["epoch"], sha256(receipt)
    ):
        raise ValueError("target does not authorize this custody receipt and domain")
    require_target_approval_window(manifest, at)

    configuration = read_document(build / "configuration.json")
    config = parse_json(configuration)
    if (hex_digest(manifest["configurationSha256"]) != hashlib.sha256(configuration).hexdigest() or
            hex_digest(manifest["eifSha256"]) != file_digest(build / "enclave.eif") or
            hex_digest(manifest["executableSha256"]) != file_digest(build / "tvc_app")):
        raise ValueError("target artifacts do not match the approved hashes")
    fields(config, "releaseId", "securityDomainId", "deployment")
    config_release, config_domain = config["releaseId"], config["securityDomainId"]
    if (config_release, config_domain) != (release, domain):
        raise ValueError("target configuration does not match the approved release and domain")
    deployment = config["deployment"]
    mode = manifest["mode"]
    next_custodians = manifest["nextCustodians"]
    next_keys = []
    if mode == "serve" and next_custodians is None:
        fields(deployment, "mode", "custody")
        source = deployment["custody"]
    elif mode == "rotate":
        fields(deployment, "mode", "previous", "recipientPublicKeys")
        source = deployment["previous"]
        recipients = deployment["recipientPublicKeys"]
        if not isinstance(recipients, list) or len(recipients) != 6 or any(
            not isinstance(spki, str) or not re.fullmatch(r"(?:[0-9a-f]{2}){1,600}", spki) for spki in recipients
        ) or len(set(recipients)) != 6:
            raise ValueError("rotation requires six distinct RSA public keys")
        current_keys = {custodian["recoveryKeyArn"] for custodian in custodians}
        for member, spki in zip(next_custodians, recipients, strict=True):
            key = member["recoveryKeyArn"]
            if key in current_keys:
                raise ValueError("rotate recovery keys before issuing fresh shares")
            next_keys.append(hashlib.sha256(bytes.fromhex(spki)).hexdigest())
    else:
        raise ValueError("expected a serving or rotation target")
    if deployment["mode"] != mode or source != receipt["custody"]:
        raise ValueError("target configuration does not use the authorized custody record")

    pins = manifest["pcrs"]
    fields(pins, "PCR0", "PCR1", "PCR2")
    measured = read_json(build / "measurements.json")["Measurements"]
    if any(hex_digest(pin, 48) != measured[name] for name, pin in pins.items()):
        raise ValueError("target measurements do not match the approval")

    return roster["keys"], wrapping_policies(manifest, custodians), next_keys


def require_reviewed_target(build, manifest, review):
    reviewed = verify_build(build, manifest["network"], review)
    if any(manifest[field] != reviewed[field] for field in (
        "configurationSha256", "eifSha256", "executableSha256", "pcrs",
    )):
        raise ValueError("target does not match the verified build provenance")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trust", type=Path)
    parser.add_argument("build", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("draft")
    prepare.add_argument("host_role")
    prepare.add_argument("wrapping_keys", type=Path)
    prepare.add_argument("expires_at", type=int)
    prepare.add_argument("--host-region", required=True)
    prepare.add_argument("--instance-id", required=True)
    prepare.add_argument("--next-roster", type=Path)
    sign = commands.add_parser("sign")
    sign.add_argument("target", type=Path)
    sign.add_argument("key")
    sign.add_argument("output", type=Path)
    sign.add_argument("--host-inspection-profile", required=True)
    sign.add_argument("--inspection-profiles", nargs=6, required=True)
    sign.add_argument("--review", type=Path, required=True)
    sign.add_argument("--next-inspection-profiles", nargs=6)
    sign.add_argument("--next-relay-build", nargs=2, type=Path, metavar=("BUILD", "REVIEW"))
    register = commands.add_parser("register")
    register.add_argument("target", type=Path)
    register.add_argument("--custody-key-profiles", type=Path, help="JSON map from custody and host accounts to read-only profiles")
    identity = commands.add_parser("host-policy")
    identity.add_argument("target", type=Path)
    commands.add_parser("attestation-pins").add_argument("target", type=Path)
    args = parser.parse_args()
    try:
        trust = read_json(args.trust)
        if args.command == "draft":
            config_path = args.build / "configuration.json"
            config = read_json(config_path)
            deployment = config["deployment"]
            mode = deployment["mode"]
            epoch = deployment["custody" if mode == "serve" else "previous"]["epoch"]
            _, receipt, custodians, _ = load_epoch_with_time(trust, epoch)
            measured = read_json(args.build / "measurements.json")["Measurements"]
            document = {"manifest": {
                "network": trust["network"], "securityDomainId": config["securityDomainId"], "custodyEpoch": epoch,
                "receiptSha256": sha256(receipt), "releaseId": config["releaseId"], "mode": mode,
                "expiresAt": args.expires_at, "eifSha256": file_digest(args.build / "enclave.eif"),
                "executableSha256": file_digest(args.build / "tvc_app"),
                "configurationSha256": file_digest(config_path), "pcrs": {pcr: measured[pcr] for pcr in ("PCR0", "PCR1", "PCR2")},
                "hostRole": args.host_role, "hostRegion": args.host_region, "instanceId": args.instance_id,
                "wrappingKeys": read_json(args.wrapping_keys),
                "nextCustodians": read_json(args.next_roster) if args.next_roster else None,
                "nextRelay": relay_pins(trust, str(int(epoch) + 1)) if mode == "rotate" else None,
                "approvalFromEpoch": approval_roster(trust)["fromEpoch"],
            }, "signatures": []}
            target(trust, document, receipt, custodians, args.build)
            print(canonical(document).decode())
            return
        document = read_json(args.target)
        if args.command == "register":
            profiles = read_json(args.custody_key_profiles) if args.custody_key_profiles else None
            register_target(trust, document, build=args.build, key_profiles=profiles)
            return
        _, receipt, custodians, receipt_at = load_epoch_with_time(trust, document["manifest"]["custodyEpoch"])
        keys, policies, next_keys = target(trust, document, receipt, custodians, args.build)
        if args.command in {"host-policy", "attestation-pins"}:
            manifest = verify_target_approval(trust, document)
            if args.command == "host-policy":
                require_active_epoch(trust, manifest["custodyEpoch"])
                print(canonical(host_policy(manifest)).decode())
            else:
                require_registered_target(trust, manifest, receipt_at=receipt_at)
                print(canonical(target_attestation(manifest)["pcrs"]).decode())
            return
        require_active_epoch(trust, receipt["custody"]["epoch"])
        manifest = document["manifest"]
        require_reviewed_target(args.build, manifest, args.review)
        require_inspection_profiles(args.inspection_profiles)
        host_account = arn(ROLE_ARN, manifest["hostRole"])[1]
        require_profile_account(args.host_inspection_profile, manifest["hostRegion"], host_account)
        if next_keys:
            successor = manifest["nextCustodians"]
            check_custody_roster(trust, str(int(manifest["custodyEpoch"]) + 1), successor, next_keys,
                                 args.next_inspection_profiles, args.next_relay_build)
        elif args.next_relay_build is not None or args.next_inspection_profiles is not None:
            raise ValueError("successor inspection is only used for rotation")
        for key, policy, profile in zip(manifest["wrappingKeys"], policies, args.inspection_profiles, strict=True):
            region, account = arn(KEY_ARN, key).groups()
            require_profile_account(profile, region, account)
            sealed_rsa_key(key, policy, profile=profile)
        require_host_state(manifest, "running", args.host_inspection_profile)

        def require_signing_window():
            require_active_epoch(trust, manifest["custodyEpoch"])
            require_target_approval_window(manifest, time.time(), remaining=LEDGER_WRITE_MARGIN_SECONDS)
            require_publication_roster(trust, manifest["approvalFromEpoch"])

        require_signing_window()
        approved = add_approval(keys, TARGET_APPROVAL, document, args.key)
        publish_new_file(args.output, canonical(approved) + b"\n", before_publish=require_signing_window)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
