"""Approve the exact EIF, configuration and KMS destinations for a release."""

import argparse
import hashlib
import re
import subprocess
import time
from pathlib import Path

from approval import (
    KEY_ARN, ROLE_ARN, add_approval, approval_roster, arn, aws, canonical, fields, file_digest, hex_digest,
    parse_json, read_document, read_json, sha256,
)
from custody_ledger import (
    LEDGER_WRITE_MARGIN_SECONDS, TARGET_APPROVAL, check_acknowledgement_key, check_recovery_roster, load_epoch,
    read_registered_target, require_active_epoch, require_publication_roster, require_target_approval_window,
    target_attestation, target_object_name, validate_target, verify_target_approval, write_once,
)
from kms_policy import decrypt_conditions, key_policy, target_boot_pins
from provenance import MAIN_REF, verify as verify_build
from relay import relay_pins

def host_policy(manifest):
    pins = target_boot_pins(manifest["hostRole"], manifest["pcrs"], manifest["instanceId"])
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": manifest["wrappingKeys"],
         "Condition": decrypt_conditions(pins)}
    ]}


def require_host_state(manifest, state, profile):
    account = arn(ROLE_ARN, manifest["hostRole"])[1]
    region, instance = manifest["hostRegion"], manifest["instanceId"]
    reservations = aws(region, "ec2", "describe-instances", ["--instance-ids", instance], profile=profile)["Reservations"]
    if len(reservations) != 1 or reservations[0].get("OwnerId") != account:
        raise ValueError(f"missing EC2 evidence for {account}/{region}/{instance}")
    instances = reservations[0].get("Instances", [])
    if (len(instances) != 1 or instances[0].get("InstanceId") != instance or
            instances[0].get("State", {}).get("Name") != state or
            (state == "running" and instances[0].get("EnclaveOptions", {}).get("Enabled") is not True)):
        raise ValueError(f"expected {account}/{region}/{instance} to be {state}")
    return {"account": account, "region": region, "instanceId": instance, "state": state}


def target_binding(manifest):
    """The registered destination remains the same when its approval is renewed."""
    return {name: value for name, value in manifest.items() if name not in {"expiresAt", "approvalFromEpoch"}}


def register_target(trust, document):
    manifest = verify_target_approval(trust, document)
    epoch = manifest["custodyEpoch"]
    _, receipt, _ = load_epoch(trust, epoch)
    if manifest["receiptSha256"] != sha256(receipt):
        raise ValueError("target does not match the committed custody receipt")
    require_active_epoch(trust, epoch)
    require_target_approval_window(manifest, time.time(), remaining=LEDGER_WRITE_MARGIN_SECONDS)
    require_publication_roster(trust, manifest["approvalFromEpoch"])
    write_once(trust, target_object_name(manifest), document,
               lambda stored: target_binding(stored["manifest"]))
    require_registered_target(trust, manifest)


def require_registered_target(trust, manifest):
    # Registration precedes the retirement check. Every wrap admitted before
    # the marker will appear in the subsequent inventory, even if it ends later.
    recorded = read_registered_target(trust, target_object_name(manifest), manifest["custodyEpoch"], manifest["receiptSha256"])
    if target_binding(recorded) != target_binding(manifest):
        raise ValueError("target does not match the immutable deployment register")
    require_active_epoch(trust, manifest["custodyEpoch"])


def target(trust, document, receipt, custodians, build):
    now = time.time()
    roster = approval_roster(trust, at=now)
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
    require_target_approval_window(manifest, now)

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
    next_custodians, host = manifest["nextCustodians"], manifest["hostRole"]
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

    wrapping_keys = manifest["wrappingKeys"]
    host_account = arn(ROLE_ARN, host)[1]
    if not isinstance(wrapping_keys, list) or len(wrapping_keys) != 6:
        raise ValueError("target requires six custody slots")
    accounts, policies = {host_account}, []
    for member, wrapper in zip(custodians, wrapping_keys, strict=True):
        recovery = member["recoveryKeyArn"]
        custodian, retirement = member["custodianRole"], member["retirementRole"]
        account = arn(KEY_ARN, recovery)[2]
        if (account in accounts or recovery == wrapper or arn(KEY_ARN, wrapper)[2] != account or
                arn(ROLE_ARN, custodian)[1] != account or arn(ROLE_ARN, retirement)[1] != account):
            raise ValueError("each custody slot requires separate keys and roles in its own account")
        accounts.add(account)
        policies.append(key_policy(host, custodian, retirement, pins, manifest["instanceId"]))
    return roster["keys"], policies, next_keys


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
    sign.add_argument("--source-commit", required=True)
    sign.add_argument("--source-ref", default=MAIN_REF)
    sign.add_argument("--next-inspection-profiles", nargs=6)
    sign.add_argument("--next-relay-build", nargs=3, metavar=("BUILD", "COMMIT", "REF"))
    register = commands.add_parser("register")
    register.add_argument("target", type=Path)
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
            _, receipt, custodians = load_epoch(trust, epoch)
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
        _, receipt, custodians = load_epoch(trust, document["manifest"]["custodyEpoch"])
        keys, _, next_keys = target(trust, document, receipt, custodians, args.build)
        if args.command == "register":
            register_target(trust, document)
            return
        if args.command in {"host-policy", "attestation-pins"}:
            require_registered_target(trust, verify_target_approval(trust, document))
            manifest = document["manifest"]
            result = host_policy(manifest) if args.command == "host-policy" else target_attestation(manifest)["pcrs"]
            print(canonical(result).decode())
            return
        require_active_epoch(trust, receipt["custody"]["epoch"])
        reviewed = verify_build(args.build, receipt["network"], args.source_commit, args.source_ref)
        manifest = document["manifest"]
        if any(manifest[field] != reviewed[field] for field in (
            "configurationSha256", "eifSha256", "executableSha256", "pcrs",
        )):
            raise ValueError("target does not match the verified build provenance")
        if next_keys:
            successor = manifest["nextCustodians"]
            check_recovery_roster(trust, str(int(manifest["custodyEpoch"]) + 1), successor, next_keys,
                                  args.next_inspection_profiles, args.next_relay_build)
            for custodian in successor:
                check_acknowledgement_key(custodian)
        elif args.next_relay_build is not None:
            raise ValueError("a successor relay build is only used for rotation")
        require_host_state(manifest, "running", args.host_inspection_profile)
        approved = add_approval(keys, TARGET_APPROVAL, document, args.key)
        with args.output.open("xb") as output:
            output.write(canonical(approved) + b"\n")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
