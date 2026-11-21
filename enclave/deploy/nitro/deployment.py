"""Approve the exact EIF, configuration and KMS destinations for a release."""

import argparse
import hashlib
import re
import subprocess
import time
from pathlib import Path

from approval import (
    KEY_ARN, ROLE_ARN, add_approval, approval_keys, arn, canonical, fields, file_digest, hex_digest, read_json, sha256,
)
from custody_ledger import check_acknowledgement_key, check_recovery_key, load_epoch, validate_roster
from kms_policy import context, key_policy
from provenance import verify as verify_build

LABEL = "target-approval"


def target(trust, document, receipt, custodians, build):
    keys = approval_keys(trust)
    fields(document, "manifest", "signatures")
    manifest = document["manifest"]
    fields(manifest, "network", "securityDomainId", "custodyEpoch", "receiptSha256", "releaseId", "mode", "expiresAt",
           "eifSha256", "configurationSha256", "pcrs", "hostRole", "wrappingKeys", "nextCustodians")
    network, domain, release = manifest["network"], manifest["securityDomainId"], manifest["releaseId"]
    if (network, domain) != (trust["network"], trust["securityDomainId"]) or (
        network, domain
    ) != (receipt["network"], receipt["securityDomainId"]) or (manifest["custodyEpoch"], manifest["receiptSha256"]) != (
        receipt["custody"]["epoch"], sha256(receipt)
    ):
        raise ValueError("target does not authorize this custody receipt and domain")
    expires = manifest["expiresAt"]
    if type(expires) is not int or not time.time() < expires <= 2**53 - 1:
        raise ValueError("target approval has expired or has an invalid deadline")

    config_path = build / "configuration.json"
    if (hex_digest(manifest["configurationSha256"]) != file_digest(config_path) or
            hex_digest(manifest["eifSha256"]) != file_digest(build / "enclave.eif")):
        raise ValueError("target artifacts do not match the approved hashes")
    config = read_json(config_path)
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
        validate_roster(next_custodians, host)
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
            next_keys.append((key, hashlib.sha256(bytes.fromhex(spki)).hexdigest()))
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
    for index, (member, wrapper) in enumerate(zip(custodians, wrapping_keys, strict=True), start=1):
        recovery = member["recoveryKeyArn"]
        custodian, retirement = member["custodianRole"], member["retirementRole"]
        account = arn(KEY_ARN, recovery)[2]
        if (account in accounts or recovery == wrapper or arn(KEY_ARN, wrapper)[2] != account or
                arn(ROLE_ARN, custodian)[1] != account or arn(ROLE_ARN, retirement)[1] != account):
            raise ValueError("each custody slot requires separate keys and roles in its own account")
        accounts.add(account)
        policies.append(key_policy(host, custodian, retirement, pins,
                                   context(network, domain, release, source["epoch"], index)))
    return keys, policies, next_keys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trust", type=Path)
    parser.add_argument("build", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("draft")
    prepare.add_argument("host_role")
    prepare.add_argument("wrapping_keys", type=Path)
    prepare.add_argument("expires_at", type=int)
    prepare.add_argument("--next-roster", type=Path)
    sign = commands.add_parser("sign")
    sign.add_argument("target", type=Path)
    sign.add_argument("key")
    sign.add_argument("output", type=Path)
    sign.add_argument("--source-commit", required=True)
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
                "configurationSha256": file_digest(config_path), "pcrs": {pcr: measured[pcr] for pcr in ("PCR0", "PCR1", "PCR2")},
                "hostRole": args.host_role, "wrappingKeys": read_json(args.wrapping_keys),
                "nextCustodians": read_json(args.next_roster) if args.next_roster else None,
            }, "signatures": []}
            target(trust, document, receipt, custodians, args.build)
            print(canonical(document).decode())
            return
        document = read_json(args.target)
        _, receipt, custodians = load_epoch(trust, document["manifest"]["custodyEpoch"])
        keys, _, next_keys = target(trust, document, receipt, custodians, args.build)
        verify_build(args.build, receipt["network"], args.source_commit)
        for key, fingerprint in next_keys:
            check_recovery_key(key, fingerprint)
        for custodian in document["manifest"]["nextCustodians"] or ():
            check_acknowledgement_key(custodian)
        approved = add_approval(keys, LABEL, document, args.key)
        with args.output.open("xb") as output:
            output.write(canonical(approved) + b"\n")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
