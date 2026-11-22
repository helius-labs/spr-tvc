"""Render a sealed KMS key policy for one note share and one Nitro target."""

import argparse
import hashlib
import json
import re

from approval import ROLE_ARN, arn, epoch_number, hex_digest


def context(network, domain, release, epoch, share):
    if network not in {"devnet", "mainnet"}:
        raise ValueError("invalid network")
    if not re.fullmatch(r"[0-9a-f]{64}", domain) or int(domain, 16) == 0:
        raise ValueError("invalid security domain")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", release) or share not in range(1, 7):
        raise ValueError("invalid release or share")
    epoch_number(epoch)
    return {
        "purpose": "spr-note-share",
        "network": network,
        "security-domain": domain,
        "release": release,
        "custody-epoch": epoch,
        "share": str(share),
    }


def target_context(manifest, index):
    return context(manifest["network"], manifest["securityDomainId"], manifest["releaseId"], manifest["custodyEpoch"], index)


def statement(sid, effect, principal, action, **conditions):
    return {"Sid": sid, "Effect": effect, "Principal": principal, "Action": action, "Resource": "*", **conditions}


def allow(sid, role, action, **conditions):
    return statement(sid, "Allow", {"AWS": role}, action, **conditions)


def deny(sid, action, **conditions):
    return statement(sid, "Deny", "*", action, **conditions)


def seal():
    return deny("SealKey", ["kms:PutKeyPolicy", "kms:CreateGrant", "kms:ReEncryptFrom",
                            "kms:ReplicateKey", "kms:UpdatePrimaryRegion"])


def retirement(role):
    return allow("KeyRetirement", role, ["kms:DescribeKey", "kms:GetKeyPolicy",
                                        "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"])


def validate_custodian_roles(custodian, key_admin):
    if custodian == key_admin or arn(ROLE_ARN, custodian)[1] != arn(ROLE_ARN, key_admin)[1]:
        raise ValueError("expected separate recovery and retirement roles in the custodian account")


def recovery_policy(custodian, key_admin, epoch):
    validate_custodian_roles(custodian, key_admin)
    epoch_number(epoch)
    return {"Version": "2012-10-17", "Statement": [
        seal(),
        deny("DenyOtherCustodian", "kms:Decrypt", Condition={"StringNotEquals": {"aws:PrincipalArn": custodian}}),
        retirement(key_admin),
        statement("ReadRecoveryPublicKey", "Allow", "*", ["kms:DescribeKey", "kms:GetPublicKey"]),
        allow(f"OpenRecoveryShareEpoch{epoch}", custodian, ["kms:GetKeyPolicy", "kms:Decrypt"]),
    ]}


def acknowledgement_policy(custodian, key_admin):
    validate_custodian_roles(custodian, key_admin)
    return {"Version": "2012-10-17", "Statement": [
        seal(),
        deny("DenyOtherCustodian", "kms:Sign", Condition={"StringNotEquals": {"aws:PrincipalArn": custodian}}),
        retirement(key_admin),
        statement("ReadAcknowledgementPublicKey", "Allow", "*", ["kms:DescribeKey", "kms:GetPublicKey"]),
        allow("AcknowledgeShare", custodian, ["kms:GetKeyPolicy", "kms:Sign"]),
    ]}


def boot_pins(host, measurements):
    pins = {key: hex_digest(measurements[key], 48) for key in ("PCR0", "PCR1", "PCR2")}
    pins["PCR3"] = hashlib.sha384(bytes(48) + host.encode()).hexdigest()
    return pins


def encryption_conditions(ctx):
    return {
        "StringEquals": {"kms:EncryptionContext:" + key: value for key, value in ctx.items()},
        "ForAllValues:StringEquals": {"kms:EncryptionContextKeys": list(ctx)},
    }


def decrypt_conditions(pins, ctx):
    return {**encryption_conditions(ctx),
            "StringEqualsIgnoreCase": attestation_fields(pins)}


def attestation_fields(pins):
    return {"kms:RecipientAttestation:" + pcr: pin for pcr, pin in pins.items()}


def deny_wrong_pcrs(pins):
    return [deny(f"DenyWrong{pcr}", "kms:Decrypt", Condition={
        "StringNotEqualsIgnoreCase": {"kms:RecipientAttestation:" + pcr: pin},
    }) for pcr, pin in pins.items()]


def relay_recovery_policy(custodian, key_admin, relay_host, measurements, epoch):
    validate_custodian_roles(custodian, key_admin)
    epoch_number(epoch)
    if arn(ROLE_ARN, relay_host)[1] == arn(ROLE_ARN, custodian)[1]:
        raise ValueError("relay host must be in a separate account from the custodian")
    pins = boot_pins(relay_host, measurements)
    algorithm = {"kms:EncryptionAlgorithm": "RSAES_OAEP_SHA_256"}
    return {"Version": "2012-10-17", "Statement": [
        seal(),
        deny("DenyOtherCustodian", "kms:Decrypt", Condition={"StringNotEquals": {"aws:PrincipalArn": custodian}}),
        *deny_wrong_pcrs(pins),
        deny("DenyOtherAlgorithm", "kms:Decrypt", Condition={"StringNotEquals": algorithm}),
        retirement(key_admin),
        statement("ReadRecoveryPublicKey", "Allow", "*", ["kms:DescribeKey", "kms:GetPublicKey"]),
        allow("InspectRecoveryPolicy", custodian, "kms:GetKeyPolicy"),
        allow(f"RelayRecoveryShareEpoch{epoch}", custodian, "kms:Decrypt", Condition={
            "StringEquals": algorithm, "StringEqualsIgnoreCase": attestation_fields(pins),
        }),
    ]}


def key_policy(host, custodian, key_admin, measurements, ctx):
    roles = [host, custodian, key_admin]
    if len({arn(ROLE_ARN, role)[0] for role in roles}) != len(roles):
        raise ValueError("expected distinct IAM roles for boot, encryption and key retirement")
    pins = boot_pins(host, measurements)
    conditions = encryption_conditions(ctx)
    return {
        "Version": "2012-10-17",
        "Statement": [
            seal(),
            # Explicit denials also apply if a key had a grant before its policy was sealed.
            deny("DenyOtherHost", "kms:Decrypt", Condition={"StringNotEquals": {"aws:PrincipalArn": host}}),
            *deny_wrong_pcrs(pins),
            *[deny(f"DenyWrongContext{index}", "kms:Decrypt", Condition={"StringNotEquals": {field: value}})
              for index, (field, value) in enumerate(conditions["StringEquals"].items())],
            deny("DenyExtraContext", "kms:Decrypt", Condition={
                "ForAnyValue:StringNotEquals": {"kms:EncryptionContextKeys": list(ctx)},
            }),
            retirement(key_admin),
            allow("InspectBeforeWrap", custodian, ["kms:DescribeKey", "kms:GetKeyPolicy"]),
            allow("WrapShare", custodian, "kms:Encrypt", Condition=conditions),
            allow("ProvisionAttestedEnclave", host, "kms:Decrypt", Condition=decrypt_conditions(pins, ctx)),
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("measurements", type=argparse.FileType("r"))
    parser.add_argument("--host-role", required=True)
    parser.add_argument("--custodian-role", required=True)
    parser.add_argument("--key-admin-role", required=True)
    parser.add_argument("--network", required=True)
    parser.add_argument("--security-domain", required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--custody-epoch", required=True)
    parser.add_argument("--share", required=True, type=int)
    args = parser.parse_args()
    ctx = context(args.network, args.security_domain, args.release, args.custody_epoch, args.share)
    measurements = json.load(args.measurements)["Measurements"]
    print(json.dumps(key_policy(args.host_role, args.custodian_role, args.key_admin_role, measurements, ctx), indent=2))


if __name__ == "__main__":
    main()
