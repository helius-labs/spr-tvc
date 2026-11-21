"""Render a sealed KMS key policy for one note share and one Nitro target."""

import argparse
import hashlib
import json
import re

from approval import ROLE_ARN, arn


def context(network, domain, release, epoch, share):
    if network not in {"devnet", "mainnet"}:
        raise ValueError("invalid network")
    if not re.fullmatch(r"[0-9a-f]{64}", domain) or int(domain, 16) == 0:
        raise ValueError("invalid security domain")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", release) or share not in range(1, 7):
        raise ValueError("invalid release or share")
    if not isinstance(epoch, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", epoch) or int(epoch) > 2**64-1:
        raise ValueError("invalid custody epoch")
    return {
        "purpose": "spr-note-share",
        "network": network,
        "security-domain": domain,
        "release": release,
        "custody-epoch": epoch,
        "share": str(share),
    }


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


def recovery_policy(custodian, key_admin):
    if custodian == key_admin or arn(ROLE_ARN, custodian)[1] != arn(ROLE_ARN, key_admin)[1]:
        raise ValueError("expected separate recovery and retirement roles in the custodian account")
    return {"Version": "2012-10-17", "Statement": [
        seal(),
        deny("DenyOtherCustodian", "kms:Decrypt", Condition={"StringNotEquals": {"aws:PrincipalArn": custodian}}),
        retirement(key_admin),
        statement("ReadRecoveryPublicKey", "Allow", "*", "kms:GetPublicKey"),
        allow("OpenRecoveryShare", custodian, ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:Decrypt"]),
    ]}


def acknowledgement_policy(custodian, key_admin):
    if custodian == key_admin or arn(ROLE_ARN, custodian)[1] != arn(ROLE_ARN, key_admin)[1]:
        raise ValueError("expected separate signing and retirement roles in the custodian account")
    return {"Version": "2012-10-17", "Statement": [
        seal(),
        deny("DenyOtherCustodian", "kms:Sign", Condition={"StringNotEquals": {"aws:PrincipalArn": custodian}}),
        retirement(key_admin),
        statement("VerifyAcknowledgement", "Allow", "*", "kms:Verify"),
        allow("AcknowledgeShare", custodian, ["kms:GetKeyPolicy", "kms:Sign"]),
    ]}


def key_policy(host, custodian, key_admin, measurements, ctx):
    roles = [host, custodian, key_admin]
    if len({arn(ROLE_ARN, role)[0] for role in roles}) != len(roles):
        raise ValueError("expected distinct IAM roles for boot, encryption and key retirement")
    pins = {key: measurements[key] for key in ("PCR0", "PCR1", "PCR2")}
    pins["PCR3"] = hashlib.sha384(bytes(48) + host.encode()).hexdigest()
    if any(not re.fullmatch(r"[0-9a-f]{96}", pin) or int(pin, 16) == 0 for pin in pins.values()):
        raise ValueError("expected normal-mode Nitro measurements")
    context_equals = {"kms:EncryptionContext:" + key: value for key, value in ctx.items()}
    conditions = {
        "StringEquals": context_equals,
        "ForAllValues:StringEquals": {"kms:EncryptionContextKeys": list(ctx)},
    }

    return {
        "Version": "2012-10-17",
        "Statement": [
            seal(),
            # Explicit denials also apply if a key had a grant before its policy was sealed.
            deny("DenyOtherHost", "kms:Decrypt", Condition={"StringNotEquals": {"aws:PrincipalArn": host}}),
            *[deny(f"DenyWrong{pcr}", "kms:Decrypt", Condition={
                "StringNotEqualsIgnoreCase": {"kms:RecipientAttestation:" + pcr: pin},
            }) for pcr, pin in pins.items()],
            *[deny(f"DenyWrongContext{index}", "kms:Decrypt", Condition={"StringNotEquals": {field: value}})
              for index, (field, value) in enumerate(context_equals.items())],
            deny("DenyExtraContext", "kms:Decrypt", Condition={
                "ForAnyValue:StringNotEquals": {"kms:EncryptionContextKeys": list(ctx)},
            }),
            retirement(key_admin),
            allow("InspectBeforeWrap", custodian, ["kms:DescribeKey", "kms:GetKeyPolicy"]),
            allow("WrapShare", custodian, "kms:Encrypt", Condition=conditions),
            allow("ProvisionAttestedEnclave", host, "kms:Decrypt", Condition={
                **conditions,
                "StringEqualsIgnoreCase": {"kms:RecipientAttestation:" + key: pin for key, pin in pins.items()},
            }),
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
