"""Render a sealed KMS key policy for one note share and one Nitro target."""

import argparse
import hashlib
import json
import re

from approval import ROLE_ARN, arn, epoch_number, hex_digest

RSA_OAEP = "RSAES_OAEP_SHA_256"
RSA_KEYS = {"RSA_2048", "RSA_3072", "RSA_4096"}


def validate_scope(network, domain, release, epoch):
    if network not in {"devnet", "mainnet"}:
        raise ValueError("invalid network")
    if not re.fullmatch(r"[0-9a-f]{64}", domain) or int(domain, 16) == 0:
        raise ValueError("invalid security domain")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", release):
        raise ValueError("invalid release")
    epoch_number(epoch)


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


def acknowledgement_policy(custodian, key_admin):
    validate_custodian_roles(custodian, key_admin)
    return {"Version": "2012-10-17", "Statement": [
        seal(),
        deny("DenyOtherCustodian", "kms:Sign", Condition={"StringNotEquals": {"aws:PrincipalArn": custodian}}),
        retirement(key_admin),
        statement("ReadAcknowledgementPublicKey", "Allow", "*", ["kms:DescribeKey", "kms:GetPublicKey"]),
        allow("InspectAcknowledgementPolicy", f"arn:aws:iam::{arn(ROLE_ARN, custodian)[1]}:root", "kms:GetKeyPolicy"),
        allow("AcknowledgeShare", custodian, ["kms:GetKeyPolicy", "kms:Sign"]),
    ]}


def boot_pins(host, measurements):
    pins = {key: hex_digest(measurements[key], 48) for key in ("PCR0", "PCR1", "PCR2")}
    pins["PCR3"] = hashlib.sha384(bytes(48) + host.encode()).hexdigest()
    return pins


def target_boot_pins(host, measurements, instance):
    if not isinstance(instance, str) or not re.fullmatch(r"i-[0-9a-f]{17}", instance):
        raise ValueError("expected an EC2 instance ID")
    return {**boot_pins(host, measurements), "PCR4": hashlib.sha384(bytes(48) + instance.encode()).hexdigest()}


def decrypt_conditions(pins):
    return {
        "StringEquals": {"kms:EncryptionAlgorithm": RSA_OAEP},
        "StringEqualsIgnoreCase": {"kms:RecipientAttestation:" + pcr: pin for pcr, pin in pins.items()},
    }


def restrict_decrypt(principal, pins):
    return [
        deny("DenyOtherPrincipal", "kms:Decrypt",
             Condition={"StringNotEquals": {"aws:PrincipalArn": principal}}),
        *(deny(f"DenyWrong{pcr}", "kms:Decrypt",
               Condition={"StringNotEqualsIgnoreCase": {"kms:RecipientAttestation:" + pcr: pin}})
          for pcr, pin in pins.items()),
        deny("DenyOtherAlgorithm", "kms:Decrypt",
             Condition={"StringNotEquals": {"kms:EncryptionAlgorithm": RSA_OAEP}}),
    ]


def recovery_policy(custodian, key_admin, relay_host, measurements, epoch):
    validate_custodian_roles(custodian, key_admin)
    epoch_number(epoch)
    if arn(ROLE_ARN, relay_host)[1] == arn(ROLE_ARN, custodian)[1]:
        raise ValueError("relay host must be in a separate account from the custodian")
    pins = boot_pins(relay_host, measurements)
    return {"Version": "2012-10-17", "Statement": [
        seal(),
        *restrict_decrypt(custodian, pins),
        retirement(key_admin),
        statement("ReadRecoveryPublicKey", "Allow", "*", ["kms:DescribeKey", "kms:GetPublicKey"]),
        allow("InspectRecoveryPolicy", custodian, "kms:GetKeyPolicy"),
        allow("DelegateRecoveryPolicyInspection", f"arn:aws:iam::{arn(ROLE_ARN, custodian)[1]}:root", "kms:GetKeyPolicy"),
        allow(f"RelayRecoveryShareEpoch{epoch}", custodian, "kms:Decrypt", Condition=decrypt_conditions(pins)),
    ]}


def key_policy(host, custodian, key_admin, measurements, instance):
    validate_custodian_roles(custodian, key_admin)
    account = arn(ROLE_ARN, custodian)[1]
    if arn(ROLE_ARN, host)[1] == account:
        raise ValueError("target host must be in a separate account from the custodian")
    pins = target_boot_pins(host, measurements, instance)
    return {"Version": "2012-10-17", "Statement": [
        seal(),
        *restrict_decrypt(host, pins),
        retirement(key_admin),
        statement("ReadWrappingKeyState", "Allow", "*", "kms:DescribeKey"),
        # The slot account may delegate read-only inspection to independent approvers.
        allow("InspectWrappingKey", f"arn:aws:iam::{account}:root", ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetPublicKey"]),
        allow("InspectBeforeWrap", custodian, ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetPublicKey"]),
        allow("ProvisionAttestedEnclave", host, "kms:Decrypt", Condition=decrypt_conditions(pins)),
    ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("measurements", type=argparse.FileType("r"))
    parser.add_argument("--host-role", required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--custodian-role", required=True)
    parser.add_argument("--key-admin-role", required=True)
    args = parser.parse_args()
    measurements = json.load(args.measurements)["Measurements"]
    print(json.dumps(key_policy(args.host_role, args.custodian_role, args.key_admin_role, measurements, args.instance_id), indent=2))


if __name__ == "__main__":
    main()
