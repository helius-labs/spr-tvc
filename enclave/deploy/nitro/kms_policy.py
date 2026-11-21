"""Render a sealed KMS key policy for one note share and one Nitro target."""

import argparse
import hashlib
import json
import re


def context(network, domain, release, share):
    if network not in {"devnet", "mainnet"}:
        raise ValueError("invalid network")
    if not re.fullmatch(r"[0-9a-f]{64}", domain) or int(domain, 16) == 0:
        raise ValueError("invalid security domain")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", release) or share not in {1, 2}:
        raise ValueError("invalid release or share")
    return {
        "purpose": "spr-note-share",
        "network": network,
        "security-domain": domain,
        "release": release,
        "share": str(share),
    }


def key_policy(host, custodian, key_admin, measurements, ctx):
    roles = [host, custodian, key_admin]
    if len(set(roles)) != len(roles) or any(
        not re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+", arn) for arn in roles
    ):
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

    def allow(sid, role, action, **args):
        return {"Sid": sid, "Effect": "Allow", "Principal": {"AWS": role},
                "Action": action, "Resource": "*", **args}

    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "SealKey", "Effect": "Deny", "Principal": "*", "Resource": "*",
             "Action": ["kms:PutKeyPolicy", "kms:CreateGrant", "kms:ReEncryptFrom",
                        "kms:ReplicateKey", "kms:UpdatePrimaryRegion"]},
            allow("KeyRetirement", key_admin, ["kms:DescribeKey", "kms:GetKeyPolicy",
                                             "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"]),
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
    parser.add_argument("--share", required=True, type=int)
    args = parser.parse_args()
    ctx = context(args.network, args.security_domain, args.release, args.share)
    measurements = json.load(args.measurements)["Measurements"]
    print(json.dumps(key_policy(args.host_role, args.custodian_role, args.key_admin_role, measurements, ctx), indent=2))


if __name__ == "__main__":
    main()
