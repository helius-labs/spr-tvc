"""Verify the EC2 parent and its cross-account KMS authorization."""

import re
import subprocess

from approval import KEY_ARN, ROLE_ARN, arn, aws, canonical, require_profile_account
from kms_policy import decrypt_conditions, target_boot_pins

HOST_BOOTSTRAP_POLICY = "spr-nitro-bootstrap"


def host_policy(manifest):
    pins = target_boot_pins(manifest["hostRole"], manifest["pcrs"], manifest["instanceId"])
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": manifest["wrappingKeys"],
         "Condition": decrypt_conditions(pins)}
    ]}


class HostUnobserved(ValueError):
    """EC2 did not return state for the requested instance."""


def require_host_role(instance, role, account, region, profile):
    attachment = instance.get("IamInstanceProfile")
    if not isinstance(attachment, dict):
        raise ValueError("target parent has no instance profile")
    profile_arn = attachment.get("Arn")
    profile_id = attachment.get("Id")
    if (not isinstance(profile_arn, str) or
            not profile_arn.startswith(f"arn:aws:iam::{account}:instance-profile/") or
            not isinstance(profile_id, str) or not profile_id):
        raise ValueError("target parent has no instance profile in its approved account")
    profile_name = profile_arn.rsplit("/", 1)[-1]
    if not re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,128}", profile_name):
        raise ValueError("invalid target instance profile name")
    installed = aws(region, "iam", "get-instance-profile", ["--instance-profile-name", profile_name],
                    profile=profile).get("InstanceProfile")
    if not isinstance(installed, dict):
        raise ValueError("IAM returned no target instance profile")
    roles = installed.get("Roles")
    if (installed.get("Arn") != profile_arn or installed.get("InstanceProfileId") != profile_id or
            not isinstance(roles, list) or len(roles) != 1 or not isinstance(roles[0], dict) or roles[0].get("Arn") != role):
        raise ValueError("target instance profile does not contain the approved host role")


def require_host_state(manifest, state, profile):
    account = arn(ROLE_ARN, manifest["hostRole"])[1]
    region, instance = manifest["hostRegion"], manifest["instanceId"]
    try:
        reservations = aws(region, "ec2", "describe-instances", ["--instance-ids", instance], profile=profile)["Reservations"]
    except (ValueError, subprocess.TimeoutExpired) as error:
        raise HostUnobserved(f"EC2 could not describe {account}/{region}/{instance}") from error
    if not reservations:
        raise HostUnobserved(f"missing EC2 evidence for {account}/{region}/{instance}")
    if len(reservations) != 1 or reservations[0].get("OwnerId") != account:
        raise ValueError(f"unexpected EC2 reservation for {account}/{region}/{instance}")
    instances = reservations[0].get("Instances", [])
    if (len(instances) != 1 or instances[0].get("InstanceId") != instance or
            instances[0].get("State", {}).get("Name") != state or
            (state == "running" and instances[0].get("EnclaveOptions", {}).get("Enabled") is not True)):
        raise ValueError(f"expected {account}/{region}/{instance} to be {state}")
    if state == "running":
        parent = instances[0]
        if parent.get("Architecture") != "x86_64":
            raise ValueError("target parent must support the reviewed x86-64 EIF")
        require_host_role(parent, manifest["hostRole"], account, region, profile)
    return {"account": account, "region": region, "instanceId": instance, "state": state, "source": "ec2"}


def allowed_wrapping_keys(manifest, keys, conditions, profile):
    by_region = {}
    for key in keys:
        by_region.setdefault(arn(KEY_ARN, key)[1], set()).add(key)
    role = manifest["hostRole"]
    account = arn(ROLE_ARN, role)[1]
    host_region, instance = manifest["hostRegion"], manifest["instanceId"]
    context = {
        **conditions["StringEquals"],
        **conditions["StringEqualsIgnoreCase"],
        "aws:PrincipalArn": role,
        "ec2:SourceInstanceARN": f"arn:aws:ec2:{host_region}:{account}:instance/{instance}",
    }
    allowed = set()
    for region, requested in sorted(by_region.items()):
        entries = [{"ContextKeyName": name, "ContextKeyValues": [value], "ContextKeyType": "string"}
                   for name, value in {**context, "aws:RequestedRegion": region}.items()]
        # This evaluates the host identity policies. Callers verify the
        # installed KMS resource policies from the custody accounts.
        reply = aws(host_region, "iam", "simulate-principal-policy", [
            "--policy-source-arn", role, "--action-names", "kms:Decrypt",
            "--resource-arns", *sorted(requested), "--context-entries", canonical(entries).decode(),
            "--no-paginate",
        ], profile=profile)
        results = reply.get("EvaluationResults")
        if (reply.get("IsTruncated") is not False or not isinstance(results, list) or len(results) != 1 or
                not isinstance(results[0], dict) or results[0].get("EvalActionName") != "kms:Decrypt"):
            raise ValueError("invalid IAM bootstrap simulation")
        decisions = results[0].get("ResourceSpecificResults")
        if not isinstance(decisions, list) or len(decisions) != len(requested):
            raise ValueError("incomplete IAM bootstrap simulation")
        seen = set()
        for result in decisions:
            key = result.get("EvalResourceName") if isinstance(result, dict) else None
            if not isinstance(key, str) or key not in requested or key in seen:
                raise ValueError("unexpected key in IAM bootstrap simulation")
            seen.add(key)
            if result.get("EvalResourceDecision") == "allowed" and result.get("MissingContextValues", []) == []:
                allowed.add(key)
    return allowed


def require_bootstrap_access(manifest, profile, *, slots=range(1, 7), minimum=None):
    role = manifest["hostRole"]
    account = arn(ROLE_ARN, role)[1]
    if not profile:
        raise ValueError(f"missing read-only inspection profile for host account {account}")
    region = manifest["hostRegion"]
    require_profile_account(profile, region, account)
    require_host_state(manifest, "running", profile)
    role_name = role.rsplit("/", 1)[-1]
    expected = host_policy(manifest)
    installed = aws(region, "iam", "get-role-policy", [
        "--role-name", role_name, "--policy-name", HOST_BOOTSTRAP_POLICY,
    ], profile=profile)
    if (installed.get("RoleName") != role_name or installed.get("PolicyName") != HOST_BOOTSTRAP_POLICY or
            installed.get("PolicyDocument") != expected):
        raise ValueError("target host's installed bootstrap policy differs from the approved policy")
    keys = {manifest["wrappingKeys"][slot - 1] for slot in slots}
    allowed = allowed_wrapping_keys(manifest, keys, expected["Statement"][0]["Condition"], profile)
    if len(allowed) < (len(keys) if minimum is None else minimum):
        raise ValueError("target host lacks effective bootstrap permission for the required wrapping keys")
