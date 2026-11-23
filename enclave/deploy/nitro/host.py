"""Verify the EC2 parent and its cross-account KMS authorization."""

import re
import subprocess

from approval import ROLE_ARN, arn, aws, require_profile_account
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


def require_bootstrap_access(manifest, profile):
    role = manifest["hostRole"]
    account = arn(ROLE_ARN, role)[1]
    if not profile:
        raise ValueError(f"missing read-only inspection profile for host account {account}")
    region = manifest["hostRegion"]
    require_profile_account(profile, region, account)
    require_host_state(manifest, "running", profile)
    role_name = role.rsplit("/", 1)[-1]
    installed = aws(region, "iam", "get-role-policy", [
        "--role-name", role_name, "--policy-name", HOST_BOOTSTRAP_POLICY,
    ], profile=profile)
    if (installed.get("RoleName") != role_name or installed.get("PolicyName") != HOST_BOOTSTRAP_POLICY or
            installed.get("PolicyDocument") != host_policy(manifest)):
        raise ValueError("target host's installed bootstrap policy differs from the approved policy")
