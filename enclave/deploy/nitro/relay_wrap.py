"""Authorize or release one registered share through the attested relay."""

import argparse
import base64
import subprocess
from pathlib import Path
from time import time

from approval import add_approval, approval_roster, canonical, check_approvals, epoch_number, read_json, sha256
from custody_ledger import load_epoch, require_active_epoch, verify_target_approval
from deployment import require_registered_target, require_reviewed_target, target
from relay import live_recipient, recover_to_relay, relay_pins, relay_request, sealed_rsa_key

LABEL = "relay-release"


def require_release_window(expires_at):
    if time() >= expires_at:
        raise ValueError("relay authorization has expired")


def require_release_scope(trust, approval, statement):
    expires_at = statement["expiresAt"]
    require_release_window(expires_at)
    verify_target_approval(trust, approval)
    require_active_epoch(trust, statement["custodyEpoch"])
    require_release_window(expires_at)


def prepare(trust, approval, build, index, port, inspection_profile=None):
    if not 1 <= index <= 6:
        raise ValueError("invalid custody slot")
    at = time()
    manifest = verify_target_approval(trust, approval, at=at)
    epoch = manifest["custodyEpoch"]
    relay = relay_pins(trust, epoch)
    _, receipt, custodians = load_epoch(trust, epoch)
    _, policies, _ = target(trust, approval, receipt, custodians, build)
    require_registered_target(trust, manifest)
    roster = approval_roster(trust, epoch=epoch)
    if epoch_number(roster["fromEpoch"]) < epoch_number(manifest["approvalFromEpoch"]):
        raise ValueError("the relay's measured approval roster has retired")
    expires = min(manifest["expiresAt"], next(
        (entry["activeFrom"] for entry in trust["approvalKeys"] if entry["activeFrom"] > at),
        manifest["expiresAt"],
    ))
    destination = sealed_rsa_key(manifest["wrappingKeys"][index - 1], policies[index - 1], profile=inspection_profile)
    key_id, evidence = live_recipient(port, relay)
    require_release_window(expires)
    statement = {
        "network": manifest["network"], "securityDomainId": manifest["securityDomainId"], "custodyEpoch": epoch,
        "slot": index, "shareCommitment": receipt["custody"]["shareCommitments"][index - 1],
        "relayKeyId": key_id, "targetDigest": sha256(manifest), "expiresAt": expires,
        "destinationPublicKey": destination.hex(),
    }
    return statement, roster["keys"], receipt, custodians[index - 1], evidence


def sign_release(trust, approval, statement, keys, authorization, key):
    if authorization["manifest"] != statement or len(authorization["signatures"]) >= 2:
        raise ValueError("relay authorization changed or already has two signatures")
    require_release_scope(trust, approval, statement)
    signed = add_approval(keys, LABEL, authorization, key)
    require_release_scope(trust, approval, statement)
    return signed


def release(trust, approval, build, index, port, authorization, *, review):
    statement, keys, receipt, custodian, evidence = prepare(trust, approval, build, index, port)
    if authorization["manifest"] != statement:
        raise ValueError("relay release does not match the live boot and registered target")
    check_approvals(keys, LABEL, authorization)
    if len(authorization["signatures"]) != 2:
        raise ValueError("relay release requires exactly two signatures")
    require_reviewed_target(build, approval["manifest"], review)

    def still_authorized():
        require_release_scope(trust, approval, statement)

    envelope = recover_to_relay(trust, receipt, custodian, index, evidence, still_authorized)
    authorities = {key["keyArn"]: i for i, key in enumerate(keys, start=1)}
    body = canonical({"statement": statement, "envelope": envelope.hex(), "approvals": [
        {"authority": authorities[signature["keyArn"]],
         "signature": base64.b64decode(signature["signature"], validate=True).hex()}
        for signature in authorization["signatures"]
    ]})
    still_authorized()
    ciphertext = relay_request(port, "/rewrap", body, 512)
    if len(ciphertext) not in (256, 384, 512):
        raise ValueError("invalid relay destination ciphertext length")
    still_authorized()
    return ciphertext


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trust", type=Path)
    parser.add_argument("target", type=Path)
    parser.add_argument("build", type=Path)
    parser.add_argument("slot", type=int, choices=range(1, 7))
    parser.add_argument("--relay-port", type=int, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    draft = commands.add_parser("draft")
    draft.add_argument("--inspection-profile", required=True)
    sign = commands.add_parser("sign")
    sign.add_argument("authorization", type=Path)
    sign.add_argument("key")
    sign.add_argument("--inspection-profile", required=True)
    wrap = commands.add_parser("wrap")
    wrap.add_argument("authorization", type=Path)
    wrap.add_argument("output", type=Path)
    wrap.add_argument("--review", type=Path, required=True)
    args = parser.parse_args()
    try:
        trust, approval = map(read_json, (args.trust, args.target))
        source = (trust, approval, args.build, args.slot, args.relay_port)
        if args.command == "wrap":
            ciphertext = release(*source, read_json(args.authorization), review=args.review)
            with args.output.open("xb") as file:
                file.write(ciphertext)
        else:
            statement, keys, _, _, _ = prepare(*source, inspection_profile=args.inspection_profile)
            document = {"manifest": statement, "signatures": []}
            if args.command == "sign":
                document = sign_release(trust, approval, statement, keys, read_json(args.authorization), args.key)
            print(canonical(document).decode())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
