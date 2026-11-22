"""Authorize or release one registered devnet share through the attested relay."""

import argparse
import base64
import http.client
import subprocess
from pathlib import Path

from approval import add_approval, approval_roster, canonical, check_approvals, read_json, sha256
from custody_ledger import load_epoch, require_active_epoch, verify_target_approval
from deployment import require_registered_target, target
from kms_policy import RSA_OAEP, target_algorithm
from relay import live_recipient, recover_to_relay, relay_pins, relay_request, sealed_rsa_key

LABEL = "relay-release"


def prepare(trust, approval, build, index, port, inspection_profile=None):
    if not 1 <= index <= 6:
        raise ValueError("invalid custody slot")
    manifest = verify_target_approval(trust, approval)
    if target_algorithm(manifest) != RSA_OAEP:
        raise ValueError("the relay requires an RSA target")
    epoch = manifest["custodyEpoch"]
    relay = relay_pins(trust, epoch)
    _, receipt, custodians = load_epoch(trust, epoch)
    keys, policies, _ = target(trust, approval, receipt, custodians, build)
    require_registered_target(trust, manifest)
    if keys != approval_roster(trust, epoch=epoch)["keys"]:
        raise ValueError("the active approval keys do not match the epoch's relay roster")
    destination = sealed_rsa_key(manifest["wrappingKeys"][index - 1], policies[index - 1], profile=inspection_profile)
    key_id, evidence = live_recipient(port, relay)
    statement = {
        "network": manifest["network"], "securityDomainId": manifest["securityDomainId"], "custodyEpoch": epoch,
        "slot": index, "shareCommitment": receipt["custody"]["shareCommitments"][index - 1],
        "relayKeyId": key_id, "targetDigest": sha256(manifest), "destinationPublicKey": destination.hex(),
    }
    return statement, keys, receipt, custodians[index - 1], evidence


def release(trust, approval, build, index, port, authorization):
    statement, keys, receipt, custodian, evidence = prepare(trust, approval, build, index, port)
    if authorization["manifest"] != statement:
        raise ValueError("relay release does not match the live boot and registered target")
    check_approvals(keys, LABEL, authorization)
    if len(authorization["signatures"]) != 2:
        raise ValueError("relay release requires exactly two signatures")

    def still_authorized():
        require_active_epoch(trust, statement["custodyEpoch"])
        verify_target_approval(trust, approval)

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
    args = parser.parse_args()
    try:
        trust, approval = map(read_json, (args.trust, args.target))
        source = (trust, approval, args.build, args.slot, args.relay_port)
        if args.command == "wrap":
            ciphertext = release(*source, read_json(args.authorization))
            with args.output.open("xb") as file:
                file.write(ciphertext)
        else:
            statement, keys, _, _, _ = prepare(*source, inspection_profile=args.inspection_profile)
            document = {"manifest": statement, "signatures": []}
            if args.command == "sign":
                document = read_json(args.authorization)
                if document["manifest"] != statement or len(document["signatures"]) >= 2:
                    raise ValueError("relay authorization changed or already has two signatures")
                verify_target_approval(trust, approval)
                require_active_epoch(trust, statement["custodyEpoch"])
                document = add_approval(keys, LABEL, document, args.key)
            print(canonical(document).decode())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, http.client.HTTPException) as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
