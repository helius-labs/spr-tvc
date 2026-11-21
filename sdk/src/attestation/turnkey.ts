// Verify the Nitro COSE signature and certificate chain against the pinned AWS
// root, using the verifier's clock. boot-proof.ts checks the replica key, PCRs,
// and canonical QOS manifest digest against the release policy.

import * as turnkeyCrypto from "@turnkey/crypto";
import type { v1AppProof, v1BootProof } from "@turnkey/sdk-types";
import { AWS_NITRO_ROOT_CERT_PEM, verifyCoseSign1Signature, type CoseSign1 } from "./aws-nitro.js";

export type TurnkeyAppProofWire = v1AppProof;
export type TurnkeyBootProofWire = v1BootProof;

export async function verifyTurnkeyAwsAttestation(
  coseSign1: CoseSign1,
  certificate: Uint8Array,
  cabundle: Uint8Array[],
  timestampMs: number
): Promise<void> {
  await verifyCoseSign1Signature(coseSign1, certificate, await turnkeyCrypto.getCryptoInstance());
  await turnkeyCrypto.verifyCertificateChain(
    cabundle,
    AWS_NITRO_ROOT_CERT_PEM,
    certificate,
    timestampMs
  );
}
