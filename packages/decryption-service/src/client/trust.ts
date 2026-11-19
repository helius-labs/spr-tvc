import type { TurnkeyAppProofWire } from "../verify/internal/turnkey-proof-seam.js";

export type DecryptionServiceTrustVerifier = {
  verifyOperationAppProof(proof: TurnkeyAppProofWire, signal?: AbortSignal): Promise<void>;
};
