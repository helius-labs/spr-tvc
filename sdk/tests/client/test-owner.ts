import { ed25519 } from "@noble/curves/ed25519";
import { getAddressDecoder, signatureBytes, type MessagePartialSigner } from "@solana/kit";

const seed = new Uint8Array(32).fill(9);
const address = getAddressDecoder().decode(ed25519.getPublicKey(seed));

export function signOwnerMessage(message: Uint8Array) {
  return signatureBytes(ed25519.sign(message, seed));
}

export const testOwner: MessagePartialSigner = {
  address,
  async signMessages(messages) {
    return messages.map(({ content }) => ({ [address]: signOwnerMessage(Uint8Array.from(content)) }));
  },
};
