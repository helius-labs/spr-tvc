import {
  address,
  getPublicKeyFromAddress,
  getTransactionDecoder,
  getTransactionEncoder,
  signatureBytes,
  verifySignature,
  type MessagePartialSigner,
  type TransactionPartialSigner,
} from "@solana/kit";
import { Turnkey } from "@turnkey/sdk-server";

export type OwnerSigner = MessagePartialSigner & TransactionPartialSigner;

export function turnkeyClient(organizationId: string, publicKey: string, privateKey: string) {
  return new Turnkey({
    apiBaseUrl: "https://api.turnkey.com",
    apiPublicKey: publicKey,
    apiPrivateKey: privateKey,
    defaultOrganizationId: organizationId,
  }).apiClient();
}

type ApiClient = ReturnType<typeof turnkeyClient>;
type TurnkeyApi = {
  signRawPayload(input: Parameters<ApiClient["signRawPayload"]>[0]): Promise<{ r: string; s: string }>;
  signTransaction(input: Parameters<ApiClient["signTransaction"]>[0]): Promise<{ signedTransaction: string }>;
};

/** Sign the SDK's exact message bytes. Verify each Turnkey signature before using it. */
export function turnkeySigner(client: TurnkeyApi, walletAddress: string): OwnerSigner {
  const signer = address(walletAddress);
  const publicKey = getPublicKeyFromAddress(signer);
  const encoder = getTransactionEncoder();
  const decoder = getTransactionDecoder();
  return {
    address: signer,
    async signMessages(messages) {
      const signatures = [];
      for (const { content } of messages) {
        const { r, s } = await client.signRawPayload({
          signWith: signer,
          payload: Buffer.from(content).toString("hex"),
          encoding: "PAYLOAD_ENCODING_HEXADECIMAL",
          hashFunction: "HASH_FUNCTION_NOT_APPLICABLE",
        });
        if (!/^[0-9a-fA-F]{64}$/.test(r) || !/^[0-9a-fA-F]{64}$/.test(s)) {
          throw new Error("Turnkey returned a malformed Ed25519 signature");
        }
        const signature = signatureBytes(new Uint8Array(Buffer.from(r + s, "hex")));
        if (!(await verifySignature(await publicKey, signature, content))) {
          throw new Error("Turnkey returned a signature for a different message or account");
        }
        signatures.push({ [signer]: signature });
      }
      return signatures;
    },
    async signTransactions(transactions) {
      const signatures = [];
      for (const transaction of transactions) {
        if (!(signer in transaction.signatures)) throw new Error("Turnkey account is not a transaction signer");
        const { signedTransaction } = await client.signTransaction({
          signWith: signer,
          unsignedTransaction: Buffer.from(encoder.encode(transaction)).toString("hex"),
          type: "TRANSACTION_TYPE_SOLANA",
        });
        const signed = decoder.decode(new Uint8Array(Buffer.from(signedTransaction, "hex")));
        if (!Buffer.from(signed.messageBytes).equals(Buffer.from(transaction.messageBytes))) {
          throw new Error("Turnkey changed the transaction message");
        }
        const signature = signed.signatures[signer];
        if (!signature || !(await verifySignature(await publicKey, signature, transaction.messageBytes))) {
          throw new Error("Turnkey returned an invalid transaction signature");
        }
        signatures.push({ [signer]: signature });
      }
      return signatures;
    },
  };
}
