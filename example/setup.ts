import "dotenv/config";

import { readFile } from "node:fs/promises";
import {
  assertIsFullySignedTransaction,
  assertIsTransactionWithinSizeLimit,
  createKeyPairSignerFromBytes,
  createSignableMessage,
  generateKeyPairSigner,
  getAddressEncoder,
  getSignatureFromTransaction,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
  type Signature,
  type Transaction,
  type TransactionPartialSigner,
} from "@solana/kit";
import {
  LocalKeys,
  createSprClient,
  initializePoseidon,
  type Bytes32,
  type SprClientConfig,
} from "@heliuslabs/spr";
import { SignedTeePolicy } from "@heliuslabs/spr/client";
import { ed25519DerivationMessage } from "@heliuslabs/spr/keypair";
import type { AssetBalance } from "@heliuslabs/spr/transaction";
import { createDecryptionService, type DecryptionService, type Network } from "@heliuslabs/spr-decryption-service";
import { createLocalDecryptionService } from "@heliuslabs/spr-decryption-service/testing";

import { turnkeyClient, turnkeySigner, type OwnerSigner } from "./turnkey.js";

type Client = Awaited<ReturnType<typeof createSprClient>>;
type ConfirmedTransaction = { readonly signature: Signature; readonly slot: bigint };
type ExampleSetup = {
  readonly zolana: Client;
  readonly sender: OwnerSigner;
  readonly recipient: OwnerSigner;
  readonly service: DecryptionService;
  readonly nitro?: Awaited<ReturnType<typeof import("./nitro.js")["nativeDevnet"]>>;
};

function env(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`set ${name}`);
  return value;
}

const DEVNET_GENESIS = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const MAINNET_GENESIS = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
function loopback(url: string | URL | undefined): boolean {
  return url !== undefined && ["127.0.0.1", "localhost", "[::1]"].includes(new URL(url).hostname);
}

function heliusUrl(network: Network, path: string): string {
  const url = new URL(path, `https://${network}.helius-rpc.com`);
  url.searchParams.set("api-key", env("API_KEY"));
  return url.toString();
}

function clientConfig(network: Network): SprClientConfig {
  const proverUrl = process.env["ZOLANA_PROVER_URL"]?.trim() || heliusUrl(network, "/v1/spr");
  const localProver = loopback(proverUrl);
  return {
    solanaRpcUrl: process.env["ZOLANA_ENDPOINT"]?.trim() || heliusUrl(network, "/"),
    indexerUrl: process.env["ZOLANA_INDEXER_URL"]?.trim() || heliusUrl(network, "/v1/spr"),
    proverUrl,
    ...(localProver ? {} : { proverTee: SignedTeePolicy.forNetwork(network) }),
    proofDataSource: "client",
  };
}

async function filePayer() {
  const secret = JSON.parse(await readFile(env("TVC_SOLANA_KEYPAIR_PATH"), "utf8")) as number[];
  const bytes = Uint8Array.from(secret);
  try {
    return await createKeyPairSignerFromBytes(bytes);
  } finally {
    bytes.fill(0);
    secret.fill(0);
  }
}

export async function setup(): Promise<ExampleSetup> {
  const network = process.env["SPR_NETWORK"]?.trim() || "devnet";
  if (network !== "devnet") throw new Error("the example is limited to devnet and localnet");
  const localEndpoint = process.env["DECRYPTION_SERVICE_LOCAL_ENDPOINT"]?.trim();
  const nitroTrust = process.env["NITRO_WALLET_TRUST"]?.trim();
  if (localEndpoint && nitroTrust) throw new Error("choose one decryption service for the example");
  if (!localEndpoint && process.env["EXAMPLE_ACCEPT_PUBLIC_RECIPIENT"] !== "1") {
    throw new Error("this flow publishes the recipient's Solana owner tag. Set EXAMPLE_ACCEPT_PUBLIC_RECIPIENT=1 to proceed");
  }
  const config = clientConfig(network);
  if (localEndpoint && !loopback(config.solanaRpcUrl)) {
    throw new Error("the local example requires loopback RPC");
  }
  await initializePoseidon();
  const zolana = await createSprClient(config);
  const genesis = await zolana.solanaRpc.getGenesisHash().send();
  if (genesis === MAINNET_GENESIS || (!localEndpoint && genesis !== DEVNET_GENESIS)) {
    throw new Error("the example requires a Solana devnet or localnet RPC");
  }
  if (localEndpoint) {
    return {
      zolana,
      sender: await filePayer(),
      recipient: await generateKeyPairSigner(),
      service: createLocalDecryptionService({ network, endpoint: new URL(localEndpoint) }),
    };
  }
  if (nitroTrust) {
    const sender = await filePayer();
    const recipient = await generateKeyPairSigner();
    const { nativeDevnet } = await import("./nitro.js");
    const nextTrust = process.env["NITRO_REPLACEMENT_TRUST"]?.trim();
    const epoch = process.env["NITRO_REPLACEMENT_EPOCH"]?.trim();
    if (nextTrust && epoch) throw new Error("choose a seed cutover or a custody rotation");
    const replacement = nextTrust ? { walletTrust: nextTrust } : { epoch: env("NITRO_REPLACEMENT_EPOCH") };
    const nitro = await nativeDevnet(nitroTrust, env("NITRO_CHECKPOINT_PATH"), replacement);
    return { zolana, sender, recipient, service: nitro.service, nitro };
  }

  const signer = turnkeySigner(
    turnkeyClient(env("TURNKEY_ORGANIZATION_ID"), env("TURNKEY_API_PUBLIC_KEY"), env("TURNKEY_API_PRIVATE_KEY")),
    env("TURNKEY_SOLANA_ADDRESS"),
  );
  const tvcOrganization = env("TVC_ORG_ID");
  const tvc = turnkeyClient(tvcOrganization, env("TVC_API_KEY_PUBLIC"), env("TVC_API_KEY_PRIVATE"));
  const service = createDecryptionService({
    network,
    endpoint: new URL(env("DECRYPTION_SERVICE_URL")),
    resolveBootProof: async ({ bootProofLookupKey }) =>
      (await tvc.getBootProof({ organizationId: tvcOrganization, ephemeralKey: bootProofLookupKey })).bootProof,
  });
  return { zolana, sender: signer, recipient: signer, service };
}

/** Derive wallet-local privacy keys from a Turnkey or local signer. */
export async function localWalletKeys(owner: OwnerSigner, proofService: Client["proofService"]) {
  const publicKey = new Uint8Array(getAddressEncoder().encode(owner.address)) as Bytes32;
  const [signatures] = await owner.signMessages([createSignableMessage(ed25519DerivationMessage(publicKey))]);
  const derivationSeed = signatures?.[owner.address];
  if (!derivationSeed) throw new Error("the owner did not sign the derivation message");
  try {
    return LocalKeys.fromDerivationSeed({ solanaPublicKey: owner.address, derivationSeed }, proofService);
  } finally {
    derivationSeed.fill(0);
  }
}

export function expectBalance(stage: string, balance: AssetBalance, amount: bigint, utxos: number): void {
  if (balance.amount !== amount || balance.utxos.length !== utxos) {
    throw new Error(`${stage}: expected ${amount} in ${utxos} notes, got ${balance.amount} in ${balance.utxos.length}`);
  }
}

export function sendAndConfirmFactory(
  client: Client,
  ...signers: TransactionPartialSigner[]
): (transaction: Transaction) => Promise<ConfirmedTransaction> {
  const send = sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc });
  return async (transaction) => {
    const signed = await signTransactionWithSigners(signers, transaction);
    assertIsFullySignedTransaction(signed);
    assertIsTransactionWithinSizeLimit(signed);
    await send(signed, { commitment: client.commitment });
    const signature = getSignatureFromTransaction(signed);
    return { signature, slot: await client.confirmTransaction(signature) };
  };
}
