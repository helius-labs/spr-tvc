import assert from "node:assert/strict";
import { test, type TestContext } from "node:test";

import {
  blockhash, compileTransaction, createTransactionMessage, generateKeyPairSigner,
  getSignatureFromTransaction, setTransactionMessageFeePayer, setTransactionMessageLifetimeUsingBlockhash,
  signTransactionWithSigners,
} from "@solana/kit";
import { createSprClient } from "@heliuslabs/spr";
import { sendAndConfirmFactory, setup } from "../setup.js";

const MAINNET = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
const DEVNET = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const LOCALNET = "11111111111111111111111111111111";

test("a policy change while the wallet signs prevents RPC broadcast", async (t) => {
  const client = await createSprClient({
    solanaRpcUrl: "http://127.0.0.1:8899/",
    indexerUrl: "http://127.0.0.1:8080/",
    proverUrl: "http://127.0.0.1:8081/",
  });
  const payer = await generateKeyPairSigner();
  const message = setTransactionMessageFeePayer(payer.address, createTransactionMessage({ version: 0 }));
  const transaction = compileTransaction(setTransactionMessageLifetimeUsingBlockhash({
    blockhash: blockhash(LOCALNET), lastValidBlockHeight: 1n,
  }, message));
  const fetch = t.mock.method(globalThis, "fetch", () => assert.fail("unexpected RPC broadcast"));
  let signed = false;
  const send = sendAndConfirmFactory(client, {
    address: payer.address,
    async signTransactions(transactions) {
      const signatures = await payer.signTransactions(transactions);
      signed = true;
      return signatures;
    },
  });

  await assert.rejects(send(transaction, async () => {
    assert.equal(signed, true);
    throw new Error("payment policy changed");
  }), /payment policy changed/);
  assert.equal(fetch.mock.callCount(), 0);
});

test("a finalized rehearsal waits for finality and retains its transaction ID on an ambiguous send", async (t) => {
  const payer = await generateKeyPairSigner();
  const transaction = compileTransaction(setTransactionMessageLifetimeUsingBlockhash(
    { blockhash: blockhash(LOCALNET), lastValidBlockHeight: 1n },
    setTransactionMessageFeePayer(payer.address, createTransactionMessage({ version: 0 })),
  ));
  const signature = getSignatureFromTransaction(await signTransactionWithSigners([payer], transaction));
  let polls = 0;
  let ambiguous = false;
  t.mock.method(globalThis, "fetch", async (_input: RequestInfo | URL, init?: RequestInit) => {
    const { id, method, params } = JSON.parse(String(init?.body));
    if (method === "sendTransaction") {
      assert.equal(params[1].preflightCommitment ?? "finalized", "finalized");
      if (ambiguous) {
        return Response.json({ jsonrpc: "2.0", id, error: { code: -32000, message: "RPC lost its reply" } });
      }
      return Response.json({ jsonrpc: "2.0", id, result: signature });
    }
    assert.equal(method, "getSignatureStatuses");
    assert.deepEqual(params[0], [signature]);
    const confirmationStatus = ++polls === 1 ? "confirmed" : "finalized";
    return Response.json({
      jsonrpc: "2.0", id, result: { context: { slot: 100 }, value: [
        { slot: 66, confirmations: polls === 1 ? 1 : null, err: null, status: { Ok: null }, confirmationStatus },
      ] },
    });
  });
  const client = await createSprClient({
    solanaRpcUrl: "http://127.0.0.1:8899/",
    indexerUrl: "http://127.0.0.1:8080/",
    proverUrl: "http://127.0.0.1:8081/",
    commitment: "finalized",
    indexerConfig: { poll: { numRetries: 2, delayMs: 1n, maxDelayMs: 1n } },
  });
  const send = sendAndConfirmFactory(client, payer);
  assert.deepEqual(await send(transaction), { signature, slot: 66n });
  assert.equal(polls, 2);
  ambiguous = true;
  await assert.rejects(send(transaction), {
    message: `check Solana transaction ${signature} before retrying the rehearsal`,
  });
  assert.equal(polls, 2);
});

function setEnv(t: TestContext, values: Record<string, string | undefined>): void {
  for (const [name, value] of Object.entries(values)) {
    const previous = process.env[name];
    t.after(() => {
      if (previous === undefined) delete process.env[name];
      else process.env[name] = previous;
    });
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
}

test("the demonstration refuses mainnet before contacting any service", async (t) => {
  setEnv(t, { SPR_NETWORK: "mainnet" });
  const fetch = t.mock.method(globalThis, "fetch", () => assert.fail("unexpected network request"));
  await assert.rejects(setup(), /limited to devnet and localnet/);
  assert.equal(fetch.mock.callCount(), 0);
});

const cases = [
  { name: "rejects mainnet genesis on hosted devnet", genesis: MAINNET, local: false, error: /requires a Solana devnet or localnet RPC/ },
  { name: "rejects unexpected genesis on hosted devnet", genesis: LOCALNET, local: false, error: /requires a Solana devnet or localnet RPC/ },
  { name: "rejects mainnet genesis on loopback", genesis: MAINNET, local: true, error: /requires a Solana devnet or localnet RPC/ },
  { name: "accepts hosted devnet genesis before loading Turnkey credentials", genesis: DEVNET, local: false, error: /set TURNKEY_ORGANIZATION_ID/ },
  { name: "accepts localnet genesis before loading the local keypair", genesis: LOCALNET, local: true, error: /set TVC_SOLANA_KEYPAIR_PATH/ },
];

for (const { name, genesis, local, error } of cases) {
  test(name, async (t) => {
    const rpc = local ? "http://127.0.0.1:8899/" : "https://rpc.example/";
    setEnv(t, {
      SPR_NETWORK: "devnet",
      EXAMPLE_ACCEPT_PUBLIC_RECIPIENT: "1",
      ZOLANA_ENDPOINT: rpc,
      ZOLANA_INDEXER_URL: "http://127.0.0.1:8080/",
      ZOLANA_PROVER_URL: "http://127.0.0.1:8081/",
      DECRYPTION_SERVICE_LOCAL_ENDPOINT: local ? "http://127.0.0.1:8082/" : undefined,
      TURNKEY_ORGANIZATION_ID: undefined,
      TVC_SOLANA_KEYPAIR_PATH: undefined,
    });
    const fetch = t.mock.method(globalThis, "fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      assert.equal(String(input), rpc);
      const body = JSON.parse(String(init?.body)) as { method: string; id: unknown };
      assert.equal(body.method, "getGenesisHash");
      return Response.json({ jsonrpc: "2.0", id: body.id, result: genesis });
    });

    await assert.rejects(setup(), error);
    assert.equal(fetch.mock.callCount(), 1);
  });
}
