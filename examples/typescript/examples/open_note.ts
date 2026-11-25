import { localService, noteFor, owner, sameBytes } from "../src/lib.js";

const service = localService();
const keys = await service.keys(await owner());
try {
  const plaintext = new TextEncoder().encode("ten usdc");
  const opened = await keys.decrypt([noteFor(keys.address().viewingPublicKey, plaintext, 0)]);
  const note = opened[0];
  if (note === undefined || !sameBytes(note, plaintext)) process.exit(1);
  console.log(`ok plaintext=${new TextDecoder().decode(note)}`);
} finally {
  keys.destroy();
}
