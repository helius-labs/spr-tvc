import { initializePoseidon } from "@heliuslabs/spr";

import { localService, owner } from "../src/lib.js";

await initializePoseidon();
const service = localService();
const keys = await service.keys(await owner());
try {
  const secret = await keys.nullifierSecret();
  console.log(`ok nullifier_secret_len=${secret.length}`);
  secret.fill(0);
} finally {
  keys.destroy();
}
