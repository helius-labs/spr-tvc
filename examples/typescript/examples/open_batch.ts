import { localService, noteFor, owner, sameBytes } from "../src/lib.js";

const service = localService();
const keys = await service.keys(await owner());
try {
  const first = new TextEncoder().encode("ten usdc");
  const second = new TextEncoder().encode("two sol");
  const viewing = keys.address().viewingPublicKey;
  const opened = await keys.decrypt([
    noteFor(viewing, first, 0),
    noteFor(viewing, second, 1),
  ]);
  const [openedFirst, openedSecond] = opened;
  if (
    openedFirst === undefined ||
    openedSecond === undefined ||
    !sameBytes(openedFirst, first) ||
    !sameBytes(openedSecond, second)
  ) {
    process.exit(1);
  }
  console.log(
    `ok plaintexts=${new TextDecoder().decode(openedFirst)},${new TextDecoder().decode(openedSecond)}`,
  );
} finally {
  keys.destroy();
}
