import { localService, lowerHex, owner } from "../src/lib.js";

const service = localService();
const recipient = await service.address((await owner()).address);
console.log(`ok viewing_public_key=${lowerHex(recipient.viewingPublicKey.toBytes())}`);
