import type { ManifestSetPolicy } from "../../src/wire/types.js";

/** Uncompressed P-256 generator, twice: the encrypt half and the signing half. */
const GENERATOR =
  "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

export const fixtureManifestSet: ManifestSetPolicy = {
  threshold: 1,
  members: [{ alias: "fixture-operator", publicKey: GENERATOR + GENERATOR }],
};
