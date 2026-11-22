import { DecryptionServiceError } from "./error.js";
import type { Network } from "./types.js";

/** `value` as a {@link Network}; anything else is `UnknownNetwork`. */
export function requireNetwork(value: unknown): Network {
  if (value !== "devnet" && value !== "mainnet") {
    throw new DecryptionServiceError("UnknownNetwork", "the network must be devnet or mainnet");
  }
  return value;
}

const GENESIS_HASHES = Object.freeze({
  devnet: "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
  mainnet: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
});

export function genesisHashForNetwork(network: Network): string {
  return GENESIS_HASHES[requireNetwork(network)];
}
