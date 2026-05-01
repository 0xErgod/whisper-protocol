/**
 * Canonical Whisper Protocol deployment IDs per network.
 *
 * These constants ship in their own sub-export so that updating
 * "the testnet address" doesn't require a code release of the main
 * SDK entry point. Consumers can also pass arbitrary `{ packageId,
 * registryId }` to the WhisperClient constructor — these are defaults,
 * not requirements.
 *
 * The values mirror the `networks` map in /networks.json at the repo
 * root. CI keeps the two in sync on contract redeploy.
 */

export interface NetworkConfig {
  rpcUrl: string;
  packageId: string | null;
  registryId: string | null;
  note?: string;
}

export const LOCALNET: NetworkConfig = {
  rpcUrl: "http://127.0.0.1:9000",
  packageId: "0x3583393a1c4b043c154b8cef883073bd854a7c1c61dc73eb0ea867aa513d6578",
  registryId: "0x0e7d57899476e92ffa2a822e050bdf4f54a7855448eb6044c221a6977961099e",
  note: "Republish on each `sui start --force-regenesis` — IDs here are local-only and not authoritative.",
};

export const TESTNET: NetworkConfig = {
  rpcUrl: "https://fullnode.testnet.sui.io:443",
  packageId: null,
  registryId: null,
  note: "Populated by deploy-contract CI workflow.",
};

export const MAINNET: NetworkConfig = {
  rpcUrl: "https://fullnode.mainnet.sui.io:443",
  packageId: null,
  registryId: null,
  note: "Mainnet deploys are not automated.",
};

export const NETWORKS = { localnet: LOCALNET, testnet: TESTNET, mainnet: MAINNET } as const;

export type NetworkName = keyof typeof NETWORKS;
