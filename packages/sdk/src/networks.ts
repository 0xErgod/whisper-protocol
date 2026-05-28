// AUTO-GENERATED FROM /networks.json. DO NOT EDIT BY HAND.
//
// Update via:
//     pnpm --filter @whisper-protocol/sdk run gen:networks
//
// CI rejects pushes where this file has drifted from networks.json
// — see scripts/generate-networks.mjs --check.

export interface NetworkConfig {
  rpcUrl: string;
  packageId: string | null;
  registryId: string | null;
  note?: string;
}

export const LOCALNET: NetworkConfig = {
  rpcUrl: "http://127.0.0.1:9000",
  packageId: null,
  registryId: null,
  note: "Localnet IDs are intentionally null — every developer regenerates them via `sui start --force-regenesis` + republish. Pass explicit IDs to WhisperClient or set VITE_PACKAGE_ID / VITE_REGISTRY_ID for the demo dApp.",
};

export const DEVNET: NetworkConfig = {
  rpcUrl: "http://sui-devnet:9000",
  packageId: "0xad371607373b0478315290792eeb9e6d8c90016499999158accdfc71148b92d0",
  registryId: "0x65a41743ee2a86f236facbb5541be9b6085caa4ca8783fe3907a44eb80b7a778",
  note: "Shared dev devnet at host `sui-devnet:9000`. IDs are populated per deploy by scripts/deploy-devnet.ps1 (writes networks.json then runs gen:networks). The default target of the demo dApp and SDK tests; override per-developer via VITE_SUI_RPC_URL / VITE_PACKAGE_ID / VITE_REGISTRY_ID.",
};

export const TESTNET: NetworkConfig = {
  rpcUrl: "https://fullnode.testnet.sui.io:443",
  packageId: "0xe95fb4727effd20883b85e724f54c74b76c8f2dc7094ded7ac6ad984443b0db5",
  registryId: "0x5545d1505304161fd814a25635e6a9d800203b74a2ebfd8a705ac7d7e214acd2",
  note: "Manually deployed; future redeployments via .github/workflows/deploy-contract.yml.",
};

export const MAINNET: NetworkConfig = {
  rpcUrl: "https://fullnode.mainnet.sui.io:443",
  packageId: null,
  registryId: null,
  note: "Mainnet deploys are not automated. Populate manually with checklist.",
};

export const NETWORKS = {
  localnet: LOCALNET,
  devnet: DEVNET,
  testnet: TESTNET,
  mainnet: MAINNET,
} as const;

export type NetworkName = keyof typeof NETWORKS;
