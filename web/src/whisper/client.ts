import { SuiClient, SuiHTTPTransport } from "@mysten/sui/client";
import { WhisperClient } from "@whisper-protocol/sdk";
import { TESTNET } from "@whisper-protocol/sdk/networks";

const env = import.meta.env;

// Default network is testnet so the demo works out of the box for users
// with a wallet that supports localnet only via custom RPC. Override
// with VITE_SUI_RPC_URL to point elsewhere.
export const RPC_URL = (env.VITE_SUI_RPC_URL as string | undefined) ?? TESTNET.rpcUrl;

export const PACKAGE_ID =
  (env.VITE_PACKAGE_ID as string | undefined) ?? TESTNET.packageId!;

export const REGISTRY_ID =
  (env.VITE_REGISTRY_ID as string | undefined) ?? TESTNET.registryId!;

// Wallets bind signatures to a chain identifier. The web demo targets
// testnet by default; bump along with RPC_URL above when changing networks.
export const ACTIVE_CHAIN = "sui:testnet" as const;

export const suiClient = new SuiClient({
  transport: new SuiHTTPTransport({ url: RPC_URL }),
});

export const whisper = new WhisperClient({
  suiClient,
  packageId: PACKAGE_ID,
  registryId: REGISTRY_ID,
});
