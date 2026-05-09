import { SuiClient, SuiHTTPTransport } from "@mysten/sui/client";
import { WhisperClient } from "@whisper-protocol/sdk";
import { TESTNET } from "@whisper-protocol/sdk/networks";

const env = import.meta.env;
const DEFAULT_NETWORK = "testnet" as const;
const NETWORK_ALIASES = new Set(["localnet", "devnet", "testnet", "mainnet"]);

// Default network is testnet so the demo works out of the box for users
// with a wallet that supports localnet only via custom RPC. Override
// with VITE_SUI_RPC_URL to point elsewhere.
export const RPC_URL = (env.VITE_SUI_RPC_URL as string | undefined) ?? TESTNET.rpcUrl;

export const PACKAGE_ID =
  (env.VITE_PACKAGE_ID as string | undefined) ?? TESTNET.packageId!;

export const REGISTRY_ID =
  (env.VITE_REGISTRY_ID as string | undefined) ?? TESTNET.registryId!;

function resolveNetworkAlias(): "localnet" | "devnet" | "testnet" | "mainnet" {
  const raw = env.VITE_SUI_NETWORK as string | undefined;
  if (!raw) return DEFAULT_NETWORK;
  const alias = raw.toLowerCase();
  if (NETWORK_ALIASES.has(alias)) {
    return alias as "localnet" | "devnet" | "testnet" | "mainnet";
  }
  throw new Error(
    `unsupported VITE_SUI_NETWORK "${raw}" (expected localnet, devnet, testnet, or mainnet)`,
  );
}

export const ACTIVE_NETWORK = resolveNetworkAlias();
export const ACTIVE_CHAIN = `sui:${ACTIVE_NETWORK}` as const;

export const suiClient = new SuiClient({
  transport: new SuiHTTPTransport({ url: RPC_URL }),
});

export const whisper = new WhisperClient({
  suiClient,
  packageId: PACKAGE_ID,
  registryId: REGISTRY_ID,
});
