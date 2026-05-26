import { SuiClient, SuiHTTPTransport } from "@mysten/sui/client";
import { WhisperClient } from "@whisper-protocol/sdk";
import { NETWORKS, type NetworkName } from "@whisper-protocol/sdk/networks";

const env = import.meta.env;

// The dev environment for this PoC is the shared sui-devnet node; that's
// what every other piece in the migration (Move publishes, prover-server,
// Playwright runs) targets. Hosted networks remain reachable via env
// overrides — VITE_SUI_NETWORK picks the named entry, and the three
// VITE_* RPC/package/registry vars take precedence over whatever the
// named entry pins.
const DEFAULT_NETWORK: NetworkName = "devnet";

function resolveActiveNetwork(): NetworkName {
  const raw = env.VITE_SUI_NETWORK as string | undefined;
  if (!raw) return DEFAULT_NETWORK;
  const alias = raw.toLowerCase();
  if (alias in NETWORKS) return alias as NetworkName;
  throw new Error(
    `unsupported VITE_SUI_NETWORK "${raw}" (expected one of: ${Object.keys(NETWORKS).join(", ")})`,
  );
}

export const ACTIVE_NETWORK = resolveActiveNetwork();
export const ACTIVE_CHAIN = `sui:${ACTIVE_NETWORK}` as const;

const activeConfig = NETWORKS[ACTIVE_NETWORK];

export const RPC_URL =
  (env.VITE_SUI_RPC_URL as string | undefined) ?? activeConfig.rpcUrl;

function requireId(envValue: string | undefined, configValue: string | null, kind: string): string {
  if (envValue) return envValue;
  if (configValue) return configValue;
  throw new Error(
    `no ${kind} configured for network "${ACTIVE_NETWORK}". Set VITE_${kind.toUpperCase()}_ID, or run scripts/deploy-devnet.ps1 to populate networks.json.`,
  );
}

export const PACKAGE_ID = requireId(
  env.VITE_PACKAGE_ID as string | undefined,
  activeConfig.packageId,
  "package",
);

export const REGISTRY_ID = requireId(
  env.VITE_REGISTRY_ID as string | undefined,
  activeConfig.registryId,
  "registry",
);

export const suiClient = new SuiClient({
  transport: new SuiHTTPTransport({ url: RPC_URL }),
});

export const whisper = new WhisperClient({
  suiClient,
  packageId: PACKAGE_ID,
  registryId: REGISTRY_ID,
});
