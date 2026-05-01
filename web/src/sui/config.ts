// Defaults match the project's local development setup. Override via Vite env
// variables (VITE_SUI_RPC_URL / VITE_PACKAGE_ID / VITE_REGISTRY_ID) when needed.
const env = import.meta.env;

export const SUI_RPC_URL = (env.VITE_SUI_RPC_URL as string | undefined) ?? "/sui-rpc";

export const PACKAGE_ID =
  (env.VITE_PACKAGE_ID as string | undefined) ??
  "0xead06c3c0c144bafbdff29b17cdf02df0d6ac7f26d36c2e55e3961dea4d12d25";

export const REGISTRY_ID =
  (env.VITE_REGISTRY_ID as string | undefined) ??
  "0xcb55e890f217540285ceac17b154118652512889159e0e3f8428688c903f6dee";

export const MODULE = "secret_sharing";
