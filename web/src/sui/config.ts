// Defaults match the project's local development setup. Override via Vite env
// variables (VITE_SUI_RPC_URL / VITE_PACKAGE_ID / VITE_REGISTRY_ID) when needed.
const env = import.meta.env;

export const SUI_RPC_URL = (env.VITE_SUI_RPC_URL as string | undefined) ?? "/sui-rpc";

export const PACKAGE_ID =
  (env.VITE_PACKAGE_ID as string | undefined) ??
  "0x3583393a1c4b043c154b8cef883073bd854a7c1c61dc73eb0ea867aa513d6578";

export const REGISTRY_ID =
  (env.VITE_REGISTRY_ID as string | undefined) ??
  "0x0e7d57899476e92ffa2a822e050bdf4f54a7855448eb6044c221a6977961099e";

export const MODULE = "secret_sharing";
