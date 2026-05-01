/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_SUI_RPC_URL?: string;
  readonly VITE_PACKAGE_ID?: string;
  readonly VITE_REGISTRY_ID?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
