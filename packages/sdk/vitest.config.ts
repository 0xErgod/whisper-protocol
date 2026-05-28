import { defineConfig } from "vitest/config";
import wasm from "vite-plugin-wasm";

// The SDK depends on `crypto-wasm`, a wasm-pack package built with the
// `--target bundler` profile. That profile produces ESM that imports the
// `.wasm` file directly; `vite-plugin-wasm` teaches Vitest's bundler
// pipeline how to instantiate it. Browser consumers (apps/curve,
// apps/zk, apps/protocol) configure the same plugin in their Vite configs.
export default defineConfig({
  plugins: [wasm()],
  test: {
    testTimeout: 30_000,
  },
});
