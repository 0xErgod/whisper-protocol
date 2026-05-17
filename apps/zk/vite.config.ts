import { defineConfig } from "vite";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

// `prover-wasm` is a wasm-pack ESM module: vite-plugin-wasm teaches Vite to
// load the `.wasm` as an ES module; vite-plugin-top-level-await lets the
// async wasm init be awaited at module scope. Same shape as apps/curve's
// crypto-wasm consumer.
export default defineConfig({
  plugins: [wasm(), topLevelAwait()],
  server: {
    // 5175 to leave 5174 (apps/curve) and 5173 (apps/protocol) alone — the
    // three demo apps can run side-by-side without port collisions.
    port: 5175,
  },
});
