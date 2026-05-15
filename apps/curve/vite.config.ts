import { defineConfig } from "vite";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

// `crypto-wasm` is a wasm-pack ESM module: `vite-plugin-wasm` teaches Vite to
// load the `.wasm` as an ES module, and `vite-plugin-top-level-await` lets the
// async wasm init be awaited at module scope. Without the second plugin you
// would need `build.target: "esnext"` and a very modern browser only.
export default defineConfig({
  plugins: [wasm(), topLevelAwait()],
  server: {
    port: 5174,
  },
});
