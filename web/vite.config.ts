import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `base` controls the URL prefix Vite emits for `<script>` / asset URLs in
// the built HTML. Locally we want `/` (default) so `pnpm dev:web` and
// `pnpm preview` both work at the root; on GitHub Pages we deploy under
// `/whisper-protocol/` so the build needs every asset URL to start with
// that path. The deploy workflow sets VITE_PAGES_BASE; nothing else
// touches it.
const PAGES_BASE = process.env.VITE_PAGES_BASE ?? "/";

export default defineConfig({
  base: PAGES_BASE,
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/sui-rpc": {
        target: "http://127.0.0.1:9000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/sui-rpc/, ""),
      },
    },
  },
});
