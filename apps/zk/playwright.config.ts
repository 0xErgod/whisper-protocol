import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright config for the zk-playground smoke tests.
 *
 * Two webServers run concurrently:
 *
 *   1. prover-server — the Rust Groth16 HTTP server. Built and
 *      launched via `cargo run --release --bin prover-server`.
 *      First boot runs trusted setup (~30s/circuit) and writes
 *      `keys/`; subsequent boots are fast.
 *
 *   2. vite preview — serves the built static bundle of this
 *      app. We use `preview` rather than `dev` so the test
 *      exercises the production-shape output (one wasm asset,
 *      one bundled JS).
 *
 * The `keys` directory created by the prover-server lives at
 * the repo root by default; that's fine for local runs and CI.
 * Per-run isolation would need a PROVER_KEYS_DIR override, but
 * for this smoke test the artifacts are deterministic across
 * boots (StdRng with a fixed seed), so a shared directory is
 * a feature, not a bug — second runs reuse the first run's
 * setup output.
 */

const SERVER_PORT = 3001;
const PREVIEW_PORT = 4173;

export default defineConfig({
  testDir: "./tests",
  fullyParallel: false, // one test at a time keeps the server's compute predictable
  timeout: 120_000, // proving can take several seconds; verify is fast
  expect: {
    timeout: 60_000, // ample headroom for the slowest prove path
  },
  use: {
    baseURL: `http://127.0.0.1:${PREVIEW_PORT}`,
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: [
    {
      // Repo-root-relative cargo invocation. `--release` because
      // debug builds of the prover hit a stack overflow on
      // Windows during sequential setups (build.rs sidesteps it
      // with a worker thread; this binary runs single-threaded
      // until tokio takes over).
      command: "cargo run --release --bin prover-server",
      cwd: "../..",
      port: SERVER_PORT,
      reuseExistingServer: !process.env.CI,
      timeout: 300_000, // first boot includes Groth16 setup
      stdout: "pipe",
      stderr: "pipe",
    },
    {
      command: "pnpm preview --port 4173 --host 127.0.0.1",
      cwd: ".",
      port: PREVIEW_PORT,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
  ],
});
