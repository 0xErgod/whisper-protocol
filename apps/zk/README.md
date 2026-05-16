# zk playground

In-browser playground for the protocol's ZK circuits. Two
panels, one per circuit (`pedersen_opens_to`,
`envelope_open_at_0`). Each panel walks the prove → verify
cycle end-to-end against a canonical fixture from the spec.

## What runs where

- **Proving** runs on the `prover-server` (HTTP, default
  `http://127.0.0.1:3001`). Server-side Groth16 prove is ~3–5
  seconds per circuit in release.
- **Verifying** runs in this browser via `prover-wasm`. Same
  path a Sui-side or off-chain verifier would take: fetch VK,
  invoke the verifier locally, no server trust required.
- **No proving keys ship to the browser.** PK lives only on
  the server. If a future variant wants zero-server-trust
  proving, the WASM bundle already exposes `prove_*` exports
  — flip the panel to call them instead of POSTing.

## Running locally

Two terminals.

**Terminal 1 — the prover server:**

```bash
cargo run --release --bin prover-server
```

First boot runs Groth16 trusted setup for each circuit (~30s
each) and writes `keys/<circuit>.{pk,vk}`. Subsequent boots
are instant.

**Terminal 2 — the page:**

```bash
cd apps/zk
pnpm install        # first time only
pnpm dev            # auto-runs `pnpm wasm` via predev hook
```

Then open the URL Vite prints (default `http://localhost:5175`).

## How to read the panels

Each panel has three buttons:

- **prove** — POST inputs to `/prove/<id>`, store the proof.
- **verify** — fetch `/vk/<id>` once and verify the proof
  locally against the canonical public inputs. Should land
  on `✓ accepted`.
- **verify (tampered)** — re-verifies the same proof against
  a deliberately wrong public-input vector. Should land on
  `✓ tampered claim correctly rejected`. This is the integrity
  demo — a proof for plaintext[0]=1 cannot be replayed as a
  proof for plaintext[0]=99.

## What the inputs box shows

The full wire-form `Inputs` JSON. For the envelope panel that
includes the recipient's secret key (`recipient_sk`) — the
panel is pedagogical, so the witness side is visible. **In
production this would never cross any boundary that's not
the prover's own process**; the page shows it because the
page IS the prover.
