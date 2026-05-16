/**
 * Entry point: initialize the prover-wasm bundle, then wire each
 * circuit panel to its DOM elements.
 *
 * Two panels, one per circuit:
 *
 *   - pedersen-panel    — the first circuit
 *   - envelope-panel    — the protocol's headline circuit
 *
 * Both share the same flow:
 *
 *   1. POST inputs to /prove/<circuit-id> on the prover-server
 *      to obtain proof bytes (server-side compute, ~3–5s).
 *   2. GET /vk/<circuit-id> to fetch the verifying key.
 *   3. Verify the proof against the public inputs IN WASM,
 *      locally — exercising the same path a Move-side or
 *      client-side verifier would take.
 *
 * The proving step runs server-side intentionally: in-browser
 * Groth16 prove is ~20s for these circuits in release, server-
 * side is ~3s. The on-chain consumer doesn't care which side
 * produced the proof; what matters is that anyone can verify
 * it without trusting the prover.
 */

import init from "prover-wasm";

import { setupEnvelopePanel } from "./envelope-panel";
import { setupPedersenPanel } from "./pedersen-panel";
import { serverUrl } from "./prover-client";

await init();

// Display the server URL so the visitor knows where /prove and
// /vk will resolve to. If the server isn't running, the panel
// reads-outs will surface the fetch error.
const serverUrlEl = document.getElementById("server-url");
if (serverUrlEl) serverUrlEl.textContent = serverUrl();

setupPedersenPanel({
  proveBtn: byId<HTMLButtonElement>("pedersen-prove"),
  verifyBtn: byId<HTMLButtonElement>("pedersen-verify"),
  tamperBtn: byId<HTMLButtonElement>("pedersen-tamper"),
  readout: byId<HTMLDivElement>("pedersen-readout"),
  inputsBox: byId<HTMLPreElement>("pedersen-inputs"),
});

setupEnvelopePanel({
  proveBtn: byId<HTMLButtonElement>("envelope-prove"),
  verifyBtn: byId<HTMLButtonElement>("envelope-verify"),
  tamperBtn: byId<HTMLButtonElement>("envelope-tamper"),
  readout: byId<HTMLDivElement>("envelope-readout"),
  inputsBox: byId<HTMLPreElement>("envelope-inputs"),
});

function byId<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing DOM element #${id}`);
  return el as T;
}
