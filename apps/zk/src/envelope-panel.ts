/**
 * The `envelope_open_at_0` circuit panel. Same shape as the
 * Pedersen panel but on the protocol's headline circuit.
 *
 * Alice's seal of `[1..=9]` to Bob under envelope id 42 is
 * pre-computed in `fixtures.ts`; the page exercises the prove
 * /verify flow on top of that canonical envelope. The wasm
 * boundary test (`crates/prover-wasm/tests/boundary.rs`)
 * cross-checks these exact values produce a valid proof, so a
 * working page means the spec contract holds end-to-end in the
 * browser.
 */

import { verify_envelope_open_at_0 } from "prover-wasm";

import {
  ENVELOPE_FIXTURE,
  envelopePublic,
  type EnvelopeOpenAt0PublicInputs,
} from "./fixtures";
import { getVk, postProve } from "./prover-client";

const CIRCUIT_ID = "envelope_open_at_0";

export interface EnvelopePanelElements {
  proveBtn: HTMLButtonElement;
  verifyBtn: HTMLButtonElement;
  tamperBtn: HTMLButtonElement;
  readout: HTMLDivElement;
  inputsBox: HTMLPreElement;
}

interface PanelState {
  proofBytes: Uint8Array | null;
  vkBytes: Uint8Array | null;
}

export function setupEnvelopePanel(els: EnvelopePanelElements): void {
  const state: PanelState = { proofBytes: null, vkBytes: null };

  // Populate the inputs box with the canonical fixture. We
  // include the full witness (including recipient_sk) so a
  // reader sees what the prover holds vs what becomes public
  // — the page is pedagogical first.
  els.inputsBox.textContent = JSON.stringify(ENVELOPE_FIXTURE, null, 2);
  setReadout(els.readout, ["ready. click prove."]);

  els.proveBtn.addEventListener("click", async () => {
    setReadout(els.readout, ["proving (~5s)…"]);
    els.proveBtn.disabled = true;
    els.verifyBtn.disabled = true;
    els.tamperBtn.disabled = true;
    try {
      const t0 = performance.now();
      const proof = await postProve(CIRCUIT_ID, ENVELOPE_FIXTURE);
      const dt = ((performance.now() - t0) / 1000).toFixed(2);
      state.proofBytes = proof;
      setReadout(els.readout, [
        `proof produced: ${proof.length} bytes in ${dt}s.`,
        "click verify to check it in-browser.",
      ]);
      els.verifyBtn.disabled = false;
      els.tamperBtn.disabled = false;
    } catch (err) {
      setReadout(els.readout, [`prove failed: ${(err as Error).message}`]);
    } finally {
      els.proveBtn.disabled = false;
    }
  });

  els.verifyBtn.addEventListener("click", async () => {
    if (!state.proofBytes) return;
    setReadout(els.readout, ["fetching VK + verifying in wasm…"]);
    try {
      if (!state.vkBytes) {
        state.vkBytes = await getVk(CIRCUIT_ID);
      }
      const publicInputs = envelopePublic(ENVELOPE_FIXTURE);
      const accepted = verify_envelope_open_at_0(
        JSON.stringify(publicInputs),
        state.proofBytes,
        state.vkBytes,
      );
      setReadout(els.readout, [
        accepted ? "✓ accepted" : "✗ rejected",
        "verified locally against the fetched VK.",
      ]);
    } catch (err) {
      setReadout(els.readout, [`verify failed: ${(err as Error).message}`]);
    }
  });

  els.tamperBtn.addEventListener("click", async () => {
    if (!state.proofBytes) return;
    setReadout(els.readout, ["verifying against tampered claim…"]);
    try {
      if (!state.vkBytes) {
        state.vkBytes = await getVk(CIRCUIT_ID);
      }
      const tampered: EnvelopeOpenAt0PublicInputs = {
        ...envelopePublic(ENVELOPE_FIXTURE),
        claimed_value: "99", // real value is 1
      };
      const accepted = verify_envelope_open_at_0(
        JSON.stringify(tampered),
        state.proofBytes,
        state.vkBytes,
      );
      setReadout(els.readout, [
        accepted ? "✗ UNEXPECTED accept" : "✓ tampered claim correctly rejected",
        "(real plaintext[0]=1, tampered=99)",
      ]);
    } catch (err) {
      setReadout(els.readout, [`verify failed: ${(err as Error).message}`]);
    }
  });
}

function setReadout(el: HTMLDivElement, lines: string[]): void {
  el.textContent = lines.join("\n");
}
