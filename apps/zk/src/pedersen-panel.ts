/**
 * The `pedersen_opens_to` circuit panel. End-to-end:
 *
 * 1. Click "prove" — POST inputs to `prover-server`, get proof
 *    bytes back.
 * 2. Click "verify" — fetch VK once, call `verify_pedersen_opens_to`
 *    in the wasm bundle against the proof + public inputs. The
 *    verify path runs locally — no server trust required to check
 *    a proof.
 * 3. Click "verify (tampered)" — same proof, but with the claimed
 *    first value replaced by 99. Demonstrates the integrity
 *    property: a proof for `stream[0]=10` does NOT verify against
 *    `claimed_first_value=99`.
 */

import { verify_pedersen_opens_to } from "prover-wasm";

import {
  PEDERSEN_FIXTURE,
  pedersenPublic,
  type PedersenOpensToPublicInputs,
} from "./fixtures";
import { getVk, postProve } from "./prover-client";

const CIRCUIT_ID = "pedersen_opens_to";

export interface PedersenPanelElements {
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

export function setupPedersenPanel(els: PedersenPanelElements): void {
  const state: PanelState = { proofBytes: null, vkBytes: null };

  // Populate the inputs box with the canonical fixture so the
  // visitor can see what the prover sends. JSON.stringify keeps
  // the values exact — these are the strings the server actually
  // receives.
  els.inputsBox.textContent = JSON.stringify(PEDERSEN_FIXTURE, null, 2);

  setReadout(els.readout, ["ready. click prove."]);

  els.proveBtn.addEventListener("click", async () => {
    setReadout(els.readout, ["proving (~3s)…"]);
    els.proveBtn.disabled = true;
    els.verifyBtn.disabled = true;
    els.tamperBtn.disabled = true;
    try {
      const t0 = performance.now();
      const proof = await postProve(CIRCUIT_ID, PEDERSEN_FIXTURE);
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
      const publicInputs = pedersenPublic(PEDERSEN_FIXTURE);
      const accepted = verify_pedersen_opens_to(
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
      const tampered: PedersenOpensToPublicInputs = {
        ...pedersenPublic(PEDERSEN_FIXTURE),
        claimed_first_value: "99", // real value is 10
      };
      const accepted = verify_pedersen_opens_to(
        JSON.stringify(tampered),
        state.proofBytes,
        state.vkBytes,
      );
      setReadout(els.readout, [
        accepted ? "✗ UNEXPECTED accept" : "✓ tampered claim correctly rejected",
        "(real claimed_first_value=10, tampered=99)",
      ]);
    } catch (err) {
      setReadout(els.readout, [`verify failed: ${(err as Error).message}`]);
    }
  });
}

function setReadout(el: HTMLDivElement, lines: string[]): void {
  el.textContent = lines.join("\n");
}
