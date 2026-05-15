/**
 * Schnorr signature demo: sign a message field element with a
 * randomized seed, plot the signer's `PK` and the signature commitment
 * point `R`, and assert the signature verifies. A tamper button
 * corrupts the signature on demand so the rejection path is visible.
 *
 * No curve math here — everything goes through `crypto-wasm`'s
 * `schnorr_sign` / `schnorr_verify` exports, anchored to
 * `specs/babyjub-schnorr.md`.
 */

import {
  keypair_from_seed,
  schnorr_sign,
  schnorr_verify,
} from "crypto-wasm";

import { drawAnchor, drawGrid, palette, shortCoord, toPixel } from "./render";

/** Baby Jubjub subgroup order `l` — needed for tampering the response
 *  scalar mod `l` so the tampered value stays a valid `Fr` element. */
const SUBGROUP_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

function randomSeed(): Uint8Array {
  const buf = new Uint8Array(64);
  crypto.getRandomValues(buf);
  return buf;
}

export interface SchnorrPanelElements {
  canvas: HTMLCanvasElement;
  messageInput: HTMLInputElement;
  randomBtn: HTMLButtonElement;
  tamperBtn: HTMLButtonElement;
  readout: HTMLDivElement;
}

interface State {
  seed: Uint8Array;
  /** When non-null, replaces `s` in the signature presented to verify —
   *  flips the panel from "ok" to "tampered" without recomputing
   *  anything else. */
  tamper_s: string | null;
}

export function setupSchnorrPanel(els: SchnorrPanelElements): void {
  const ctx = els.canvas.getContext("2d")!;
  const W = els.canvas.width;
  const H = els.canvas.height;

  const state: State = {
    seed: randomSeed(),
    tamper_s: null,
  };

  function update(): void {
    let pk, sig;
    try {
      pk = keypair_from_seed(state.seed);
      sig = schnorr_sign(state.seed, els.messageInput.value);
    } catch (err) {
      const m = err instanceof Error ? err.message : String(err);
      els.readout.innerHTML = `<span class="error">sign failed: ${m}</span>`;
      return;
    }

    // The signature actually presented to `verify` may be tampered.
    const s_for_verify = state.tamper_s ?? sig.s;

    let ok;
    try {
      ok = schnorr_verify(
        pk.pk_x,
        pk.pk_y,
        els.messageInput.value,
        sig.r_x,
        sig.r_y,
        s_for_verify,
      );
    } catch (err) {
      const m = err instanceof Error ? err.message : String(err);
      els.readout.innerHTML = `<span class="error">verify failed: ${m}</span>`;
      return;
    }

    // Plot
    ctx.clearRect(0, 0, W, H);
    drawGrid(ctx, W, H);

    const pPk = toPixel(pk.pk_x, pk.pk_y, W, H);
    const pR = toPixel(sig.r_x, sig.r_y, W, H);

    // Faint line from PK to R — both are signer-derived, suggests
    // "these belong together." When tampered, the color flips to a
    // warning to make the bad state visible at a glance.
    ctx.save();
    ctx.globalAlpha = 0.25;
    ctx.strokeStyle = ok ? palette.shared : palette.bad;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(pPk.px, pPk.py);
    ctx.lineTo(pR.px, pR.py);
    ctx.stroke();
    ctx.restore();

    drawAnchor(ctx, pPk.px, pPk.py, palette.actorA, "PK");
    drawAnchor(ctx, pR.px, pR.py, palette.shared, "R");

    els.readout.innerHTML = `
      <div class="row"><span class="label">m</span> <code>${els.messageInput.value}</code></div>
      <div class="row"><span class="label">PK.x</span> <code>${shortCoord(pk.pk_x)}</code></div>
      <div class="row"><span class="label">R.x</span> <code>${shortCoord(sig.r_x)}</code></div>
      <div class="row"><span class="label">s</span> <code>${shortCoord(s_for_verify)}</code>${state.tamper_s ? ' <span class="label">(tampered)</span>' : ""}</div>
      <div class="row symmetry ${ok ? "ok" : "bad"}">
        ${ok ? "✓ s·G == R + c·PK   (signature verifies)" : "✗ verification rejected"}
      </div>
    `;
  }

  els.messageInput.addEventListener("input", () => {
    // A new message invalidates any prior tamper — the user's signing
    // a fresh message now.
    state.tamper_s = null;
    update();
  });
  els.randomBtn.addEventListener("click", () => {
    state.seed = randomSeed();
    state.tamper_s = null;
    update();
  });
  els.tamperBtn.addEventListener("click", () => {
    // Toggle: if already tampered, restore; otherwise tamper by
    // adding 1 mod l to the response scalar. Adding 1 always changes
    // the value — no surprise edge cases.
    if (state.tamper_s) {
      state.tamper_s = null;
    } else {
      // We need the current valid `s` first. Re-sign to get it.
      try {
        const sig = schnorr_sign(state.seed, els.messageInput.value);
        const tampered = (BigInt(sig.s) + 1n) % SUBGROUP_ORDER;
        state.tamper_s = tampered.toString();
      } catch {
        // If signing fails (bad message input) the tamper button is a
        // no-op rather than introducing a different error state.
        return;
      }
    }
    update();
  });

  // Initialize with a friendly message and a fresh random seed.
  els.messageInput.value = "42";
  update();
}
