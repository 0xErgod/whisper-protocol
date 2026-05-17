/**
 * Schnorr signature demo: sign a stream-shaped message with a
 * randomized seed, plot the signer's `PK` and the signature
 * commitment point `R`, and assert the signature verifies. A tamper
 * button corrupts the signature on demand so the rejection path is
 * visible.
 *
 * Messages are entered as comma-separated decimal field elements
 * (length 0..11). The initial frame uses the spec's vector-4
 * `text-utf8-v1`-shaped message `[0, 1, 2, ..., 8]`.
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

/** Parse a comma-separated stream of non-negative decimal integers.
 *  Whitespace around each element is trimmed. Empty input yields an
 *  empty stream — a valid message under this scheme. */
function parseStream(s: string): string[] | { error: string } {
  const trimmed = s.trim();
  if (trimmed === "") return [];
  const parts = trimmed.split(",").map((p) => p.trim());
  for (const p of parts) {
    if (!/^[0-9]+$/.test(p)) {
      return { error: `"${p}" is not a non-negative decimal integer` };
    }
  }
  return parts;
}

function isStreamError(
  x: string[] | { error: string },
): x is { error: string } {
  return !Array.isArray(x);
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
  /** When non-null, replaces `s` in the signature presented to verify
   *  — flips the panel from "ok" to "tampered" without recomputing
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
    const parsed = parseStream(els.messageInput.value);
    if (isStreamError(parsed)) {
      els.readout.innerHTML = `<span class="error">${parsed.error}</span>`;
      ctx.clearRect(0, 0, W, H);
      drawGrid(ctx, W, H);
      return;
    }

    let pk, sig;
    try {
      pk = keypair_from_seed(state.seed);
      sig = schnorr_sign(state.seed, parsed);
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
        parsed,
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

    // Faint line from PK to R; turns red when tampered.
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
      <div class="row"><span class="label">|message|</span> <code>${parsed.length}</code></div>
      <div class="row"><span class="label">PK.x</span> <code>${shortCoord(pk.pk_x)}</code></div>
      <div class="row"><span class="label">R.x</span> <code>${shortCoord(sig.r_x)}</code></div>
      <div class="row"><span class="label">s</span> <code>${shortCoord(s_for_verify)}</code>${state.tamper_s ? ' <span class="label">(tampered)</span>' : ""}</div>
      <div class="row symmetry ${ok ? "ok" : "bad"}">
        ${ok ? "✓ s·G == R + c·PK   (signature verifies)" : "✗ verification rejected"}
      </div>
    `;
  }

  els.messageInput.addEventListener("input", () => {
    // A new message invalidates any prior tamper — a fresh message
    // implies a fresh signature, no tamper carryover.
    state.tamper_s = null;
    update();
  });
  els.randomBtn.addEventListener("click", () => {
    state.seed = randomSeed();
    state.tamper_s = null;
    update();
  });
  els.tamperBtn.addEventListener("click", () => {
    if (state.tamper_s) {
      state.tamper_s = null;
    } else {
      try {
        const parsed = parseStream(els.messageInput.value);
        if (isStreamError(parsed)) return;
        const sig = schnorr_sign(state.seed, parsed);
        const tampered = (BigInt(sig.s) + 1n) % SUBGROUP_ORDER;
        state.tamper_s = tampered.toString();
      } catch {
        return;
      }
    }
    update();
  });

  // Initialize with the spec's vector-4 message (text-utf8-v1 shape).
  els.messageInput.value = "0, 1, 2, 3, 4, 5, 6, 7, 8";
  update();
}
