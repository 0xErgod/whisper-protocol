/**
 * Keypair playground: a 64-byte seed in, the derived public key plotted
 * on the curve canvas.
 *
 * This panel is the apps-side proof that `crypto-wasm`'s
 * `keypair_from_seed` works end-to-end. It also makes the seed-to-key
 * relationship tangible: drag the "randomize" button, watch the public
 * key hop somewhere new — that hop is the discrete-log hardness, exactly
 * the same property the cyclic walk visualizes, but anchored to a
 * keypair derivation now instead of an exposed scalar.
 */

import { keypair_from_seed } from "crypto-wasm";

import { drawAnchor, drawGrid, shortCoord, toPixel } from "./render";

/**
 * Generate a cryptographically random 64-byte seed via the browser's
 * Web Crypto API. The same primitive a production caller might use; the
 * keypair primitive itself is indifferent to its origin.
 */
function randomSeed(): Uint8Array {
  const buf = new Uint8Array(64);
  crypto.getRandomValues(buf);
  return buf;
}

/**
 * Render `seed` to a hex string for the "what bytes are you derived
 * from?" readout. Truncated like the coordinates so it fits in the
 * sidebar.
 */
function seedHex(seed: Uint8Array): string {
  const full = Array.from(seed, (b) => b.toString(16).padStart(2, "0")).join(
    "",
  );
  return `${full.slice(0, 16)}…${full.slice(-16)}`;
}

/** Parse a hex string back into a 64-byte `Uint8Array`. Lenient on case
 *  and whitespace; rejects wrong-length input. Returns `null` on failure
 *  so the caller can show a typed-error state. */
function parseSeedHex(input: string): Uint8Array | null {
  const cleaned = input.replace(/\s+/g, "").toLowerCase();
  if (cleaned.length !== 128) return null;
  if (!/^[0-9a-f]+$/.test(cleaned)) return null;
  const out = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    out[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export interface KeypairPanelElements {
  canvas: HTMLCanvasElement;
  seedInput: HTMLTextAreaElement;
  randomBtn: HTMLButtonElement;
  readout: HTMLDivElement;
}

export function setupKeypairPanel(els: KeypairPanelElements): void {
  const ctx = els.canvas.getContext("2d")!;
  const W = els.canvas.width;
  const H = els.canvas.height;

  let currentSeed = randomSeed();

  /** Derive PK from the current seed via the WASM binding, then plot it. */
  function update(): void {
    let pkX: string;
    let pkY: string;
    let errorMessage: string | null = null;

    try {
      const kp = keypair_from_seed(currentSeed);
      pkX = kp.pk_x;
      pkY = kp.pk_y;
    } catch (err) {
      // The binding only errors on wrong length, which `currentSeed`
      // never violates — but we type the failure path anyway so the
      // panel cannot crash from a future binding change.
      errorMessage = err instanceof Error ? err.message : String(err);
      ctx.clearRect(0, 0, W, H);
      drawGrid(ctx, W, H);
      els.readout.innerHTML = `<span class="error">derivation failed: ${errorMessage}</span>`;
      return;
    }

    // Plot
    ctx.clearRect(0, 0, W, H);
    drawGrid(ctx, W, H);
    const { px, py } = toPixel(pkX, pkY, W, H);
    drawAnchor(ctx, px, py, "#f59e0b", "PK");

    els.readout.innerHTML = `
      <div class="row"><span class="label">seed</span> <code>${seedHex(currentSeed)}</code></div>
      <div class="row"><span class="label">PK.x</span> <code>${shortCoord(pkX)}</code></div>
      <div class="row"><span class="label">PK.y</span> <code>${shortCoord(pkY)}</code></div>
    `;
    els.seedInput.value = Array.from(currentSeed, (b) =>
      b.toString(16).padStart(2, "0"),
    ).join("");
  }

  els.randomBtn.addEventListener("click", () => {
    currentSeed = randomSeed();
    update();
  });

  els.seedInput.addEventListener("input", () => {
    const parsed = parseSeedHex(els.seedInput.value);
    if (parsed) {
      currentSeed = parsed;
      update();
    } else {
      els.readout.innerHTML = `<span class="error">seed must be 128 hex chars (64 bytes)</span>`;
    }
  });

  update();
}
