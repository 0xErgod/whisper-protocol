/**
 * ECDH demo: two seeds → two keypairs → one shared point.
 *
 * Plots Alice and Bob's public keys side by side and draws the shared
 * point both parties land on, asserting `Alice_sk · PK_Bob ==
 * Bob_sk · PK_Alice` at the byte level (the spec's symmetry property).
 * The two shared computations always agree — that visual coincidence
 * IS the protocol's first multi-party security primitive in action.
 *
 * No curve math here; everything goes through `crypto-wasm`.
 */

import { ecdh, keypair_from_seed } from "crypto-wasm";

import { drawAnchor, drawGrid, shortCoord, toPixel } from "./render";

function randomSeed(): Uint8Array {
  const buf = new Uint8Array(64);
  crypto.getRandomValues(buf);
  return buf;
}

export interface EcdhPanelElements {
  canvas: HTMLCanvasElement;
  randomBtn: HTMLButtonElement;
  readout: HTMLDivElement;
}

export function setupEcdhPanel(els: EcdhPanelElements): void {
  const ctx = els.canvas.getContext("2d")!;
  const W = els.canvas.width;
  const H = els.canvas.height;

  let aliceSeed = randomSeed();
  let bobSeed = randomSeed();

  function update(): void {
    let pkA, pkB;
    let sharedAB, sharedBA;

    try {
      pkA = keypair_from_seed(aliceSeed);
      pkB = keypair_from_seed(bobSeed);
      sharedAB = ecdh(aliceSeed, pkB.pk_x, pkB.pk_y);
      sharedBA = ecdh(bobSeed, pkA.pk_x, pkA.pk_y);
    } catch (err) {
      const m = err instanceof Error ? err.message : String(err);
      els.readout.innerHTML = `<span class="error">ECDH failed: ${m}</span>`;
      return;
    }

    // The defining property — surface it visually and as an assertion.
    // If this ever fails, the panel turns red instead of silently
    // showing wrong data.
    const symmetric = sharedAB.x === sharedBA.x && sharedAB.y === sharedBA.y;

    // Plot
    ctx.clearRect(0, 0, W, H);
    drawGrid(ctx, W, H);

    const a = toPixel(pkA.pk_x, pkA.pk_y, W, H);
    const b = toPixel(pkB.pk_x, pkB.pk_y, W, H);
    const s = toPixel(sharedAB.x, sharedAB.y, W, H);

    // Faint lines from each party's PK to the shared point — visually
    // suggests "both parties walk to the same place."
    ctx.strokeStyle = "rgba(110, 231, 183, 0.25)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(a.px, a.py);
    ctx.lineTo(s.px, s.py);
    ctx.moveTo(b.px, b.py);
    ctx.lineTo(s.px, s.py);
    ctx.stroke();

    drawAnchor(ctx, a.px, a.py, "#60a5fa", "PK_A");
    drawAnchor(ctx, b.px, b.py, "#f472b6", "PK_B");
    drawAnchor(ctx, s.px, s.py, "#6ee7b7", "shared");

    els.readout.innerHTML = `
      <div class="row"><span class="label">Alice PK.x</span> <code>${shortCoord(pkA.pk_x)}</code></div>
      <div class="row"><span class="label">Bob PK.x  </span> <code>${shortCoord(pkB.pk_x)}</code></div>
      <div class="row"><span class="label">shared.x  </span> <code>${shortCoord(sharedAB.x)}</code></div>
      <div class="row"><span class="label">shared.y  </span> <code>${shortCoord(sharedAB.y)}</code></div>
      <div class="row symmetry ${symmetric ? "ok" : "bad"}">
        ${symmetric ? "✓ Alice_sk·PK_B == Bob_sk·PK_A (symmetry holds)" : "✗ symmetry violated"}
      </div>
    `;
  }

  els.randomBtn.addEventListener("click", () => {
    aliceSeed = randomSeed();
    bobSeed = randomSeed();
    update();
  });

  update();
}
