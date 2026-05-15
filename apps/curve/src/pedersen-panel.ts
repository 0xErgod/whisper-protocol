/**
 * Pedersen commitment demo: the additive-homomorphism property,
 * visualized.
 *
 * Two value + blinding pairs (`a, r_a`) and (`b, r_b`) → three plotted
 * commitments: `C_a`, `C_b`, and the "summed-scalars" commitment
 * `C_sum = commit(a+b, r_a+r_b)`. By Pedersen's additive
 * homomorphism `C_a + C_b == C_sum` in the group; this panel doesn't
 * compute that group sum (the wasm binding doesn't expose point
 * addition), but it does show that the same `C_sum` point arrives
 * deterministically from the two inputs, which is the load-bearing
 * thing the rest of the protocol relies on.
 *
 * `H` is also plotted as a fixed anchor — the protocol's pinned
 * second generator, the load-bearing security parameter of the whole
 * scheme.
 */

import { pedersen_commit, pedersen_h } from "crypto-wasm";

import { drawAnchor, drawGrid, palette, shortCoord, toPixel } from "./render";

/** Baby Jubjub subgroup order `l`, from `specs/babyjub-curve.md`. JS
 *  side does scalar addition mod `l` here to compute the summed-scalar
 *  commit; the wasm binding only takes already-reduced decimal strings. */
const SUBGROUP_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

function addMod(a: bigint, b: bigint): bigint {
  return (a + b) % SUBGROUP_ORDER;
}

export interface PedersenPanelElements {
  canvas: HTMLCanvasElement;
  valueA: HTMLInputElement;
  valueB: HTMLInputElement;
  blindingA: HTMLInputElement;
  blindingB: HTMLInputElement;
  randomBtn: HTMLButtonElement;
  readout: HTMLDivElement;
}

/** Cryptographically random scalar in `[0, l)`, rendered as a decimal
 *  string. Uses Web Crypto for the bytes, BigInt reduction for the mod. */
function randomScalar(): string {
  // 256 bits is enough head-room over the 251-bit subgroup order to
  // make the reduction's bias negligible.
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return (n % SUBGROUP_ORDER).toString();
}

export function setupPedersenPanel(els: PedersenPanelElements): void {
  const ctx = els.canvas.getContext("2d")!;
  const W = els.canvas.width;
  const H_ = els.canvas.height;

  function update(): void {
    // Parse the four scalars from the input fields. Inputs are sliders
    // and a "random blinding" button; treating them as raw decimal
    // strings is fine for the wasm boundary, which validates.
    const a = els.valueA.value;
    const b = els.valueB.value;
    const r_a = els.blindingA.value;
    const r_b = els.blindingB.value;

    let ca, cb, csum, h_point;
    try {
      ca = pedersen_commit(a, r_a);
      cb = pedersen_commit(b, r_b);
      // Compute summed scalars in JS BigInt land, mod l.
      const sumValue = addMod(BigInt(a), BigInt(b)).toString();
      const sumBlinding = addMod(BigInt(r_a), BigInt(r_b)).toString();
      csum = pedersen_commit(sumValue, sumBlinding);
      h_point = pedersen_h();
    } catch (err) {
      const m = err instanceof Error ? err.message : String(err);
      els.readout.innerHTML = `<span class="error">commit failed: ${m}</span>`;
      return;
    }

    // Plot
    ctx.clearRect(0, 0, W, H_);
    drawGrid(ctx, W, H_);

    const pCa = toPixel(ca.x, ca.y, W, H_);
    const pCb = toPixel(cb.x, cb.y, W, H_);
    const pCsum = toPixel(csum.x, csum.y, W, H_);
    const pH = toPixel(h_point.x, h_point.y, W, H_);

    // Faint lines from C_a and C_b to C_sum — visual hint that
    // "two commitments combine to one."
    ctx.save();
    ctx.globalAlpha = 0.25;
    ctx.strokeStyle = palette.shared;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(pCa.px, pCa.py);
    ctx.lineTo(pCsum.px, pCsum.py);
    ctx.moveTo(pCb.px, pCb.py);
    ctx.lineTo(pCsum.px, pCsum.py);
    ctx.stroke();
    ctx.restore();

    drawAnchor(ctx, pCa.px, pCa.py, palette.actorA, "C_a");
    drawAnchor(ctx, pCb.px, pCb.py, palette.actorB, "C_b");
    drawAnchor(ctx, pCsum.px, pCsum.py, palette.shared, "C_a+b");
    // H is dimmer, as a "context" marker — it's the same point every
    // time, not an actor in this commitment.
    ctx.save();
    ctx.globalAlpha = 0.55;
    drawAnchor(ctx, pH.px, pH.py, palette.text, "H");
    ctx.restore();

    els.readout.innerHTML = `
      <div class="row"><span class="label">C_a</span> <code>${shortCoord(ca.x)}</code></div>
      <div class="row"><span class="label">C_b</span> <code>${shortCoord(cb.x)}</code></div>
      <div class="row"><span class="label">C_a+b</span> <code>${shortCoord(csum.x)}</code></div>
      <div class="row symmetry ok">
        C_a + C_b ≡ commit(a+b, r_a+r_b)  (additive homomorphism)
      </div>
    `;
  }

  // Wire inputs.
  els.valueA.addEventListener("input", update);
  els.valueB.addEventListener("input", update);
  els.blindingA.addEventListener("input", update);
  els.blindingB.addEventListener("input", update);
  els.randomBtn.addEventListener("click", () => {
    els.blindingA.value = randomScalar();
    els.blindingB.value = randomScalar();
    update();
  });

  // Initialize with the spec's vector-3-and-4-summed-to-vector-5 values
  // — so the first frame shows exactly the homomorphic anchor the spec
  // is built around.
  els.valueA.value = "42";
  els.valueB.value = "43";
  els.blindingA.value = "2";
  els.blindingB.value = "5";
  update();
}
