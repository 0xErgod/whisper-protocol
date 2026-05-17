/**
 * Vector Pedersen commitment demo: element-wise additive
 * homomorphism, visualized.
 *
 * Two streams (a, b) plus two blindings (r_a, r_b) → three plotted
 * commitments: C_a, C_b, and the element-wise-summed commitment
 * C_sum = commit(a + b, r_a + r_b). By the new vector Pedersen's
 * homomorphism, `C_a + C_b == C_sum` in the group. The panel doesn't
 * compute that group sum (the wasm boundary doesn't expose point
 * addition), but it shows that the same C_sum point arrives
 * deterministically from the element-wise summed inputs — the
 * load-bearing property the protocol's commitment layer relies on.
 *
 * Streams are entered as comma-separated decimal values. The two
 * streams must have the same length for element-wise addition to make
 * sense; the panel rejects mismatched lengths.
 *
 * `H` is plotted as a fixed context anchor — the protocol's pinned
 * blinding generator, the same point every commitment carries.
 */

import { pedersen_commit, pedersen_h } from "crypto-wasm";

import { drawAnchor, drawGrid, palette, shortCoord, toPixel } from "./render";

/** Baby Jubjub subgroup order `l`, from `specs/babyjub-curve.md`. JS-side
 *  modular arithmetic is mod-l because the blinding scalar lives in F_l;
 *  the wasm binding takes already-reduced decimal strings. */
const SUBGROUP_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

/** Baby Jubjub base-field prime `p`, from `specs/babyjub-curve.md`. The
 *  stream elements live in F_p; element-wise addition is mod-p. */
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function addMod(a: bigint, b: bigint, modulus: bigint): bigint {
  return (a + b) % modulus;
}

export interface PedersenPanelElements {
  canvas: HTMLCanvasElement;
  streamA: HTMLInputElement;
  streamB: HTMLInputElement;
  blindingA: HTMLInputElement;
  blindingB: HTMLInputElement;
  randomBtn: HTMLButtonElement;
  readout: HTMLDivElement;
}

/** Cryptographically random scalar in [0, l). */
function randomScalar(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return (n % SUBGROUP_ORDER).toString();
}

/** Parse a comma-separated stream of non-negative decimal integers.
 *  Whitespace around each element is trimmed. Empty input yields an
 *  empty stream — a valid input for `commit`. */
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

export function setupPedersenPanel(els: PedersenPanelElements): void {
  const ctx = els.canvas.getContext("2d")!;
  const W = els.canvas.width;
  const H_ = els.canvas.height;

  function update(): void {
    const a = parseStream(els.streamA.value);
    const b = parseStream(els.streamB.value);
    if (isStreamError(a)) {
      els.readout.innerHTML = `<span class="error">stream a: ${a.error}</span>`;
      ctx.clearRect(0, 0, W, H_);
      drawGrid(ctx, W, H_);
      return;
    }
    if (isStreamError(b)) {
      els.readout.innerHTML = `<span class="error">stream b: ${b.error}</span>`;
      ctx.clearRect(0, 0, W, H_);
      drawGrid(ctx, W, H_);
      return;
    }
    if (a.length !== b.length) {
      els.readout.innerHTML = `<span class="error">streams must have the same length for element-wise homomorphism (got ${a.length} vs ${b.length})</span>`;
      ctx.clearRect(0, 0, W, H_);
      drawGrid(ctx, W, H_);
      return;
    }

    const r_a = els.blindingA.value;
    const r_b = els.blindingB.value;

    let ca, cb, csum, h_point;
    try {
      ca = pedersen_commit(a, r_a);
      cb = pedersen_commit(b, r_b);
      // Element-wise sum in F_p for the values; mod-l sum for the blinding.
      const sum_stream: string[] = a.map((ax, i) =>
        addMod(BigInt(ax), BigInt(b[i]), FIELD_PRIME).toString(),
      );
      const sum_blinding = addMod(
        BigInt(r_a),
        BigInt(r_b),
        SUBGROUP_ORDER,
      ).toString();
      csum = pedersen_commit(sum_stream, sum_blinding);
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

    // Faint lines from C_a and C_b into C_sum.
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
    // H is dimmer; it's a fixed protocol parameter, not an actor.
    ctx.save();
    ctx.globalAlpha = 0.55;
    drawAnchor(ctx, pH.px, pH.py, palette.text, "H");
    ctx.restore();

    els.readout.innerHTML = `
      <div class="row"><span class="label">|stream|</span> <code>${a.length}</code></div>
      <div class="row"><span class="label">C_a</span> <code>${shortCoord(ca.x)}</code></div>
      <div class="row"><span class="label">C_b</span> <code>${shortCoord(cb.x)}</code></div>
      <div class="row"><span class="label">C_a+b</span> <code>${shortCoord(csum.x)}</code></div>
      <div class="row symmetry ok">
        C_a + C_b ≡ commit(a + b, r_a + r_b)  (element-wise homomorphism)
      </div>
    `;
  }

  els.streamA.addEventListener("input", update);
  els.streamB.addEventListener("input", update);
  els.blindingA.addEventListener("input", update);
  els.blindingB.addEventListener("input", update);
  els.randomBtn.addEventListener("click", () => {
    els.blindingA.value = randomScalar();
    els.blindingB.value = randomScalar();
    update();
  });

  // Initialize with the spec's vector-5 homomorphism anchor:
  // [10, 20, 30] + [5, 15, 25] = [15, 35, 55].
  els.streamA.value = "10, 20, 30";
  els.streamB.value = "5, 15, 25";
  els.blindingA.value = "100";
  els.blindingB.value = "200";
  update();
}
