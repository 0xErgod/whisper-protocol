/**
 * text-utf8-v1 encoding playground: a text payload in, the 9-element
 * field stream out, and the round-trip back to text.
 *
 * This panel is different from the others because the encoding doesn't
 * produce a single curve point — it produces a stream of 9 field
 * elements. So instead of plotting a point in 2D, we render the stream
 * as 9 horizontal "slots" across the canvas, with each slot's
 * intensity proportional to its field element's magnitude. The leftmost
 * slot is f_0 (the length prefix); the other 8 are the byte chunks.
 *
 * The round-trip is verified at the byte level inside this panel: any
 * difference between input bytes and `decode(encode(input))` flips the
 * readout's symmetry line to red. The Rust + WASM test suites already
 * pin the byte-level fidelity; this panel is the human-scannable
 * confirmation.
 */

import { text_utf8_v1_decode, text_utf8_v1_encode } from "crypto-wasm";

import { drawGrid, palette, shortCoord } from "./render";

export interface EncodingPanelElements {
  canvas: HTMLCanvasElement;
  textInput: HTMLTextAreaElement;
  readout: HTMLDivElement;
}

/** Number of field elements text-utf8-v1 produces. Pinned in the spec. */
const FIELD_COUNT = 9;

export function setupEncodingPanel(els: EncodingPanelElements): void {
  const ctx = els.canvas.getContext("2d")!;
  const W = els.canvas.width;
  const H = els.canvas.height;

  function update(): void {
    const input = els.textInput.value;
    const bytes = new TextEncoder().encode(input);

    let stream: string[];
    let decoded: Uint8Array;
    let error: string | null = null;
    let roundTripOk = false;

    try {
      stream = text_utf8_v1_encode(bytes);
      decoded = text_utf8_v1_decode(stream);
      roundTripOk =
        decoded.length === bytes.length &&
        decoded.every((b, i) => b === bytes[i]);
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
      stream = [];
      decoded = new Uint8Array(0);
    }

    // Render canvas: 9 horizontal slots, each filled proportionally to
    // the magnitude of its field element. f_0 (length prefix) is
    // colored distinctly from the chunk slots.
    ctx.clearRect(0, 0, W, H);
    drawGrid(ctx, W, H);

    if (!error) {
      const slotW = W / FIELD_COUNT;
      const padding = 4;
      stream.forEach((decimal, i) => {
        const x = i * slotW + padding;
        const w = slotW - padding * 2;
        // Magnitude as a 0..1 number — we just check non-zero for the
        // chunks (the actual decimal is too large to bar-plot
        // meaningfully). f_0 plots its actual numeric value scaled
        // against MAX_BYTES (248).
        let magnitude: number;
        if (i === 0) {
          magnitude = Number(BigInt(decimal)) / 248;
        } else {
          magnitude = decimal === "0" ? 0 : 1;
        }
        const h = magnitude * (H - padding * 2);
        ctx.save();
        ctx.globalAlpha = i === 0 ? 0.85 : 0.6;
        ctx.fillStyle = i === 0 ? palette.brand : palette.actorA;
        ctx.fillRect(x, H - padding - h, w, h);
        ctx.restore();

        // Label
        ctx.fillStyle = palette.text;
        ctx.font = '11px "Geist Mono", ui-monospace, monospace';
        ctx.fillText(`f_${i}`, x + 2, H - padding - 2);
      });
    }

    // Render readout
    if (error) {
      els.readout.innerHTML = `<span class="error">encode failed: ${error}</span>`;
      return;
    }

    const decodedText = new TextDecoder().decode(decoded);
    els.readout.innerHTML = `
      <div class="row"><span class="label">input.len</span> <code>${bytes.length} bytes</code></div>
      <div class="row"><span class="label">f_0 (len)</span> <code>${stream[0]}</code></div>
      <div class="row"><span class="label">f_1</span> <code>${shortCoord(stream[1])}</code></div>
      <div class="row"><span class="label">f_2..f_8</span> <code>${
        stream.slice(2).every((s) => s === "0")
          ? "all zero (payload fits in f_1)"
          : "non-zero — payload spans chunks"
      }</code></div>
      <div class="row"><span class="label">decoded</span> <code>${escapeHtml(decodedText)}</code></div>
      <div class="row symmetry ${roundTripOk ? "ok" : "bad"}">
        ${roundTripOk ? "✓ decode(encode(bytes)) == bytes  (round-trip holds)" : "✗ round-trip mismatch"}
      </div>
    `;
  }

  els.textInput.addEventListener("input", update);
  els.textInput.value = "hello, world!";
  update();
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
