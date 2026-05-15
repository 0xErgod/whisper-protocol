/**
 * The cyclic walk panel — `1·G, 2·G, …, n·G` plotted as a connected
 * path. Extracted from the original `main.ts` into its own module
 * alongside the keypair and ECDH panels.
 *
 * No curve math here; `mul_generator` does it through the WASM
 * boundary.
 */

import { generator, mul_generator } from "crypto-wasm";

import { drawGrid, palette, project } from "./render";

interface WalkPoint {
  k: number;
  x: string;
  y: string;
  px: number;
  py: number;
}

export interface WalkPanelElements {
  canvas: HTMLCanvasElement;
  stepsInput: HTMLInputElement;
  stepsVal: HTMLSpanElement;
  readout: HTMLDivElement;
}

export function setupWalkPanel(els: WalkPanelElements): void {
  const ctx = els.canvas.getContext("2d")!;
  const W = els.canvas.width;
  const H = els.canvas.height;

  function computeWalk(steps: number): WalkPoint[] {
    const out: WalkPoint[] = [];
    for (let k = 1; k <= steps; k++) {
      const p = mul_generator(String(k));
      out.push({
        k,
        x: p.x,
        y: p.y,
        px: project(p.x, W),
        py: H - project(p.y, H),
      });
    }
    return out;
  }

  function render(walk: WalkPoint[]): void {
    ctx.clearRect(0, 0, W, H);
    drawGrid(ctx, W, H);

    // Connecting path — the walk itself, drawn faint with globalAlpha
    // so the per-point dots read on top.
    ctx.save();
    ctx.globalAlpha = 0.35;
    ctx.strokeStyle = palette.brand;
    ctx.lineWidth = 1;
    ctx.beginPath();
    walk.forEach((p, i) => {
      if (i === 0) ctx.moveTo(p.px, p.py);
      else ctx.lineTo(p.px, p.py);
    });
    ctx.stroke();
    ctx.restore();

    // Per-point dots, brightening (via globalAlpha) toward the most
    // recent multiple so the direction of travel reads.
    walk.forEach((p, i) => {
      const t = i / Math.max(1, walk.length - 1);
      const r = 2 + t * 2;
      ctx.save();
      ctx.globalAlpha = 0.3 + t * 0.7;
      ctx.fillStyle = palette.brand;
      ctx.beginPath();
      ctx.arc(p.px, p.py, r, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
    });

    // Mark `1·G` distinctly — the anchor of the whole walk.
    const g = walk[0];
    ctx.strokeStyle = palette.text;
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.arc(g.px, g.py, 6, 0, Math.PI * 2);
    ctx.stroke();
  }

  function update(): void {
    const steps = Number(els.stepsInput.value);
    els.stepsVal.textContent = String(steps);

    const walk = computeWalk(steps);
    render(walk);

    const last = walk[walk.length - 1];
    els.readout.innerHTML = `
      <span class="k">${last.k}·G</span>
      <span class="coord">x = ${last.x}</span>
      <span class="coord">y = ${last.y}</span>
    `;
  }

  els.stepsInput.addEventListener("input", update);

  // Startup sanity check: the generator from WASM must be Base8.
  const gen = generator();
  console.assert(
    gen.x ===
      "5299619240641551281634865583518297030282874472190772894086521144482721001553",
    "generator x is not Base8 — WASM boundary may be broken",
  );

  update();
}
