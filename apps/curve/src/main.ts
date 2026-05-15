/**
 * Baby Jubjub curve visualization — the cyclic walk of generator multiples.
 *
 * The curve math is NOT reimplemented here. It comes entirely from
 * `crypto-wasm`, the WASM binding over the Rust `crypto` crate — the same
 * code, validated against `specs/babyjub-curve.md`, that the protocol's
 * primitives will use. This app is purely a *consumer* of that binding; it is
 * the first end-to-end exercise of the Rust → WASM → TypeScript chain.
 *
 * Why a "walk" and not a scatter: a Baby Jubjub point is `(x, y)` with both
 * coordinates in a 254-bit field. Plotted as real numbers the point set looks
 * like uniform noise in a square — there is no visible smooth curve, because
 * the curve structure only exists under modular arithmetic. What *is* legible
 * is the sequence: drawing `1·G → 2·G → 3·G → …` as a connected path shows
 * scalar multiplication as a walk that hops unpredictably (discrete-log
 * hardness, visualized) and eventually cycles through the whole subgroup.
 */

// `crypto-wasm` is a wasm-pack ESM module. The default export is the async
// init; it must be awaited before any binding function is called. Vite's
// wasm + top-level-await plugins make this awaitable at module scope.
import init, { generator, mul_generator } from "crypto-wasm";

await init();

// --- field-element -> canvas-pixel projection ------------------------------

/**
 * The Baby Jubjub base field prime, from `specs/babyjub-curve.md`. Point
 * coordinates are integers in `[0, p)`; we map that range onto canvas pixels.
 */
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const canvas = document.getElementById("stage") as HTMLCanvasElement;
const ctx = canvas.getContext("2d")!;
const W = canvas.width;
const H = canvas.height;

/**
 * Project a field-element coordinate (a decimal string from the WASM boundary)
 * onto a canvas axis. The field is astronomically larger than the pixel grid,
 * so this is a lossy `coord / p * extent` scaling — fine for intuition, and
 * the whole point is that the result looks scattered.
 */
function project(coord: string, extent: number): number {
  // BigInt division would floor to 0 for almost every input, so scale first:
  // multiply into a wide integer, then divide. 1e6 precision is plenty here.
  const scaled = (BigInt(coord) * BigInt(extent) * 1_000_000n) / FIELD_PRIME;
  return Number(scaled) / 1_000_000;
}

// --- the walk --------------------------------------------------------------

interface WalkPoint {
  k: number;
  x: string;
  y: string;
  px: number;
  py: number;
}

/**
 * Compute `1·G, 2·G, …, steps·G` via the WASM binding and project each onto
 * the canvas. This is the only place curve operations happen — and they all
 * go through `crypto-wasm`.
 */
function computeWalk(steps: number): WalkPoint[] {
  const out: WalkPoint[] = [];
  for (let k = 1; k <= steps; k++) {
    // `mul_generator` takes the scalar as a decimal string and returns a
    // `Point` with `.x` / `.y` string getters — the boundary representation
    // pinned in the spec.
    const p = mul_generator(String(k));
    out.push({
      k,
      x: p.x,
      y: p.y,
      px: project(p.x, W),
      py: H - project(p.y, H), // canvas y grows downward; flip so it reads up
    });
  }
  return out;
}

function render(walk: WalkPoint[]): void {
  ctx.clearRect(0, 0, W, H);

  // faint grid, just for spatial reference
  ctx.strokeStyle = "#15171e";
  ctx.lineWidth = 1;
  for (let i = 1; i < 8; i++) {
    const g = (i / 8) * W;
    ctx.beginPath();
    ctx.moveTo(g, 0);
    ctx.lineTo(g, H);
    ctx.moveTo(0, g);
    ctx.lineTo(W, g);
    ctx.stroke();
  }

  // the connecting path — the "walk"
  ctx.strokeStyle = "rgba(110, 231, 183, 0.35)";
  ctx.lineWidth = 1;
  ctx.beginPath();
  walk.forEach((p, i) => {
    if (i === 0) ctx.moveTo(p.px, p.py);
    else ctx.lineTo(p.px, p.py);
  });
  ctx.stroke();

  // the points themselves, brightening toward the most recent multiple
  walk.forEach((p, i) => {
    const t = i / Math.max(1, walk.length - 1);
    const r = 2 + t * 2;
    ctx.fillStyle = `rgba(110, 231, 183, ${0.3 + t * 0.7})`;
    ctx.beginPath();
    ctx.arc(p.px, p.py, r, 0, Math.PI * 2);
    ctx.fill();
  });

  // mark the generator (k = 1) distinctly — the anchor of the whole walk
  const g = walk[0];
  ctx.strokeStyle = "#e6e7ea";
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.arc(g.px, g.py, 6, 0, Math.PI * 2);
  ctx.stroke();
}

// --- wire up the controls --------------------------------------------------

const stepsInput = document.getElementById("steps") as HTMLInputElement;
const stepsVal = document.getElementById("steps-val") as HTMLSpanElement;
const readout = document.getElementById("readout") as HTMLDivElement;

function update(): void {
  const steps = Number(stepsInput.value);
  stepsVal.textContent = String(steps);

  const walk = computeWalk(steps);
  render(walk);

  // show the last multiple's actual coordinates — the raw field elements,
  // so the "these are huge numbers" point lands
  const last = walk[walk.length - 1];
  readout.innerHTML = `
    <span class="k">${last.k}·G</span>
    <span class="coord">x = ${last.x}</span>
    <span class="coord">y = ${last.y}</span>
  `;
}

stepsInput.addEventListener("input", update);

// sanity check at startup: the generator from WASM must be Base8, the exact
// decimals pinned in specs/babyjub-curve.md. If the boundary is broken, this
// is the first thing that would show it.
const g = generator();
console.assert(
  g.x === "5299619240641551281634865583518297030282874472190772894086521144482721001553",
  "generator x is not Base8 — WASM boundary may be broken",
);

update();
