/**
 * Shared canvas rendering primitives for the Baby Jubjub visualizations.
 *
 * No curve math lives here — only field-element-to-pixel projection and
 * canvas drawing helpers used by every panel. The curve math is in
 * `crypto-wasm`, behind the WASM boundary.
 *
 * Canvas colors come from the same CSS custom properties as the rest of
 * the app: a theme change in `styles/tokens.css` carries through. We read
 * them once at module load — the protocol's design language is static, so
 * re-reading on every frame would just be waste.
 */

/**
 * Resolve a CSS custom property value from the document root. Used to
 * pull design tokens into canvas drawing without hardcoding hex literals.
 */
function token(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/** Canvas palette — one source of truth, named by role. */
export const palette = {
  grid: token("--gray-15"),
  text: token("--text"),
  brand: token("--brand"),
  // Distinct accents for the three "actors" in the ECDH and keypair views.
  // Kept as direct values from the token scheme rather than per-actor
  // tokens — the canvas is the only consumer.
  actorA: token("--bright-orange"),
  actorB: token("--bright-magenta"),
  shared: token("--bright-green"),
  // The semantic "rejected / broken" color, mirroring the readout's
  // `.symmetry.bad` style on the canvas side.
  bad: token("--bad"),
};

/**
 * The Baby Jubjub base field prime, from `specs/babyjub-curve.md`. Point
 * coordinates are integers in `[0, p)`; we map that range onto canvas
 * pixels.
 */
export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Project a field-element coordinate (a decimal string from the WASM
 * boundary) onto a canvas axis. The field is astronomically larger than
 * any pixel grid, so this is a lossy `coord / p * extent` scaling — fine
 * for intuition; the scatter is the point.
 */
export function project(coord: string, extent: number): number {
  // BigInt division would floor to 0 for almost every input, so scale
  // first: multiply into a wide integer, then divide. 1e6 precision is
  // plenty.
  const scaled = (BigInt(coord) * BigInt(extent) * 1_000_000n) / FIELD_PRIME;
  return Number(scaled) / 1_000_000;
}

/**
 * Convert a `(field_x, field_y)` decimal pair into canvas pixel
 * coordinates for a canvas of the given size. Y is flipped so it reads
 * upward.
 */
export function toPixel(
  x: string,
  y: string,
  width: number,
  height: number,
): { px: number; py: number } {
  return { px: project(x, width), py: height - project(y, height) };
}

/** Draw a faint 8x8 reference grid into a canvas context. */
export function drawGrid(
  ctx: CanvasRenderingContext2D,
  width: number,
  height: number,
): void {
  ctx.strokeStyle = palette.grid;
  ctx.lineWidth = 1;
  for (let i = 1; i < 8; i++) {
    const gx = (i / 8) * width;
    const gy = (i / 8) * height;
    ctx.beginPath();
    ctx.moveTo(gx, 0);
    ctx.lineTo(gx, height);
    ctx.moveTo(0, gy);
    ctx.lineTo(width, gy);
    ctx.stroke();
  }
}

/** Draw a labelled, ring-marked anchor point — e.g. for a keypair's PK. */
export function drawAnchor(
  ctx: CanvasRenderingContext2D,
  px: number,
  py: number,
  color: string,
  label: string,
): void {
  ctx.fillStyle = color;
  ctx.beginPath();
  ctx.arc(px, py, 5, 0, Math.PI * 2);
  ctx.fill();

  ctx.strokeStyle = color;
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.arc(px, py, 9, 0, Math.PI * 2);
  ctx.stroke();

  ctx.fillStyle = palette.text;
  ctx.font = '11px "Geist Mono", ui-monospace, monospace';
  ctx.fillText(label, px + 12, py - 8);
}

/**
 * Truncate a long decimal coordinate string for compact display.
 * Keeps the first and last few digits so the "this is a huge number"
 * feel survives without overflowing the readout.
 */
export function shortCoord(s: string): string {
  if (s.length <= 18) return s;
  return `${s.slice(0, 8)}…${s.slice(-8)}`;
}
