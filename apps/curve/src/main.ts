/**
 * Entry point: initializes the WASM module once, then wires each
 * visualization panel to its DOM elements.
 *
 * No curve math here — that's all behind `crypto-wasm`. Each panel
 * lives in its own module:
 *
 *  - `walk-panel`      — cyclic walk of generator multiples
 *  - `keypair-panel`   — 64-byte seed → public key
 *  - `ecdh-panel`      — Alice + Bob seeds → shared point (with the
 *                        symmetry property asserted visually)
 *  - `pedersen-panel`  — two (value, blinding) pairs → three
 *                        commitments showing the additive-homomorphism
 *                        property
 *  - `schnorr-panel`   — sign a field-element message, plot PK + R,
 *                        verify in-page; tamper button to demo the
 *                        rejection path
 *
 * All three panels exist for the same reason: each is an end-to-end
 * exercise of the Rust → WASM → TypeScript chain against a different
 * primitive, anchored to the same `specs/babyjub-*.md` contracts the
 * Rust tests pin.
 */

import init from "crypto-wasm";

import { setupEcdhPanel } from "./ecdh-panel";
import { setupKeypairPanel } from "./keypair-panel";
import { setupPedersenPanel } from "./pedersen-panel";
import { setupSchnorrPanel } from "./schnorr-panel";
import { setupWalkPanel } from "./walk-panel";

await init();

setupWalkPanel({
  canvas: document.getElementById("stage-walk") as HTMLCanvasElement,
  stepsInput: document.getElementById("steps") as HTMLInputElement,
  stepsVal: document.getElementById("steps-val") as HTMLSpanElement,
  readout: document.getElementById("readout-walk") as HTMLDivElement,
});

setupKeypairPanel({
  canvas: document.getElementById("stage-keypair") as HTMLCanvasElement,
  seedInput: document.getElementById("seed-input") as HTMLTextAreaElement,
  randomBtn: document.getElementById("seed-random") as HTMLButtonElement,
  readout: document.getElementById("readout-keypair") as HTMLDivElement,
});

setupEcdhPanel({
  canvas: document.getElementById("stage-ecdh") as HTMLCanvasElement,
  randomBtn: document.getElementById("ecdh-random") as HTMLButtonElement,
  readout: document.getElementById("readout-ecdh") as HTMLDivElement,
});

setupPedersenPanel({
  canvas: document.getElementById("stage-pedersen") as HTMLCanvasElement,
  valueA: document.getElementById("pedersen-value-a") as HTMLInputElement,
  valueB: document.getElementById("pedersen-value-b") as HTMLInputElement,
  blindingA: document.getElementById("pedersen-blinding-a") as HTMLInputElement,
  blindingB: document.getElementById("pedersen-blinding-b") as HTMLInputElement,
  randomBtn: document.getElementById("pedersen-random") as HTMLButtonElement,
  readout: document.getElementById("readout-pedersen") as HTMLDivElement,
});

setupSchnorrPanel({
  canvas: document.getElementById("stage-schnorr") as HTMLCanvasElement,
  messageInput: document.getElementById("schnorr-message") as HTMLInputElement,
  randomBtn: document.getElementById("schnorr-random") as HTMLButtonElement,
  tamperBtn: document.getElementById("schnorr-tamper") as HTMLButtonElement,
  readout: document.getElementById("readout-schnorr") as HTMLDivElement,
});
