// Single import site for the crypto-wasm bindings. Every other SDK
// module reaches into the BJJ + Poseidon primitives through this file
// — the indirection exists so that if we ever swap the underlying
// crate (e.g. a wasm-pack target change) there's exactly one import
// to update.
//
// crypto-wasm is built with `--target bundler` (see
// packages/sdk/package.json `wasm` script). Consumers don't need a
// top-level `await init()`; the bundler instantiates the WASM at
// build time. In tests, `vitest.config.ts` enables `vite-plugin-wasm`
// to do the same thing inside Vitest's transformer.
import * as wasm from "crypto-wasm";

export const cryptoWasm = wasm;
export type CryptoWasm = typeof wasm;
