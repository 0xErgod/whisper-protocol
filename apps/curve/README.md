# curve-viz

Baby Jubjub curve visualization — creative-coding intuition for the curve the
protocol's primitives live on.

It plots the **cyclic walk** of generator multiples: `1·G, 2·G, 3·G, …`. The
points are 254-bit field elements, so plotted directly they look like noise in
a square — and that is the lesson. The connecting path shows scalar
multiplication as a walk that hops unpredictably (discrete-log hardness, made
visual) and eventually cycles through the prime-order subgroup.

## The point of this app, structurally

It is the **first consumer of the `crates/crypto` → `crates/crypto-wasm` →
TypeScript chain.** It reimplements no curve math: every point comes from the
WASM binding over the Rust `crypto` crate — the same code, validated against
`specs/babyjub-curve.md`, that the protocol's real primitives use. If the WASM
boundary regressed, this app would render wrong.

## Running

```sh
pnpm --filter curve-viz dev
```

The `predev` / `prebuild` scripts run `wasm-pack` first, regenerating
`crates/crypto-wasm/pkg/` (a build artifact, gitignored) from the Rust source.
So a fresh checkout just needs `pnpm install` once and then the command above —
the WASM is built on demand.

The `wasm` script uses `--release`, not `--dev`. arkworks generates functions
whose local-count exceeds the wasm spec's 50,000-per-function limit in debug
builds; the release profile inlines them below the limit. Same constraint
documented in `crates/crypto-wasm/tests/boundary.rs`. Build time is ~30s once,
cached after.

Requires the `wasm32-unknown-unknown` Rust target and `wasm-pack` on PATH:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

## NOTE: the `apps/` directory

`apps/` is the home for applications and demos built on the protocol. Sibling
to this one is `apps/protocol` — the dApp demo (formerly `web/`). New apps and
demos go under `apps/`.
