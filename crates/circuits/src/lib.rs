//! Groth16-on-BN254 circuits expressing the protocol's provable
//! claims.
//!
//! Each module under this crate defines one circuit — a
//! `ConstraintSynthesizer<Fq>` impl over BN254's base field —
//! composing gadgets from `crates/gadgets`. Circuits do NOT
//! contain cryptographic logic of their own; their job is to
//! wire gadgets together and pin a claim's public-input layout.
//!
//! ## Discipline
//!
//! Each circuit follows the conventions pinned in
//! `specs/zk/stack.md`:
//!
//! - **One `ConstraintSynthesizer` impl per circuit.** No
//!   builders, no macros.
//! - **Witness fields are `Option<T>`.** The trusted-setup path
//!   instantiates the circuit with `Some(default)` witnesses to
//!   extract constraint structure without needing real values.
//! - **`empty()` constructor for setup.** Returns a circuit
//!   instance with dummy witnesses that satisfy structural
//!   constraints (correct lengths, etc.). The prover crate calls
//!   this during trusted setup; tests call it to assert the
//!   constraint count is stable.
//! - **Public-input cap is 8.** Sui's Groth16 verifier rejects
//!   anything wider. Each circuit's spec must declare its public
//!   inputs at design time and either fit under 8 or compress
//!   via the signal-hash pattern.
//! - **Per-circuit spec doc** at `specs/zk/circuit-<name>.md`.
//!   The spec pins the claim, the public/private layout, the
//!   gadget composition, and worked-example vectors for the
//!   end-to-end prove + verify path.
//!
//! ## What this crate is NOT
//!
//! - **Not the prover.** Trusted setup, proof generation, and
//!   verification live in `crates/prover`. This crate exposes
//!   circuits as types; the prover crate consumes them.
//! - **Not WASM-bound.** No `wasm-bindgen`. A future
//!   `crates/prover-wasm` will reach into this crate alongside
//!   `prover` if in-browser proving lands.

pub mod envelope_open_at_0;
pub mod pedersen_opens_to;
