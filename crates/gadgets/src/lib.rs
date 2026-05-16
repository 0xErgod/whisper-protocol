//! R1CS gadgets mirroring the protocol's native cryptographic primitives.
//!
//! This crate is the in-circuit twin of `crypto`. For every native
//! function `f(inputs: &[Fq]) -> Fq` in `crypto`, this crate exposes
//! a gadget `f_var(cs, inputs: &[FpVar<Fq>]) -> Result<FpVar<Fq>,
//! SynthesisError>` that produces the same `Fq` output when the
//! constraint system is satisfied.
//!
//! ## Equivalence as a contract
//!
//! Each gadget ships with a **native↔circuit equivalence test**: it
//! runs the native primitive on a fixed input, runs the gadget on
//! the same input allocated as witnesses, and asserts the two
//! agree before checking `cs.is_satisfied()`. This is the
//! load-bearing test discipline pinned in
//! `specs/zk/stack.md § Equivalence discipline`; a gadget without
//! this test is not a complete brick.
//!
//! ## Field naming
//!
//! Throughout this crate, **`Fq`** means BN254's base field — the
//! same `Fq` `crypto::babyjub::Fq` aliases. It is the field every
//! protocol value (Baby Jubjub coordinates, Poseidon hashes, KDF
//! outputs, MAC tags, ciphertext elements) lives in, and the field
//! every circuit witness and public input is an element of.
//!
//! Arkworks' Groth16 also has a scalar field for proof construction
//! internally; application code never touches it. The `Fq` re-export
//! below is the only field type any gadget caller needs.
//!
//! ## Scope
//!
//! Each native module in `crypto::babyjub` (and `crypto::poseidon`)
//! has a sibling module here. Gadgets land alongside their native
//! references one at a time:
//!
//! - `poseidon` — fixed-arity and sponge variants over circomlib
//!   parameters. The substrate every other gadget builds on.
//! - (future) `babyjub::curve` — twisted-Edwards point addition and
//!   scalar multiplication.
//! - (future) `babyjub::pedersen`, `babyjub::ecdh`, `babyjub::kdf`,
//!   `babyjub::cipher`, `babyjub::mac`, `babyjub::schnorr`,
//!   `babyjub::keypair`.
//!
//! ## What this crate is NOT
//!
//! - **Not a circuit.** Circuits (one `ConstraintSynthesizer` impl
//!   per provable claim) live in `crates/circuits` and compose
//!   these gadgets. This crate only exposes reusable building
//!   blocks.
//! - **Not the prover.** Trusted setup, proof generation, and
//!   verification live in `crates/prover`. This crate has no
//!   `ProvingKey` / `Proof` types.
//! - **Not WASM-bound.** No `wasm-bindgen` dependency. A future
//!   `crates/prover-wasm` will own the boundary; this crate stays
//!   native-only so it composes cleanly into either the server or
//!   the WASM build.

pub mod poseidon;

/// BN254's base field — the field every protocol value lives in.
/// Same type as `crypto::babyjub::Fq`. Re-exported here so gadget
/// callers can write `gadgets::Fq` without dragging in `crypto`'s
/// curve module.
pub use crypto::babyjub::Fq;
