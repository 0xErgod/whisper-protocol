//! Cryptographic primitives for the provable communication protocol.
//!
//! NOTE(name): this crate is `crypto` as a working name. The protocol's public
//! name is undecided — keep product names out of crate/module/type identifiers
//! so a future rename touches `Cargo.toml` and nothing else.
//!
//! ## Scope
//!
//! Brick-by-brick primitives, each implemented natively here in Rust as the
//! single source of truth, then later (a) reproduced as in-circuit constraints
//! for the prover and (b) exposed to the TypeScript SDK via a WASM binding
//! crate. A published spec + worked-example fixture is the cross-language
//! contract that keeps all three faces in agreement.
//!
//! Currently implemented:
//! - [`babyjub`] — the Baby Jubjub twisted Edwards curve (ERC-2494 dialect):
//!   the curve as a group, plus on-curve / prime-subgroup checks.
//!
//! Planned, building on `babyjub`: keypairs, ECDH key agreement, Pedersen
//! commitments, Schnorr-style signatures.

pub mod babyjub;
pub mod encoding;
pub mod poseidon;
