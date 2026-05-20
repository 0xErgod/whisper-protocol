//! Protocol-level compositions of the native cryptographic
//! primitives.
//!
//! This crate is the opinionated layer on top of
//! `crates/crypto`. It adds **no cryptographic claims**; it adds
//! **protocol claims** about how the primitives compose into
//! application-meaningful operations.
//!
//! ## What lives here
//!
//! - [`envelope`] — the canonical authenticated, confidential
//!   message from one wallet to another. Composes ECDH, KDF,
//!   stream cipher, and MAC into a single typed bundle. Spec:
//!   [`specs/protocol-envelope.md`](../../specs/protocol-envelope.md).
//! - [`commitment`] — a vector Pedersen commitment to a
//!   [`Payload`](crypto::encoding::Payload), with the payload's
//!   encoding id bound as the position-0 committed element. Spec:
//!   [`specs/protocol-commitment.md`](../../specs/protocol-commitment.md).
//!
//! Future:
//!
//! - `handshake` — multi-step session-establishment flow (if
//!   one is needed; current envelope use cases are single-shot).
//!
//! ## Discipline
//!
//! Each module corresponds to one spec doc in
//! [`specs/protocol-*.md`](../../specs/) and pins exactly the
//! same construction rule the spec does. The spec is the source
//! of truth; this crate is the Rust manifestation.
//!
//! ## What this crate is NOT
//!
//! - **Not a transport.** No HTTP, no WASM, no Move. The
//!   `prover-server`, `prover-wasm`, and on-chain Move crates
//!   consume protocol types via their own bindings.
//! - **Not a wallet.** Secret keys are inputs to the API, not
//!   stored state. Where the keys come from (wallet derivation,
//!   wallet signature, seed) is the caller's concern.

pub mod commitment;
pub mod envelope;
