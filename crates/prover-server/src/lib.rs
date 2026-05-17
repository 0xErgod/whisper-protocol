//! Axum HTTP server exposing the protocol's Groth16 circuits.
//!
//! ## Shape
//!
//! Per circuit, the server exposes three routes:
//!
//! - `POST /prove/<circuit-id>` — body is the circuit's
//!   wire-form `Inputs` JSON; response is the compressed
//!   proof bytes (`application/octet-stream`).
//! - `GET /vk/<circuit-id>` — response is the compressed VK
//!   bytes. Used by the on-chain deployment step and by any
//!   off-chain verifier.
//! - `POST /verify/<circuit-id>` — body is `{public_inputs,
//!   proof}` JSON (proof bytes hex-encoded); response is
//!   `{accepted: bool}`. Useful for testing and for a verifier
//!   service that doesn't want to run pairing code itself.
//!
//! Adding a new circuit means: one set of three handlers in
//! `routes.rs` calling that circuit's `Inputs` / `TryFrom` /
//! `public_inputs_from` (defined in `crates/circuits`), one
//! row in [`keys::Registry`], one `Router::merge` line in
//! `main.rs`. The disciplined-per-Plan-B duplication; we
//! consolidate into a trait when a third circuit makes the
//! shape obvious.
//!
//! ## PK/VK lifecycle
//!
//! On boot, for each registered circuit, the server:
//!
//! 1. Checks `keys/<circuit>.pk` and `keys/<circuit>.vk` on disk.
//! 2. If both exist, deserializes them.
//! 3. If either is missing, runs Groth16 trusted setup with
//!    `ark_std::test_rng()` (dev only — production needs a
//!    ceremony), writes both files, and continues.
//!
//! All PKs stay in memory for the process lifetime, wrapped in
//! `Arc` so the per-request handlers can clone the handle
//! cheaply without copying the multi-megabyte keys.
//!
//! ## No tracing_subscriber
//!
//! Pinned in `specs/zk/stack.md`. Logs are `println!`.

pub mod errors;
pub mod keys;
pub mod routes;
