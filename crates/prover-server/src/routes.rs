//! HTTP route handlers, one set per circuit.
//!
//! Plan B (see `lib.rs`) means each circuit ships its own three
//! handlers. The shape is identical across circuits and shouts
//! "extract a trait" — we deliberately keep the duplication
//! visible until the third circuit lands and the right shape is
//! obvious.
//!
//! Each circuit's handler trio shares the same internal flow:
//!
//! 1. Pull the circuit's keys from the registry (handlers do not
//!    re-run setup; that's `keys::build`'s job at boot).
//! 2. Deserialize the request body into the circuit's wire-form
//!    `Inputs` struct, defined in `crates/circuits`.
//! 3. For `/prove`: `TryFrom<Inputs> for Circuit` → `prove` →
//!    serialize → return bytes.
//!    For `/vk`: serialize the cached VK → return bytes.
//!    For `/verify`: deserialize the proof, build the public-input
//!    vector from the request's `PublicInputs` → `verify` →
//!    return `{accepted}`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use circuits::pedersen_opens_to::{
    public_inputs_from as pedersen_public_inputs_from,
    PedersenOpensTo, PedersenOpensToInputs, PedersenOpensToPublicInputs,
};
use prover::{deserialize_proof, prove, serialize_proof, serialize_vk, verify};

use crate::errors::{ServerError, ServerResult};
use crate::keys::Registry;

/// Application state shared with every request handler. Cheap to
/// clone — the `Registry` lives behind `Arc` and the inner PKs
/// are also `Arc`-wrapped.
#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<Registry>,
}

/// Build the full router. The per-circuit functions below assemble
/// one sub-router each; merging is the only line `main.rs` needs to
/// touch when a new circuit is added.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .merge(pedersen_opens_to_routes())
        .with_state(state)
}

// =====================================================================
// pedersen_opens_to handlers
// =====================================================================

fn pedersen_opens_to_routes() -> Router<AppState> {
    Router::new()
        .route("/prove/pedersen_opens_to", post(prove_pedersen_opens_to))
        .route("/vk/pedersen_opens_to", get(vk_pedersen_opens_to))
        .route(
            "/verify/pedersen_opens_to",
            post(verify_pedersen_opens_to),
        )
}

/// `POST /prove/pedersen_opens_to`
///
/// Body: `PedersenOpensToInputs` JSON.
/// Response: proof bytes, `application/octet-stream`.
async fn prove_pedersen_opens_to(
    State(state): State<AppState>,
    Json(inputs): Json<PedersenOpensToInputs>,
) -> ServerResult<impl IntoResponse> {
    let keys = state
        .registry
        .get("pedersen_opens_to")
        .ok_or_else(|| ServerError::UnknownCircuit("pedersen_opens_to".to_string()))?;

    // Validate + build the circuit. `try_into` performs the wire
    // decoder check on the commitment (off-curve / small-subgroup
    // come back as 400), parses every decimal, fails fast on the
    // first malformed slot.
    let circuit: PedersenOpensTo = inputs.try_into()?;

    // Prove. Each request gets its own RNG so concurrent provers
    // don't share state; using OsRng-style randomness on the
    // prove side is fine — the protocol does not require
    // determinism for proof bytes.
    let mut rng = rand::rngs::OsRng;
    let proof = prove(circuit, &keys.pk, &mut rng)?;

    let bytes = serialize_proof(&proof)?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        bytes,
    ))
}

/// `GET /vk/pedersen_opens_to`
///
/// Response: VK bytes, `application/octet-stream`.
async fn vk_pedersen_opens_to(
    State(state): State<AppState>,
) -> ServerResult<impl IntoResponse> {
    let keys = state
        .registry
        .get("pedersen_opens_to")
        .ok_or_else(|| ServerError::UnknownCircuit("pedersen_opens_to".to_string()))?;
    let bytes = serialize_vk(&keys.vk)?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        bytes,
    ))
}

/// Verify-request body shape: public inputs (the verifier-side
/// subset, decimal strings) plus the proof bytes hex-encoded.
///
/// Proof bytes go through hex because JSON doesn't have a clean
/// way to carry binary. The HTTP shape of `/prove` returns raw
/// bytes; clients that want to round-trip through `/verify`
/// hex-encode before sending. (If this turns out to be friction,
/// a `multipart/form-data` variant is a future option.)
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub public_inputs: PedersenOpensToPublicInputs,
    /// Hex-encoded proof bytes (no 0x prefix).
    pub proof_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub accepted: bool,
}

/// `POST /verify/pedersen_opens_to`
///
/// Body: `VerifyRequest` JSON.
/// Response: `{ "accepted": bool }`.
async fn verify_pedersen_opens_to(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> ServerResult<Json<VerifyResponse>> {
    let keys = state
        .registry
        .get("pedersen_opens_to")
        .ok_or_else(|| ServerError::UnknownCircuit("pedersen_opens_to".to_string()))?;

    let public_inputs = pedersen_public_inputs_from(&req.public_inputs)?;

    let proof_bytes = hex::decode(&req.proof_hex)
        .map_err(|e| ServerError::BadProofBytes(e.to_string()))?;
    let proof = deserialize_proof(&proof_bytes)
        .map_err(|e| ServerError::BadProofBytes(e.to_string()))?;

    let accepted = verify(&keys.vk, &public_inputs, &proof)?;
    Ok(Json(VerifyResponse { accepted }))
}
