//! WASM bindings for in-browser Groth16 proving.
//!
//! ## What this crate is
//!
//! A *thin binding*, in the same shape as `crates/crypto-wasm`.
//! Every exported function does exactly three things:
//!
//! 1. Deserialize a JSON `Inputs` string from JS into the
//!    circuit's typed `Inputs` struct (defined in
//!    `crates/circuits`).
//! 2. Call the already-tested `prover` crate.
//! 3. Hand the byte result back as a `Uint8Array`.
//!
//! No cryptographic logic lives here. No PK/VK lifecycle —
//! the caller supplies PK and VK as `Uint8Array`s, fetched from
//! wherever they prefer (the `prover-server` HTTP `/vk/<id>` and
//! a paired `/pk/<id>` endpoint, an IPFS pin, a Sui object,
//! bundled `include_bytes!`, etc.). This crate doesn't pick a
//! distribution strategy.
//!
//! ## Per-circuit shape
//!
//! Per circuit, two exports:
//!
//! - `prove_<circuit>(inputs_json, pk_bytes) -> Uint8Array`
//!   — the proof bytes, ready to ship on-chain or to a verifier.
//! - `verify_<circuit>(public_inputs_json, proof_bytes, vk_bytes) -> bool`
//!   — useful for client-side smoke checks; production
//!   verification happens on-chain or at the prover-server.
//!
//! Adding a new circuit means two more `#[wasm_bindgen]` exports
//! and one more pair of JSON shape definitions imported from
//! `crates/circuits`. Same Plan B discipline as the HTTP
//! server.
//!
//! ## What this crate is NOT
//!
//! - **Not a setup runner.** Groth16 trusted setup is heavy and
//!   security-critical; browsers should never run it. PK/VK come
//!   from elsewhere.
//! - **Not a key-distribution layer.** No `fetch`, no IndexedDB,
//!   no caching. The JS caller decides where the bytes come
//!   from and how they're cached.
//! - **Not a worker.** A future apps/zk demo will run this in a
//!   `Web Worker` to keep the main thread responsive during
//!   proving (which can take 5–60 seconds in WASM); the worker
//!   wrapper lives in TS, not here.
//!
//! ## Boundary representation
//!
//! - **Inputs:** JSON strings, matching the wire-form `Inputs`
//!   structs in `crates/circuits` (decimal strings for field
//!   elements).
//! - **PK / VK / proof:** raw `Uint8Array`. Compressed canonical
//!   arkworks encoding — the same bytes `prover::serialize_*`
//!   produce.

use wasm_bindgen::prelude::*;

use circuits::envelope_open_at_0::{
    public_inputs_from as envelope_open_public_inputs_from, EnvelopeOpenAt0,
    EnvelopeOpenAt0Inputs, EnvelopeOpenAt0PublicInputs,
};
use circuits::pedersen_opens_to::{
    public_inputs_from as pedersen_public_inputs_from, PedersenOpensTo,
    PedersenOpensToInputs, PedersenOpensToPublicInputs,
};
use prover::{deserialize_pk, deserialize_proof, deserialize_vk, prove, serialize_proof, verify};

// =====================================================================
// pedersen_opens_to
// =====================================================================

/// Generate a Groth16 proof for the `pedersen_opens_to` circuit.
///
/// `inputs_json` is a JSON string with the wire-form shape of
/// `PedersenOpensToInputs` (see `crates/circuits` for the exact
/// fields). `pk_bytes` is the proving key in arkworks' compressed
/// canonical encoding — the same bytes the prover-server's
/// `/vk/pedersen_opens_to` companion endpoint would hand out (or
/// a `prover::serialize_pk` byte blob from any other distribution
/// channel).
///
/// Returns the proof as a `Vec<u8>` — wasm-bindgen exposes this
/// to JS as a `Uint8Array`. Errors (malformed inputs, bad PK
/// bytes, etc.) come back as a JS exception, not a panic.
#[wasm_bindgen]
pub fn prove_pedersen_opens_to(
    inputs_json: &str,
    pk_bytes: &[u8],
) -> Result<Vec<u8>, JsError> {
    // Deserialize JSON → typed Inputs.
    let inputs: PedersenOpensToInputs =
        serde_json::from_str(inputs_json).map_err(|e| JsError::new(&format!("inputs json: {e}")))?;

    // Parse + validate via the circuit crate's TryFrom (the same
    // boundary the HTTP server uses).
    let circuit: PedersenOpensTo = inputs
        .try_into()
        .map_err(|e: circuits::pedersen_opens_to::InputsError| JsError::new(&e.to_string()))?;

    // Decode the PK.
    let pk =
        deserialize_pk(pk_bytes).map_err(|e| JsError::new(&format!("pk decode: {e}")))?;

    // Prove. `OsRng` doesn't exist on `wasm32-unknown-unknown`;
    // the `getrandom` `js` feature on this crate routes
    // `OsRng`-style consumption through the browser's
    // `crypto.getRandomValues`. arkworks' `ark_std::rand`
    // surface provides a compatible `RngCore + CryptoRng` impl.
    let mut rng = ark_rng_for_wasm()?;
    let proof = prove(circuit, &pk, &mut rng).map_err(|e| JsError::new(&e.to_string()))?;

    let bytes = serialize_proof(&proof).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(bytes)
}

/// Verify a Groth16 proof for the `pedersen_opens_to` circuit.
///
/// `public_inputs_json` is a JSON string with the wire-form
/// shape of `PedersenOpensToPublicInputs`. `proof_bytes` and
/// `vk_bytes` are arkworks-compressed encodings. Returns `true`
/// iff the proof is valid; malformed inputs throw a JS
/// exception (distinguishing "valid but bad proof" from
/// "broken input").
#[wasm_bindgen]
pub fn verify_pedersen_opens_to(
    public_inputs_json: &str,
    proof_bytes: &[u8],
    vk_bytes: &[u8],
) -> Result<bool, JsError> {
    let public: PedersenOpensToPublicInputs = serde_json::from_str(public_inputs_json)
        .map_err(|e| JsError::new(&format!("public_inputs json: {e}")))?;

    let public_inputs = pedersen_public_inputs_from(&public)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let proof =
        deserialize_proof(proof_bytes).map_err(|e| JsError::new(&format!("proof decode: {e}")))?;
    let vk = deserialize_vk(vk_bytes).map_err(|e| JsError::new(&format!("vk decode: {e}")))?;

    let accepted = verify(&vk, &public_inputs, &proof).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(accepted)
}

// =====================================================================
// RNG plumbing
// =====================================================================

/// Build an RNG suitable for Groth16 proving on
/// `wasm32-unknown-unknown`. Routes through the browser's
/// `crypto.getRandomValues` via the `getrandom` crate's `js`
/// feature. Satisfies `RngCore + CryptoRng`, which is what
/// `prover::prove`'s bound demands.
///
/// **Why not `from_entropy()`.** That method requires the `rand`
/// crate's `getrandom` feature to be wired through to `OsRng`,
/// which arkworks' `ark-std` does not enable in its default
/// feature set. We sidestep by pulling 32 bytes from
/// `getrandom` ourselves and seeding `StdRng::from_seed`. Same
/// entropy source, more explicit dependency graph.
fn ark_rng_for_wasm() -> Result<impl ark_std::rand::RngCore + ark_std::rand::CryptoRng, JsError> {
    use ark_std::rand::SeedableRng;
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| JsError::new(&format!("getrandom: {e}")))?;
    Ok(ark_std::rand::rngs::StdRng::from_seed(seed))
}

// =====================================================================
// envelope_open_at_0
// =====================================================================

/// Generate a Groth16 proof for the `envelope_open_at_0`
/// circuit. Shape mirrors [`prove_pedersen_opens_to`]:
/// JSON inputs + PK bytes in, proof bytes out.
#[wasm_bindgen]
pub fn prove_envelope_open_at_0(
    inputs_json: &str,
    pk_bytes: &[u8],
) -> Result<Vec<u8>, JsError> {
    let inputs: EnvelopeOpenAt0Inputs = serde_json::from_str(inputs_json)
        .map_err(|e| JsError::new(&format!("inputs json: {e}")))?;

    let circuit: EnvelopeOpenAt0 = inputs
        .try_into()
        .map_err(|e: circuits::envelope_open_at_0::InputsError| {
            JsError::new(&e.to_string())
        })?;

    let pk = deserialize_pk(pk_bytes)
        .map_err(|e| JsError::new(&format!("pk decode: {e}")))?;

    let mut rng = ark_rng_for_wasm()?;
    let proof = prove(circuit, &pk, &mut rng).map_err(|e| JsError::new(&e.to_string()))?;
    let bytes = serialize_proof(&proof).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(bytes)
}

/// Verify a Groth16 proof for the `envelope_open_at_0` circuit.
#[wasm_bindgen]
pub fn verify_envelope_open_at_0(
    public_inputs_json: &str,
    proof_bytes: &[u8],
    vk_bytes: &[u8],
) -> Result<bool, JsError> {
    let public: EnvelopeOpenAt0PublicInputs = serde_json::from_str(public_inputs_json)
        .map_err(|e| JsError::new(&format!("public_inputs json: {e}")))?;

    let public_inputs = envelope_open_public_inputs_from(&public)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let proof = deserialize_proof(proof_bytes)
        .map_err(|e| JsError::new(&format!("proof decode: {e}")))?;
    let vk = deserialize_vk(vk_bytes)
        .map_err(|e| JsError::new(&format!("vk decode: {e}")))?;

    let accepted = verify(&vk, &public_inputs, &proof).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(accepted)
}
