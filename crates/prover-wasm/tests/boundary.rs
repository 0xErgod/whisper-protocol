//! Boundary fixture test — runs in a real headless browser via
//! `wasm-pack test`.
//!
//! Same shape as `crypto-wasm/tests/boundary.rs`: prove the
//! values survive the JS<->WASM boundary unchanged, by exercising
//! the actual `wasm32` codegen + wasm-bindgen marshalling.
//!
//! A passing `cargo test -p prover-wasm` does NOT imply a passing
//! boundary. Only the wasm artifact, run in a browser, exercises
//! the edge `apps/zk` will hit.
//!
//! ## Why we don't run setup in the browser
//!
//! Groth16 trusted setup in wasm32 is minutes-slow. The boundary
//! test's job is to exercise *marshalling*, not the prover's
//! compute path — so the (PK, VK, honest proof) fixture is
//! pre-generated natively by this crate's build script (see
//! `build.rs`) and `include_bytes!`'d here.
//!
//! Run with: `wasm-pack test --headless --chrome --release crates/prover-wasm`
//! (or `--firefox`).
//!
//! `--release` is required: arkworks generates functions whose
//! local-count exceeds the wasm spec's 50,000-per-function limit
//! in debug builds. Same gotcha `crypto-wasm`'s boundary test
//! flags.

use wasm_bindgen_test::*;

use prover_wasm::{prove_pedersen_opens_to, verify_pedersen_opens_to};

wasm_bindgen_test_configure!(run_in_browser);

// Fixtures generated natively by build.rs. The PK is multi-MB;
// the VK is small; the inputs and public-inputs JSON are short.
const PK_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/test_fixtures/pedersen_opens_to.pk"
));
const VK_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/test_fixtures/pedersen_opens_to.vk"
));
const PROOF_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/test_fixtures/pedersen_opens_to.proof"
));
const INPUTS_JSON: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/test_fixtures/pedersen_opens_to.inputs.json"
));
const PUBLIC_JSON: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/test_fixtures/pedersen_opens_to.public.json"
));

/// Verify the pre-computed honest proof against the
/// pre-computed VK across the wasm boundary. The lightest test
/// — exercises only the verify path, no Groth16 prove math
/// inside the browser.
#[wasm_bindgen_test]
fn verify_honest_proof_accepts() {
    let accepted = verify_pedersen_opens_to(PUBLIC_JSON, PROOF_BYTES, VK_BYTES)
        .expect("verify ok");
    assert!(accepted, "honest proof must verify across the boundary");
}

/// Verification with tampered public inputs MUST reject. The
/// integrity property at the boundary.
#[wasm_bindgen_test]
fn verify_rejects_tampered_public_inputs() {
    // Same shape as PUBLIC_JSON but with a different
    // claimed_first_value.
    let tampered = format!(
        r#"{{"commitment_x":"{cx}","commitment_y":"{cy}","claimed_first_value":"99"}}"#,
        cx = parse_field(PUBLIC_JSON, "commitment_x"),
        cy = parse_field(PUBLIC_JSON, "commitment_y"),
    );
    let accepted =
        verify_pedersen_opens_to(&tampered, PROOF_BYTES, VK_BYTES).expect("verify ok");
    assert!(!accepted, "tampered public inputs must NOT verify");
}

/// End-to-end across the boundary: prove with the wasm export,
/// verify the result with the wasm export, accept. This is the
/// heaviest test — Groth16 prove runs in the browser. In release
/// it takes seconds; in debug it would be unbounded.
#[wasm_bindgen_test]
fn prove_then_verify_roundtrips() {
    // Prove using the wasm export. Inputs come from the same
    // honest fixture the verify-only test uses, so the proof
    // produced here is a valid alternative proof for the same
    // public statement.
    let proof_bytes = prove_pedersen_opens_to(INPUTS_JSON, PK_BYTES).expect("prove ok");
    assert!(!proof_bytes.is_empty(), "proof bytes must be non-empty");

    let accepted = verify_pedersen_opens_to(PUBLIC_JSON, &proof_bytes, VK_BYTES)
        .expect("verify ok");
    assert!(accepted, "wasm-minted proof must verify");
}

/// Malformed inputs JSON throws a JS exception (not a panic).
/// Pins the boundary's error contract.
#[wasm_bindgen_test]
fn prove_rejects_malformed_inputs_json() {
    let bad = "this is not json";
    assert!(prove_pedersen_opens_to(bad, PK_BYTES).is_err());
}

/// Off-curve commitment in the inputs JSON throws. Same
/// boundary as the HTTP /prove endpoint's 400 case.
#[wasm_bindgen_test]
fn prove_rejects_off_curve_commitment() {
    let off_curve = r#"{
        "commitment_x": "1",
        "commitment_y": "1",
        "claimed_first_value": "0",
        "stream": ["0","0","0","0","0","0","0","0","0"],
        "blinding": "1"
    }"#;
    assert!(prove_pedersen_opens_to(off_curve, PK_BYTES).is_err());
}

/// Tiny helper: pull a string-valued field out of a small JSON
/// blob. Avoids dragging serde into the boundary test (the wasm
/// boundary already pulls serde_json, but explicitly avoiding
/// it in test helpers keeps the test surface minimal).
fn parse_field(json: &str, field: &str) -> String {
    let needle = format!("\"{field}\":\"");
    let start = json.find(&needle).expect("field present") + needle.len();
    let end = json[start..].find('"').expect("closing quote") + start;
    json[start..end].to_string()
}
