//! End-to-end HTTP test: bind a real TCP listener, drive the
//! pedersen_opens_to flow over HTTP, prove, fetch the VK, verify
//! both server-side (via /verify) and client-side (using the
//! `prover` crate directly).
//!
//! Run with `cargo test -p prover-server --release`. Debug works
//! but setup takes ~30s vs ~3s in release.
//!
//! The test writes PK/VK to a temp directory so it doesn't
//! conflict with a developer's local `./keys/`. The directory is
//! cleaned up on drop.

use std::sync::Arc;

use ark_ed_on_bn254::Fr;
use ark_ff::PrimeField;

use circuits::pedersen_opens_to::{
    PedersenOpensToInputs, PedersenOpensToPublicInputs, STREAM_LEN,
};
use crypto::babyjub::{commit as native_commit, Fq};
use prover_server::keys::build as build_registry;
use prover_server::routes::{build_router, AppState, VerifyRequest, VerifyResponse};

/// Spin up the server on an ephemeral port. Returns the bound
/// address and a handle that drops the server when the test
/// ends.
async fn spawn_server() -> (String, tempfile::TempDir) {
    let temp = tempfile::tempdir().expect("temp dir");
    let registry = Arc::new(
        build_registry(temp.path()).expect("registry"),
    );
    let state = AppState { registry };
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    // Tiny yield to make sure the server is actually accepting
    // connections by the time the test issues its first request.
    tokio::task::yield_now().await;

    (addr, temp)
}

/// Build the honest wire-form inputs used across the test cases.
fn honest_inputs() -> (
    PedersenOpensToInputs,
    PedersenOpensToPublicInputs,
    crypto::babyjub::EdwardsAffine,
) {
    let stream: [Fq; STREAM_LEN] = [
        Fq::from(10u64),
        Fq::from(20u64),
        Fq::from(30u64),
        Fq::from(40u64),
        Fq::from(50u64),
        Fq::from(60u64),
        Fq::from(70u64),
        Fq::from(80u64),
        Fq::from(90u64),
    ];
    let blinding = Fr::from(12345u64);
    let commitment = native_commit(&stream, blinding);

    let inputs = PedersenOpensToInputs {
        commitment_x: commitment.x.into_bigint().to_string(),
        commitment_y: commitment.y.into_bigint().to_string(),
        claimed_first_value: stream[0].into_bigint().to_string(),
        stream: [
            stream[0].into_bigint().to_string(),
            stream[1].into_bigint().to_string(),
            stream[2].into_bigint().to_string(),
            stream[3].into_bigint().to_string(),
            stream[4].into_bigint().to_string(),
            stream[5].into_bigint().to_string(),
            stream[6].into_bigint().to_string(),
            stream[7].into_bigint().to_string(),
            stream[8].into_bigint().to_string(),
        ],
        blinding: blinding.into_bigint().to_string(),
    };

    let public_inputs = PedersenOpensToPublicInputs {
        commitment_x: inputs.commitment_x.clone(),
        commitment_y: inputs.commitment_y.clone(),
        claimed_first_value: inputs.claimed_first_value.clone(),
    };

    (inputs, public_inputs, commitment)
}

/// The headline integration test: prove via HTTP, fetch VK,
/// verify via HTTP. Establishes the full server-to-server flow
/// that a real dApp will take.
#[tokio::test]
async fn http_prove_then_verify_accepts_honest() {
    let (addr, _tempdir) = spawn_server().await;
    let base = format!("http://{addr}");

    let (inputs, public_inputs, _commitment) = honest_inputs();

    // POST /prove/pedersen_opens_to
    let client = reqwest::Client::new();
    let prove_resp = client
        .post(format!("{base}/prove/pedersen_opens_to"))
        .json(&inputs)
        .send()
        .await
        .expect("prove req");
    assert_eq!(prove_resp.status(), 200, "prove must 200");
    let proof_bytes = prove_resp.bytes().await.expect("proof body").to_vec();
    assert!(!proof_bytes.is_empty(), "proof bytes must be non-empty");

    // POST /verify/pedersen_opens_to — round-trip the proof via
    // the verify endpoint. Real consumers would call this from
    // a different service or skip it and verify locally with
    // the VK; here we exercise both paths.
    let verify_body = VerifyRequest {
        public_inputs: public_inputs.clone(),
        proof_hex: hex::encode(&proof_bytes),
    };
    let verify_resp: VerifyResponse = client
        .post(format!("{base}/verify/pedersen_opens_to"))
        .json(&verify_body)
        .send()
        .await
        .expect("verify req")
        .json()
        .await
        .expect("verify body json");
    assert!(verify_resp.accepted, "honest proof must verify server-side");
}

/// Tampering with the public-input vector AFTER the prover
/// signed off MUST reject. The integrity property over HTTP.
#[tokio::test]
async fn http_verify_rejects_tampered_public_inputs() {
    let (addr, _tempdir) = spawn_server().await;
    let base = format!("http://{addr}");

    let (inputs, _real_public_inputs, _commitment) = honest_inputs();
    let client = reqwest::Client::new();
    let proof_bytes = client
        .post(format!("{base}/prove/pedersen_opens_to"))
        .json(&inputs)
        .send()
        .await
        .expect("prove")
        .bytes()
        .await
        .expect("proof bytes")
        .to_vec();

    // Verifier checks against a DIFFERENT claimed_first_value
    // than the prover committed to.
    let lying_public_inputs = PedersenOpensToPublicInputs {
        commitment_x: inputs.commitment_x.clone(),
        commitment_y: inputs.commitment_y.clone(),
        claimed_first_value: "99".to_string(),
    };
    let verify_body = VerifyRequest {
        public_inputs: lying_public_inputs,
        proof_hex: hex::encode(&proof_bytes),
    };
    let verify_resp: VerifyResponse = client
        .post(format!("{base}/verify/pedersen_opens_to"))
        .json(&verify_body)
        .send()
        .await
        .expect("verify")
        .json()
        .await
        .expect("verify body");
    assert!(
        !verify_resp.accepted,
        "tampered public inputs must NOT verify",
    );
}

/// `GET /vk/pedersen_opens_to` returns VK bytes that the
/// `prover::deserialize_vk` round-trip accepts. This is the
/// path the Move-side deployment step will take to fetch the
/// VK for on-chain deployment.
#[tokio::test]
async fn http_get_vk_returns_deserializable_bytes() {
    let (addr, _tempdir) = spawn_server().await;
    let base = format!("http://{addr}");

    let vk_bytes = reqwest::get(format!("{base}/vk/pedersen_opens_to"))
        .await
        .expect("vk req")
        .bytes()
        .await
        .expect("vk body")
        .to_vec();
    assert!(!vk_bytes.is_empty(), "vk bytes must be non-empty");

    // Round-trip: the VK we serve must deserialize correctly via
    // the same `prover` crate the Move-side toolchain will use to
    // hand the VK to chain.
    let _ = prover::deserialize_vk(&vk_bytes).expect("vk deser");
}

/// Cross-path consistency: a proof minted via /prove verifies
/// against the VK fetched via /vk when checked locally (without
/// going through /verify). This is the path a JS-side or
/// Move-side verifier will take: pull VK once, verify many
/// proofs.
#[tokio::test]
async fn http_proof_verifies_against_fetched_vk_locally() {
    let (addr, _tempdir) = spawn_server().await;
    let base = format!("http://{addr}");

    let (inputs, public_inputs, _commitment) = honest_inputs();
    let client = reqwest::Client::new();

    // Fetch the VK first.
    let vk_bytes = client
        .get(format!("{base}/vk/pedersen_opens_to"))
        .send()
        .await
        .expect("vk req")
        .bytes()
        .await
        .expect("vk body")
        .to_vec();
    let vk = prover::deserialize_vk(&vk_bytes).expect("vk deser");

    // Prove.
    let proof_bytes = client
        .post(format!("{base}/prove/pedersen_opens_to"))
        .json(&inputs)
        .send()
        .await
        .expect("prove req")
        .bytes()
        .await
        .expect("proof body")
        .to_vec();
    let proof = prover::deserialize_proof(&proof_bytes).expect("proof deser");

    // Build the public-input vector via the circuit crate's
    // helper, then verify locally.
    let public_inputs_vec = circuits::pedersen_opens_to::public_inputs_from(
        &public_inputs,
    )
    .expect("public inputs");
    let accepted = prover::verify(&vk, &public_inputs_vec, &proof).expect("verify");
    assert!(
        accepted,
        "proof from /prove must verify locally against /vk's VK",
    );
}

/// An unknown circuit id returns 404. Sanity check on the
/// routing layer.
#[tokio::test]
async fn http_unknown_circuit_returns_404() {
    let (addr, _tempdir) = spawn_server().await;
    let base = format!("http://{addr}");

    let resp = reqwest::get(format!("{base}/vk/does_not_exist"))
        .await
        .expect("req");
    assert_eq!(resp.status(), 404);
}

/// A malformed inputs JSON returns 400, not 500. Pins the
/// "broken input is the caller's fault, not the server's"
/// boundary.
#[tokio::test]
async fn http_bad_inputs_returns_400() {
    let (addr, _tempdir) = spawn_server().await;
    let base = format!("http://{addr}");

    // Off-curve commitment (1, 1).
    let bad_inputs = PedersenOpensToInputs {
        commitment_x: "1".to_string(),
        commitment_y: "1".to_string(),
        claimed_first_value: "0".to_string(),
        stream: std::array::from_fn(|_| "0".to_string()),
        blinding: "1".to_string(),
    };

    let resp = reqwest::Client::new()
        .post(format!("{base}/prove/pedersen_opens_to"))
        .json(&bad_inputs)
        .send()
        .await
        .expect("req");
    assert_eq!(resp.status(), 400);
}
