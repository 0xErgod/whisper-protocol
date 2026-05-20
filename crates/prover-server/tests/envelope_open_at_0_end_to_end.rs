//! End-to-end HTTP test for the `envelope_open_at_0` circuit.
//!
//! Walks the full protocol-level flow:
//!
//! 1. Alice seals a 9-element plaintext to Bob using
//!    `protocol::envelope::seal`.
//! 2. The prover-server boots, runs setup if needed, exposes
//!    /prove and /verify routes.
//! 3. Bob's side computes the `signal` from the envelope, builds
//!    the wire-form `Inputs`, POSTs to `/prove/envelope_open_at_0`.
//! 4. The returned proof verifies — both server-side (via
//!    `/verify`) and client-side (via the prover crate against
//!    a locally-fetched VK).
//! 5. Tampering with the public claim — claiming a different
//!    `plaintext[0]` — produces a proof that does NOT verify.
//!
//! Run with `cargo test -p prover-server --release
//! --test envelope_open_at_0_end_to_end`. Release because
//! Groth16 setup + prove combined is slow in debug.

use std::sync::Arc;

use ark_ff::PrimeField;

use circuits::envelope_open_at_0::{
    compute_signal_native, EnvelopeOpenAt0Inputs, EnvelopeOpenAt0PublicInputs,
    STREAM_LEN,
};
use crypto::babyjub::{keypair_from_seed, Fq, Seed};
use crypto::encoding::{id::encoding_id, Payload};
use protocol::envelope::{seal, Envelope};
use prover_server::keys::build as build_registry;
use prover_server::routes::{build_router, AppState, EnvelopeOpenAt0VerifyRequest, VerifyResponse};

/// Spin up the server on an ephemeral port; return its bound
/// address and the temp dir handle that holds the PK/VK
/// artifacts.
async fn spawn_server() -> (String, tempfile::TempDir) {
    let temp = tempfile::tempdir().expect("temp dir");
    let registry = Arc::new(build_registry(temp.path()).expect("registry"));
    let state = AppState { registry };
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    tokio::task::yield_now().await;
    (addr, temp)
}

/// Build the honest envelope + matching wire-form inputs for
/// the canonical Alice/Bob/envelope-42 fixture.
fn honest_fixture() -> (
    Envelope,
    ark_ed_on_bn254::Fr, // recipient_sk (Bob's)
    [Fq; STREAM_LEN],     // plaintext
    EnvelopeOpenAt0Inputs,
    EnvelopeOpenAt0PublicInputs,
) {
    let mut seed_a = [0u8; 64];
    seed_a[0] = 1;
    let mut seed_b = [0u8; 64];
    seed_b[0] = 2;
    let (sk_a, pk_a) = keypair_from_seed(&Seed::from_bytes(seed_a));
    let (sk_b, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));

    let plaintext: [Fq; STREAM_LEN] = [
        Fq::from(1u64),
        Fq::from(2u64),
        Fq::from(3u64),
        Fq::from(4u64),
        Fq::from(5u64),
        Fq::from(6u64),
        Fq::from(7u64),
        Fq::from(8u64),
        Fq::from(9u64),
    ];

    let eid = encoding_id("specs/encodings/text-utf8-v1.md");
    let payload = Payload::new(eid, plaintext.to_vec());
    let envelope = seal(&sk_a, &pk_a, &pk_b, Fq::from(42u64), &payload);

    let signal = compute_signal_native(
        &envelope.sender_pk,
        &envelope.recipient_pk,
        envelope.envelope_id,
        envelope.encoding_id,
        envelope.mac_tag,
        &envelope.ciphertext,
    );

    let ciphertext_strs: [String; STREAM_LEN] =
        std::array::from_fn(|i| envelope.ciphertext[i].into_bigint().to_string());

    let inputs = EnvelopeOpenAt0Inputs {
        signal: signal.into_bigint().to_string(),
        claimed_value: plaintext[0].into_bigint().to_string(),
        recipient_sk: sk_b.scalar().into_bigint().to_string(),
        sender_pk_x: envelope.sender_pk.x.into_bigint().to_string(),
        sender_pk_y: envelope.sender_pk.y.into_bigint().to_string(),
        recipient_pk_x: envelope.recipient_pk.x.into_bigint().to_string(),
        recipient_pk_y: envelope.recipient_pk.y.into_bigint().to_string(),
        envelope_id: envelope.envelope_id.into_bigint().to_string(),
        encoding_id: envelope.encoding_id.into_bigint().to_string(),
        ciphertext: ciphertext_strs,
        mac_tag: envelope.mac_tag.into_bigint().to_string(),
    };

    let public_inputs = EnvelopeOpenAt0PublicInputs {
        signal: inputs.signal.clone(),
        claimed_value: inputs.claimed_value.clone(),
    };

    (envelope, *sk_b.scalar(), plaintext, inputs, public_inputs)
}

/// Headline test: Alice seals to Bob; Bob proves "I'm the
/// recipient AND plaintext[0] == 1" without revealing his sk
/// or the rest of the plaintext. The proof verifies via the
/// server's /verify endpoint.
#[tokio::test]
async fn http_envelope_prove_then_verify_accepts_honest() {
    let (addr, _tempdir) = spawn_server().await;
    let base = format!("http://{addr}");

    let (_envelope, _sk_b, _pt, inputs, public_inputs) = honest_fixture();

    let client = reqwest::Client::new();
    let prove_resp = client
        .post(format!("{base}/prove/envelope_open_at_0"))
        .json(&inputs)
        .send()
        .await
        .expect("prove req");
    assert_eq!(prove_resp.status(), 200, "prove must 200");
    let proof_bytes = prove_resp.bytes().await.expect("proof body").to_vec();
    assert!(!proof_bytes.is_empty(), "proof bytes non-empty");

    let verify_body = EnvelopeOpenAt0VerifyRequest {
        public_inputs: public_inputs.clone(),
        proof_hex: hex::encode(&proof_bytes),
    };
    let verify_resp: VerifyResponse = client
        .post(format!("{base}/verify/envelope_open_at_0"))
        .json(&verify_body)
        .send()
        .await
        .expect("verify req")
        .json()
        .await
        .expect("verify json");
    assert!(
        verify_resp.accepted,
        "honest envelope-open proof must verify",
    );
}

/// Claiming the wrong plaintext[0] AFTER proving with the
/// honest witness MUST reject. Pins integrity at the HTTP
/// boundary.
#[tokio::test]
async fn http_envelope_verify_rejects_wrong_claimed_value() {
    let (addr, _tempdir) = spawn_server().await;
    let base = format!("http://{addr}");

    let (_envelope, _sk_b, _pt, inputs, _public_inputs) = honest_fixture();

    let client = reqwest::Client::new();
    let proof_bytes = client
        .post(format!("{base}/prove/envelope_open_at_0"))
        .json(&inputs)
        .send()
        .await
        .expect("prove")
        .bytes()
        .await
        .expect("body")
        .to_vec();

    let lying_public_inputs = EnvelopeOpenAt0PublicInputs {
        signal: inputs.signal.clone(),
        claimed_value: "99".to_string(),
    };
    let verify_body = EnvelopeOpenAt0VerifyRequest {
        public_inputs: lying_public_inputs,
        proof_hex: hex::encode(&proof_bytes),
    };
    let verify_resp: VerifyResponse = client
        .post(format!("{base}/verify/envelope_open_at_0"))
        .json(&verify_body)
        .send()
        .await
        .expect("verify")
        .json()
        .await
        .expect("json");
    assert!(
        !verify_resp.accepted,
        "wrong claimed_value must NOT verify",
    );
}

/// Cross-path consistency: VK fetched via /vk verifies the
/// proof locally (using the prover crate directly). The
/// path a JS-side or Move-side verifier will take.
#[tokio::test]
async fn http_envelope_proof_verifies_against_fetched_vk_locally() {
    let (addr, _tempdir) = spawn_server().await;
    let base = format!("http://{addr}");

    let (_envelope, _sk_b, _pt, inputs, public_inputs) = honest_fixture();
    let client = reqwest::Client::new();

    let vk_bytes = client
        .get(format!("{base}/vk/envelope_open_at_0"))
        .send()
        .await
        .expect("vk req")
        .bytes()
        .await
        .expect("vk body")
        .to_vec();
    let vk = prover::deserialize_vk(&vk_bytes).expect("vk deser");

    let proof_bytes = client
        .post(format!("{base}/prove/envelope_open_at_0"))
        .json(&inputs)
        .send()
        .await
        .expect("prove req")
        .bytes()
        .await
        .expect("proof body")
        .to_vec();
    let proof = prover::deserialize_proof(&proof_bytes).expect("proof deser");

    let public_vec =
        circuits::envelope_open_at_0::public_inputs_from(&public_inputs).expect("public");
    let accepted = prover::verify(&vk, &public_vec, &proof).expect("verify");
    assert!(
        accepted,
        "proof from /prove must verify locally against /vk's VK",
    );
}

/// Sealing the same plaintext to Bob under envelope id 43
/// (instead of 42) produces a DIFFERENT ciphertext and signal;
/// the proof for id-42 envelope must NOT verify against the
/// id-43 envelope's public inputs. Pins that envelope_id is
/// load-bearing in the signal binding.
#[tokio::test]
async fn http_envelope_proof_is_tied_to_specific_envelope() {
    let (addr, _tempdir) = spawn_server().await;
    let base = format!("http://{addr}");

    let (_envelope, _sk_b, _pt, inputs, _public_inputs) = honest_fixture();

    let client = reqwest::Client::new();
    let proof_bytes = client
        .post(format!("{base}/prove/envelope_open_at_0"))
        .json(&inputs)
        .send()
        .await
        .expect("prove req")
        .bytes()
        .await
        .expect("proof body")
        .to_vec();

    // Now build a DIFFERENT envelope (id 43, same plaintext)
    // and try to verify the id-42 proof against its public
    // inputs. The signal differs, so verify rejects.
    let mut seed_a = [0u8; 64];
    seed_a[0] = 1;
    let mut seed_b = [0u8; 64];
    seed_b[0] = 2;
    let (sk_a, pk_a) = keypair_from_seed(&Seed::from_bytes(seed_a));
    let (_sk_b, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));
    let plaintext: [Fq; STREAM_LEN] = std::array::from_fn(|i| Fq::from((i + 1) as u64));

    let eid = encoding_id("specs/encodings/text-utf8-v1.md");
    let payload43 = Payload::new(eid, plaintext.to_vec());
    let env43 = seal(&sk_a, &pk_a, &pk_b, Fq::from(43u64), &payload43);
    let signal43 = compute_signal_native(
        &env43.sender_pk,
        &env43.recipient_pk,
        env43.envelope_id,
        env43.encoding_id,
        env43.mac_tag,
        &env43.ciphertext,
    );

    let wrong_public_inputs = EnvelopeOpenAt0PublicInputs {
        signal: signal43.into_bigint().to_string(),
        claimed_value: "1".to_string(),
    };
    let verify_body = EnvelopeOpenAt0VerifyRequest {
        public_inputs: wrong_public_inputs,
        proof_hex: hex::encode(&proof_bytes),
    };
    let verify_resp: VerifyResponse = client
        .post(format!("{base}/verify/envelope_open_at_0"))
        .json(&verify_body)
        .send()
        .await
        .expect("verify")
        .json()
        .await
        .expect("json");
    assert!(
        !verify_resp.accepted,
        "envelope-42's proof must NOT verify against envelope-43's signal",
    );
}
