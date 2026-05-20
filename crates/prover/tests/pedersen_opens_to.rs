//! End-to-end Groth16 prove + verify integration test for the
//! `pedersen_opens_to` circuit.
//!
//! This is the protocol's first real ZK proof: trusted setup
//! against the empty circuit, prove against an honest witness,
//! verify against the public inputs, expect acceptance. Plus the
//! mandatory negative direction — verification under a wrong
//! claimed value MUST be rejected.
//!
//! Run with `cargo test -p prover --release`. Debug builds work
//! but the setup + prove combined takes around 10–15 seconds in
//! debug vs. sub-second in release; that's expected for Groth16
//! over arkworks. The test is checked into release-tolerant
//! shape.

use ark_ed_on_bn254::Fr;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;

use circuits::pedersen_opens_to::{PedersenOpensTo, STREAM_LEN};
use crypto::babyjub::{commit as native_commit, Fq};
use crypto::encoding::id::encoding_id;
use prover::{prove, setup, verify};

/// Build a deterministic RNG. Setup and prove get the same
/// stream so the test is reproducible; in production each call
/// gets fresh randomness from the OS RNG.
fn det_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// Build an honest fixture: a stream, a blinding, the native
/// commitment, and the claimed first value. Reused across the
/// positive and negative cases below so the witness is identical
/// except for what the test deliberately changes.
fn honest_fixture() -> (
    [Fq; STREAM_LEN],
    Fr,
    crypto::babyjub::EdwardsAffine,
    Fq,
    Fq,
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
    let encoding_id_val = encoding_id("specs/encodings/text-utf8-v1.md");
    // The commitment is over the augmented [encoding_id, ...stream],
    // matching protocol::commitment and the circuit.
    let augmented = PedersenOpensTo::augmented_stream(encoding_id_val, &stream);
    let commitment = native_commit(&augmented, blinding);
    let claimed_first_value = stream[0];
    (stream, blinding, commitment, claimed_first_value, encoding_id_val)
}

/// The spec's pinned commitment coordinates must match the
/// native commitment computation. Pins the worked-example
/// fixture in `specs/zk/circuit-pedersen-opens-to.md §
/// Worked Example` against the actual Pedersen output.
///
/// If this test fails, either the spec's quoted decimals are
/// wrong OR the native Pedersen generators drifted. Either way,
/// the spec needs updating before any conformant verifier can
/// deploy.
#[test]
fn worked_example_commitment_matches_spec() {
    use ark_ff::PrimeField;
    let (_, _, commitment, _, _) = honest_fixture();
    assert_eq!(
        commitment.x.into_bigint().to_string(),
        "14178428728361130724833880240122318573449800233918657877722353700842024882875",
        "commitment.x drifted from the spec's worked example",
    );
    assert_eq!(
        commitment.y.into_bigint().to_string(),
        "19246693951740292838985087626008218915644570097536058114244575946261704440826",
        "commitment.y drifted from the spec's worked example",
    );
}

/// End-to-end honest path: setup, prove, verify, accept.
///
/// Establishes that every layer of the ZK stack is wired
/// correctly:
///
/// - Trusted setup produces a (PK, VK) for the circuit.
/// - Proving with an honest witness succeeds.
/// - Verifying with the matching public inputs accepts.
#[test]
fn pedersen_opens_to_proof_accepts_honest_witness() {
    let mut rng = det_rng(1);

    // Setup once against the empty circuit.
    let (pk, vk) = setup(PedersenOpensTo::empty(), &mut rng).expect("setup ok");

    // Build the honest witness and the matching public inputs.
    let (stream, blinding, commitment, claimed_first_value, encoding_id_val) = honest_fixture();
    let circuit = PedersenOpensTo::new(commitment, encoding_id_val, claimed_first_value, stream, blinding);
    let public_inputs = [commitment.x, commitment.y, encoding_id_val, claimed_first_value];

    // Prove.
    let proof = prove(circuit, &pk, &mut rng).expect("prove ok");

    // Verify.
    let accepted = verify(&vk, &public_inputs, &proof).expect("verify ok");
    assert!(accepted, "honest proof must verify");
}

/// Verification with wrong public inputs (a claimed value that
/// doesn't match the witness's `stream[0]`) MUST reject.
///
/// This is the integrity property at the highest level: a prover
/// who has the witness for one (commitment, value) claim cannot
/// reuse the resulting proof to assert a different value.
#[test]
fn pedersen_opens_to_proof_rejects_wrong_claimed_value() {
    let mut rng = det_rng(2);

    let (pk, vk) = setup(PedersenOpensTo::empty(), &mut rng).expect("setup ok");

    let (stream, blinding, commitment, claimed_first_value, encoding_id_val) = honest_fixture();
    let circuit = PedersenOpensTo::new(commitment, encoding_id_val, claimed_first_value, stream, blinding);
    let proof = prove(circuit, &pk, &mut rng).expect("prove ok");

    // Verifier checks against a DIFFERENT claimed value than the
    // one the prover committed to. Real first value is 10; we
    // claim 99.
    let lying_public_inputs = [commitment.x, commitment.y, encoding_id_val, Fq::from(99u64)];
    let accepted = verify(&vk, &lying_public_inputs, &proof).expect("verify ok");
    assert!(!accepted, "proof must NOT verify against wrong claimed value");
}

/// A proof generated for one circuit MUST NOT verify against a
/// VK from a different setup run. Sanity-check that the VK is
/// load-bearing — without it, anyone could swap in an arbitrary
/// VK to forge acceptance.
#[test]
fn pedersen_opens_to_proof_rejects_wrong_vk() {
    let mut rng_a = det_rng(3);
    let mut rng_b = det_rng(4);

    // Two independent setups produce two independent (PK, VK)
    // pairs.
    let (pk_a, _vk_a) = setup(PedersenOpensTo::empty(), &mut rng_a).expect("setup a");
    let (_pk_b, vk_b) = setup(PedersenOpensTo::empty(), &mut rng_b).expect("setup b");

    let (stream, blinding, commitment, claimed_first_value, encoding_id_val) = honest_fixture();
    let circuit = PedersenOpensTo::new(commitment, encoding_id_val, claimed_first_value, stream, blinding);
    let public_inputs = [commitment.x, commitment.y, encoding_id_val, claimed_first_value];

    // Prove under setup A's PK.
    let proof = prove(circuit, &pk_a, &mut rng_a).expect("prove ok");

    // Try to verify under setup B's VK.
    let accepted = verify(&vk_b, &public_inputs, &proof).expect("verify ok");
    assert!(!accepted, "proof must NOT verify against a different VK");
}

/// PK / VK / proof byte-blob round-trips. Pins the persistence
/// format the future `prover-server` will use to write artifacts
/// to disk and serve proofs to clients.
#[test]
fn artifact_serialization_roundtrips() {
    use prover::{
        deserialize_pk, deserialize_proof, deserialize_vk, serialize_pk,
        serialize_proof, serialize_vk,
    };

    let mut rng = det_rng(5);

    let (pk, vk) = setup(PedersenOpensTo::empty(), &mut rng).expect("setup ok");

    let pk_bytes = serialize_pk(&pk).expect("pk ser");
    let pk_back = deserialize_pk(&pk_bytes).expect("pk deser");

    let vk_bytes = serialize_vk(&vk).expect("vk ser");
    let vk_back = deserialize_vk(&vk_bytes).expect("vk deser");

    // Use the round-tripped PK / VK end-to-end: prove with
    // pk_back, verify with vk_back. If either lost information
    // in serialization, this fails.
    let (stream, blinding, commitment, claimed_first_value, encoding_id_val) = honest_fixture();
    let circuit = PedersenOpensTo::new(commitment, encoding_id_val, claimed_first_value, stream, blinding);
    let public_inputs = [commitment.x, commitment.y, encoding_id_val, claimed_first_value];
    let proof = prove(circuit, &pk_back, &mut rng).expect("prove ok");

    let proof_bytes = serialize_proof(&proof).expect("proof ser");
    let proof_back = deserialize_proof(&proof_bytes).expect("proof deser");

    let accepted = verify(&vk_back, &public_inputs, &proof_back).expect("verify ok");
    assert!(accepted, "round-tripped artifacts must produce a valid proof");
}
