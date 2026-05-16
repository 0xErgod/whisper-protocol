//! Build script: generate (PK, VK) for every circuit and a
//! matching honest fixture, write the byte blobs alongside the
//! crate. The wasm boundary tests `include_bytes!` these so
//! `wasm-pack test` doesn't need to run Groth16 setup inside the
//! browser (which would be minutes-slow).
//!
//! Runs once when Cargo decides the build script needs to fire.
//! The generated files live under `OUT_DIR/test_fixtures/`; the
//! boundary tests read them via `concat!(env!("OUT_DIR"), ...)`.
//!
//! ## Rerun policy
//!
//! Cargo's default is "rerun on any source change," which would
//! re-do setup on every `cargo build`. We narrow it via
//! `cargo:rerun-if-changed` to just the build script itself —
//! the fixtures are deterministic in the seed, so they only
//! need regenerating if the build script changes (or if
//! Cargo decides to rerun, e.g. after `cargo clean`).

use std::fs;
use std::path::PathBuf;

use ark_ed_on_bn254::Fr;
use ark_ff::PrimeField;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;

use circuits::pedersen_opens_to::{PedersenOpensTo, PedersenOpensToInputs, STREAM_LEN};
use crypto::babyjub::{commit as native_commit, Fq};
use prover::{prove, serialize_pk, serialize_proof, serialize_vk, setup};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let fixtures_dir = out_dir.join("test_fixtures");
    fs::create_dir_all(&fixtures_dir).expect("create fixtures dir");

    generate_pedersen_opens_to(&fixtures_dir);
}

fn generate_pedersen_opens_to(dir: &std::path::Path) {
    let mut rng = StdRng::seed_from_u64(0xCAFE_BABE_DEAD_BEEFu64);

    // Setup: produce a (PK, VK) for the empty circuit. The same
    // fixed seed every build cycle so the fixtures are
    // deterministic — that's important for `include_bytes!`
    // because changes to the bytes would surface as
    // build-script rebuilds even when no logic changed.
    let (pk, vk) = setup(PedersenOpensTo::empty(), &mut rng).expect("setup");

    // Honest fixture: a stream, a blinding, the native
    // commitment, plus a proof for the wasm test to verify
    // against. The proof is also pre-computed natively so the
    // wasm test only exercises the VERIFY path; PROVE is
    // exercised separately, with a fresh witness, inside the
    // wasm test itself (smaller circuit cost than verifying a
    // dishonest one).
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
    let circuit = PedersenOpensTo::new(commitment, stream[0], stream, blinding);
    let proof = prove(circuit, &pk, &mut rng).expect("prove");

    // Persist PK, VK, proof. The wasm test reads them via
    // include_bytes!.
    let pk_bytes = serialize_pk(&pk).expect("pk ser");
    let vk_bytes = serialize_vk(&vk).expect("vk ser");
    let proof_bytes = serialize_proof(&proof).expect("proof ser");
    fs::write(dir.join("pedersen_opens_to.pk"), &pk_bytes).expect("write pk");
    fs::write(dir.join("pedersen_opens_to.vk"), &vk_bytes).expect("write vk");
    fs::write(dir.join("pedersen_opens_to.proof"), &proof_bytes).expect("write proof");

    // Also write a JSON fixture with the public inputs and the
    // honest witness, so the wasm test can construct exactly
    // the same `Inputs` payload without round-tripping through
    // arkworks decimal formatting twice.
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
    let inputs_json = serde_json::to_string(&inputs).expect("inputs ser");
    fs::write(dir.join("pedersen_opens_to.inputs.json"), inputs_json)
        .expect("write inputs json");

    // Public-input-only JSON for the verify side.
    let public_json = format!(
        r#"{{"commitment_x":"{}","commitment_y":"{}","claimed_first_value":"{}"}}"#,
        commitment.x.into_bigint(),
        commitment.y.into_bigint(),
        stream[0].into_bigint(),
    );
    fs::write(dir.join("pedersen_opens_to.public.json"), public_json)
        .expect("write public json");
}
