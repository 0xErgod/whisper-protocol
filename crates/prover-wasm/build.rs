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

use circuits::envelope_open_at_0::{
    compute_signal_native, EnvelopeOpenAt0, EnvelopeOpenAt0Inputs,
    STREAM_LEN as ENV_STREAM_LEN,
};
use circuits::pedersen_opens_to::{PedersenOpensTo, PedersenOpensToInputs, STREAM_LEN};
use crypto::encoding::id::encoding_id;
use crypto::babyjub::{
    commit as native_commit, encrypt as native_encrypt, kdf_derive as native_kdf,
    keypair_from_seed, mac_compute as native_mac, shared_secret, Fq, Seed,
};
use crypto::poseidon::domain_tag;
use prover::{prove, serialize_pk, serialize_proof, serialize_vk, setup};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Run the fixture generation on a thread with a larger
    // stack. Groth16 setup over arkworks 0.5 in debug mode
    // (which is how build scripts compile) is stack-hungry —
    // running multiple circuit setups in sequence overflows
    // the default ~8MB main-thread stack on Windows. A 64MB
    // worker thread sidesteps the issue without forcing a
    // release-profile build.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(run)
        .expect("spawn build worker")
        .join()
        .expect("build worker panic");
}

fn run() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let fixtures_dir = out_dir.join("test_fixtures");
    fs::create_dir_all(&fixtures_dir).expect("create fixtures dir");

    generate_pedersen_opens_to(&fixtures_dir);
    generate_envelope_open_at_0(&fixtures_dir);
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
    let eid = encoding_id("specs/encodings/text-utf8-v1.md");
    let augmented = PedersenOpensTo::augmented_stream(eid, &stream);
    let commitment = native_commit(&augmented, blinding);
    let circuit = PedersenOpensTo::new(commitment, eid, stream[0], stream, blinding);
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
        encoding_id: eid.into_bigint().to_string(),
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
        r#"{{"commitment_x":"{}","commitment_y":"{}","encoding_id":"{}","claimed_first_value":"{}"}}"#,
        commitment.x.into_bigint(),
        commitment.y.into_bigint(),
        eid.into_bigint(),
        stream[0].into_bigint(),
    );
    fs::write(dir.join("pedersen_opens_to.public.json"), public_json)
        .expect("write public json");
}

/// Generate (PK, VK, proof, inputs JSON, public JSON) for the
/// envelope_open_at_0 circuit. The Alice/Bob fixture matches
/// the spec's worked example.
fn generate_envelope_open_at_0(dir: &std::path::Path) {
    let mut rng = StdRng::seed_from_u64(0xBEEFCAFE);

    // Setup.
    let (pk, vk) = setup(EnvelopeOpenAt0::empty(), &mut rng).expect("setup");

    // Alice/Bob fixture: same seeds as the spec's worked
    // example, 9-element plaintext, envelope id 42.
    let mut seed_a = [0u8; 64];
    seed_a[0] = 1;
    let mut seed_b = [0u8; 64];
    seed_b[0] = 2;
    let (sk_a, pk_a) = keypair_from_seed(&Seed::from_bytes(seed_a));
    let (sk_b, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));

    let plaintext: [Fq; ENV_STREAM_LEN] = [
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

    // Native seal (replicated from protocol::envelope::seal to
    // avoid pulling the protocol crate into this build script's
    // dep graph — the math is identical and pinned in
    // specs/protocol-envelope.md).
    let envelope_id = Fq::from(42u64);
    let env_encoding_id = encoding_id("specs/encodings/text-utf8-v1.md");
    let shared = shared_secret(&sk_a, &pk_b);
    let key_enc = native_kdf(
        &shared,
        &[domain_tag("envelope-cipher-key"), envelope_id],
    )
    .expect("kdf");
    let key_mac = native_kdf(
        &shared,
        &[domain_tag("envelope-mac-key"), envelope_id],
    )
    .expect("kdf");
    let ciphertext_vec = native_encrypt(key_enc, &plaintext);
    let ciphertext: [Fq; ENV_STREAM_LEN] = ciphertext_vec
        .clone()
        .try_into()
        .expect("cipher length-preserving");
    // MAC over [encoding_id, ...ciphertext] (Option-A binding).
    let mut env_mac_input = Vec::with_capacity(1 + ciphertext_vec.len());
    env_mac_input.push(env_encoding_id);
    env_mac_input.extend_from_slice(&ciphertext_vec);
    let mac_tag = native_mac(key_mac, &env_mac_input);

    let signal = compute_signal_native(
        pk_a.point(),
        pk_b.point(),
        envelope_id,
        env_encoding_id,
        mac_tag,
        &ciphertext_vec,
    );

    let claimed_value = plaintext[0];

    // Build the proof.
    let circuit = EnvelopeOpenAt0::new(
        signal,
        claimed_value,
        *sk_b.scalar(),
        *pk_a.point(),
        *pk_b.point(),
        envelope_id,
        env_encoding_id,
        ciphertext,
        mac_tag,
    );
    let proof = prove(circuit, &pk, &mut rng).expect("prove");

    // Persist.
    let pk_bytes = serialize_pk(&pk).expect("pk ser");
    let vk_bytes = serialize_vk(&vk).expect("vk ser");
    let proof_bytes = serialize_proof(&proof).expect("proof ser");
    fs::write(dir.join("envelope_open_at_0.pk"), &pk_bytes).expect("write pk");
    fs::write(dir.join("envelope_open_at_0.vk"), &vk_bytes).expect("write vk");
    fs::write(dir.join("envelope_open_at_0.proof"), &proof_bytes).expect("write proof");

    // Inputs JSON.
    let inputs = EnvelopeOpenAt0Inputs {
        signal: signal.into_bigint().to_string(),
        claimed_value: claimed_value.into_bigint().to_string(),
        recipient_sk: sk_b.scalar().into_bigint().to_string(),
        sender_pk_x: pk_a.point().x.into_bigint().to_string(),
        sender_pk_y: pk_a.point().y.into_bigint().to_string(),
        recipient_pk_x: pk_b.point().x.into_bigint().to_string(),
        recipient_pk_y: pk_b.point().y.into_bigint().to_string(),
        envelope_id: envelope_id.into_bigint().to_string(),
        encoding_id: env_encoding_id.into_bigint().to_string(),
        ciphertext: std::array::from_fn(|i| ciphertext[i].into_bigint().to_string()),
        mac_tag: mac_tag.into_bigint().to_string(),
    };
    let inputs_json = serde_json::to_string(&inputs).expect("inputs ser");
    fs::write(dir.join("envelope_open_at_0.inputs.json"), inputs_json)
        .expect("write inputs json");

    // Public-input-only JSON.
    let public_json = format!(
        r#"{{"signal":"{}","claimed_value":"{}"}}"#,
        signal.into_bigint(),
        claimed_value.into_bigint(),
    );
    fs::write(dir.join("envelope_open_at_0.public.json"), public_json)
        .expect("write public json");
}
