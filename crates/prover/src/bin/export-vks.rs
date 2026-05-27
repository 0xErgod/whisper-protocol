//! Emit verifying-key byte arrays for the protocol's circuits in a
//! form `contracts/sources/proofs.move` can paste directly as
//! `const` declarations.
//!
//! ## Why this binary exists
//!
//! The Move-side Groth16 verifier (`sui::groth16::verify_groth16_proof`)
//! needs each circuit's VK as a byte array at the point of
//! verification. We bake those bytes into `proofs.move` as `const`
//! declarations so the on-chain verifier has nothing to fetch and
//! every published deployment binds to a known VK.
//!
//! The VK bytes are produced by Groth16 trusted setup, which is
//! deterministic given a fixed RNG seed (see
//! `specs/zk/stack.md § Setup randomness`). This binary re-runs
//! setup under the exact same seeds the prover-server uses, then
//! serializes each VK in the arkworks-canonical compressed
//! encoding Sui's `prepare_verifying_key` expects (per its
//! docstring: "An Arkworks canonical compressed serialization of
//! a verifying key").
//!
//! ## Output
//!
//! Stdout is a Move source snippet:
//!
//! ```move
//! const VK_PEDERSEN_OPENS_TO: vector<u8> = vector[ /* bytes */ ];
//! const VK_ENVELOPE_OPEN_AT_0: vector<u8> = vector[ /* bytes */ ];
//! ```
//!
//! `scripts/deploy-devnet.ps1` uses the same emitter to diff
//! against the bytes already pasted into `proofs.move`. Any drift
//! between the rebuilt VK and the committed source fails the
//! deploy fast.
//!
//! ## Why compressed
//!
//! The Sui `groth16::prepare_verifying_key` native function
//! handles decompression itself; it accepts the compact arkworks
//! compressed encoding directly. Compressed bytes are also what
//! `prover::serialize_vk` produces for off-chain consumers, so
//! one encoding spans both call sites.

use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;

use circuits::envelope_open_at_0::EnvelopeOpenAt0;
use circuits::pedersen_opens_to::PedersenOpensTo;
use prover::{serialize_vk, setup};

/// One circuit's metadata: the Move constant name, the seed used
/// in trusted setup, and a thunk that runs setup. Kept as a
/// tagged list rather than a trait so adding a circuit means
/// adding one row.
struct CircuitEntry {
    move_const: &'static str,
    seed: u64,
    setup_and_serialize: fn(u64) -> Vec<u8>,
}

fn setup_pedersen_opens_to(seed: u64) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let (_pk, vk) = setup(PedersenOpensTo::empty(), &mut rng).expect("pedersen setup");
    serialize_vk(&vk).expect("pedersen vk ser")
}

fn setup_envelope_open_at_0(seed: u64) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let (_pk, vk) = setup(EnvelopeOpenAt0::empty(), &mut rng).expect("envelope setup");
    serialize_vk(&vk).expect("envelope vk ser")
}

/// The list MUST match `crates/prover-server/src/keys.rs` —
/// same circuit id, same seed. Drift here means the bytes
/// `proofs.move` embeds will not match the bytes the
/// `prover-server` serves, and end-to-end verification breaks.
const CIRCUITS: &[CircuitEntry] = &[
    CircuitEntry {
        move_const: "VK_PEDERSEN_OPENS_TO",
        seed: 0xDEADBEEF,
        setup_and_serialize: setup_pedersen_opens_to,
    },
    CircuitEntry {
        move_const: "VK_ENVELOPE_OPEN_AT_0",
        seed: 0xBEEFCAFE,
        setup_and_serialize: setup_envelope_open_at_0,
    },
];

/// Render one VK as `const NAME: vector<u8> = vector[0x01, 0x02, …];`,
/// wrapped at ~16 bytes per line so the diff is readable.
fn render_move_const(name: &str, bytes: &[u8]) -> String {
    let mut out = String::new();
    out.push_str(&format!("const {name}: vector<u8> = vector[\n"));
    for (i, b) in bytes.iter().enumerate() {
        if i % 16 == 0 {
            out.push_str("    ");
        }
        out.push_str(&format!("0x{b:02x}"));
        if i + 1 < bytes.len() {
            out.push(',');
            if (i + 1) % 16 == 0 {
                out.push('\n');
            } else {
                out.push(' ');
            }
        }
    }
    out.push_str("\n];\n");
    out
}

fn main() {
    for entry in CIRCUITS {
        let bytes = (entry.setup_and_serialize)(entry.seed);
        print!("{}", render_move_const(entry.move_const, &bytes));
        println!();
    }
}
