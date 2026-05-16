//! One-shot constraint-count probe. Run with:
//!   cargo run -p circuits --example pedersen_opens_to_stats --release
//!
//! Reports the structural shape of the circuit (constraint
//! count, public-input count, witness count) for the spec doc's
//! "Constraint shape" section. These numbers should be stable
//! across arkworks 0.5.x patch releases; if they change, the
//! spec needs updating.
//!
//! Delete this file once the numbers land in the spec? No —
//! keep it. It's the canonical way to reproduce the numbers
//! when the gadget substrate changes (e.g. a Poseidon round
//! count tweak), so a contributor can re-run it and update the
//! spec without re-deriving by hand.

use ark_ed_on_bn254::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

use circuits::pedersen_opens_to::{PedersenOpensTo, STREAM_LEN};
use crypto::babyjub::{commit, Fq};

fn main() {
    // Build an honest circuit instance, populate it, run
    // constraint synthesis. The numbers don't depend on which
    // values we pick (constraint shape is value-independent in
    // R1CS); we just need *something* concrete.
    let stream: [Fq; STREAM_LEN] = [Fq::from(1u64); STREAM_LEN];
    let blinding = Fr::from(2u64);
    let commitment = commit(&stream, blinding);
    let circuit = PedersenOpensTo::new(commitment, stream[0], stream, blinding);

    let cs = ConstraintSystem::<Fq>::new_ref();
    circuit.generate_constraints(cs.clone()).expect("synth ok");
    cs.finalize();

    println!("== pedersen_opens_to circuit shape ==");
    println!("STREAM_LEN              = {STREAM_LEN}");
    println!("num_constraints         = {}", cs.num_constraints());
    println!("num_instance_variables  = {}", cs.num_instance_variables());
    println!("num_witness_variables   = {}", cs.num_witness_variables());
    println!("is_satisfied            = {:?}", cs.is_satisfied());

    // Worked-example fixture: a pinned (stream, blinding,
    // commitment) tuple the spec quotes verbatim. Re-running
    // this example must reproduce these decimals exactly.
    use ark_ff::PrimeField;
    let fixture_stream: [Fq; STREAM_LEN] = [
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
    let fixture_blinding = Fr::from(12345u64);
    let fixture_commitment = commit(&fixture_stream, fixture_blinding);
    println!();
    println!("== worked-example fixture ==");
    println!("stream      = [10, 20, 30, 40, 50, 60, 70, 80, 90]");
    println!("blinding    = 12345");
    println!(
        "commitment.x = {}",
        fixture_commitment.x.into_bigint(),
    );
    println!(
        "commitment.y = {}",
        fixture_commitment.y.into_bigint(),
    );
    println!("claimed_first_value = 10");
    println!(
        "public_inputs = [{}, {}, {}]",
        fixture_commitment.x.into_bigint(),
        fixture_commitment.y.into_bigint(),
        10,
    );
}
