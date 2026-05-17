//! Constraint-shape probe for `envelope_open_at_0`. Run with:
//!   cargo run -p circuits --example envelope_open_at_0_stats --release
//!
//! Same shape as `pedersen_opens_to_stats`: reports the
//! circuit's R1CS dimensions for the spec doc's "Constraint
//! shape" section. Numbers should be stable across
//! `ark-r1cs-std 0.5.x` patch releases.

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

use circuits::envelope_open_at_0::EnvelopeOpenAt0;
use crypto::babyjub::Fq;

fn main() {
    let circuit = EnvelopeOpenAt0::empty();
    let cs = ConstraintSystem::<Fq>::new_ref();
    circuit.generate_constraints(cs.clone()).expect("synth ok");
    cs.finalize();

    println!("== envelope_open_at_0 circuit shape ==");
    println!("STREAM_LEN              = 9");
    println!("POSITION                = 0");
    println!("num_constraints         = {}", cs.num_constraints());
    println!("num_instance_variables  = {}", cs.num_instance_variables());
    println!("num_witness_variables   = {}", cs.num_witness_variables());
    println!("is_satisfied            = {:?}", cs.is_satisfied());
}
