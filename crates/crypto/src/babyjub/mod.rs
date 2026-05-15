//! Baby Jubjub: the twisted Edwards curve over the BN254 scalar field, in the
//! ERC-2494 / circomlib dialect.
//!
//! This module is the algebraic substrate for the protocol's keypairs,
//! commitments, key agreement, and signatures. It deliberately exposes only the
//! curve *as a group* — keypairs, ECDH, commitments, and signatures are built
//! in sibling modules on top of what is re-exported here.

mod config;
mod curve;

pub use config::{BabyJubConfig, EdwardsAffine, EdwardsProjective, Fq, Fr};
pub use curve::{generator, is_in_prime_subgroup, is_on_curve, mul, IDENTITY};
