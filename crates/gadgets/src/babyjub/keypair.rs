//! In-circuit Baby Jubjub keypair derivation.
//!
//! Mirrors the public-key-from-secret-key half of
//! `crypto::babyjub::keypair::keypair_from_seed`: given `sk ∈ Fr`,
//! compute `pk = sk · Base8` on the curve.
//!
//! ## Scope: pk-from-sk only
//!
//! The native `keypair_from_seed` runs two steps:
//!
//! 1. **Seed → sk.** 64-byte seed split into two `Fq` chunks,
//!    hashed via `Poseidon-3(keypair_domain, chunks)`, then
//!    reduced into the scalar field `Fr`.
//! 2. **sk → pk.** `Base8 · sk`.
//!
//! This gadget only covers step 2. The seed half is deliberately
//! omitted because there is **no current use case** for proving
//! "I derived sk from this seed" in a circuit:
//!
//! - The seed is wallet-secret. Wallets do not expose seeds to
//!   circuit witnesses; they expose the derived `sk` (or a
//!   signature that's used as a deterministic key seed) instead.
//! - Even hypothetically, a circuit that wanted to bind sk to a
//!   seed would prove `sk == Poseidon-3(keypair_domain,
//!   chunks)`, which is a `poseidon_hash_fixed_var` call plus
//!   `Fq → Fr` reduction. It's a 50-line brick on top of existing
//!   gadgets when the use case arrives, not a now-decision.
//!
//! Documenting this as a deliberate non-goal so a future
//! contributor doesn't add the seed half on speculation.
//!
//! ## What pk-from-sk enables
//!
//! The canonical claim: **"I know the secret key behind this
//! public key."** Public input `PK`, witness `sk`, constraint
//! `pk_from_sk_var(sk) == PK`. Foundational for any circuit that
//! authenticates the prover as the holder of a specific keypair —
//! Schnorr verify uses the same scalar-mul-on-generator
//! internally, but a circuit may want the explicit "I am this
//! pubkey" claim as a separate, cheaper-to-compose constraint.

use ark_ed_on_bn254::Fr;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crypto::babyjub::Fq;

use super::{generator_constant, scalar_mul_var, BabyJubAffineVar};

/// In-circuit `pk = sk · Base8`.
///
/// `sk` is the scalar witness; the generator is a circuit constant
/// (no witness slot). Returns the public key as a
/// `BabyJubAffineVar`, constrained equal to the native
/// `mul(&sk, &generator())` when `sk` matches.
pub fn pk_from_sk_var(
    cs: ConstraintSystemRef<Fq>,
    sk: Fr,
) -> Result<BabyJubAffineVar, SynthesisError> {
    let g = generator_constant();
    scalar_mul_var(cs, sk, &g)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::alloc_point_witness;
    use ark_r1cs_std::eq::EqGadget;
    use ark_relations::r1cs::ConstraintSystem;
    use crypto::babyjub::{keypair_from_seed, Seed};

    /// Native↔circuit equivalence on a pinned seed. The gadget
    /// must compute the same `pk` the native side derives.
    #[test]
    fn pk_from_sk_var_matches_native() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let mut seed = [0u8; 64];
        seed[0] = 7;
        let (sk, pk) = keypair_from_seed(&Seed::from_bytes(seed));

        let pk_var = pk_from_sk_var(cs.clone(), *sk.scalar()).unwrap();

        let expected_var = alloc_point_witness(cs.clone(), *pk.point()).unwrap();
        pk_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// A wrong `sk` (one off the seed-derived value) MUST land on
    /// a different `pk`, unsatisfying `enforce_equal`. Negative-
    /// direction confirmation that the equivalence isn't passing
    /// by accident.
    #[test]
    fn pk_from_sk_var_rejects_wrong_sk() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let mut seed = [0u8; 64];
        seed[0] = 7;
        let (_sk_real, pk_real) = keypair_from_seed(&Seed::from_bytes(seed));

        // Deliberately wrong sk.
        let wrong_sk = Fr::from(12345u64);
        let pk_var = pk_from_sk_var(cs.clone(), wrong_sk).unwrap();

        let real_pk_var = alloc_point_witness(cs.clone(), *pk_real.point()).unwrap();
        pk_var.enforce_equal(&real_pk_var).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
