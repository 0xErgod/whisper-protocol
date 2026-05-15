//! Pedersen commitments over Baby Jubjub.
//!
//! `commit(value, blinding) = value · G + blinding · H`
//!
//! where `G` is the protocol's standard generator `Base8` and `H` is a
//! second prime-order-subgroup point whose discrete log relative to `G`
//! is unknown — derived from a fixed, public string via a documented
//! nothing-up-my-sleeve procedure (see `specs/babyjub-pedersen.md`).
//!
//! ## Properties this brick gives you
//!
//! - **Binding** — the committer cannot open `C` to a different value
//!   without knowing `log_G(H)`, which is computationally infeasible
//!   for an honestly-derived `H`.
//! - **Hiding** — for `blinding` sampled uniformly from `F_l`, `C`
//!   reveals nothing about `value`.
//! - **Additive homomorphism** —
//!   `commit(a, r_a) + commit(b, r_b) == commit(a+b, r_a+r_b)`. Pinned
//!   as a runtime test; the protocol's commitment layer relies on it.
//!
//! ## Scope intentionally NOT in this brick
//!
//! - **Multi-message vector Pedersen** (`Σ h_i · G_i + r · H`). A
//!   straightforward extension via additional published generators in
//!   the same spec; no consumer needs it yet.
//! - **Pedersen-hash** (commit-to-bit-vector without blinding). A
//!   different primitive entirely; circomlib has one.
//! - **`verify(C, value, blinding)`** — verification is literally
//!   `commit(value, blinding) == C`. Adding a function just to wrap
//!   `==` would obscure the relationship.
//! - **Zero-knowledge proofs of opening** — future bricks.
//!
//! Randomness for the blinding scalar is the caller's responsibility,
//! consistent with the keypair-from-seed pattern. A `commit_random`
//! convenience can land later if useful.

use ark_ec::CurveGroup;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_std::Zero;
use blake2::{digest::consts::U32, Blake2b, Digest};
use std::sync::OnceLock;

use super::config::{BabyJubConfig, EdwardsAffine, EdwardsProjective, Fq, Fr};
use super::curve::{generator, mul};
use ark_ec::twisted_edwards::TECurveConfig;

/// Domain string for the `H` derivation. Pinned in
/// `specs/babyjub-pedersen.md`; changing it changes `H`, which changes
/// every commitment.
pub const H_DOMAIN: &str = "babyjub-pedersen-h-v1";

/// Cached `H` — computed once via `derive_h()`, reused thereafter.
/// `OnceLock` keeps the cost off the hot path while ensuring a single
/// derivation runs even under concurrent first calls.
static H: OnceLock<EdwardsAffine> = OnceLock::new();

/// The second generator `H`, derived from `H_DOMAIN`. Computed once,
/// then cached. Lives in the prime-order subgroup; its discrete log
/// with respect to `Base8` is unknown by construction.
pub fn h_generator() -> EdwardsAffine {
    *H.get_or_init(derive_h)
}

/// Derive `H` from `H_DOMAIN` via the procedure pinned in the spec.
/// Public for the fixture/spec tooling; production callers should use
/// `h_generator()` to avoid recomputing.
pub fn derive_h() -> EdwardsAffine {
    let seed = Blake2b::<U32>::digest(H_DOMAIN.as_bytes());

    for counter in 0u32..1_000 {
        // 32-byte seed || 4-byte big-endian counter -> Blake2b -> 32 bytes.
        // Successive candidates are visibly "version 1, attempt N" in any
        // audit trace.
        let mut buf = Vec::with_capacity(36);
        buf.extend_from_slice(&seed);
        buf.extend_from_slice(&counter.to_be_bytes());
        let digest = Blake2b::<U32>::digest(&buf);

        // y = digest interpreted as big-endian unsigned, reduced mod p.
        // 256 bits -> 254-bit field; the resulting bias is ~2^-250, fine
        // for a fixed nothing-up-my-sleeve point.
        let y = Fq::from_be_bytes_mod_order(&digest);

        // Top bit of the digest deterministically picks which of the two
        // roots of x^2 to use. arkworks' `sqrt()` returns one of the two
        // without specifying which, so we normalize.
        let want_odd_x = (digest[0] >> 7) == 1;

        if let Some(p) = point_from_y(y, want_odd_x) {
            // Cofactor-clear into the prime-order subgroup. Any on-curve
            // point times the cofactor 8 lands in the subgroup; cheaper
            // than randomly sampling until we hit a prime-order point.
            let p_proj = EdwardsProjective::from(p);
            let cleared = (p_proj + p_proj + p_proj + p_proj + p_proj + p_proj + p_proj + p_proj)
                .into_affine();

            // Skip if cofactor-clearing degenerated to the identity.
            // Final defense-in-depth check: confirm subgroup membership.
            // Mathematically redundant after cofactor-clearing, but pins
            // the invariant so a subgroup-order constant bug fails loudly.
            if !cleared.is_zero()
                && cleared.is_in_correct_subgroup_assuming_on_curve()
            {
                return cleared;
            }
        }
    }

    // Searching for a candidate `y` is overwhelmingly likely to succeed in
    // the first 1–2 iterations: roughly half of all `Fq` elements are
    // valid `y`-coordinates, and the cofactor-clear succeeds for any
    // non-identity on-curve point. 1000 iterations is "the sky has
    // fallen" territory — making it a panic keeps the success path clean.
    panic!(
        "babyjub-pedersen-h-v1: failed to derive H in 1000 iterations; \
         this indicates a parameter-set inconsistency, not a real outcome",
    );
}

/// Given a candidate `y` and a sign bit, return the on-curve point
/// `(x, y)` whose `x` matches the sign bit, or `None` if no `x` exists.
///
/// Twisted Edwards curve equation: `a·x² + y² = 1 + d·x²·y²`. Solving
/// for `x²`:
///   `x² · (a - d·y²) = 1 - y²`
///   `x² = (1 - y²) / (a - d·y²)`
fn point_from_y(y: Fq, want_odd_x: bool) -> Option<EdwardsAffine> {
    let a = <BabyJubConfig as TECurveConfig>::COEFF_A;
    let d = <BabyJubConfig as TECurveConfig>::COEFF_D;

    let y2 = y * y;
    let numerator = Fq::ONE - y2;
    let denominator = a - d * y2;

    // `denominator == 0` would mean `y² == a/d`, an edge case where no
    // (finite) x exists. Treat as "no solution, try the next y".
    if denominator.is_zero() {
        return None;
    }

    let x_squared = numerator * denominator.inverse().unwrap();
    let x = x_squared.sqrt()?;

    // Normalize: pick the negation whose low bit matches `want_odd_x`.
    // `into_bigint().is_odd()` is the canonical "lowest bit set" test.
    let chosen_x = if x.into_bigint().is_odd() == want_odd_x {
        x
    } else {
        -x
    };

    let candidate = EdwardsAffine::new_unchecked(chosen_x, y);
    if candidate.is_on_curve() {
        Some(candidate)
    } else {
        None
    }
}

/// Compute a Pedersen commitment: `C = value · G + blinding · H`.
///
/// Both inputs are scalars in `F_l`; the result is an affine point in
/// the prime-order subgroup. `value` and `blinding` are taken by value
/// because `Fr` is `Copy`.
pub fn commit(value: Fr, blinding: Fr) -> EdwardsAffine {
    let value_term = mul(&value, &generator());
    let blinding_term = mul(&blinding, &h_generator());
    (EdwardsProjective::from(value_term) + EdwardsProjective::from(blinding_term)).into_affine()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::is_in_prime_subgroup;
    use ark_ff::AdditiveGroup;

    /// `H` must satisfy every property the spec promises.
    #[test]
    fn h_is_a_valid_subgroup_point() {
        let h = h_generator();
        assert!(h.is_on_curve(), "H must be on the curve");
        assert!(is_in_prime_subgroup(&h), "H must be in the prime subgroup");
        assert!(!h.is_zero(), "H must not be the identity");
    }

    /// `H` must not equal `G`. If it did, the commitment degenerates to
    /// `(value + blinding) · G`, losing the hiding property.
    #[test]
    fn h_is_distinct_from_generator() {
        assert_ne!(h_generator(), generator());
    }

    /// The cached `h_generator()` and a fresh `derive_h()` must agree.
    /// Catches a future cache bug (wrong static, racy init, etc.).
    #[test]
    fn h_cache_matches_fresh_derivation() {
        assert_eq!(h_generator(), derive_h());
    }

    /// The load-bearing property: Pedersen is additively homomorphic.
    /// `commit(a, r_a) + commit(b, r_b) == commit(a+b, r_a+r_b)`.
    #[test]
    fn commit_is_additively_homomorphic() {
        let a = Fr::from(7u64);
        let b = Fr::from(13u64);
        let r_a = Fr::from(101u64);
        let r_b = Fr::from(202u64);

        let c_a = commit(a, r_a);
        let c_b = commit(b, r_b);
        let sum = (EdwardsProjective::from(c_a) + EdwardsProjective::from(c_b)).into_affine();
        let c_sum = commit(a + b, r_a + r_b);
        assert_eq!(sum, c_sum);
    }

    /// Different blindings on the same value yield different commitments.
    /// (If they didn't, the blinding wouldn't be doing its job.)
    #[test]
    fn different_blindings_yield_different_commitments() {
        let value = Fr::from(42u64);
        let r1 = Fr::from(1u64);
        let r2 = Fr::from(2u64);
        assert_ne!(commit(value, r1), commit(value, r2));
    }

    /// Different values with the same blinding yield different commitments.
    /// (Otherwise the commitment isn't actually committing to the value.)
    #[test]
    fn different_values_yield_different_commitments() {
        let r = Fr::from(99u64);
        assert_ne!(commit(Fr::from(1u64), r), commit(Fr::from(2u64), r));
    }

    /// `commit(0, 0) == identity` — both terms vanish, mathematically
    /// trivial but pins the edge case.
    #[test]
    fn commit_of_zero_zero_is_identity() {
        use crate::babyjub::IDENTITY;
        assert_eq!(commit(Fr::ZERO, Fr::ZERO), IDENTITY);
    }

    /// Every commitment must land in the prime-order subgroup. Follows
    /// mathematically from `G` and `H` both being subgroup generators,
    /// but pinning it catches a future change that produces off-subgroup
    /// commitments.
    #[test]
    fn commitments_live_in_prime_subgroup() {
        let c = commit(Fr::from(5u64), Fr::from(11u64));
        assert!(is_in_prime_subgroup(&c));
    }
}
