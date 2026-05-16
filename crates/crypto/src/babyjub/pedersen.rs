//! Vector Pedersen commitments over Baby Jubjub.
//!
//! `commit(stream, blinding) = Σ stream_i · G_i + blinding · H`
//!
//! where:
//!
//! - `G_0, G_1, G_2, ...` is an unbounded family of value generators,
//!   each derived deterministically from its index via a documented
//!   nothing-up-my-sleeve procedure.
//! - `H` is the single blinding generator, derived from a separate
//!   fixed string by the same procedure.
//!
//! See `specs/babyjub-pedersen.md` for the construction and the
//! pinned worked-example fixture.
//!
//! ## Properties this brick gives you
//!
//! - **Binding** — the committer cannot open `C` to a different stream
//!   without finding a non-trivial linear combination of the
//!   generators that equals zero, which is computationally infeasible
//!   for honestly-derived generators.
//! - **Hiding** — for `blinding` sampled uniformly from `F_l`, `C`
//!   reveals nothing about the stream.
//! - **Element-wise additive homomorphism** —
//!   `commit(a, r_a) + commit(b, r_b) == commit(a + b, r_a + r_b)`
//!   where `a + b` is the element-wise sum of streams. Pinned as a
//!   runtime test; the protocol's commitment layer relies on it.
//! - **Single-element addressability** — because each stream element
//!   is bound to a distinct generator, a future ZK predicate can prove
//!   "the i-th element of the committed stream is X" by isolating
//!   `stream_i · G_i` without revealing the other elements.
//!
//! ## Scope intentionally NOT in this brick
//!
//! - **Length-hiding commitments.** This commitment leaks the stream
//!   length to anyone who knows which generator set was used (the
//!   encoding's tag exposes it anyway in normal protocol use). If a
//!   future use case needs length to be secret, the construction
//!   would zero-pad to a fixed `MAX_LEN`.
//! - **Pedersen-hash** (commit-to-bit-vector without blinding). A
//!   different primitive entirely; circomlib has one.
//! - **`verify(C, stream, blinding)`** — verification is literally
//!   `commit(stream, blinding) == C`. Adding a function just to wrap
//!   `==` would obscure the relationship.
//! - **Zero-knowledge proofs of opening** — future bricks.
//!
//! Randomness for the blinding scalar is the caller's responsibility,
//! consistent with the keypair-from-seed pattern.

use std::sync::OnceLock;

use ark_ec::CurveGroup;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_std::Zero;
use blake2::{digest::consts::U32, Blake2b, Digest};

use super::config::{BabyJubConfig, EdwardsAffine, EdwardsProjective, Fq, Fr};
use super::curve::mul;

/// Domain string for the blinding-generator `H` derivation. Pinned in
/// `specs/babyjub-pedersen.md`; changing it changes `H`, which
/// changes every commitment.
pub const H_DOMAIN: &str = "babyjub-pedersen-h-v1";

/// Domain string for the value-generator family `G_i` derivation.
/// Each `G_i` is derived from `Blake2b-256(G_DOMAIN || i_be_4_bytes)`
/// via the same try-and-increment procedure as `H`.
pub const G_DOMAIN: &str = "babyjub-pedersen-G";

/// Cached `H` — computed once, reused thereafter.
static H: OnceLock<EdwardsAffine> = OnceLock::new();

/// Cached value generators `G_0, G_1, G_2, ...`. Lazily populated:
/// each call to `g_generator(i)` extends the vector if `i` is past
/// the current end. Stays inside a `OnceLock<RwLock<Vec<_>>>` so the
/// init runs at most once and subsequent extensions are thread-safe.
///
/// Concurrent calls to `g_generator(i)` for distinct `i` block each
/// other briefly during the lock; this is fine because typical
/// usage iterates `0..n` once during a commit and the per-derivation
/// cost is microseconds.
static G_TABLE: OnceLock<std::sync::RwLock<Vec<EdwardsAffine>>> = OnceLock::new();

fn g_table() -> &'static std::sync::RwLock<Vec<EdwardsAffine>> {
    G_TABLE.get_or_init(|| std::sync::RwLock::new(Vec::new()))
}

/// The blinding generator `H`. Computed once, then cached. Lives in
/// the prime-order subgroup; its discrete log with respect to
/// `Base8` is unknown by construction.
pub fn h_generator() -> EdwardsAffine {
    *H.get_or_init(derive_h)
}

/// The `i`-th value generator `G_i`. Computed on first access for
/// each index, then cached. Each `G_i` lives in the prime-order
/// subgroup; the discrete logs between any two generators
/// (`G_i ↔ G_j`, `G_i ↔ H`, `G_i ↔ Base8`) are unknown by construction.
///
/// Indices are unbounded — a future longer encoding does not need to
/// pre-publish generators, only consume the prefix it needs.
pub fn g_generator(i: usize) -> EdwardsAffine {
    {
        let table = g_table().read().expect("G_TABLE rwlock poisoned");
        if let Some(g) = table.get(i) {
            return *g;
        }
    }
    let g = derive_g_at(i);
    let mut table = g_table().write().expect("G_TABLE rwlock poisoned");
    // After re-acquiring the write lock, another thread may have
    // already populated this index. Idempotent fill — just resize
    // sparsely with derived values up to (and including) `i`.
    while table.len() <= i {
        let next_idx = table.len();
        let g_next = if next_idx == i {
            g
        } else {
            derive_g_at(next_idx)
        };
        table.push(g_next);
    }
    table[i]
}

/// Derive `H` from `H_DOMAIN`. Public for the fixture/spec tooling;
/// production callers should use `h_generator()` to avoid recomputing.
pub fn derive_h() -> EdwardsAffine {
    let seed = Blake2b::<U32>::digest(H_DOMAIN.as_bytes());
    try_and_increment_from_seed(&seed, "babyjub-pedersen-h-v1")
}

/// Derive `G_i` from `G_DOMAIN` and the index `i`. Public for the
/// fixture/spec tooling; production callers should use
/// `g_generator(i)` to avoid recomputing.
pub fn derive_g_at(i: usize) -> EdwardsAffine {
    // Bind the index into the seed so `G_0`, `G_1`, ... are distinct
    // by construction even if Blake2b were ever weakened. Using a
    // 4-byte big-endian counter caps the natural family at 2^32
    // generators — far more than any conceivable encoding length.
    assert!(
        i < u32::MAX as usize,
        "babyjub-pedersen: G_i index out of range (i < 2^32 required)",
    );
    let idx = (i as u32).to_be_bytes();
    let mut seed_input = Vec::with_capacity(G_DOMAIN.len() + 4);
    seed_input.extend_from_slice(G_DOMAIN.as_bytes());
    seed_input.extend_from_slice(&idx);
    let seed = Blake2b::<U32>::digest(&seed_input);
    try_and_increment_from_seed(&seed, "babyjub-pedersen-G")
}

/// Try-and-increment hash-to-curve from a 32-byte seed: hash
/// `seed || counter_be_4_bytes` repeatedly until the digest decodes
/// to an on-curve point, cofactor-clear into the prime subgroup,
/// confirm subgroup membership defensively, and return.
///
/// `context_for_panic` is purely cosmetic — included in the
/// failure-mode panic message so a developer can tell which
/// generator's derivation went wrong if it ever does (it won't).
fn try_and_increment_from_seed(seed: &[u8], context_for_panic: &str) -> EdwardsAffine {
    for counter in 0u32..1_000 {
        let mut buf = Vec::with_capacity(seed.len() + 4);
        buf.extend_from_slice(seed);
        buf.extend_from_slice(&counter.to_be_bytes());
        let digest = Blake2b::<U32>::digest(&buf);

        // y = digest interpreted as big-endian unsigned, reduced mod p.
        let y = Fq::from_be_bytes_mod_order(&digest);

        // Top bit of the digest deterministically picks which root of
        // x² is used. arkworks' `sqrt()` returns one of the two
        // without specifying which, so we normalize.
        let want_odd_x = (digest[0] >> 7) == 1;

        if let Some(p) = point_from_y(y, want_odd_x) {
            // Cofactor-clear into the prime-order subgroup.
            let p_proj = EdwardsProjective::from(p);
            let cleared = (p_proj + p_proj + p_proj + p_proj + p_proj + p_proj + p_proj + p_proj)
                .into_affine();

            // Defense-in-depth subgroup check; mathematically redundant
            // after cofactor-clearing but pins the invariant.
            if !cleared.is_zero()
                && cleared.is_in_correct_subgroup_assuming_on_curve()
            {
                return cleared;
            }
        }
    }
    panic!(
        "{context_for_panic}: failed to derive in 1000 iterations; \
         this indicates a parameter-set inconsistency, not a real outcome",
    );
}

/// Given a candidate `y` and a sign bit, return the on-curve point
/// `(x, y)` whose `x` matches the sign bit, or `None` if no `x`
/// exists.
fn point_from_y(y: Fq, want_odd_x: bool) -> Option<EdwardsAffine> {
    let a = <BabyJubConfig as TECurveConfig>::COEFF_A;
    let d = <BabyJubConfig as TECurveConfig>::COEFF_D;

    let y2 = y * y;
    let numerator = Fq::ONE - y2;
    let denominator = a - d * y2;

    if denominator.is_zero() {
        return None;
    }

    let x_squared = numerator * denominator.inverse().unwrap();
    let x = x_squared.sqrt()?;

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

/// Reduce an `Fq` (base-field) element into `Fr` (scalar field) for
/// use as a scalar multiplier. The stream's elements live in `Fq`
/// because that's what every encoding produces; scalar multiplication
/// takes `Fr`-valued scalars. The reduction is by serializing to
/// little-endian bytes and re-parsing into `Fr`.
///
/// The bias from `p` (254 bits) to `l` (251 bits) on encoding-uniform
/// input is roughly `2⁻²⁵¹`, far below cryptographic relevance — same
/// reduction the keypair derivation already uses.
fn fq_to_fr(x: &Fq) -> Fr {
    Fr::from_le_bytes_mod_order(&x.into_bigint().to_bytes_le())
}

/// Compute a vector Pedersen commitment:
/// `C = Σ stream_i · G_i + blinding · H`.
///
/// Stream elements live in `Fq` (the base field, what every encoding
/// produces); blinding is in `Fr` (the scalar field). The function
/// internally reduces stream elements into `Fr` for the scalar mul.
/// Result is an affine point in the prime-order subgroup.
///
/// An empty stream produces `C = blinding · H`, a commitment to "no
/// content" — well-defined, no special-case.
pub fn commit(stream: &[Fq], blinding: Fr) -> EdwardsAffine {
    let mut acc = EdwardsProjective::from(mul(&blinding, &h_generator()));
    for (i, x) in stream.iter().enumerate() {
        let scalar = fq_to_fr(x);
        let term = mul(&scalar, &g_generator(i));
        acc += EdwardsProjective::from(term);
    }
    acc.into_affine()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::{generator, is_in_prime_subgroup};
    use ark_ff::AdditiveGroup;

    /// `H` and the first few `G_i` must each be on the curve and in
    /// the prime subgroup. The fundamental property; everything else
    /// depends on it.
    #[test]
    fn generators_are_valid_subgroup_points() {
        let h = h_generator();
        assert!(h.is_on_curve());
        assert!(is_in_prime_subgroup(&h));
        assert!(!h.is_zero());

        for i in 0..16 {
            let g = g_generator(i);
            assert!(g.is_on_curve(), "G_{i} must be on the curve");
            assert!(is_in_prime_subgroup(&g), "G_{i} must be in the prime subgroup");
            assert!(!g.is_zero(), "G_{i} must not be the identity");
        }
    }

    /// All generators are distinct from each other and from `Base8`.
    /// If any pair coincided, the commitment would collapse two stream
    /// positions into one, losing addressability.
    #[test]
    fn generators_are_pairwise_distinct() {
        let mut seen: Vec<EdwardsAffine> = vec![h_generator(), generator()];
        for i in 0..16 {
            let g = g_generator(i);
            for prior in &seen {
                assert_ne!(g, *prior, "G_{i} collides with another generator");
            }
            seen.push(g);
        }
    }

    /// Caches are correct: a second call returns the same value as
    /// a fresh derivation.
    #[test]
    fn caches_match_fresh_derivation() {
        assert_eq!(h_generator(), derive_h());
        for i in [0usize, 1, 3, 7, 11] {
            assert_eq!(g_generator(i), derive_g_at(i), "G_{i} cache drift");
        }
    }

    /// The load-bearing property: vector Pedersen is additively
    /// homomorphic, element-wise.
    /// `commit(a, r_a) + commit(b, r_b) == commit(a + b, r_a + r_b)`
    /// where `a + b` is the element-wise sum of streams.
    #[test]
    fn commit_is_element_wise_additively_homomorphic() {
        let a = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        let b = [Fq::from(10u64), Fq::from(20u64), Fq::from(30u64)];
        let sum_stream: Vec<Fq> = a.iter().zip(b.iter()).map(|(x, y)| *x + *y).collect();
        let r_a = Fr::from(101u64);
        let r_b = Fr::from(202u64);

        let c_a = commit(&a, r_a);
        let c_b = commit(&b, r_b);
        let sum =
            (EdwardsProjective::from(c_a) + EdwardsProjective::from(c_b)).into_affine();
        let c_sum = commit(&sum_stream, r_a + r_b);
        assert_eq!(sum, c_sum);
    }

    /// Different blindings on the same stream yield different commitments.
    #[test]
    fn different_blindings_yield_different_commitments() {
        let stream = [Fq::from(42u64), Fq::from(43u64)];
        let r1 = Fr::from(1u64);
        let r2 = Fr::from(2u64);
        assert_ne!(commit(&stream, r1), commit(&stream, r2));
    }

    /// Different streams with the same blinding yield different
    /// commitments. (Including the i-th-position-distinct case below,
    /// this collectively proves the commitment binds every stream
    /// position.)
    #[test]
    fn different_streams_yield_different_commitments() {
        let r = Fr::from(99u64);
        let a = [Fq::from(1u64), Fq::from(2u64)];
        let b = [Fq::from(1u64), Fq::from(3u64)];
        assert_ne!(commit(&a, r), commit(&b, r));
    }

    /// Single-element addressability: changing position i of the stream
    /// produces a commitment that differs from the original by exactly
    /// `(new_i - old_i) · G_i`. This isolates each generator's
    /// contribution and is the property a future ZK "i-th element is
    /// X" predicate will lean on.
    #[test]
    fn single_element_change_isolates_to_one_generator() {
        let r = Fr::from(7u64);
        let stream_a = [Fq::from(10u64), Fq::from(20u64), Fq::from(30u64)];
        let mut stream_b = stream_a;
        stream_b[1] = Fq::from(99u64);

        let c_a = commit(&stream_a, r);
        let c_b = commit(&stream_b, r);
        let diff = (EdwardsProjective::from(c_b) - EdwardsProjective::from(c_a)).into_affine();

        // Predicted difference: `(99 - 20) · G_1 = 79 · G_1`.
        let predicted = mul(&fq_to_fr(&(Fq::from(99u64) - Fq::from(20u64))), &g_generator(1));
        assert_eq!(diff, predicted);
    }

    /// `commit([], 0) == identity` — the trivial case (no value
    /// terms, no blinding term). Pins the edge case.
    #[test]
    fn commit_of_empty_zero_is_identity() {
        use crate::babyjub::IDENTITY;
        assert_eq!(commit(&[], Fr::ZERO), IDENTITY);
    }

    /// `commit([], r) == r · H` for nonzero `r` — the "no content"
    /// commitment with hiding. Useful as a placeholder for commitments
    /// over streams that haven't been populated yet.
    #[test]
    fn commit_of_empty_with_blinding_is_r_times_h() {
        let r = Fr::from(123u64);
        let c = commit(&[], r);
        let expected = mul(&r, &h_generator());
        assert_eq!(c, expected);
    }

    /// Every commitment lands in the prime-order subgroup. Follows
    /// mathematically from all generators being subgroup elements,
    /// but pinning it catches a future change that produces
    /// off-subgroup commitments.
    #[test]
    fn commitments_live_in_prime_subgroup() {
        let stream = [Fq::from(5u64), Fq::from(11u64), Fq::from(13u64)];
        let c = commit(&stream, Fr::from(17u64));
        assert!(is_in_prime_subgroup(&c));
    }
}
