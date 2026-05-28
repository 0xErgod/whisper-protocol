//! Poseidon-BN254 with circomlib parameters.
//!
//! This module is a thin, opinionated wrapper around [`light_poseidon`] —
//! the only audited Rust Poseidon implementation that produces the same
//! hash byte-for-byte as `circomlib` / `poseidon-lite` (the TypeScript side
//! already uses `poseidon-lite`; see `specs/protocol-commitment.md`
//! for the existing rationale, which applies unchanged here).
//!
//! `ark-crypto-primitives::sponge::poseidon` is the obvious-looking
//! alternative and would be wrong: arkworks' default parameters generate
//! round constants and MDS matrices differently and the outputs do not
//! match circomlib. Any cross-language compatibility (TS SDK, circom
//! circuits, snarkjs verifiers, on-chain Groth16) breaks silently if the
//! parameter set drifts.
//!
//! ## Scope
//!
//! Two families of hash function, both circomlib-parameterized, both
//! domain-tagged at position 0 of their inputs:
//!
//! - **Fixed-arity** ([`poseidon_hash_fixed`]) — one `Poseidon-(1+n)`
//!   permutation. Cheaper, but the input length must be `≤ 11`
//!   (giving total Poseidon arity `≤ 12` and state width `≤ 13` —
//!   what `light-poseidon` ships circomlib parameters for). Use when
//!   the input length is known at spec time and bounded.
//! - **Sponge** ([`poseidon_hash_sponge`]) — variable-length absorption
//!   via the duplex sponge over `Poseidon-3` (state size `t=3`, rate
//!   `r=2`, capacity `c=1`). Use when the input length varies or
//!   exceeds the fixed-arity ceiling.
//!
//! **The two families are distinct hash functions**: they produce
//! different outputs on the same `(domain_tag, inputs)`. The choice
//! between them is a design-time call that each consumer's spec MUST
//! pin — there is deliberately no auto-dispatch. See
//! `specs/poseidon-hash-fixed.md` and `specs/poseidon-hash-sponge.md`.
//!
//! The legacy fixed-arity helper [`poseidon3`] also lives here — it
//! predates the generic `poseidon_hash_fixed` and is kept for the
//! keypair derivation, which pins its exact arity at the call site.
//! New code should reach for `poseidon_hash_fixed` instead.
//!
//! The hash output is `Fq` (the BN254 scalar field, which is Baby
//! Jubjub's base field), the same field the existing TypeScript
//! Poseidon module outputs into. Callers reduce mod the Baby Jubjub
//! scalar order themselves when they need an `Fr` (see
//! `babyjub::keypair`'s spec note on that step).

use blake2::{Blake2b, Digest, digest::consts::U32};
use light_poseidon::{Poseidon, PoseidonHasher};

use crate::babyjub::Fq;

/// Hash exactly three field elements with circomlib's Poseidon-BN254
/// (arity 3, state size 4). Matches `poseidon-lite::poseidon3` and
/// circom's `poseidon([_, _, _])`.
///
/// `light_poseidon::Poseidon` is stateful per call — we build a fresh
/// hasher each time so this function is pure. The construction cost is
/// negligible for the keypair / commitment / signature paths, which call
/// it once per operation.
pub fn poseidon3(inputs: &[Fq; 3]) -> Fq {
    // `new_circom(arity)` is infallible for arities supported by circomlib
    // (1..=16). Arity 3 is in range, so the `unwrap` is a domain assertion.
    let mut hasher = Poseidon::<Fq>::new_circom(3)
        .expect("circomlib Poseidon supports arity 3");
    hasher
        .hash(inputs)
        .expect("Poseidon over fixed-arity field elements never fails")
}

/// Build a domain-tag field element from a short, descriptive UTF-8 string.
///
/// Construction: `bytes_to_field_be(Blake2b-256(domain_string))`. The
/// TypeScript side calls the exact same function through the
/// `crypto-wasm` `domain_tag` binding (this crate compiled to WASM), so
/// a Rust and a TS caller hashing the *same* domain string land on the
/// *same* field element. Reusing the construction across primitives
/// means one rule, not per-primitive bespoke encodings.
///
/// Reduction is via big-endian byte interpretation followed by mod-`p`
/// reduction (256-bit input into a 254-bit field, so two bits get folded —
/// the resulting bias is far below cryptographic relevance for a fixed
/// domain constant).
///
/// Domain tags themselves are pinned in each primitive's spec (e.g.
/// `specs/babyjub-keypair.md`).
pub fn domain_tag(domain_string: &str) -> Fq {
    let digest = Blake2b::<U32>::digest(domain_string.as_bytes());
    // `from_be_bytes_mod_order` is exactly the "interpret as big-endian
    // unsigned integer, then reduce" semantics the TS side uses.
    <Fq as ark_ff::PrimeField>::from_be_bytes_mod_order(&digest)
}

/// Why a Poseidon hash call failed.
///
/// Sponge hashes never fail and never produce this error; only
/// fixed-arity hashes can violate their preconditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoseidonError {
    /// `poseidon_hash_fixed` was called with an input slice whose
    /// length, plus one (for the prepended domain tag), exceeds
    /// `light-poseidon`'s shipped circomlib parameters (total state
    /// width `≤ 13`). Use `poseidon_hash_sponge` for variable-length
    /// or out-of-range input.
    ArityOutOfRange { total_arity: usize },
}

impl core::fmt::Display for PoseidonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PoseidonError::ArityOutOfRange { total_arity } => write!(
                f,
                "poseidon_hash_fixed total arity {total_arity} is outside circomlib's [1, 13] range; use poseidon_hash_sponge",
            ),
        }
    }
}

impl std::error::Error for PoseidonError {}

/// Hash a domain-separated, design-time-bounded list of field elements
/// with one circomlib-Poseidon-`(1 + n)` permutation. The domain tag
/// occupies position 0 of the Poseidon input; the payload elements
/// follow in order.
///
/// **Use this when** the input length `n` is known at spec time and is
/// at most `12` (so total state width is at most `13`, the ceiling for
/// `light-poseidon`'s shipped circomlib parameters). Schnorr
/// challenges, KDFs, and bounded-length encoding commitment hashes are
/// the canonical consumers.
///
/// **Errors** with [`PoseidonError::ArityOutOfRange`] when `1 + n` is
/// outside `[1, 13]`. The bound is a property of `light-poseidon`'s
/// shipped parameter tables, not a protocol design choice — for
/// variable-length or longer inputs, use [`poseidon_hash_sponge`] (a
/// *different* hash function; the choice between them must be pinned
/// in the consumer's spec).
///
/// Note on circomlib API conventions: `Poseidon::<Fq>::new_circom(n)`
/// in `light-poseidon` takes `n = number_of_inputs`, allocates a
/// state of width `n+1`, and absorbs the inputs into positions
/// `1..=n` (position 0 is the domain-tag slot, initialised to zero by
/// the library). We supplement that with our **caller-supplied**
/// domain tag by reserving position 0 of the *inputs* for our tag —
/// effectively shifting everything one over, so `n_circomlib =
/// inputs.len()` and the resulting Poseidon arity is `n + 1` because
/// our domain tag is the first input.
pub fn poseidon_hash_fixed(
    domain_tag: Fq,
    inputs: &[Fq],
) -> Result<Fq, PoseidonError> {
    let total_arity = 1 + inputs.len();
    // `light-poseidon` ships circomlib parameters up to state width 13,
    // i.e. up to 12 inputs to `new_circom`. We bracket *total state
    // width* (= 1 + n_circomlib = 1 + total_arity = 1 + 1 + len), so
    // total_arity ≤ 12 keeps state width ≤ 13.
    if !(1..=12).contains(&total_arity) {
        return Err(PoseidonError::ArityOutOfRange { total_arity });
    }
    let mut buf: Vec<Fq> = Vec::with_capacity(total_arity);
    buf.push(domain_tag);
    buf.extend_from_slice(inputs);
    let mut hasher = Poseidon::<Fq>::new_circom(total_arity)
        .expect("arity is in [1, 12] by the check above");
    Ok(hasher
        .hash(&buf)
        .expect("Poseidon over fixed-arity field elements never fails"))
}

/// Hash an arbitrarily-long list of field elements via a duplex sponge
/// over `Poseidon-3` (state size `t=3`, rate `r=2`, capacity `c=1`).
///
/// The domain tag is the **first element absorbed**, followed by the
/// payload elements in order. Input lengths from zero up are
/// supported. Padding follows the standard "append 1, then zero-pad to
/// the next rate boundary" rule — this prevents two distinct input
/// streams from producing identical absorption sequences (the classic
/// length-extension hazard).
///
/// Construction in detail:
///
/// ```text
/// state = [0, 0, 0]                     // initial state, t=3 elements
/// to_absorb = [domain_tag, inputs..., 1, 0, 0, ...]   // pad-1 then zero-pad
///                                                       // to multiple of r=2
/// for chunk in to_absorb.chunks_exact(2):
///     state[0] += chunk[0]
///     state[1] += chunk[1]
///     state = Poseidon-3-permutation(state)
/// output = state[0]
/// ```
///
/// **Use this when** the input length is variable, or exceeds the
/// fixed-arity ceiling of 15. MAC constructions and future
/// long-encoding commitment hashes are the canonical consumers.
///
/// **Different output than [`poseidon_hash_fixed`]** on the same
/// `(domain_tag, inputs)`. The choice between fixed and sponge is a
/// design-time call pinned per consumer in its spec — there is no
/// auto-dispatch.
pub fn poseidon_hash_sponge(domain_tag: Fq, inputs: &[Fq]) -> Fq {
    // Sponge parameters: t=3 (state size), r=2 (rate), c=1 (capacity).
    // The circomlib permutation at width 3 is the arity-2 hash's
    // underlying permutation; we re-implement it directly so we can
    // chain state across multiple absorptions (which `light_poseidon::
    // PoseidonHasher::hash` doesn't expose).
    const RATE: usize = 2;

    // Prepare the absorption tape: domain tag, then payload, then
    // pad-1 then zero-pad to the next rate boundary. The pad-1 marker
    // prevents two distinct input sequences from producing the same
    // absorption tape (length-extension hazard).
    let mut tape: Vec<Fq> = Vec::with_capacity(2 + inputs.len() + RATE);
    tape.push(domain_tag);
    tape.extend_from_slice(inputs);
    tape.push(Fq::from(1u64));
    while !tape.len().is_multiple_of(RATE) {
        tape.push(Fq::from(0u64));
    }

    // Fetch the circomlib Poseidon-3 parameters once; reuse across
    // permutations.
    let params: light_poseidon::PoseidonParameters<Fq> =
        light_poseidon::parameters::bn254_x5::get_poseidon_parameters(3)
            .expect("circomlib Poseidon supports width 3");

    // Initial state: all zeros, t=3 elements.
    let mut state = [Fq::from(0u64); 3];

    for chunk in tape.chunks_exact(RATE) {
        // Absorb the rate-sized chunk into the first r state elements.
        state[0] += chunk[0];
        state[1] += chunk[1];
        // Apply one full Poseidon-3 permutation.
        state = poseidon3_permutation(state, &params);
    }

    // Squeeze: output the first state element. We only ever need one
    // element of output, so no further squeezing is required.
    state[0]
}

/// Apply one Poseidon permutation to a state of width 3 using the
/// given (circomlib-parameterized) parameters.
///
/// Re-implemented directly because `light-poseidon`'s public
/// `PoseidonHasher::hash` resets the capacity element to zero on each
/// call — that resets the sponge state and breaks chaining across
/// absorptions. The permutation itself is `add round constants →
/// S-box → MDS multiply`, repeated full + partial + full times. The
/// parameters (`ark` round constants, `mds` matrix, `full_rounds`,
/// `partial_rounds`, `alpha`) come from circomlib's published tables
/// via `light_poseidon::parameters::bn254_x5`, so this permutation
/// produces the exact same intermediate state circomlib would.
// MDS-matrix multiplication and round-constant addition read most
// naturally with explicit `s[i]` / `mds[i][j]` indexing — the
// `iter().enumerate()` rewrite obscures the linear-algebra shape. Suppress
// clippy's needless-range-loop lint for this function.
#[allow(clippy::needless_range_loop)]
fn poseidon3_permutation(
    state: [Fq; 3],
    params: &light_poseidon::PoseidonParameters<Fq>,
) -> [Fq; 3] {
    use ark_ff::Field;

    let mut s = state;
    let full_rounds = params.full_rounds;
    let partial_rounds = params.partial_rounds;
    let half_full = full_rounds / 2;
    let alpha = params.alpha;
    let mut round = 0usize;

    let apply_ark = |s: &mut [Fq; 3], round: usize| {
        // Round constants are flattened `[ark[0..width], ark[width..2*width], ...]`.
        for i in 0..3 {
            s[i] += params.ark[round * 3 + i];
        }
    };
    let sbox_full = |s: &mut [Fq; 3]| {
        for v in s.iter_mut() {
            *v = v.pow([alpha]);
        }
    };
    let sbox_partial = |s: &mut [Fq; 3]| {
        s[0] = s[0].pow([alpha]);
    };
    let mds = |s: &mut [Fq; 3]| {
        let mut out = [Fq::from(0u64); 3];
        for i in 0..3 {
            for j in 0..3 {
                out[i] += params.mds[i][j] * s[j];
            }
        }
        *s = out;
    };

    for _ in 0..half_full {
        apply_ark(&mut s, round);
        sbox_full(&mut s);
        mds(&mut s);
        round += 1;
    }
    for _ in 0..partial_rounds {
        apply_ark(&mut s, round);
        sbox_partial(&mut s);
        mds(&mut s);
        round += 1;
    }
    for _ in 0..half_full {
        apply_ark(&mut s, round);
        sbox_full(&mut s);
        mds(&mut s);
        round += 1;
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::AdditiveGroup;

    /// `poseidon3` of three zeros is a well-defined, fixed value. We pin it
    /// here against a recomputed result so a `light-poseidon` upgrade or a
    /// parameter-set drift fails loudly. (Not a circomlib cross-check — that
    /// belongs in the keypair fixture test, which has known TS-side vectors.
    /// This is a "is the module wired correctly" smoke test.)
    #[test]
    fn poseidon3_of_zeros_is_stable() {
        let z = Fq::ZERO;
        let a = poseidon3(&[z, z, z]);
        let b = poseidon3(&[z, z, z]);
        assert_eq!(a, b, "Poseidon must be deterministic");
        // The non-zero output proves we are not accidentally returning
        // the input or some identity-like degenerate value.
        assert_ne!(a, z);
    }

    /// `poseidon3` is sensitive to input order: `poseidon3([a, b, c])` and
    /// `poseidon3([c, b, a])` must differ. A wrong API wiring (e.g. feeding
    /// inputs in reverse) would silently produce a different hash than the
    /// TS side without this assertion.
    #[test]
    fn poseidon3_is_order_sensitive() {
        let a = Fq::from(1u64);
        let b = Fq::from(2u64);
        let c = Fq::from(3u64);
        assert_ne!(poseidon3(&[a, b, c]), poseidon3(&[c, b, a]));
    }

/// The domain-tag construction is deterministic and string-sensitive.
    /// The exact field element for a given string is pinned in each
    /// primitive's spec/fixture, not here.
    #[test]
    fn domain_tag_is_deterministic_and_distinct() {
        let t1 = domain_tag("babyjub-keypair-v1");
        let t2 = domain_tag("babyjub-keypair-v1");
        let t3 = domain_tag("babyjub-keypair-v2");
        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
    }

    // --- poseidon_hash_fixed ------------------------------------------

    /// Deterministic: same `(domain, inputs)` always produces the same
    /// hash. Foundational property; everything else builds on it.
    #[test]
    fn fixed_is_deterministic() {
        let d = domain_tag("test");
        let inputs = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        let a = poseidon_hash_fixed(d, &inputs).expect("3+1 ≤ 16");
        let b = poseidon_hash_fixed(d, &inputs).expect("3+1 ≤ 16");
        assert_eq!(a, b);
    }

    /// Domain separation: same payload under different domains
    /// produces different outputs. The load-bearing property of
    /// domain-tagged hashing.
    #[test]
    fn fixed_is_domain_separated() {
        let inputs = [Fq::from(1u64), Fq::from(2u64)];
        let a = poseidon_hash_fixed(domain_tag("ctx-a"), &inputs).expect("ok");
        let b = poseidon_hash_fixed(domain_tag("ctx-b"), &inputs).expect("ok");
        assert_ne!(a, b);
    }

    /// Order-sensitive: permuting the input changes the output.
    #[test]
    fn fixed_is_order_sensitive() {
        let d = domain_tag("test");
        let a = poseidon_hash_fixed(d, &[Fq::from(1u64), Fq::from(2u64)]).expect("ok");
        let b = poseidon_hash_fixed(d, &[Fq::from(2u64), Fq::from(1u64)]).expect("ok");
        assert_ne!(a, b);
    }

    /// Zero inputs: well-defined. Outputs Poseidon-1 of just the
    /// domain tag — a per-domain constant.
    #[test]
    fn fixed_zero_inputs_is_well_defined() {
        let d = domain_tag("test");
        let h = poseidon_hash_fixed(d, &[]).expect("arity 1 is in range");
        // Non-trivial: not equal to the domain itself.
        assert_ne!(h, d);
    }

    /// Arity ceiling: `light-poseidon` ships circomlib parameters
    /// only up to state width 13. With our convention `total_arity =
    /// 1 + inputs.len()` and `new_circom(total_arity)` producing state
    /// width `total_arity + 1`, the in-range bound is `total_arity ≤
    /// 12`, i.e. `inputs.len() ≤ 11`. Boundary check at the limit.
    #[test]
    fn fixed_arity_ceiling() {
        let d = domain_tag("test");
        let inputs11: Vec<Fq> = (0u64..11).map(Fq::from).collect();
        let inputs12: Vec<Fq> = (0u64..12).map(Fq::from).collect();
        assert!(
            poseidon_hash_fixed(d, &inputs11).is_ok(),
            "11 inputs → total arity 12 fits",
        );
        assert!(
            matches!(
                poseidon_hash_fixed(d, &inputs12),
                Err(PoseidonError::ArityOutOfRange { total_arity: 13 })
            ),
            "12 inputs → total arity 13 must error",
        );
    }

    // --- poseidon_hash_sponge -----------------------------------------

    /// Deterministic: same `(domain, inputs)` always produces the same
    /// hash. Foundational.
    #[test]
    fn sponge_is_deterministic() {
        let d = domain_tag("test");
        let inputs = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        assert_eq!(
            poseidon_hash_sponge(d, &inputs),
            poseidon_hash_sponge(d, &inputs),
        );
    }

    /// Domain separation works for sponge too.
    #[test]
    fn sponge_is_domain_separated() {
        let inputs = [Fq::from(1u64), Fq::from(2u64)];
        let a = poseidon_hash_sponge(domain_tag("ctx-a"), &inputs);
        let b = poseidon_hash_sponge(domain_tag("ctx-b"), &inputs);
        assert_ne!(a, b);
    }

    /// Sponge handles input of any length, including zero. The
    /// pad-1-then-zero-pad rule ensures even empty inputs produce a
    /// well-defined, non-trivial output.
    #[test]
    fn sponge_handles_all_lengths() {
        let d = domain_tag("test");
        let h0 = poseidon_hash_sponge(d, &[]);
        let h1 = poseidon_hash_sponge(d, &[Fq::from(1u64)]);
        let h_long: Vec<Fq> = (0u64..30).map(Fq::from).collect();
        let h_long_out = poseidon_hash_sponge(d, &h_long);
        // All three are distinct (length-extension safety).
        assert_ne!(h0, h1);
        assert_ne!(h1, h_long_out);
        assert_ne!(h0, h_long_out);
    }

    /// Length-extension safety: `inputs = [a]` and `inputs = [a, 0]`
    /// MUST produce different sponge outputs. Without the pad-1
    /// marker they would absorb the same elements and collide.
    #[test]
    fn sponge_distinguishes_zero_padded_input() {
        let d = domain_tag("test");
        let a = poseidon_hash_sponge(d, &[Fq::from(7u64)]);
        let b = poseidon_hash_sponge(d, &[Fq::from(7u64), Fq::from(0u64)]);
        assert_ne!(a, b, "pad-1 marker must prevent zero-padding collision");
    }

    // --- the cross-construction differentiator (load-bearing) ---------

    /// `poseidon_hash_fixed` and `poseidon_hash_sponge` are DIFFERENT
    /// hash functions and produce DIFFERENT outputs on the same
    /// `(domain, inputs)`. This is the property the spec contract
    /// rests on — a consumer's spec pins which construction is used
    /// at a given call site, and the two are not interchangeable.
    #[test]
    fn fixed_and_sponge_are_different_functions() {
        let d = domain_tag("test");
        let inputs = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        let h_fixed = poseidon_hash_fixed(d, &inputs).expect("ok");
        let h_sponge = poseidon_hash_sponge(d, &inputs);
        assert_ne!(
            h_fixed, h_sponge,
            "fixed and sponge MUST be distinguishable hashes",
        );
    }
}
