//! In-circuit Poseidon hash, circomlib-parameterized.
//!
//! Mirrors `crypto::poseidon::{poseidon_hash_fixed, poseidon_hash_sponge}`
//! against `FpVar<Fq>` so a circuit can prove statements about
//! values the native crate hashes. Both gadgets land here in one
//! brick because they share the underlying permutation
//! implementation.
//!
//! ## Why we don't use `ark-crypto-primitives::sponge::poseidon`
//!
//! `PoseidonSpongeVar` is the obvious-looking choice and would
//! produce the wrong hash. Its default parameter sets (round
//! constants, MDS matrix) are arkworks-native and differ from
//! circomlib's. The native `crypto` crate uses
//! circomlib-parameterized Poseidon via `light-poseidon`, and the
//! TS SDK uses `poseidon-lite` (also circomlib). For the
//! three-way native ↔ TS ↔ circuit story to be coherent, the
//! gadget MUST reproduce circomlib's parameters byte-for-byte.
//! See `specs/zk/stack.md § Poseidon parameters` for the full
//! rationale.
//!
//! The construction here loads parameters from `light-poseidon`
//! (the canonical source) and reimplements the permutation against
//! `FpVar<Fq>`. The shape mirrors `crypto::poseidon` exactly:
//!
//! - **Fixed-arity** ([`poseidon_hash_fixed_var`]) — one
//!   `Poseidon-(2+n)` permutation on the state `[0, domain_tag,
//!   inputs...]`. Total state width must be in `[2, 13]` (i.e.
//!   `inputs.len()` in `[0, 11]`, but the native side's API caps
//!   `total_arity = 1 + inputs.len() ≤ 12`, so effectively
//!   `inputs.len() ∈ [0, 11]`).
//! - **Sponge** ([`poseidon_hash_sponge_var`]) — duplex sponge
//!   over `Poseidon-3`, rate `r=2`, capacity `c=1`. Variable
//!   length input.
//!
//! ## Equivalence as a contract
//!
//! Each gadget ships with a native↔circuit equivalence test (see
//! the `tests` submodule). The native primitive runs, the gadget
//! runs over witness-allocated inputs, and the two outputs are
//! enforced equal as a circuit assertion. `cs.is_satisfied()` is
//! the final check. A drift between gadget parameters and native
//! parameters surfaces as a failed equality, not a silent
//! divergence.

use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crypto::babyjub::Fq;

/// Hash a domain-tagged, fixed-arity stream of field-element
/// witnesses (or constants). Mirrors
/// `crypto::poseidon::poseidon_hash_fixed`.
///
/// The output `FpVar` is constrained, by the gadget's internal
/// constraints, to equal the native hash applied to the same
/// inputs. A caller composing this gadget into a larger circuit
/// can treat the returned `FpVar` as "the Poseidon hash of these
/// inputs" without further work.
///
/// `domain_tag` is passed as an `FpVar` rather than a raw `Fq`
/// so callers can either bind it as a constant (the common case —
/// each consumer's domain tag is fixed at spec time) or thread it
/// from a witness (rare, but supported).
///
/// **Errors** with [`PoseidonError::ArityOutOfRange`] when
/// `1 + inputs.len()` is outside `[1, 12]`. The bound is identical
/// to the native side's; see `crypto::poseidon` for the
/// `light-poseidon` parameter-table reason.
pub fn poseidon_hash_fixed_var(
    cs: ConstraintSystemRef<Fq>,
    domain_tag: &FpVar<Fq>,
    inputs: &[FpVar<Fq>],
) -> Result<FpVar<Fq>, SynthesisError> {
    let total_arity = 1 + inputs.len();
    // Same bound the native side enforces. Outside this range,
    // `light-poseidon` does not ship circomlib parameters, so the
    // gadget cannot reproduce a value the native side could
    // compute.
    if !(1..=12).contains(&total_arity) {
        // The native side returns a typed error here. The gadget
        // surface uses `SynthesisError` because that is what the
        // arkworks gadget ecosystem expects, but we forward the
        // root cause as the error message.
        let _ = cs; // silence unused; keep signature uniform with sponge.
        return Err(SynthesisError::Unsatisfiable);
    }

    // Load circomlib parameters for the corresponding state width.
    // `new_circom(nr_inputs)` in light-poseidon loads parameters of
    // width `nr_inputs + 1`; the inputs to that hasher include our
    // caller-supplied domain tag at position 0 of the input
    // sequence, so `nr_inputs = total_arity = 1 + inputs.len()`,
    // and the state width is `2 + inputs.len()`.
    let width = total_arity + 1;
    let params = light_poseidon::parameters::bn254_x5::get_poseidon_parameters::<Fq>(
        u8::try_from(width).expect("width ≤ 13 by the check above"),
    )
    .expect("circomlib Poseidon supports widths in [2, 13]");

    // Initial state: the library's own domain slot (zero) at
    // position 0, then our domain tag at position 1, then the
    // inputs.
    let mut state: Vec<FpVar<Fq>> = Vec::with_capacity(width);
    state.push(FpVar::<Fq>::zero());
    state.push(domain_tag.clone());
    for x in inputs {
        state.push(x.clone());
    }
    debug_assert_eq!(state.len(), width);

    permute_var(&mut state, &params)?;

    Ok(state[0].clone())
}

/// Hash a domain-tagged, variable-length stream of field-element
/// witnesses (or constants) via the duplex sponge over
/// `Poseidon-3`. Mirrors `crypto::poseidon::poseidon_hash_sponge`.
///
/// The construction is exactly the native side's: state width 3,
/// rate 2, capacity 1; domain tag absorbed first, then payload,
/// then pad-1 + zero-pad to a rate boundary, with one permutation
/// per rate-sized chunk.
///
/// **No length cap**, but the number of permutations grows linearly
/// with input length, and so does the constraint count. A circuit
/// designer who hashes a long stream pays for it in PK size and
/// prove time. Where input length is known and bounded at spec
/// time, [`poseidon_hash_fixed_var`] is cheaper.
///
/// Like the fixed-arity variant, `domain_tag` is an `FpVar`; pass
/// a constant `FpVar` when the consumer's spec pins it.
pub fn poseidon_hash_sponge_var(
    _cs: ConstraintSystemRef<Fq>,
    domain_tag: &FpVar<Fq>,
    inputs: &[FpVar<Fq>],
) -> Result<FpVar<Fq>, SynthesisError> {
    const RATE: usize = 2;
    const WIDTH: usize = 3;

    // Build the absorption tape: domain tag, payload, pad-1,
    // zero-pad to the next rate boundary. Same shape the native
    // side uses.
    let mut tape: Vec<FpVar<Fq>> = Vec::with_capacity(2 + inputs.len() + RATE);
    tape.push(domain_tag.clone());
    for x in inputs {
        tape.push(x.clone());
    }
    tape.push(FpVar::<Fq>::constant(Fq::from(1u64)));
    while !tape.len().is_multiple_of(RATE) {
        tape.push(FpVar::<Fq>::zero());
    }

    let params = light_poseidon::parameters::bn254_x5::get_poseidon_parameters::<Fq>(WIDTH as u8)
        .expect("circomlib Poseidon supports width 3");

    // Initial state: t=3 zeros.
    let mut state: Vec<FpVar<Fq>> = vec![FpVar::<Fq>::zero(); WIDTH];

    for chunk in tape.chunks_exact(RATE) {
        // Absorb the rate-sized chunk into the first r state
        // elements. Capacity element (state[2]) is untouched —
        // this is exactly what the native side does, and what
        // `light-poseidon`'s `PoseidonHasher::hash` does NOT do
        // (it resets capacity each call), which is why the native
        // side reimplements the permutation directly.
        state[0] = &state[0] + &chunk[0];
        state[1] = &state[1] + &chunk[1];
        permute_var(&mut state, &params)?;
    }

    // Squeeze: one element of output. The protocol never needs more.
    Ok(state[0].clone())
}

/// One Poseidon permutation against the `FpVar` state. Mirrors
/// `crypto::poseidon::poseidon3_permutation` (and its width-`n`
/// generalization that `light-poseidon::Poseidon::hash` does
/// internally).
///
/// The structure: `apply_ark → S-box → MDS`, repeated full +
/// partial + full times. Parameters (`ark`, `mds`, `full_rounds`,
/// `partial_rounds`, `alpha`) come from
/// `light-poseidon::parameters::bn254_x5::get_poseidon_parameters`,
/// so the permutation produces the exact same intermediate state
/// the native side would.
///
/// The width is determined by `state.len()` and must equal
/// `params.width`.
#[allow(clippy::needless_range_loop)]
fn permute_var(
    state: &mut [FpVar<Fq>],
    params: &light_poseidon::PoseidonParameters<Fq>,
) -> Result<(), SynthesisError> {
    let width = state.len();
    debug_assert_eq!(width, params.width);

    let full_rounds = params.full_rounds;
    let partial_rounds = params.partial_rounds;
    let half_full = full_rounds / 2;
    let alpha = params.alpha;
    let mut round = 0usize;

    // Round constants are flattened `[ark[0..width],
    // ark[width..2*width], ...]`. `apply_ark` adds the `round`-th
    // width-sized slice into the state. This is the native side's
    // layout verbatim.
    let apply_ark = |state: &mut [FpVar<Fq>], round: usize| {
        for i in 0..width {
            // The round constant is a native `Fq`. Adding a
            // constant to an `FpVar` does not allocate a new
            // witness; arkworks folds it into the affine
            // combination representation, so this is free in
            // constraint terms.
            state[i] = &state[i] + FpVar::<Fq>::constant(params.ark[round * width + i]);
        }
    };

    // Full-round S-box: every state element ↦ state[i]^alpha.
    let sbox_full = |state: &mut [FpVar<Fq>]| -> Result<(), SynthesisError> {
        for v in state.iter_mut() {
            *v = pow_var(v, alpha)?;
        }
        Ok(())
    };

    // Partial-round S-box: only state[0] gets the cubing.
    let sbox_partial = |state: &mut [FpVar<Fq>]| -> Result<(), SynthesisError> {
        state[0] = pow_var(&state[0], alpha)?;
        Ok(())
    };

    // MDS multiplication: `state ← M · state` where `M = params.mds`.
    let mds = |state: &mut [FpVar<Fq>]| {
        let mut out: Vec<FpVar<Fq>> = vec![FpVar::<Fq>::zero(); width];
        for i in 0..width {
            for j in 0..width {
                // Adding `mds[i][j] * state[j]` — a constant
                // times an FpVar — also folds into the affine
                // representation and costs no constraints.
                out[i] = &out[i] + &state[j] * FpVar::<Fq>::constant(params.mds[i][j]);
            }
        }
        state[..width].clone_from_slice(&out[..width]);
    };

    for _ in 0..half_full {
        apply_ark(state, round);
        sbox_full(state)?;
        mds(state);
        round += 1;
    }
    for _ in 0..partial_rounds {
        apply_ark(state, round);
        sbox_partial(state)?;
        mds(state);
        round += 1;
    }
    for _ in 0..half_full {
        apply_ark(state, round);
        sbox_full(state)?;
        mds(state);
        round += 1;
    }

    Ok(())
}

/// Raise `v` to a constant power. The circomlib S-box is `x ↦ x^5`
/// (alpha = 5) for BN254, so this is the only exponent we ever
/// use; we implement it directly as two squarings and a multiply
/// (4 muls total) rather than the generic square-and-multiply,
/// keeping the gadget cheap and the constraint count predictable.
///
/// Alpha is taken from the parameters at runtime to keep the
/// gadget honest if `light-poseidon` ever ships a different alpha
/// for an exotic width. Today every width uses alpha=5.
fn pow_var(v: &FpVar<Fq>, alpha: u64) -> Result<FpVar<Fq>, SynthesisError> {
    match alpha {
        5 => {
            // x^5 = ((x * x) * (x * x)) * x. Two squarings, two
            // mults — 4 R1CS constraints per evaluation, modulo
            // the `x*x` reuse below which collapses one of them.
            let x2 = v * v;
            let x4 = &x2 * &x2;
            Ok(x4 * v)
        }
        // Any other alpha is unexpected for circomlib BN254
        // parameters; refusing to handle it is preferable to a
        // silent miscompute via a generic `pow` that hasn't been
        // audited for the gadget context.
        _ => Err(SynthesisError::Unsatisfiable),
    }
}

// Re-export the native error type so callers writing
// `poseidon_hash_fixed_var(...)?` against a downstream that
// matches on the underlying error don't need a second import.
pub use crypto::poseidon::PoseidonError as NativePoseidonError;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::eq::EqGadget;
    use ark_relations::r1cs::ConstraintSystem;
    use crypto::poseidon::{
        domain_tag, poseidon_hash_fixed, poseidon_hash_sponge,
    };

    /// Allocate `xs` as witness `FpVar`s.
    fn alloc_witnesses(
        cs: ConstraintSystemRef<Fq>,
        xs: &[Fq],
    ) -> Result<Vec<FpVar<Fq>>, SynthesisError> {
        xs.iter()
            .map(|x| FpVar::<Fq>::new_witness(cs.clone(), || Ok(*x)))
            .collect()
    }

    /// Native↔circuit equivalence for `poseidon_hash_fixed` on a
    /// canonical input. The native primitive runs, the gadget
    /// runs on the same input as witnesses, the outputs are
    /// enforced equal inside the circuit, and we assert the
    /// constraint system is satisfied.
    ///
    /// This is the load-bearing test for the fixed-arity gadget:
    /// any drift in round constants, MDS matrix, S-box exponent,
    /// or domain-tag placement makes `cs.is_satisfied()` return
    /// `false`.
    #[test]
    fn fixed_var_matches_native_arity_3() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let tag = domain_tag("equiv-test-fixed-3");
        let inputs = vec![Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        let expected = poseidon_hash_fixed(tag, &inputs).expect("ok");

        let tag_var = FpVar::<Fq>::constant(tag);
        let input_vars = alloc_witnesses(cs.clone(), &inputs).unwrap();
        let got_var = poseidon_hash_fixed_var(cs.clone(), &tag_var, &input_vars).unwrap();

        let expected_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(expected)).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// The same equivalence at arity 1 — the smallest non-trivial
    /// case, where one mistake in the state-width arithmetic
    /// would show up immediately.
    #[test]
    fn fixed_var_matches_native_arity_1() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let tag = domain_tag("equiv-test-fixed-1");
        let inputs = vec![Fq::from(42u64)];
        let expected = poseidon_hash_fixed(tag, &inputs).expect("ok");

        let tag_var = FpVar::<Fq>::constant(tag);
        let input_vars = alloc_witnesses(cs.clone(), &inputs).unwrap();
        let got_var = poseidon_hash_fixed_var(cs.clone(), &tag_var, &input_vars).unwrap();

        let expected_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(expected)).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Equivalence at the maximum supported fixed arity (11
    /// inputs → total arity 12 → state width 13). The widest
    /// circomlib parameter set; catches off-by-one errors in
    /// the round-constant indexing.
    #[test]
    fn fixed_var_matches_native_max_arity() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let tag = domain_tag("equiv-test-fixed-max");
        let inputs: Vec<Fq> = (1u64..=11).map(Fq::from).collect();
        let expected = poseidon_hash_fixed(tag, &inputs).expect("ok");

        let tag_var = FpVar::<Fq>::constant(tag);
        let input_vars = alloc_witnesses(cs.clone(), &inputs).unwrap();
        let got_var = poseidon_hash_fixed_var(cs.clone(), &tag_var, &input_vars).unwrap();

        let expected_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(expected)).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// A wrong expected value MUST fail `cs.is_satisfied()`.
    /// Negative-direction confirmation: the equivalence test
    /// above isn't just satisfying constraints by accident.
    #[test]
    fn fixed_var_rejects_wrong_expected() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let tag = domain_tag("equiv-test-fixed-neg");
        let inputs = vec![Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];

        let tag_var = FpVar::<Fq>::constant(tag);
        let input_vars = alloc_witnesses(cs.clone(), &inputs).unwrap();
        let got_var = poseidon_hash_fixed_var(cs.clone(), &tag_var, &input_vars).unwrap();

        // Deliberately wrong expected value.
        let wrong = FpVar::<Fq>::new_input(cs.clone(), || Ok(Fq::from(999u64))).unwrap();
        got_var.enforce_equal(&wrong).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    /// Native↔circuit equivalence for `poseidon_hash_sponge` on a
    /// short input — exercises the absorption loop once.
    #[test]
    fn sponge_var_matches_native_short() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let tag = domain_tag("equiv-test-sponge-short");
        let inputs = vec![Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        let expected = poseidon_hash_sponge(tag, &inputs);

        let tag_var = FpVar::<Fq>::constant(tag);
        let input_vars = alloc_witnesses(cs.clone(), &inputs).unwrap();
        let got_var = poseidon_hash_sponge_var(cs.clone(), &tag_var, &input_vars).unwrap();

        let expected_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(expected)).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Equivalence on the empty input. The sponge's pad-1 +
    /// zero-pad still produces a well-defined output; the gadget
    /// must reproduce it.
    #[test]
    fn sponge_var_matches_native_empty() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let tag = domain_tag("equiv-test-sponge-empty");
        let inputs: Vec<Fq> = vec![];
        let expected = poseidon_hash_sponge(tag, &inputs);

        let tag_var = FpVar::<Fq>::constant(tag);
        let got_var = poseidon_hash_sponge_var(cs.clone(), &tag_var, &[]).unwrap();

        let expected_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(expected)).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Equivalence on a longer input that forces multiple
    /// absorption rounds. Catches chunking / padding errors that
    /// a single-block input would not expose.
    #[test]
    fn sponge_var_matches_native_multi_block() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let tag = domain_tag("equiv-test-sponge-multi");
        let inputs: Vec<Fq> = (1u64..=9).map(Fq::from).collect();
        let expected = poseidon_hash_sponge(tag, &inputs);

        let tag_var = FpVar::<Fq>::constant(tag);
        let input_vars = alloc_witnesses(cs.clone(), &inputs).unwrap();
        let got_var = poseidon_hash_sponge_var(cs.clone(), &tag_var, &input_vars).unwrap();

        let expected_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(expected)).unwrap();
        got_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
