//! Circuit: prove a Pedersen commitment opens to a stream whose
//! first element equals a publicly-known value.
//!
//! ## The claim
//!
//! The prover knows a stream `[x_0, x_1, ..., x_{N-1}]` and a
//! blinding `r` such that:
//!
//! ```text
//! commitment = Σ_i x_i · G_i + r · H
//! x_0        = claimed_first_value
//! ```
//!
//! The verifier learns nothing about `x_1..x_{N-1}` or `r` —
//! only that the commitment opens to *some* stream, and that
//! whatever stream it is, the first element equals the claimed
//! value.
//!
//! ## Why this is the first circuit
//!
//! Smallest non-trivial protocol claim that meaningfully uses
//! the gadget substrate:
//!
//! - **Exercises the Pedersen gadget**, the heaviest gadget by
//!   constraint count. If trusted setup, prove, and verify
//!   work for this circuit, they'll work for everything
//!   lighter.
//! - **No signature math.** Pedersen alone — no curve scalar-
//!   mul beyond what the commit gadget already does. Keeps the
//!   plumbing minimal so prover-crate bugs are visible.
//! - **Public-input count well under Sui's cap.** Three field
//!   elements: two commitment coordinates plus the claimed
//!   value. No signal-hash compression needed.
//! - **Real protocol shape.** "Commit to a stream, later reveal
//!   one element" is a building block any envelope-style flow
//!   ends up using.
//!
//! ## Public inputs (3 of 8)
//!
//! | Position | Meaning |
//! |----------|---------|
//! | `commitment_x` | x-coordinate of the Pedersen commitment |
//! | `commitment_y` | y-coordinate of the Pedersen commitment |
//! | `claimed_first_value` | the value the prover claims `x_0` equals |
//!
//! Room for 5 more public inputs in future variants (range
//! constraints, position selection, etc.) without hitting Sui's
//! 8-element cap.
//!
//! ## Stream length
//!
//! Pinned at `N = 9`. Matches the `text-utf8-v1` encoding's
//! canonical size. A future variant may parameterize over `N`,
//! but each `N` is its own circuit with its own PK / VK.

use ark_ed_on_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crypto::babyjub::{EdwardsAffine, Fq};
use gadgets::babyjub::{alloc_point_witness, commit_var};

/// Pinned stream length for this circuit. Same as the
/// `text-utf8-v1` encoding's output size.
pub const STREAM_LEN: usize = 9;

/// The circuit. All fields are `Option<T>` so the same struct can
/// be instantiated for trusted setup (`empty()`) and for actual
/// proving (with real witness values).
///
/// **Public** fields are the three public inputs the verifier
/// sees: the commitment's coordinates and the claimed first
/// element.
///
/// **Private** fields are the witness: the full stream and the
/// blinding scalar. Both are `Option`s so the setup path can pass
/// `None`-style dummies via `empty()`.
#[derive(Clone)]
pub struct PedersenOpensTo {
    // --- public inputs ---
    /// Commitment x-coordinate. Public.
    pub commitment_x: Option<Fq>,
    /// Commitment y-coordinate. Public.
    pub commitment_y: Option<Fq>,
    /// The value the prover claims equals `stream[0]`. Public.
    pub claimed_first_value: Option<Fq>,

    // --- witnesses ---
    /// The committed stream. Witness.
    pub stream: Option<[Fq; STREAM_LEN]>,
    /// The Pedersen blinding scalar. Witness.
    pub blinding: Option<Fr>,
}

impl PedersenOpensTo {
    /// Construct a fully-populated circuit instance for proving.
    /// All witnesses and public inputs are bound to concrete
    /// values; the resulting circuit is ready to be passed to
    /// `Groth16::prove`.
    pub fn new(
        commitment: EdwardsAffine,
        claimed_first_value: Fq,
        stream: [Fq; STREAM_LEN],
        blinding: Fr,
    ) -> Self {
        Self {
            commitment_x: Some(commitment.x),
            commitment_y: Some(commitment.y),
            claimed_first_value: Some(claimed_first_value),
            stream: Some(stream),
            blinding: Some(blinding),
        }
    }

    /// Construct a circuit instance for trusted setup. Witness
    /// slots carry dummy values that satisfy structural
    /// constraints (correct length, valid field element); the
    /// setup path only inspects the constraint shape, not the
    /// values.
    ///
    /// We pick `stream = [0; N]`, `blinding = 1`. The resulting
    /// dummy commitment is `Σ 0·G_i + 1·H = H`, which lives on
    /// the curve and in the prime-order subgroup, so the
    /// allocation path succeeds. `claimed_first_value` is `0`,
    /// which equals `stream[0]`, so the equality constraint is
    /// satisfiable. The setup does not actually evaluate these
    /// to a useful proof — it just needs every gadget's
    /// constraint graph to be reachable.
    pub fn empty() -> Self {
        // Dummy stream and blinding chosen so that the dummy
        // public inputs (computed below) satisfy every
        // structural constraint.
        let stream = [Fq::from(0u64); STREAM_LEN];
        let blinding = Fr::from(1u64);
        let commitment = crypto::babyjub::commit(&stream, blinding);
        let claimed_first_value = stream[0];

        Self::new(commitment, claimed_first_value, stream, blinding)
    }
}

impl ConstraintSynthesizer<Fq> for PedersenOpensTo {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fq>,
    ) -> Result<(), SynthesisError> {
        // --- allocate public inputs ---
        // Order matters: the same order is used when serializing
        // public inputs for the verifier. `new_input` in
        // arkworks places the value in the public-input slot of
        // the witness assignment.
        let commitment_x_var = FpVar::<Fq>::new_input(cs.clone(), || {
            self.commitment_x.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let commitment_y_var = FpVar::<Fq>::new_input(cs.clone(), || {
            self.commitment_y.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let claimed_first_value_var = FpVar::<Fq>::new_input(cs.clone(), || {
            self.claimed_first_value
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // --- allocate witnesses ---
        // The stream becomes N FpVar witnesses; the blinding
        // becomes an Fr value threaded into commit_var (which
        // allocates the bit decomposition internally).
        let stream_vals: [Fq; STREAM_LEN] =
            self.stream.unwrap_or([Fq::from(0u64); STREAM_LEN]);
        let stream_vars: [FpVar<Fq>; STREAM_LEN] = {
            let v: Vec<FpVar<Fq>> = stream_vals
                .iter()
                .map(|x| FpVar::<Fq>::new_witness(cs.clone(), || Ok(*x)))
                .collect::<Result<Vec<_>, _>>()?;
            v.try_into()
                .map_err(|_| SynthesisError::Unsatisfiable)?
        };
        let blinding = self.blinding.unwrap_or(Fr::from(1u64));

        // --- constraint 1: commitment matches ---
        let computed_commitment = commit_var(cs.clone(), &stream_vars, blinding)?;
        computed_commitment.x.enforce_equal(&commitment_x_var)?;
        computed_commitment.y.enforce_equal(&commitment_y_var)?;

        // --- constraint 2: claimed first value matches ---
        stream_vars[0].enforce_equal(&claimed_first_value_var)?;

        // The `alloc_point_witness` import is unused in this
        // circuit; flagged here so a future reviewer sees the
        // path was considered (we could allocate the commitment
        // as a single `BabyJubAffineVar` witness, but breaking
        // it into x and y is what matches Sui's public-input
        // layout — Move-side verifiers see field elements, not
        // gadget points).
        let _ = alloc_point_witness;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use crypto::babyjub::commit as native_commit;

    /// The honest path: a real stream and blinding, the
    /// commitment computed correctly natively, the claimed value
    /// matches `stream[0]`. The constraint system must be
    /// satisfied.
    ///
    /// This is the load-bearing positive test: a Groth16 proof
    /// generated against this exact witness will verify.
    #[test]
    fn honest_witness_satisfies() {
        let cs = ConstraintSystem::<Fq>::new_ref();

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
        let commitment = native_commit(&stream, blinding);

        let circuit = PedersenOpensTo::new(commitment, stream[0], stream, blinding);
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    /// A prover who claims the wrong first value MUST fail. The
    /// claim is wired through `enforce_equal`, so a mismatch
    /// unsatisfies the system regardless of whether the
    /// commitment is itself correct.
    #[test]
    fn wrong_claimed_value_unsatisfies() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let stream: [Fq; STREAM_LEN] = [Fq::from(10u64); STREAM_LEN];
        let blinding = Fr::from(7u64);
        let commitment = native_commit(&stream, blinding);

        // Real stream[0] = 10, prover claims 99.
        let circuit = PedersenOpensTo::new(commitment, Fq::from(99u64), stream, blinding);
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    /// A prover who supplies a stream that doesn't open to the
    /// committed point MUST fail. Pins that the commitment
    /// constraint is wired through `commit_var` properly.
    #[test]
    fn wrong_stream_unsatisfies() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let real_stream: [Fq; STREAM_LEN] = [Fq::from(10u64); STREAM_LEN];
        let blinding = Fr::from(7u64);
        let commitment = native_commit(&real_stream, blinding);

        // Different stream — same length and shape, different
        // values. Prover keeps `stream[0]` consistent with the
        // claim to isolate the commitment check.
        let lying_stream: [Fq; STREAM_LEN] = [
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

        let circuit = PedersenOpensTo::new(
            commitment,
            lying_stream[0],
            lying_stream,
            blinding,
        );
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    /// A prover who supplies a wrong blinding MUST fail, even if
    /// the stream is correct.
    #[test]
    fn wrong_blinding_unsatisfies() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let stream: [Fq; STREAM_LEN] = [Fq::from(10u64); STREAM_LEN];
        let real_blinding = Fr::from(7u64);
        let commitment = native_commit(&stream, real_blinding);

        let wrong_blinding = Fr::from(8u64);
        let circuit = PedersenOpensTo::new(commitment, stream[0], stream, wrong_blinding);
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    /// `empty()` produces a satisfiable instance. This is the
    /// path trusted setup takes: instantiate the circuit with
    /// dummy values, extract constraint shape. If `empty()` is
    /// unsatisfiable, setup would still succeed (it doesn't care
    /// about witness satisfaction), but a sanity check here
    /// catches dummy-value mismatches that would surface as
    /// confusing prover errors later.
    #[test]
    fn empty_is_satisfiable() {
        let cs = ConstraintSystem::<Fq>::new_ref();
        PedersenOpensTo::empty().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
