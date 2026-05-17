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
#[derive(Clone, Debug)]
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

// --- wire-form inputs --------------------------------------------------
//
// The struct below is the JSON-shaped twin of `PedersenOpensTo::new`'s
// argument list. It lives next to the circuit (not in `prover-server` or
// `prover-wasm`) so the two transport crates pick up I/O changes in one
// place. Field elements cross as base-10 decimal strings — same convention
// `crates/crypto-wasm` already uses at the boundary.

/// Wire-form inputs for the `pedersen_opens_to` circuit.
///
/// Field elements are base-10 decimal strings. The shape mirrors
/// `PedersenOpensTo::new`: three public inputs (the commitment and
/// the claimed first value) plus two witnesses (the stream and the
/// blinding).
///
/// This struct is consumed by:
///
/// - **`prover-server`** — deserialized from the HTTP request body.
/// - **`prover-wasm`** — deserialized from a JSON string the JS
///   caller hands in.
///
/// Both transports parse, validate via [`TryFrom`], call
/// `prover::prove`, and return the proof bytes. They do not
/// re-define this shape; if the I/O contract changes, this is the
/// one place to change it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PedersenOpensToInputs {
    /// Commitment x-coordinate, decimal string.
    pub commitment_x: String,
    /// Commitment y-coordinate, decimal string.
    pub commitment_y: String,
    /// The value the prover claims `stream[0]` equals, decimal string.
    pub claimed_first_value: String,
    /// The committed stream, exactly `STREAM_LEN` decimal strings.
    pub stream: [String; STREAM_LEN],
    /// The Pedersen blinding scalar, decimal string in `Fr`.
    pub blinding: String,
}

/// Errors from parsing wire-form inputs into a typed circuit
/// instance. Each variant pins one boundary failure mode so the
/// HTTP / WASM caller can surface a useful message.
#[derive(Debug, thiserror::Error)]
pub enum InputsError {
    /// A field-element decimal string failed to parse. The
    /// `field` names the offending input slot.
    #[error("field {field}: not a non-negative base-10 integer")]
    BadFieldDecimal { field: &'static str },

    /// A scalar (in `Fr`) decimal string failed to parse.
    #[error("scalar {field}: not a non-negative base-10 integer")]
    BadScalarDecimal { field: &'static str },

    /// A point's coordinates pair, taken together, does not land
    /// on the Baby Jubjub curve or in the prime-order subgroup.
    /// The wire decoder enforces this so off-curve / small-
    /// subgroup commitments are rejected before any circuit math
    /// runs.
    #[error("commitment: not a valid Baby Jubjub point: {0}")]
    InvalidCommitment(String),
}

/// Parse a base-10 decimal string into an `Fq` element. Rejects
/// negative signs, empty strings, or non-digit characters —
/// matching the convention `crates/crypto-wasm` already pins.
fn parse_fq(s: &str, field: &'static str) -> Result<Fq, InputsError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(InputsError::BadFieldDecimal { field });
    }
    s.parse::<Fq>()
        .map_err(|_| InputsError::BadFieldDecimal { field })
}

/// Parse a base-10 decimal string into an `Fr` (scalar field)
/// element. Same digit-shape gate as `parse_fq`.
fn parse_fr(s: &str, field: &'static str) -> Result<Fr, InputsError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(InputsError::BadScalarDecimal { field });
    }
    s.parse::<Fr>()
        .map_err(|_| InputsError::BadScalarDecimal { field })
}

impl TryFrom<PedersenOpensToInputs> for PedersenOpensTo {
    type Error = InputsError;

    fn try_from(i: PedersenOpensToInputs) -> Result<Self, Self::Error> {
        // Parse and validate the commitment as a real curve point
        // through the existing wire decoder. Off-curve and small-
        // subgroup inputs come back as typed errors; the gadget
        // does NOT re-validate, so this is the security-relevant
        // gate.
        let commitment = crypto::babyjub::point_from_strings(
            &i.commitment_x,
            &i.commitment_y,
        )
        .map_err(|e| InputsError::InvalidCommitment(e.to_string()))?;

        // Parse the public claimed_first_value.
        let claimed_first_value = parse_fq(&i.claimed_first_value, "claimed_first_value")?;

        // Parse the stream witnesses. Stable error attribution by
        // synthesizing a `stream[i]` field name; this needs a
        // small leak to `&'static str` via `Box::leak`. The leak
        // is one-shot per malformed input and the boundary is the
        // failure path, so the cost is fine.
        let mut stream_fq: Vec<Fq> = Vec::with_capacity(STREAM_LEN);
        for (idx, s) in i.stream.iter().enumerate() {
            // Stable field name "stream[N]" without allocation:
            // we need a `'static` lifetime for the error variant,
            // and the index is bounded by STREAM_LEN so we can
            // use a const lookup table.
            let field_name = stream_field_name(idx);
            stream_fq.push(parse_fq(s, field_name)?);
        }
        let stream: [Fq; STREAM_LEN] = stream_fq
            .try_into()
            .expect("STREAM_LEN elements pushed above");

        // Parse the blinding scalar.
        let blinding = parse_fr(&i.blinding, "blinding")?;

        Ok(PedersenOpensTo::new(
            commitment,
            claimed_first_value,
            stream,
            blinding,
        ))
    }
}

/// Static `&'static str` names for each `stream[i]` slot. Lets
/// `InputsError::BadFieldDecimal` carry a stable field-attribution
/// string without leaking heap allocations on the failure path.
const STREAM_FIELD_NAMES: [&str; STREAM_LEN] = [
    "stream[0]",
    "stream[1]",
    "stream[2]",
    "stream[3]",
    "stream[4]",
    "stream[5]",
    "stream[6]",
    "stream[7]",
    "stream[8]",
];

fn stream_field_name(idx: usize) -> &'static str {
    STREAM_FIELD_NAMES[idx]
}

/// Extract the verifier-side public-input vector from
/// `PedersenOpensToInputs` *without* building the full circuit.
/// Used by the HTTP / WASM verify paths where the caller has the
/// proof + public inputs but no witness.
///
/// Returns the inputs in the order the circuit's
/// `generate_constraints` allocates them: `[commitment_x,
/// commitment_y, claimed_first_value]`. A verifier that calls
/// `prover::verify(vk, &public_inputs, &proof)` MUST consume this
/// exact ordering.
///
/// **Subset shape.** Takes a separate `PedersenOpensToPublicInputs`
/// struct rather than the full witness-bearing `Inputs` — the
/// verifier doesn't have the witness, so requiring it would force
/// callers to fabricate dummy values.
pub fn public_inputs_from(
    p: &PedersenOpensToPublicInputs,
) -> Result<Vec<Fq>, InputsError> {
    // Re-validate the commitment at the verifier boundary too —
    // an attacker who controls the wire could feed a malformed
    // pair, and we want the typed error rather than a panic in
    // arkworks' internals.
    let _ = crypto::babyjub::point_from_strings(&p.commitment_x, &p.commitment_y)
        .map_err(|e| InputsError::InvalidCommitment(e.to_string()))?;

    let cx = parse_fq(&p.commitment_x, "commitment_x")?;
    let cy = parse_fq(&p.commitment_y, "commitment_y")?;
    let cv = parse_fq(&p.claimed_first_value, "claimed_first_value")?;
    Ok(vec![cx, cy, cv])
}

/// Public-input-only subset of [`PedersenOpensToInputs`]. The
/// shape the verifier consumes: no witness, just what the
/// commitment and the claim look like on the wire.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PedersenOpensToPublicInputs {
    /// Commitment x-coordinate, decimal string.
    pub commitment_x: String,
    /// Commitment y-coordinate, decimal string.
    pub commitment_y: String,
    /// The value the prover claims `stream[0]` equals, decimal string.
    pub claimed_first_value: String,
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

    // --- wire-form input tests --------------------------------------

    /// Round-trip an honest fixture through the wire form:
    /// JSON-shape inputs → `TryFrom` → typed circuit → satisfied
    /// constraint system. The load-bearing test for the parsing
    /// layer.
    #[test]
    fn inputs_try_from_builds_satisfiable_circuit() {
        use ark_ff::PrimeField;

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

        let inputs = PedersenOpensToInputs {
            commitment_x: commitment.x.into_bigint().to_string(),
            commitment_y: commitment.y.into_bigint().to_string(),
            claimed_first_value: stream[0].into_bigint().to_string(),
            stream: [
                stream[0].into_bigint().to_string(),
                stream[1].into_bigint().to_string(),
                stream[2].into_bigint().to_string(),
                stream[3].into_bigint().to_string(),
                stream[4].into_bigint().to_string(),
                stream[5].into_bigint().to_string(),
                stream[6].into_bigint().to_string(),
                stream[7].into_bigint().to_string(),
                stream[8].into_bigint().to_string(),
            ],
            blinding: {
                use ark_ff::PrimeField;
                blinding.into_bigint().to_string()
            },
        };

        let circuit: PedersenOpensTo = inputs.try_into().expect("parse ok");
        let cs = ConstraintSystem::<Fq>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// A garbage commitment coordinate gets caught at the wire
    /// decoder, before any circuit math runs. Surfaces as
    /// `InvalidCommitment`.
    #[test]
    fn inputs_try_from_rejects_off_curve_commitment() {
        let inputs = PedersenOpensToInputs {
            commitment_x: "1".to_string(),
            commitment_y: "1".to_string(), // not on Baby Jubjub
            claimed_first_value: "10".to_string(),
            stream: std::array::from_fn(|_| "0".to_string()),
            blinding: "1".to_string(),
        };
        let result: Result<PedersenOpensTo, _> = inputs.try_into();
        assert!(matches!(result, Err(InputsError::InvalidCommitment(_))));
    }

    /// A non-decimal string in the stream MUST come back as
    /// `BadFieldDecimal`, naming the specific slot that failed.
    #[test]
    fn inputs_try_from_rejects_bad_stream_decimal() {
        // Need a valid commitment so we get past the wire decoder
        // and into the stream-parsing layer.
        let stream: [Fq; STREAM_LEN] = [Fq::from(0u64); STREAM_LEN];
        let commitment = native_commit(&stream, Fr::from(1u64));
        use ark_ff::PrimeField;

        let mut stream_wire: [String; STREAM_LEN] =
            std::array::from_fn(|_| "0".to_string());
        stream_wire[3] = "not-a-number".to_string();

        let inputs = PedersenOpensToInputs {
            commitment_x: commitment.x.into_bigint().to_string(),
            commitment_y: commitment.y.into_bigint().to_string(),
            claimed_first_value: "0".to_string(),
            stream: stream_wire,
            blinding: "1".to_string(),
        };
        let result: Result<PedersenOpensTo, _> = inputs.try_into();
        match result {
            Err(InputsError::BadFieldDecimal { field }) => {
                assert_eq!(field, "stream[3]");
            }
            other => panic!("expected BadFieldDecimal {{ field: stream[3] }}, got {other:?}"),
        }
    }

    /// `public_inputs_from` extracts the verifier-side input
    /// vector in the exact order the circuit allocates them:
    /// `[commitment_x, commitment_y, claimed_first_value]`.
    /// Pins the verifier interface from the wire form.
    #[test]
    fn public_inputs_from_returns_inputs_in_circuit_order() {
        use ark_ff::PrimeField;

        let stream: [Fq; STREAM_LEN] = [Fq::from(10u64); STREAM_LEN];
        let commitment = native_commit(&stream, Fr::from(7u64));
        let public = PedersenOpensToPublicInputs {
            commitment_x: commitment.x.into_bigint().to_string(),
            commitment_y: commitment.y.into_bigint().to_string(),
            claimed_first_value: "10".to_string(),
        };

        let public_inputs = public_inputs_from(&public).expect("ok");
        assert_eq!(public_inputs.len(), 3);
        assert_eq!(public_inputs[0], commitment.x);
        assert_eq!(public_inputs[1], commitment.y);
        assert_eq!(public_inputs[2], Fq::from(10u64));
    }

    /// JSON round-trip: serialize an `Inputs`, deserialize it
    /// back, the result deserialized identical. Pins the
    /// wire format the HTTP and WASM transports will marshal
    /// in/out of.
    #[test]
    fn inputs_json_roundtrip() {
        let inputs = PedersenOpensToInputs {
            commitment_x: "1".to_string(),
            commitment_y: "2".to_string(),
            claimed_first_value: "3".to_string(),
            stream: std::array::from_fn(|i| (i as u64).to_string()),
            blinding: "42".to_string(),
        };

        let json = serde_json::to_string(&inputs).expect("ser");
        let back: PedersenOpensToInputs = serde_json::from_str(&json).expect("deser");

        assert_eq!(back.commitment_x, inputs.commitment_x);
        assert_eq!(back.commitment_y, inputs.commitment_y);
        assert_eq!(back.claimed_first_value, inputs.claimed_first_value);
        assert_eq!(back.stream, inputs.stream);
        assert_eq!(back.blinding, inputs.blinding);
    }
}
