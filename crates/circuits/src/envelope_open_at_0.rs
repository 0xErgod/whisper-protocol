//! Circuit: prove the prover is the recipient of an envelope and
//! reveal the first element of the recovered plaintext.
//!
//! See [`specs/zk/circuit-envelope-open-at-0.md`](../../specs/zk/circuit-envelope-open-at-0.md)
//! for the full claim, the public-input layout, and the
//! worked-example fixture.
//!
//! ## Shape at a glance
//!
//! ```text
//! Public inputs:  [signal, claimed_value]
//! Witnesses:      recipient_sk, sender_pk, recipient_pk,
//!                 envelope_id, ciphertext[9], mac_tag
//! Enforced:       (a) recipient_pk == recipient_sk · G
//!                 (b) mac(key_mac, ciphertext) == mac_tag
//!                 (c) decrypt(key_enc, ciphertext)[0] == claimed_value
//!                 (d) signal == sponge(envelope fields)
//! ```
//!
//! where `key_enc` and `key_mac` are derived from the ECDH
//! shared point and the protocol's pinned role tags.

use ark_ed_on_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crypto::babyjub::{EdwardsAffine, Fq};
use crypto::poseidon::domain_tag;
use gadgets::babyjub::{
    alloc_point_witness, decrypt_var, kdf_derive_var, mac_var, pk_from_sk_var, scalar_mul_var,
};
use gadgets::poseidon::poseidon_hash_sponge_var;

/// Pinned stream length for this circuit. Same as
/// `text-utf8-v1`'s output size and same as `pedersen_opens_to`
/// — keeps the protocol's circuit family on one stream shape
/// for now.
pub const STREAM_LEN: usize = 9;

/// The position of the plaintext slot this circuit variant
/// reveals. Compile-time-fixed; revealing a different position
/// is a different circuit.
pub const POSITION: usize = 0;

/// Domain tag for the signal-hash sponge. Pinned in
/// [`specs/zk/circuit-envelope-open-at-0.md § Signal construction`](../../specs/zk/circuit-envelope-open-at-0.md);
/// changing it breaks compatibility with the Move-side
/// verifier's signal reconstruction.
pub const SIGNAL_DOMAIN: &str = "envelope-open-signal";

/// Role tags the envelope's KDF context uses, re-exported here
/// in their string form so the circuit references the same
/// domain as the native side
/// (`protocol::envelope::{CIPHER_ROLE, MAC_ROLE}`).
const CIPHER_ROLE: &str = "envelope-cipher-key";
const MAC_ROLE: &str = "envelope-mac-key";

/// The circuit. Public-facing fields are the verifier's
/// `[signal, claimed_value]`; everything else is a witness.
/// All fields are `Option<T>` so `empty()` can supply dummies
/// for the trusted-setup pass.
#[derive(Clone, Debug)]
pub struct EnvelopeOpenAt0 {
    // --- public inputs ---
    pub signal: Option<Fq>,
    pub claimed_value: Option<Fq>,

    // --- witnesses ---
    pub recipient_sk: Option<Fr>,
    pub sender_pk: Option<EdwardsAffine>,
    pub recipient_pk: Option<EdwardsAffine>,
    pub envelope_id: Option<Fq>,
    pub ciphertext: Option<[Fq; STREAM_LEN]>,
    pub mac_tag: Option<Fq>,
}

impl EnvelopeOpenAt0 {
    /// Construct a fully-populated circuit for proving. All
    /// witnesses and public inputs are bound to concrete
    /// values; the resulting circuit is ready for
    /// `Groth16::prove`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signal: Fq,
        claimed_value: Fq,
        recipient_sk: Fr,
        sender_pk: EdwardsAffine,
        recipient_pk: EdwardsAffine,
        envelope_id: Fq,
        ciphertext: [Fq; STREAM_LEN],
        mac_tag: Fq,
    ) -> Self {
        Self {
            signal: Some(signal),
            claimed_value: Some(claimed_value),
            recipient_sk: Some(recipient_sk),
            sender_pk: Some(sender_pk),
            recipient_pk: Some(recipient_pk),
            envelope_id: Some(envelope_id),
            ciphertext: Some(ciphertext),
            mac_tag: Some(mac_tag),
        }
    }

    /// Construct a circuit instance for trusted setup. Witness
    /// slots carry dummy values that satisfy structural
    /// constraints (the dummy envelope is a real native seal
    /// between two dummy keypairs); setup only inspects the
    /// constraint graph, but having a satisfiable dummy
    /// instance makes `empty_is_satisfiable` a useful sanity
    /// test.
    pub fn empty() -> Self {
        use crypto::babyjub::{keypair_from_seed, Seed};

        // Two dummy keypairs. Seeds chosen so the resulting
        // public keys are NOT the canonical Alice/Bob from
        // protocol-envelope.md (this is a setup dummy, not the
        // fixture).
        let mut seed_a = [0u8; 64];
        seed_a[0] = 0xA;
        let mut seed_b = [0u8; 64];
        seed_b[0] = 0xB;
        let (sk_a, pk_a) = keypair_from_seed(&Seed::from_bytes(seed_a));
        let (sk_b, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));

        // A dummy envelope sealed by sk_a to pk_b. Plaintext
        // length matches STREAM_LEN. The plaintext's first
        // element is 0 so claimed_value can also be 0 and the
        // equality constraint is satisfiable.
        let plaintext: [Fq; STREAM_LEN] = [Fq::from(0u64); STREAM_LEN];
        let envelope = protocol_envelope_seal(
            &sk_a,
            &pk_a,
            &pk_b,
            Fq::from(1u64),
            &plaintext,
        );

        let claimed_value = plaintext[POSITION];
        let signal = compute_signal_native(
            &envelope.sender_pk,
            &envelope.recipient_pk,
            envelope.envelope_id,
            envelope.mac_tag,
            &envelope.ciphertext,
        );

        let ct_array: [Fq; STREAM_LEN] = envelope
            .ciphertext
            .clone()
            .try_into()
            .expect("dummy plaintext is STREAM_LEN, cipher is length-preserving");

        Self::new(
            signal,
            claimed_value,
            *sk_b.scalar(),
            envelope.sender_pk,
            envelope.recipient_pk,
            envelope.envelope_id,
            ct_array,
            envelope.mac_tag,
        )
    }
}

impl ConstraintSynthesizer<Fq> for EnvelopeOpenAt0 {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fq>,
    ) -> Result<(), SynthesisError> {
        // ---- public inputs (in pinned order) ----
        let signal_var = FpVar::<Fq>::new_input(cs.clone(), || {
            self.signal.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let claimed_value_var = FpVar::<Fq>::new_input(cs.clone(), || {
            self.claimed_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ---- witnesses ----
        let recipient_sk = self.recipient_sk.unwrap_or(Fr::from(1u64));
        let sender_pk = self.sender_pk.unwrap_or_else(default_dummy_point);
        let recipient_pk = self.recipient_pk.unwrap_or_else(default_dummy_point);
        let envelope_id_val = self.envelope_id.unwrap_or(Fq::from(0u64));
        let ciphertext_vals = self.ciphertext.unwrap_or([Fq::from(0u64); STREAM_LEN]);
        let mac_tag_val = self.mac_tag.unwrap_or(Fq::from(0u64));

        let sender_pk_var = alloc_point_witness(cs.clone(), sender_pk)?;
        let recipient_pk_var = alloc_point_witness(cs.clone(), recipient_pk)?;
        let envelope_id_var =
            FpVar::<Fq>::new_witness(cs.clone(), || Ok(envelope_id_val))?;
        let mac_tag_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(mac_tag_val))?;

        let ciphertext_vars: [FpVar<Fq>; STREAM_LEN] = {
            let v: Vec<FpVar<Fq>> = ciphertext_vals
                .iter()
                .map(|x| FpVar::<Fq>::new_witness(cs.clone(), || Ok(*x)))
                .collect::<Result<Vec<_>, _>>()?;
            v.try_into()
                .map_err(|_| SynthesisError::Unsatisfiable)?
        };

        // ---- Constraint (a): recipient_pk == recipient_sk · G ----
        // Load-bearing: ties the witness recipient_sk to the
        // witness recipient_pk. Without this, a malicious
        // prover could supply arbitrary (sk, recipient_pk)
        // values that produce a valid shared point with
        // sender_pk but don't actually correspond to the
        // envelope's recipient.
        let derived_recipient_pk = pk_from_sk_var(cs.clone(), recipient_sk)?;
        derived_recipient_pk.enforce_equal(&recipient_pk_var)?;

        // ---- Compute the shared point: sk_b · sender_pk ----
        let shared = scalar_mul_var(cs.clone(), recipient_sk, &sender_pk_var)?;

        // ---- Derive cipher and MAC keys ----
        let cipher_role_tag = FpVar::<Fq>::constant(domain_tag(CIPHER_ROLE));
        let mac_role_tag = FpVar::<Fq>::constant(domain_tag(MAC_ROLE));
        let key_enc = kdf_derive_var(
            cs.clone(),
            &shared,
            &[cipher_role_tag, envelope_id_var.clone()],
        )?;
        let key_mac = kdf_derive_var(
            cs.clone(),
            &shared,
            &[mac_role_tag, envelope_id_var.clone()],
        )?;

        // ---- Constraint (b): MAC verifies ----
        // computed_mac == mac_tag binds the witness mac_tag to
        // the cryptographic relation. A wrong sk or wrong
        // sender_pk yields a wrong shared → wrong key_mac →
        // wrong computed_mac.
        let computed_mac = mac_var(cs.clone(), &key_mac, &ciphertext_vars)?;
        computed_mac.enforce_equal(&mac_tag_var)?;

        // ---- Constraint (c): plaintext[POSITION] == claimed_value ----
        // Run decryption to obtain the plaintext stream, then
        // enforce equality at position POSITION (compile-time
        // 0 for this variant).
        let plaintext_vars = decrypt_var(cs.clone(), &key_enc, &ciphertext_vars)?;
        plaintext_vars[POSITION].enforce_equal(&claimed_value_var)?;

        // ---- Constraint (d): signal binds to envelope ----
        // Hash every envelope field in pinned order and check
        // against the public signal input. This is the
        // signal-hash compression pattern: the on-chain
        // verifier reconstructs `signal` from authoritative
        // envelope bytes and passes it as the public input,
        // forcing the circuit's witness envelope to match.
        let signal_domain_tag = FpVar::<Fq>::constant(domain_tag(SIGNAL_DOMAIN));
        let mut signal_inputs: Vec<FpVar<Fq>> = Vec::with_capacity(6 + STREAM_LEN);
        signal_inputs.push(sender_pk_var.x.clone());
        signal_inputs.push(sender_pk_var.y.clone());
        signal_inputs.push(recipient_pk_var.x.clone());
        signal_inputs.push(recipient_pk_var.y.clone());
        signal_inputs.push(envelope_id_var);
        signal_inputs.push(mac_tag_var);
        for c in ciphertext_vars.iter() {
            signal_inputs.push(c.clone());
        }
        let computed_signal =
            poseidon_hash_sponge_var(cs.clone(), &signal_domain_tag, &signal_inputs)?;
        computed_signal.enforce_equal(&signal_var)?;

        Ok(())
    }
}

/// Compute the signal hash natively (outside any circuit).
/// Same construction as the in-circuit version; the verifier
/// AND the prover both use this to produce the public input
/// `signal` from envelope fields.
pub fn compute_signal_native(
    sender_pk: &EdwardsAffine,
    recipient_pk: &EdwardsAffine,
    envelope_id: Fq,
    mac_tag: Fq,
    ciphertext: &[Fq],
) -> Fq {
    let mut inputs: Vec<Fq> = Vec::with_capacity(6 + ciphertext.len());
    inputs.push(sender_pk.x);
    inputs.push(sender_pk.y);
    inputs.push(recipient_pk.x);
    inputs.push(recipient_pk.y);
    inputs.push(envelope_id);
    inputs.push(mac_tag);
    inputs.extend_from_slice(ciphertext);
    crypto::poseidon::poseidon_hash_sponge(domain_tag(SIGNAL_DOMAIN), &inputs)
}

/// Native envelope seal — moved here as a private helper rather
/// than depending on the `protocol` crate. The `circuits` crate
/// can't sensibly depend on `protocol` (it would create a layer
/// inversion: `protocol` is the higher-level composition
/// crate). Instead, this helper replicates exactly the same
/// seal construction `protocol::envelope::seal` does — the
/// integration fixture cross-checks that both produce
/// identical envelopes.
fn protocol_envelope_seal(
    sender_sk: &crypto::babyjub::SecretKey,
    sender_pk: &crypto::babyjub::PublicKey,
    recipient_pk: &crypto::babyjub::PublicKey,
    envelope_id: Fq,
    plaintext: &[Fq],
) -> EnvelopeStruct {
    use crypto::babyjub::{
        encrypt as native_encrypt, kdf_derive as native_kdf, mac_compute as native_mac,
        shared_secret,
    };

    let shared = shared_secret(sender_sk, recipient_pk);
    let key_enc = native_kdf(&shared, &[domain_tag(CIPHER_ROLE), envelope_id])
        .expect("kdf context length 2");
    let key_mac = native_kdf(&shared, &[domain_tag(MAC_ROLE), envelope_id])
        .expect("kdf context length 2");
    let ciphertext = native_encrypt(key_enc, plaintext);
    let mac_tag = native_mac(key_mac, &ciphertext);

    EnvelopeStruct {
        sender_pk: *sender_pk.point(),
        recipient_pk: *recipient_pk.point(),
        envelope_id,
        ciphertext,
        mac_tag,
    }
}

/// Local envelope shape — mirrors `protocol::envelope::Envelope`
/// without creating a crate-level dependency. The fixture test
/// cross-checks identity.
struct EnvelopeStruct {
    sender_pk: EdwardsAffine,
    recipient_pk: EdwardsAffine,
    envelope_id: Fq,
    ciphertext: Vec<Fq>,
    mac_tag: Fq,
}

/// A safe dummy point for setup-time witness slots that don't
/// have real values yet. Uses the curve generator — it's
/// guaranteed on-curve and in the prime-order subgroup, so
/// `alloc_point_witness` won't trigger any structural failure.
fn default_dummy_point() -> EdwardsAffine {
    crypto::babyjub::generator()
}

// --- wire-form inputs --------------------------------------------------
//
// JSON-shaped twins of `EnvelopeOpenAt0::new`'s argument list,
// consumed identically by `prover-server` and `prover-wasm`.
// Field elements cross as decimal strings; points cross as a
// pair of decimal strings for (x, y).

/// Wire-form proving inputs for `envelope_open_at_0`. Pairs
/// with [`TryFrom`] to produce a typed circuit instance.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EnvelopeOpenAt0Inputs {
    // --- public ---
    /// Signal hash (Poseidon-sponge over envelope fields).
    pub signal: String,
    /// The value the prover claims equals `plaintext[0]`.
    pub claimed_value: String,
    // --- witness ---
    /// Recipient's secret scalar in `Fr`.
    pub recipient_sk: String,
    /// Sender public-key x-coordinate.
    pub sender_pk_x: String,
    /// Sender public-key y-coordinate.
    pub sender_pk_y: String,
    /// Recipient public-key x-coordinate.
    pub recipient_pk_x: String,
    /// Recipient public-key y-coordinate.
    pub recipient_pk_y: String,
    /// Envelope id (the per-envelope binding scalar).
    pub envelope_id: String,
    /// Ciphertext stream, exactly `STREAM_LEN` decimal strings.
    pub ciphertext: [String; STREAM_LEN],
    /// MAC tag over the ciphertext.
    pub mac_tag: String,
}

/// Public-input-only subset: the shape the verifier consumes
/// when it has a proof and the chain's authoritative envelope
/// but no witness.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EnvelopeOpenAt0PublicInputs {
    pub signal: String,
    pub claimed_value: String,
}

/// Errors from parsing wire-form inputs. Each variant pins a
/// specific boundary failure mode so the HTTP/WASM caller can
/// surface a useful message.
#[derive(Debug, thiserror::Error)]
pub enum InputsError {
    /// A field-element decimal string failed to parse.
    #[error("field {field}: not a non-negative base-10 integer")]
    BadFieldDecimal { field: &'static str },

    /// A scalar (in `Fr`) decimal string failed to parse.
    #[error("scalar {field}: not a non-negative base-10 integer")]
    BadScalarDecimal { field: &'static str },

    /// A point's coordinate pair does not land on the Baby
    /// Jubjub curve or in the prime-order subgroup.
    #[error("{field}: not a valid Baby Jubjub point: {message}")]
    InvalidPoint {
        field: &'static str,
        message: String,
    },
}

fn parse_fq(s: &str, field: &'static str) -> Result<Fq, InputsError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(InputsError::BadFieldDecimal { field });
    }
    s.parse::<Fq>()
        .map_err(|_| InputsError::BadFieldDecimal { field })
}

fn parse_fr(s: &str, field: &'static str) -> Result<Fr, InputsError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(InputsError::BadScalarDecimal { field });
    }
    s.parse::<Fr>()
        .map_err(|_| InputsError::BadScalarDecimal { field })
}

/// Static `&'static str` slot names for each `ciphertext[i]`,
/// pinned for stable error attribution without heap
/// allocation on the failure path.
const CIPHERTEXT_SLOT_NAMES: [&str; STREAM_LEN] = [
    "ciphertext[0]",
    "ciphertext[1]",
    "ciphertext[2]",
    "ciphertext[3]",
    "ciphertext[4]",
    "ciphertext[5]",
    "ciphertext[6]",
    "ciphertext[7]",
    "ciphertext[8]",
];

impl TryFrom<EnvelopeOpenAt0Inputs> for EnvelopeOpenAt0 {
    type Error = InputsError;

    fn try_from(i: EnvelopeOpenAt0Inputs) -> Result<Self, Self::Error> {
        let signal = parse_fq(&i.signal, "signal")?;
        let claimed_value = parse_fq(&i.claimed_value, "claimed_value")?;
        let recipient_sk = parse_fr(&i.recipient_sk, "recipient_sk")?;

        // Validate both points through the wire decoder
        // (off-curve / small-subgroup rejected with a typed
        // error before any circuit math runs).
        let sender_pk = crypto::babyjub::point_from_strings(&i.sender_pk_x, &i.sender_pk_y)
            .map_err(|e| InputsError::InvalidPoint {
                field: "sender_pk",
                message: e.to_string(),
            })?;
        let recipient_pk =
            crypto::babyjub::point_from_strings(&i.recipient_pk_x, &i.recipient_pk_y)
                .map_err(|e| InputsError::InvalidPoint {
                    field: "recipient_pk",
                    message: e.to_string(),
                })?;

        let envelope_id = parse_fq(&i.envelope_id, "envelope_id")?;

        let mut ct_vec: Vec<Fq> = Vec::with_capacity(STREAM_LEN);
        for (idx, s) in i.ciphertext.iter().enumerate() {
            ct_vec.push(parse_fq(s, CIPHERTEXT_SLOT_NAMES[idx])?);
        }
        let ciphertext: [Fq; STREAM_LEN] = ct_vec
            .try_into()
            .expect("STREAM_LEN elements pushed above");

        let mac_tag = parse_fq(&i.mac_tag, "mac_tag")?;

        Ok(EnvelopeOpenAt0::new(
            signal,
            claimed_value,
            recipient_sk,
            sender_pk,
            recipient_pk,
            envelope_id,
            ciphertext,
            mac_tag,
        ))
    }
}

/// Extract the verifier-side public-input vector from
/// [`EnvelopeOpenAt0PublicInputs`]. The verifier doesn't have
/// the witness; calling this function gives the
/// `prover::verify` API exactly the two `Fq` values it needs,
/// in pinned order.
pub fn public_inputs_from(
    p: &EnvelopeOpenAt0PublicInputs,
) -> Result<Vec<Fq>, InputsError> {
    let signal = parse_fq(&p.signal, "signal")?;
    let claimed_value = parse_fq(&p.claimed_value, "claimed_value")?;
    Ok(vec![signal, claimed_value])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use crypto::babyjub::{keypair_from_seed, Seed};

    /// Build the canonical Alice/Bob fixture: a real envelope
    /// for envelope id 42 with a 9-element plaintext.
    fn alice_bob_envelope_with_plaintext() -> (
        EnvelopeStruct,
        crypto::babyjub::SecretKey,
        [Fq; STREAM_LEN],
    ) {
        let mut seed_a = [0u8; 64];
        seed_a[0] = 1;
        let mut seed_b = [0u8; 64];
        seed_b[0] = 2;
        let (sk_a, pk_a) = keypair_from_seed(&Seed::from_bytes(seed_a));
        let (sk_b, pk_b) = keypair_from_seed(&Seed::from_bytes(seed_b));

        let plaintext: [Fq; STREAM_LEN] = [
            Fq::from(1u64),
            Fq::from(2u64),
            Fq::from(3u64),
            Fq::from(4u64),
            Fq::from(5u64),
            Fq::from(6u64),
            Fq::from(7u64),
            Fq::from(8u64),
            Fq::from(9u64),
        ];
        let envelope = protocol_envelope_seal(
            &sk_a,
            &pk_a,
            &pk_b,
            Fq::from(42u64),
            &plaintext,
        );
        (envelope, sk_b, plaintext)
    }

    /// Honest path: real envelope, prover holds sk_b, claims
    /// the correct first element. Constraint system MUST be
    /// satisfied.
    #[test]
    fn honest_witness_satisfies() {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let (envelope, sk_b, plaintext) = alice_bob_envelope_with_plaintext();

        let signal = compute_signal_native(
            &envelope.sender_pk,
            &envelope.recipient_pk,
            envelope.envelope_id,
            envelope.mac_tag,
            &envelope.ciphertext,
        );

        let ct: [Fq; STREAM_LEN] =
            envelope.ciphertext.clone().try_into().unwrap();

        let circuit = EnvelopeOpenAt0::new(
            signal,
            plaintext[POSITION],
            *sk_b.scalar(),
            envelope.sender_pk,
            envelope.recipient_pk,
            envelope.envelope_id,
            ct,
            envelope.mac_tag,
        );
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Claiming the wrong first value unsatisfies. The
    /// "revelation" constraint catches it.
    #[test]
    fn wrong_claimed_value_unsatisfies() {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let (envelope, sk_b, _) = alice_bob_envelope_with_plaintext();
        let signal = compute_signal_native(
            &envelope.sender_pk,
            &envelope.recipient_pk,
            envelope.envelope_id,
            envelope.mac_tag,
            &envelope.ciphertext,
        );
        let ct: [Fq; STREAM_LEN] =
            envelope.ciphertext.clone().try_into().unwrap();

        // Real plaintext[0] = 1; claim 99.
        let circuit = EnvelopeOpenAt0::new(
            signal,
            Fq::from(99u64),
            *sk_b.scalar(),
            envelope.sender_pk,
            envelope.recipient_pk,
            envelope.envelope_id,
            ct,
            envelope.mac_tag,
        );
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    /// Wrong `recipient_sk` unsatisfies. Multiple constraints
    /// can fail here — first, recipient_pk == sk · G fails
    /// because the wrong sk lands on a different pk. Second,
    /// the shared point is wrong → wrong keys → MAC fails.
    /// Either failure unsatisfies the system.
    #[test]
    fn wrong_recipient_sk_unsatisfies() {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let (envelope, _sk_b, plaintext) = alice_bob_envelope_with_plaintext();
        let signal = compute_signal_native(
            &envelope.sender_pk,
            &envelope.recipient_pk,
            envelope.envelope_id,
            envelope.mac_tag,
            &envelope.ciphertext,
        );
        let ct: [Fq; STREAM_LEN] =
            envelope.ciphertext.clone().try_into().unwrap();

        let wrong_sk = Fr::from(0xDEAD_u64);
        let circuit = EnvelopeOpenAt0::new(
            signal,
            plaintext[POSITION],
            wrong_sk,
            envelope.sender_pk,
            envelope.recipient_pk,
            envelope.envelope_id,
            ct,
            envelope.mac_tag,
        );
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    /// Tampering with `mac_tag` (in the witness) fails BOTH
    /// the MAC verify (because computed_mac no longer equals
    /// the tampered tag) AND the signal binding (because the
    /// signal includes mac_tag and the public signal was
    /// computed from the un-tampered tag).
    #[test]
    fn tampered_mac_tag_in_witness_unsatisfies() {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let (envelope, sk_b, plaintext) = alice_bob_envelope_with_plaintext();
        let signal = compute_signal_native(
            &envelope.sender_pk,
            &envelope.recipient_pk,
            envelope.envelope_id,
            envelope.mac_tag,
            &envelope.ciphertext,
        );
        let ct: [Fq; STREAM_LEN] =
            envelope.ciphertext.clone().try_into().unwrap();

        // Witness mac_tag is changed; public signal is the
        // real one (computed from the real mac_tag above).
        let tampered_mac_tag = envelope.mac_tag + Fq::from(1u64);
        let circuit = EnvelopeOpenAt0::new(
            signal,
            plaintext[POSITION],
            *sk_b.scalar(),
            envelope.sender_pk,
            envelope.recipient_pk,
            envelope.envelope_id,
            ct,
            tampered_mac_tag,
        );
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    /// Tampering with a ciphertext element fails both MAC
    /// verify and signal binding. Catches the case where a
    /// prover tries to claim about a "fake" ciphertext.
    #[test]
    fn tampered_ciphertext_in_witness_unsatisfies() {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let (envelope, sk_b, plaintext) = alice_bob_envelope_with_plaintext();
        let signal = compute_signal_native(
            &envelope.sender_pk,
            &envelope.recipient_pk,
            envelope.envelope_id,
            envelope.mac_tag,
            &envelope.ciphertext,
        );
        let mut ct: [Fq; STREAM_LEN] =
            envelope.ciphertext.clone().try_into().unwrap();
        ct[3] += Fq::from(1u64);

        let circuit = EnvelopeOpenAt0::new(
            signal,
            plaintext[POSITION],
            *sk_b.scalar(),
            envelope.sender_pk,
            envelope.recipient_pk,
            envelope.envelope_id,
            ct,
            envelope.mac_tag,
        );
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    /// Public signal that doesn't match the witness envelope
    /// unsatisfies. The signal-binding constraint catches a
    /// prover who tries to "swap" the public signal for a
    /// different envelope's hash.
    #[test]
    fn mismatched_public_signal_unsatisfies() {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let (envelope, sk_b, plaintext) = alice_bob_envelope_with_plaintext();
        let ct: [Fq; STREAM_LEN] =
            envelope.ciphertext.clone().try_into().unwrap();

        // Pass a public signal that doesn't match the
        // witness envelope.
        let wrong_signal = Fq::from(0xCAFEu64);
        let circuit = EnvelopeOpenAt0::new(
            wrong_signal,
            plaintext[POSITION],
            *sk_b.scalar(),
            envelope.sender_pk,
            envelope.recipient_pk,
            envelope.envelope_id,
            ct,
            envelope.mac_tag,
        );
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    /// `empty()` is satisfiable — the dummy envelope it builds
    /// is a real native seal, so every constraint holds. Pins
    /// that the trusted-setup path doesn't accidentally
    /// produce an unsatisfiable structural witness.
    #[test]
    fn empty_is_satisfiable() {
        let cs = ConstraintSystem::<Fq>::new_ref();
        EnvelopeOpenAt0::empty()
            .generate_constraints(cs.clone())
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    // --- wire-form input tests --------------------------------------

    /// Round-trip an honest fixture through the wire form:
    /// JSON-shape inputs → `TryFrom` → typed circuit →
    /// satisfied constraint system.
    #[test]
    fn inputs_try_from_builds_satisfiable_circuit() {
        use ark_ff::PrimeField;

        let (envelope, sk_b, plaintext) = alice_bob_envelope_with_plaintext();
        let signal = compute_signal_native(
            &envelope.sender_pk,
            &envelope.recipient_pk,
            envelope.envelope_id,
            envelope.mac_tag,
            &envelope.ciphertext,
        );

        let inputs = EnvelopeOpenAt0Inputs {
            signal: signal.into_bigint().to_string(),
            claimed_value: plaintext[POSITION].into_bigint().to_string(),
            recipient_sk: sk_b.scalar().into_bigint().to_string(),
            sender_pk_x: envelope.sender_pk.x.into_bigint().to_string(),
            sender_pk_y: envelope.sender_pk.y.into_bigint().to_string(),
            recipient_pk_x: envelope.recipient_pk.x.into_bigint().to_string(),
            recipient_pk_y: envelope.recipient_pk.y.into_bigint().to_string(),
            envelope_id: envelope.envelope_id.into_bigint().to_string(),
            ciphertext: std::array::from_fn(|i| {
                envelope.ciphertext[i].into_bigint().to_string()
            }),
            mac_tag: envelope.mac_tag.into_bigint().to_string(),
        };

        let circuit: EnvelopeOpenAt0 = inputs.try_into().expect("parse ok");
        let cs = ConstraintSystem::<Fq>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Off-curve sender_pk is caught at the wire decoder.
    #[test]
    fn inputs_try_from_rejects_off_curve_sender_pk() {
        let inputs = EnvelopeOpenAt0Inputs {
            signal: "0".to_string(),
            claimed_value: "0".to_string(),
            recipient_sk: "1".to_string(),
            sender_pk_x: "1".to_string(),
            sender_pk_y: "1".to_string(), // not on Baby Jubjub
            recipient_pk_x: "1".to_string(),
            recipient_pk_y: "1".to_string(),
            envelope_id: "0".to_string(),
            ciphertext: std::array::from_fn(|_| "0".to_string()),
            mac_tag: "0".to_string(),
        };
        let result: Result<EnvelopeOpenAt0, _> = inputs.try_into();
        match result {
            Err(InputsError::InvalidPoint { field, .. }) => {
                assert_eq!(field, "sender_pk");
            }
            other => panic!("expected InvalidPoint, got {other:?}"),
        }
    }

    /// `public_inputs_from` returns the verifier vector in the
    /// pinned order `[signal, claimed_value]`.
    #[test]
    fn public_inputs_from_returns_inputs_in_circuit_order() {
        let public = EnvelopeOpenAt0PublicInputs {
            signal: "7".to_string(),
            claimed_value: "11".to_string(),
        };
        let v = public_inputs_from(&public).expect("ok");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], Fq::from(7u64));
        assert_eq!(v[1], Fq::from(11u64));
    }

    /// JSON round-trip of `Inputs` preserves the wire form.
    #[test]
    fn inputs_json_roundtrip() {
        let inputs = EnvelopeOpenAt0Inputs {
            signal: "1".to_string(),
            claimed_value: "2".to_string(),
            recipient_sk: "3".to_string(),
            sender_pk_x: "4".to_string(),
            sender_pk_y: "5".to_string(),
            recipient_pk_x: "6".to_string(),
            recipient_pk_y: "7".to_string(),
            envelope_id: "8".to_string(),
            ciphertext: std::array::from_fn(|i| (i as u64).to_string()),
            mac_tag: "42".to_string(),
        };
        let json = serde_json::to_string(&inputs).expect("ser");
        let back: EnvelopeOpenAt0Inputs = serde_json::from_str(&json).expect("deser");
        assert_eq!(back.signal, inputs.signal);
        assert_eq!(back.ciphertext, inputs.ciphertext);
        assert_eq!(back.recipient_pk_y, inputs.recipient_pk_y);
    }
}
