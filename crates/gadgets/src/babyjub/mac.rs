//! In-circuit Baby Jubjub MAC.
//!
//! Mirrors `crypto::babyjub::mac::{mac, verify}` against
//! `FpVar<Fq>`. The native construction:
//!
//! ```text
//! tag = poseidon_hash_sponge(mac_domain, [key, m_0, m_1, ..., m_{n-1}])
//! verify(key, message, tag) = (mac(key, message) == tag)
//! ```
//!
//! Sponge variant, not fixed — message length is variable on the
//! native side; the gadget inherits the same shape, with the same
//! caveat that in a circuit the absorption-loop length must be
//! fixed at circuit-design time. A circuit hashing a "variable
//! length" message in practice pads to a maximum.
//!
//! ## What the gadget is FOR
//!
//! - **In-circuit envelope verification.** Prove "I hold the MAC
//!   key and the ciphertext, and the published tag verifies under
//!   them" — without revealing the key. The canonical encrypt-then
//!   -MAC composition lives one layer up; this gadget is the
//!   integrity half.
//! - **Selective integrity proofs.** Prove a tag verifies for some
//!   committed ciphertext shape (e.g. after partial revelation)
//!   without exposing the underlying key.
//!
//! ## Verification at the gadget level
//!
//! The "verify" half is naturally expressed as an
//! `enforce_equal(mac_var(key, msg), tag)` in the consumer
//! circuit. We do NOT export a `mac_verify_var` returning a
//! `Boolean<Fq>` because the consumer pattern is always "MAC must
//! match, otherwise the proof is invalid," which is the
//! enforce-equal shape — not a runtime branch on a boolean. A
//! future consumer that needs the soft form can compute
//! `mac_var(...).is_eq(&tag)` directly.

use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crypto::babyjub::Fq;
use crypto::babyjub::MAC_DOMAIN;
use crypto::poseidon::domain_tag;

use ark_r1cs_std::fields::FieldVar;

use crate::poseidon::poseidon_hash_sponge_var;

/// Compute a MAC tag over a field-element stream under a symmetric
/// key, in-circuit. Mirrors `crypto::babyjub::mac::mac`.
///
/// The returned `FpVar` is the tag. Consumers verify by
/// `tag_var.enforce_equal(&expected_tag_var)` — see the module
/// docs for why there's no separate `verify_var`.
pub fn mac_var(
    cs: ConstraintSystemRef<Fq>,
    key: &FpVar<Fq>,
    message: &[FpVar<Fq>],
) -> Result<FpVar<Fq>, SynthesisError> {
    // Build the sponge input: key first, then message. Same shape
    // as the native side.
    let mut inputs: Vec<FpVar<Fq>> = Vec::with_capacity(1 + message.len());
    inputs.push(key.clone());
    for m in message {
        inputs.push(m.clone());
    }

    let tag = FpVar::<Fq>::constant(domain_tag(MAC_DOMAIN));
    poseidon_hash_sponge_var(cs, &tag, &inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::eq::EqGadget;
    use ark_relations::r1cs::ConstraintSystem;
    use crypto::babyjub::mac_compute as native_mac;

    fn alloc_witnesses(
        cs: ConstraintSystemRef<Fq>,
        xs: &[Fq],
    ) -> Result<Vec<FpVar<Fq>>, SynthesisError> {
        xs.iter()
            .map(|x| FpVar::<Fq>::new_witness(cs.clone(), || Ok(*x)))
            .collect()
    }

    /// Native↔circuit equivalence on a canonical 4-element
    /// message. The load-bearing test: pins the sponge construction
    /// (domain tag, key-as-first-input placement) against the native
    /// MAC, and transitively against `specs/babyjub-mac.md`'s pinned
    /// vectors via the native fixture.
    #[test]
    fn mac_var_matches_native() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let key = Fq::from(42u64);
        let message = [
            Fq::from(1u64),
            Fq::from(2u64),
            Fq::from(3u64),
            Fq::from(4u64),
        ];
        let expected = native_mac(key, &message);

        let key_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(key)).unwrap();
        let msg_vars = alloc_witnesses(cs.clone(), &message).unwrap();
        let tag_var = mac_var(cs.clone(), &key_var, &msg_vars).unwrap();

        let expected_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(expected)).unwrap();
        tag_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Equivalence on the empty message — produces a per-key
    /// constant tag.
    #[test]
    fn mac_var_matches_native_empty() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let key = Fq::from(7u64);
        let expected = native_mac(key, &[]);

        let key_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(key)).unwrap();
        let tag_var = mac_var(cs.clone(), &key_var, &[]).unwrap();

        let expected_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(expected)).unwrap();
        tag_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// Equivalence on a longer message that forces multiple sponge
    /// absorption blocks. Catches chunking errors that a
    /// single-block input would not expose.
    #[test]
    fn mac_var_matches_native_multi_block() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let key = Fq::from(42u64);
        let message: Vec<Fq> = (1u64..=9).map(Fq::from).collect();
        let expected = native_mac(key, &message);

        let key_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(key)).unwrap();
        let msg_vars = alloc_witnesses(cs.clone(), &message).unwrap();
        let tag_var = mac_var(cs.clone(), &key_var, &msg_vars).unwrap();

        let expected_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(expected)).unwrap();
        tag_var.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    /// A tampered message under the right key MUST unsatisfy
    /// `enforce_equal(tag_var, real_tag)`. This is the integrity
    /// property at the gadget level — a circuit that uses
    /// `mac_var` to authenticate inputs cannot be fooled by a
    /// changed message that produces a different tag.
    #[test]
    fn mac_var_rejects_tampered_message() {
        let cs = ConstraintSystem::<Fq>::new_ref();

        let key = Fq::from(42u64);
        let message = [
            Fq::from(1u64),
            Fq::from(2u64),
            Fq::from(3u64),
            Fq::from(4u64),
        ];
        let real_tag = native_mac(key, &message);

        let key_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(key)).unwrap();
        let tampered = [
            Fq::from(1u64),
            Fq::from(2u64),
            Fq::from(3u64),
            Fq::from(5u64),
        ];
        let tampered_vars = alloc_witnesses(cs.clone(), &tampered).unwrap();
        let tag_var = mac_var(cs.clone(), &key_var, &tampered_vars).unwrap();

        let real_tag_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(real_tag)).unwrap();
        tag_var.enforce_equal(&real_tag_var).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
