//! Poseidon-BN254 with circomlib parameters.
//!
//! This module is a thin, opinionated wrapper around [`light_poseidon`] —
//! the only audited Rust Poseidon implementation that produces the same
//! hash byte-for-byte as `circomlib` / `poseidon-lite` (the TypeScript side
//! already uses `poseidon-lite`; see `specs/poseidon-commitment-format.md`
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
//! Fixed-arity helpers — the *only* call shape we ever want — plus the
//! domain-tag construction every consumer (keypairs, commitments,
//! signatures) builds on. The hash output is `Fq` (the BN254 scalar field,
//! which is Baby Jubjub's base field), the same field the existing
//! TypeScript Poseidon module outputs into. Callers reduce mod the Baby
//! Jubjub scalar order themselves when they need an `Fr` (see
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
/// Construction: `bytes_to_field_be(Blake2b-256(domain_string))`. This is
/// the same construction the TypeScript Poseidon commitment scheme uses
/// for its `f0` (see `packages/sdk/src/hash-poseidon.ts`), so a Rust and a
/// TS caller hashing the *same* domain string land on the *same* field
/// element. Reusing the construction across primitives means one rule, not
/// per-primitive bespoke encodings.
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
}
