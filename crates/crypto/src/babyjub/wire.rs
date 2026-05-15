//! Decimal-string wire encoding for Baby Jubjub scalars and points.
//!
//! The native arkworks types (`Fr`, `EdwardsAffine`) cannot cross a
//! language boundary directly. This module is the canonical boundary form:
//! base-10 decimal strings, the *same* representation `specs/babyjub-curve.md`
//! uses for its fixture vectors. That choice is deliberate — it means a
//! boundary consumer (the WASM binding, and through it the TypeScript apps)
//! sees exactly the digits the spec pins, so the cross-language fixture test
//! compares like-for-like with no re-encoding step in between.
//!
//! Decimal strings are not the most compact encoding (bytes would be), but
//! the boundary's first consumer is a *visualization* — legibility and
//! spec-alignment matter, compactness does not. A byte encoding can be added
//! later as a sibling without disturbing this one.
//!
//! This logic lives in `crypto`, not in the WASM crate: the WASM crate must
//! stay a thin binding with zero arithmetic or arkworks-internal knowledge.
//! Anything that touches `Fr`/`Fq` field internals belongs here, behind a
//! tested API.

use core::fmt;

use ark_ff::PrimeField;

use super::config::{EdwardsAffine, Fr};

/// Why a decimal string failed to decode into a scalar or coordinate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The string was not a valid base-10 integer (empty, non-digit chars,
    /// stray sign, etc.).
    NotDecimal(String),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::NotDecimal(s) => {
                write!(f, "not a base-10 integer: {s:?}")
            }
        }
    }
}

impl std::error::Error for WireError {}

/// A Baby Jubjub point in the boundary wire form: both affine coordinates as
/// base-10 decimal strings. This is what crosses into JavaScript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointStrings {
    /// Affine `x` coordinate, base-10.
    pub x: String,
    /// Affine `y` coordinate, base-10.
    pub y: String,
}

/// Parse a base-10 decimal string into a Baby Jubjub scalar (`Fr`).
///
/// The value is reduced modulo the scalar field order `l` — a string larger
/// than `l` does not error, it wraps, which is the correct behaviour for a
/// field element.
///
/// The accepted form is a *non-negative* base-10 integer. `Fr`'s own
/// `FromStr` would also accept a leading `-` and interpret it as field
/// negation, but the wire boundary's inputs come from JavaScript
/// `BigInt.toString()` on values that are conceptually unsigned — silently
/// wrapping `"-3"` to a huge positive scalar would be a confusing footgun, so
/// a leading sign is rejected as malformed.
pub fn scalar_from_decimal(s: &str) -> Result<Fr, WireError> {
    if !s.bytes().all(|b| b.is_ascii_digit()) || s.is_empty() {
        return Err(WireError::NotDecimal(s.to_string()));
    }
    // `Fr`'s `FromStr` accepts a base-10 integer and reduces mod `l`. After
    // the digit-only guard above, the only thing it can still reject is a
    // string with no digits, already handled — but keep the map for safety.
    s.parse::<Fr>().map_err(|_| WireError::NotDecimal(s.to_string()))
}

/// Render a Baby Jubjub scalar as its canonical base-10 decimal string.
pub fn scalar_to_decimal(scalar: &Fr) -> String {
    scalar.into_bigint().to_string()
}

/// Render a Baby Jubjub point as decimal-string coordinates.
///
/// The point is taken in affine form, so the strings are the canonical
/// coordinates — the same ones `specs/babyjub-curve.md` lists.
pub fn point_to_strings(point: &EdwardsAffine) -> PointStrings {
    PointStrings {
        x: point.x.into_bigint().to_string(),
        y: point.y.into_bigint().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::{generator, mul};

    /// A scalar must round-trip: decimal -> Fr -> decimal is the identity for
    /// any in-range value.
    #[test]
    fn scalar_decimal_roundtrip() {
        for s in ["0", "1", "2", "1000", "4242424242"] {
            let scalar = scalar_from_decimal(s).expect("valid decimal");
            assert_eq!(scalar_to_decimal(&scalar), s);
        }
    }

    /// Garbage in -> typed error out, not a panic.
    #[test]
    fn scalar_from_garbage_errors() {
        for bad in ["", "abc", "1.5", "-3", "0x10", " 12"] {
            assert!(
                matches!(scalar_from_decimal(bad), Err(WireError::NotDecimal(_))),
                "expected NotDecimal for {bad:?}",
            );
        }
    }

    /// The generator rendered to strings must equal the `Base8` decimals from
    /// `specs/babyjub-curve.md`. This pins the wire encoding to the spec: if
    /// `point_to_strings` ever changed representation, this catches it.
    #[test]
    fn generator_to_strings_matches_spec_base8() {
        let s = point_to_strings(&generator());
        assert_eq!(
            s.x,
            "5299619240641551281634865583518297030282874472190772894086521144482721001553",
        );
        assert_eq!(
            s.y,
            "16950150798460657717958625567821834550301663161624707787222815936182638968203",
        );
    }

    /// End-to-end through the boundary form: take a spec fixture scalar, parse
    /// it from a string, multiply the generator, render back to strings, and
    /// check against the pinned `k * Base8` vector. This is the exact path the
    /// WASM binding will exercise.
    #[test]
    fn scalar_mul_through_wire_form_matches_fixture() {
        let k = scalar_from_decimal("1000").expect("valid decimal");
        let product = mul(&k, &generator());
        let s = point_to_strings(&product);
        assert_eq!(
            s.x,
            "20366147795936572600700348767835863189204735700033902769792878907543918679364",
        );
        assert_eq!(
            s.y,
            "17979751125406099319734770781608767238997398840154679652223692501113096137972",
        );
    }
}
