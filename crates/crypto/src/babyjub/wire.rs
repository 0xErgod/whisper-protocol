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

use super::config::{EdwardsAffine, Fq, Fr};
use super::curve::{is_in_prime_subgroup, is_on_curve};

/// Why a decimal string failed to decode into a scalar or coordinate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The string was not a valid base-10 integer (empty, non-digit chars,
    /// stray sign, etc.).
    NotDecimal(String),
    /// `(x, y)` parsed as field elements but does not satisfy the Baby
    /// Jubjub curve equation `a·x² + y² = 1 + d·x²·y²`. The point may have
    /// been forged or the encoding is from a different curve.
    NotOnCurve,
    /// `(x, y)` is on the curve but is in a small-order component rather
    /// than the prime-order subgroup. Accepting it would enable
    /// subgroup-confinement attacks, so the decoder rejects it.
    NotInPrimeSubgroup,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::NotDecimal(s) => {
                write!(f, "not a base-10 integer: {s:?}")
            }
            WireError::NotOnCurve => {
                write!(f, "point is not on the Baby Jubjub curve")
            }
            WireError::NotInPrimeSubgroup => {
                write!(f, "point is on the curve but not in the prime-order subgroup")
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

/// Parse a base-10 decimal string into a Baby Jubjub *base-field* element
/// (`Fq`). Used internally by `point_from_strings`. Same accepted form as
/// `scalar_from_decimal`: a non-negative base-10 integer, reduced mod the
/// base-field prime `p`.
fn coord_from_decimal(s: &str) -> Result<Fq, WireError> {
    if !s.bytes().all(|b| b.is_ascii_digit()) || s.is_empty() {
        return Err(WireError::NotDecimal(s.to_string()));
    }
    s.parse::<Fq>().map_err(|_| WireError::NotDecimal(s.to_string()))
}

/// Parse decimal-string coordinates into a Baby Jubjub point.
///
/// **Validates everything that matters before returning.** A caller of this
/// function expects the resulting point to be safe to use cryptographically:
///
///  1. Both coordinates must be valid base-10 integers (otherwise
///     `NotDecimal`).
///  2. `(x, y)` must satisfy the Baby Jubjub curve equation `a·x² + y² =
///     1 + d·x²·y²` (otherwise `NotOnCurve`).
///  3. `(x, y)` must be in the prime-order subgroup generated by `Base8` —
///     not just any on-curve point (otherwise `NotInPrimeSubgroup`). A
///     small-order point would enable subgroup-confinement attacks against
///     ECDH and similar protocols, so the decoder rejects it here, once,
///     rather than relying on every caller to remember.
///
/// This is the boundary contract for any public key, ECDH ephemeral, or
/// commitment point that arrives from outside the process (a JS caller, a
/// wire-decoded envelope, a stored on-chain value): if it survives this
/// function, downstream code can treat it as a genuine subgroup point.
pub fn point_from_strings(x: &str, y: &str) -> Result<EdwardsAffine, WireError> {
    let px = coord_from_decimal(x)?;
    let py = coord_from_decimal(y)?;
    let point = EdwardsAffine::new_unchecked(px, py);
    if !is_on_curve(&point) {
        return Err(WireError::NotOnCurve);
    }
    if !is_in_prime_subgroup(&point) {
        return Err(WireError::NotInPrimeSubgroup);
    }
    Ok(point)
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

    /// `point_to_strings` and `point_from_strings` are inverses on the
    /// canonical generator. Round-trip is the most basic contract any wire
    /// codec must satisfy.
    #[test]
    fn point_strings_roundtrip_on_generator() {
        let s = point_to_strings(&generator());
        let decoded = point_from_strings(&s.x, &s.y).expect("Base8 round-trips");
        assert_eq!(decoded, generator());
    }

    /// `point_from_strings` rejects garbage coordinates as `NotDecimal`, not
    /// as `NotOnCurve` — the digit-shape check happens before any field
    /// arithmetic.
    #[test]
    fn point_from_strings_rejects_garbage_coords() {
        let result = point_from_strings("abc", "1");
        assert!(matches!(result, Err(WireError::NotDecimal(_))));
    }

    /// A point that parses as field elements but does not satisfy the curve
    /// equation must be rejected as `NotOnCurve`. `(1, 1)` is the simplest
    /// off-curve point: `a·1 + 1 = a + 1 ≠ 1 + d` for any non-trivial `(a, d)`.
    #[test]
    fn point_from_strings_rejects_off_curve_point() {
        let result = point_from_strings("1", "1");
        assert!(matches!(result, Err(WireError::NotOnCurve)));
    }
}
