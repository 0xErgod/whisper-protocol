//! Baby Jubjub curve configuration — ERC-2494 / circomlib dialect.
//!
//! Baby Jubjub is a twisted Edwards curve whose base field is the BN254 scalar
//! field. The 2018 WhiteHat–Baylina–Bellés paper fixes the field, the subgroup
//! order, the cofactor, and the Montgomery coefficient — but leaves the Edwards
//! *coordinate convention* and the *generator point* to the implementer. Two
//! good-faith conventions exist:
//!
//! - arkworks' default `ark-ed-on-bn254`: the paper's literal `a = 1` form.
//! - ERC-2494 / circomlib / iden3: the twisted `a = 168700` form, with `Base8`
//!   as the prime-order-subgroup generator.
//!
//! They are the *same curve* (same field, same order, same cofactor) in
//! different coordinates with different chosen generators — but they serialize
//! points to different bytes. The entire circom ecosystem (snarkjs, circomlib,
//! every existing Baby Jubjub circuit and test vector) speaks the ERC-2494
//! dialect, so that is what we implement here. We define the curve directly via
//! `TECurveConfig` rather than adopting `ark-ed-on-bn254`'s defaults.
//!
//! Constants below are transcribed from ERC-2494 and cross-checked against
//! `iden3/circomlibjs` `src/babyjub.js`; both sources agree digit-for-digit.

use ark_ec::{
    twisted_edwards::{Affine, MontCurveConfig, Projective, TECurveConfig},
    CurveConfig,
};
use ark_ff::MontFp;

/// Base field of Baby Jubjub: the scalar field of BN254. Point coordinates and
/// curve parameters live here.
pub type Fq = ark_bn254::Fr;

/// Scalar field of Baby Jubjub: integers mod the prime subgroup order `l`.
/// Private keys / scalars used in scalar multiplication live here.
///
/// Reused from `ark-ed-on-bn254`: the subgroup order is paper-fixed and the
/// same in both curve dialects — only `a`, `d`, and the generator differ, and
/// those we override below. No point re-deriving a field arkworks already
/// ships verified.
pub type Fr = ark_ed_on_bn254::Fr;

/// A Baby Jubjub point in affine `(x, y)` coordinates.
pub type EdwardsAffine = Affine<BabyJubConfig>;

/// A Baby Jubjub point in projective coordinates (cheaper for repeated
/// arithmetic; convert to affine only when you need canonical bytes).
pub type EdwardsProjective = Projective<BabyJubConfig>;

/// Baby Jubjub in the ERC-2494 twisted Edwards dialect.
///
/// Curve equation: `a·x² + y² = 1 + d·x²·y²` over `Fq`, with `a = 168700` and
/// `d = 168696`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BabyJubConfig;

impl CurveConfig for BabyJubConfig {
    /// Base field — BN254 scalar field. Coordinates and `a`, `d` are elements
    /// of this field.
    type BaseField = Fq;
    /// Scalar field — integers mod the prime subgroup order.
    type ScalarField = Fr;

    /// Cofactor `h = 8`. Total curve order is `8 · l`; `Base8` generates the
    /// order-`l` prime subgroup.
    const COFACTOR: &'static [u64] = &[8];

    /// Inverse of the cofactor modulo the scalar field order, used by
    /// `mul_by_cofactor_inv`. `8⁻¹ mod l`.
    ///
    /// VERIFIED: the test `babyjub::config::tests::cofactor_inv_is_correct`
    /// recomputes `8⁻¹` in `Fr` and asserts it equals this literal — so this
    /// constant is checked by the build, not trusted from transcription. (It
    /// already earned its keep: the first hand-typed value was wrong and the
    /// test rejected it. This value is the test's computed `8⁻¹ mod l`.)
    const COFACTOR_INV: Fr =
        MontFp!("2394026564107420727433200628387514462817212225638746351800188703329891451411");
}

impl TECurveConfig for BabyJubConfig {
    /// Twisted Edwards `a` coefficient — ERC-2494 fixes this at `168700`.
    /// (arkworks' incompatible default dialect uses `1` here.)
    const COEFF_A: Fq = MontFp!("168700");

    /// Twisted Edwards `d` coefficient — ERC-2494 fixes this at `168696`.
    const COEFF_D: Fq = MontFp!("168696");

    /// The conventional group generator: `Base8`, the point circomlib and
    /// snarkjs use as *the* generator. It already lies in the prime-order
    /// subgroup (it is `8 · G` for the paper-style generator `G`), so
    /// scalar-by-`Fr` multiplication stays inside the subgroup.
    const GENERATOR: EdwardsAffine = EdwardsAffine::new_unchecked(
        MontFp!("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
        MontFp!("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );

    /// Montgomery form of the same curve, used by arkworks for the
    /// Edwards↔Montgomery birational map.
    type MontCurveConfig = BabyJubConfig;
}

impl MontCurveConfig for BabyJubConfig {
    /// Montgomery `A` coefficient from the Baby Jubjub paper: `168698`.
    const COEFF_A: Fq = MontFp!("168698");

    /// Montgomery `B` coefficient. ERC-2494's Montgomery form is `B·v² = u³ +
    /// A·u² + u` with `B = 1`.
    const COEFF_B: Fq = MontFp!("1");

    type TECurveConfig = BabyJubConfig;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;

    /// `COFACTOR_INV` is a transcribed-looking literal, so don't trust it —
    /// recompute `8⁻¹` in the scalar field and assert equality. If the literal
    /// is wrong, the build's test run catches it here rather than silently
    /// corrupting any future `mul_by_cofactor_inv` caller.
    #[test]
    fn cofactor_inv_is_correct() {
        let eight = Fr::from(8u64);
        let computed = eight.inverse().expect("8 is invertible in a prime field");
        assert_eq!(computed, BabyJubConfig::COFACTOR_INV);
    }
}
