//! Cross-language compatibility fixture for the Baby Jubjub curve.
//!
//! These tests are the executable form of `specs/babyjub-curve.md § Worked
//! Example`. If the curve config in `src/babyjub/config.rs` ever drifts from
//! the ERC-2494 dialect — wrong `a`/`d`, wrong generator, wrong field — these
//! fail. They are an integration test (in `tests/`, not `#[cfg(test)]` inside
//! the module) deliberately: the fixture is a *public contract*, exercised
//! through the crate's public API exactly as the future WASM binding and any
//! third-party consumer would exercise it.
//!
//! Two independent anchors:
//!
//!  - **Anchor 1** — vectors lifted verbatim from `iden3/circomlib` and
//!    `circomlibjs` `test/babyjub.js`. External to this codebase: passing them
//!    proves our curve *is* circomlib's curve, not merely self-consistent.
//!  - **Anchor 2** — `k · Base8` vectors. Anchors outputs to *this protocol's*
//!    generator. The contract the Rust circuit and TS SDK must reproduce.
//!
//! Keep this file and `specs/babyjub-curve.md` in lockstep. A change to one
//! without the other is a bug.

use ark_ec::{twisted_edwards::Projective, CurveGroup};
use ark_ff::PrimeField;

use crypto::babyjub::{generator, is_in_prime_subgroup, is_on_curve, mul, EdwardsAffine, Fq, Fr};

/// Build an affine point from decimal coordinate strings and assert it is a
/// genuine prime-subgroup curve point while we are at it — every fixture point
/// should satisfy that, and a typo in a constant tends to violate it.
fn point(x: &str, y: &str) -> EdwardsAffine {
    // `from_str` on the field, via `Fq`'s `FromStr`, then `new_unchecked` +
    // explicit validation — so an off-curve typo fails loudly here rather than
    // silently producing a bogus point.
    let px: Fq = x.parse().expect("x is a valid field element");
    let py: Fq = y.parse().expect("y is a valid field element");
    let p = EdwardsAffine::new_unchecked(px, py);
    assert!(is_on_curve(&p), "fixture point ({x}, {y}) is not on the curve");
    p
}

/// Affine point addition through the projective group law, returned affine —
/// mirrors what `curve::mul` does internally, but for `+`.
fn add(a: &EdwardsAffine, b: &EdwardsAffine) -> EdwardsAffine {
    (Projective::from(*a) + Projective::from(*b)).into_affine()
}

// --- Anchor 1: circomlib reference vectors --------------------------------

/// `P` — the working point used throughout circomlib's `test/babyjub.js`.
fn circomlib_p() -> EdwardsAffine {
    point(
        "17777552123799933955779906779655732241715742912184938656739573121738514868268",
        "2626589144620713026669568689430873010625803728049924121243784502389097019475",
    )
}

/// `Q` — circomlib's second test point, used for the point-addition vector.
fn circomlib_q() -> EdwardsAffine {
    point(
        "16540640123574156134436876038791482806971768689494387082833631921987005038935",
        "20819045374670962167435360035096875258406992893633759881276124905556507972311",
    )
}

/// circomlib `test/babyjub.js`: doubling `P` (i.e. `P + P`).
#[test]
fn circomlib_point_doubling() {
    let expected = point(
        "6890855772600357754907169075114257697580319025794532037257385534741338397365",
        "4338620300185947561074059802482547481416142213883829469920100239455078257889",
    );
    assert_eq!(add(&circomlib_p(), &circomlib_p()), expected);
}

/// circomlib `test/babyjub.js`: adding two distinct points `P + Q`.
#[test]
fn circomlib_point_addition() {
    let expected = point(
        "7916061937171219682591368294088513039687205273691143098332585753343424131937",
        "14035240266687799601661095864649209771790948434046947201833777492504781204499",
    );
    assert_eq!(add(&circomlib_p(), &circomlib_q()), expected);
}

/// circomlib `test/babyjub.js`: scalar multiplication `3 · P`.
#[test]
fn circomlib_scalar_mul_by_3() {
    let expected = point(
        "19372461775513343691590086534037741906533799473648040012278229434133483800898",
        "9458658722007214007257525444427903161243386465067105737478306991484593958249",
    );
    assert_eq!(mul(&Fr::from(3u64), &circomlib_p()), expected);
}

// --- Anchor 2: k · Base8 vectors ------------------------------------------

/// Every `(k, x, y)` row from `specs/babyjub-curve.md § Worked Example`,
/// Anchor 2. The scalars that fit in a `u64` are listed here; `2^200` is
/// covered separately below.
const BASE8_VECTORS: &[(u64, &str, &str)] = &[
    (
        1,
        "5299619240641551281634865583518297030282874472190772894086521144482721001553",
        "16950150798460657717958625567821834550301663161624707787222815936182638968203",
    ),
    (
        2,
        "10031262171927540148667355526369034398030886437092045105752248699557385197826",
        "633281375905621697187330766174974863687049529291089048651929454608812697683",
    ),
    (
        3,
        "2763488322167937039616325905516046217694264098671987087929565332380420898366",
        "15305195750036305661220525648961313310481046260814497672243197092298550508693",
    ),
    (
        8,
        "7582035475627193640797276505418002166691739036475590846121162698650004832581",
        "7801528930831391612913542953849263092120765287178679640990215688947513841260",
    ),
    (
        1000,
        "20366147795936572600700348767835863189204735700033902769792878907543918679364",
        "17979751125406099319734770781608767238997398840154679652223692501113096137972",
    ),
    (
        4242424242,
        "8197680051882628970410681376493202672655988696749960149267822370593492838760",
        "12894077115825233362045965817688273159131941840146661890364266485669764812312",
    ),
];

/// Each `k · Base8` must equal the pinned coordinates. This is the contract a
/// conformant ERC-2494 implementation — in any language — has to reproduce.
#[test]
fn base8_scalar_mul_vectors() {
    let g = generator();
    for &(k, x, y) in BASE8_VECTORS {
        let expected = point(x, y);
        assert_eq!(
            mul(&Fr::from(k), &g),
            expected,
            "k = {k}: k · Base8 did not match the pinned fixture vector",
        );
    }
}

/// The large-scalar vector: `2^200 · Base8`. Split out because the scalar does
/// not fit in a `u64`.
#[test]
fn base8_scalar_mul_large_scalar() {
    let g = generator();
    // 2^200 as a field element.
    let two = Fr::from(2u64);
    let mut k = Fr::from(1u64);
    for _ in 0..200 {
        k *= two;
    }
    let expected = point(
        "5724625655608868645689535268422070084543995927732212059724113152068754891373",
        "10308923700401579816603597606813811960552754413890927913080984195249222032507",
    );
    assert_eq!(mul(&k, &g), expected, "2^200 · Base8 did not match the pinned fixture vector");
}

// --- Generator sanity (mirrors specs/babyjub-curve.md § Generator) --------

/// `Base8` is `1 · Base8` — trivially — but also the first Anchor-2 row. This
/// asserts the generator the crate exposes *is* the spec's `Base8`, by exact
/// coordinates, so a wrong generator constant cannot slip through.
#[test]
fn exposed_generator_is_base8() {
    let base8 = point(
        "5299619240641551281634865583518297030282874472190772894086521144482721001553",
        "16950150798460657717958625567821834550301663161624707787222815936182638968203",
    );
    assert_eq!(generator(), base8);
    assert!(is_in_prime_subgroup(&generator()));
}

/// The base-field prime pinned in the spec must be the modulus the crate's
/// `Fq` actually uses. Catches a wrong field underneath everything else.
///
/// Note `p` cannot be written as an `Fq` literal — it would reduce to 0. We
/// parse it straight into the `BigInt` representation and compare against
/// `Fq::MODULUS`.
#[test]
fn base_field_modulus_matches_spec() {
    use ark_ff::BigInteger;

    let spec_p = num_bigint::BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("spec prime parses");

    let modulus_biguint: num_bigint::BigUint = <Fq as PrimeField>::MODULUS.into();
    assert_eq!(modulus_biguint, spec_p);

    // And the bit length is what we expect for the BN254 scalar field (254
    // bits) — a cheap independent sanity check on the same fact.
    assert_eq!(<Fq as PrimeField>::MODULUS.num_bits(), 254);
}
