//! WASM bindings for the `crypto` crate.
//!
//! NOTE(name): working name only — see `Cargo.toml`. No product name here.
//!
//! ## What this crate is
//!
//! A *thin binding*. Every function here does exactly one thing: take JS-side
//! values (strings), hand them to an already-tested `crypto::babyjub`
//! function, and hand the result back as JS-side values. There is no
//! cryptographic logic, no arithmetic, and no arkworks-internal knowledge in
//! this file — all of that lives in `crypto`, behind its own tests.
//!
//! The reason for the strict separation: `crypto` is also compiled *natively*
//! (for the future prover and circuits), so it must not depend on
//! `wasm-bindgen`. Keeping the binding glue in its own crate means the native
//! consumers never pull in WASM machinery, and the JS<->WASM marshalling code
//! lives in exactly one place.
//!
//! ## Boundary representation
//!
//! Scalars and point coordinates cross as **base-10 decimal strings** — the
//! same representation `specs/babyjub-curve.md` uses for its fixture vectors,
//! and the form JS `BigInt` parses and emits natively. See
//! `crypto::babyjub::wire` for the rationale.
//!
//! ## Testing
//!
//! `wasm-bindgen-test` exercises these bindings in a real headless browser
//! (`wasm-pack test`). That is deliberate: `crypto`'s own tests prove the math,
//! but only a real browser run proves the *boundary* — that values survive the
//! `wasm32` codegen and the JS marshalling unchanged. See `tests/`.

use wasm_bindgen::prelude::*;

use crypto::babyjub;

/// A Baby Jubjub point as it crosses into JavaScript: both affine coordinates
/// as base-10 decimal strings.
///
/// `wasm-bindgen` exposes this as a JS object with `x` and `y` string
/// properties (and getters). It mirrors `crypto::babyjub::PointStrings`; the
/// two are kept separate so the binding's exported shape can evolve without
/// touching the core crate.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct Point {
    x: String,
    y: String,
}

#[wasm_bindgen]
impl Point {
    /// Affine `x` coordinate, base-10.
    #[wasm_bindgen(getter)]
    pub fn x(&self) -> String {
        self.x.clone()
    }

    /// Affine `y` coordinate, base-10.
    #[wasm_bindgen(getter)]
    pub fn y(&self) -> String {
        self.y.clone()
    }
}

impl From<babyjub::PointStrings> for Point {
    fn from(p: babyjub::PointStrings) -> Self {
        Point { x: p.x, y: p.y }
    }
}

/// The Baby Jubjub generator (`Base8`), as decimal-string coordinates.
///
/// Every public key in the protocol is a scalar multiple of this point;
/// `apps/curve` plots `1·G, 2·G, 3·G, …` starting here.
#[wasm_bindgen]
pub fn generator() -> Point {
    babyjub::point_to_strings(&babyjub::generator()).into()
}

/// Scalar multiplication against the generator: `scalar · Base8`.
///
/// This is the one curve operation the visualization needs: the cyclic walk
/// `apps/curve` draws is `mul_generator("1")`, `mul_generator("2")`, … —
/// the sequence of generator multiples.
///
/// `scalar` is a non-negative base-10 integer; values `>= l` (the subgroup
/// order) wrap, which is correct field behaviour. A malformed `scalar` —
/// non-digit characters, a sign, empty — comes back as a JS exception, not a
/// panic.
///
/// Arbitrary-base scalar multiplication is intentionally not exposed yet: it
/// needs a `point_from_strings` decoder in `crypto::babyjub::wire`, and no
/// consumer needs it until a primitive past the curve does. Adding it later is
/// a new export here plus a tested decoder there — it does not disturb this
/// function.
#[wasm_bindgen]
pub fn mul_generator(scalar: &str) -> Result<Point, JsError> {
    let k = babyjub::scalar_from_decimal(scalar)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let product = babyjub::mul(&k, &babyjub::generator());
    Ok(babyjub::point_to_strings(&product).into())
}
