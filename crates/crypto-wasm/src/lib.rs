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
#[wasm_bindgen]
pub fn mul_generator(scalar: &str) -> Result<Point, JsError> {
    let k = babyjub::scalar_from_decimal(scalar)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let product = babyjub::mul(&k, &babyjub::generator());
    Ok(babyjub::point_to_strings(&product).into())
}

/// Validate a point arriving from JavaScript as decimal-string coordinates.
///
/// Returns the same coordinates unchanged on success (so the JS caller can
/// chain into other operations); returns a JS exception if either
/// coordinate is malformed, or the point is off-curve, or the point is on
/// the curve but not in the prime-order subgroup. This is the public
/// `babyjub::point_from_strings` decoder exposed across the boundary —
/// every external public key or ephemeral arriving from JS should pass
/// through it before any cryptographic use downstream.
#[wasm_bindgen]
pub fn validate_point(x: &str, y: &str) -> Result<Point, JsError> {
    let _ = babyjub::point_from_strings(x, y)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(Point {
        x: x.to_string(),
        y: y.to_string(),
    })
}

/// A Baby Jubjub keypair derived from a 64-byte seed, in the boundary's
/// wire form.
///
/// Only the **public** half crosses the boundary as `pk_x` / `pk_y` decimal
/// strings. The secret scalar `sk` is **deliberately not exposed**: the
/// production path is `wallet-derived-keys` re-deriving from a wallet
/// signature when needed, never storing or transporting `sk` across the
/// boundary. Test code that wants to confirm the derivation matches the
/// spec checks `(pk_x, pk_y)` instead, which is mathematically equivalent —
/// `Base8` is injective on `F_l`, so a matching public key uniquely pins
/// the secret scalar.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct Keypair {
    pk_x: String,
    pk_y: String,
}

#[wasm_bindgen]
impl Keypair {
    /// Public-key affine `x` coordinate, base-10.
    #[wasm_bindgen(getter)]
    pub fn pk_x(&self) -> String {
        self.pk_x.clone()
    }

    /// Public-key affine `y` coordinate, base-10.
    #[wasm_bindgen(getter)]
    pub fn pk_y(&self) -> String {
        self.pk_y.clone()
    }
}

/// Derive a Baby Jubjub keypair from a 64-byte seed.
///
/// The seed is bytes — a `Uint8Array` from JavaScript — by design: the
/// derivation is byte-exact and a decimal-string seed would obscure that.
/// Length is enforced at the boundary: anything other than 64 bytes is a JS
/// exception.
///
/// See `specs/babyjub-keypair.md` for the derivation and worked-example
/// vectors. The `wasm-pack test` boundary test pins those vectors against
/// this exact entry point — so a passing JS-side call here lands on the
/// same public key the spec promises.
#[wasm_bindgen]
pub fn keypair_from_seed(seed: &[u8]) -> Result<Keypair, JsError> {
    let bytes: [u8; 64] = seed
        .try_into()
        .map_err(|_| JsError::new("seed must be exactly 64 bytes"))?;
    let (_sk, pk) = babyjub::keypair_from_seed(&babyjub::Seed::from_bytes(bytes));
    let pk_strings = babyjub::point_to_strings(pk.point());
    Ok(Keypair {
        pk_x: pk_strings.x,
        pk_y: pk_strings.y,
    })
}
