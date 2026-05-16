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

/// Baby Jubjub ECDH: compute the shared point between the caller's
/// keypair (derived from `my_seed`) and the peer's public key
/// (`peer_pk_x` / `peer_pk_y` as decimal strings).
///
/// Two parties calling this on each other's `(seed, peer_pk)` land on
/// the same point (`Alice_sk · PK_Bob == Bob_sk · PK_Alice`). The
/// `wasm-pack test` boundary fixture pins this property byte-for-byte
/// against `specs/babyjub-ecdh.md`.
///
/// The peer's public key is validated as part of decoding: a malformed,
/// off-curve, or small-subgroup point comes back as a JS exception
/// rather than silently producing a degenerate shared secret. The
/// caller's seed length is enforced at the boundary.
///
/// **Returns the raw shared point, not a derived encryption key.** The
/// envelope-suite brick will add a KDF (Poseidon over the shared point
/// plus context); doing that here would tie ECDH to one consumer. For
/// non-envelope uses (equality proofs, PAKEs) the raw point is what's
/// wanted anyway.
#[wasm_bindgen]
pub fn ecdh(my_seed: &[u8], peer_pk_x: &str, peer_pk_y: &str) -> Result<Point, JsError> {
    let bytes: [u8; 64] = my_seed
        .try_into()
        .map_err(|_| JsError::new("seed must be exactly 64 bytes"))?;
    let (sk, _) = babyjub::keypair_from_seed(&babyjub::Seed::from_bytes(bytes));

    // The peer's PK is decoded through the validating wire decoder:
    // garbage -> NotDecimal, off-curve -> NotOnCurve, small-subgroup
    // -> NotInPrimeSubgroup. Each becomes a JS exception, none reach
    // the curve operation. `from_validated_point` is sound here
    // because `point_from_strings` enforces both on-curve and
    // prime-subgroup membership before returning.
    let peer_point = babyjub::point_from_strings(peer_pk_x, peer_pk_y)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let peer_pk = babyjub::PublicKey::from_validated_point(peer_point);

    let shared = babyjub::shared_secret(&sk, &peer_pk);
    Ok(babyjub::point_to_strings(&shared).into())
}

/// Pedersen commitment over Baby Jubjub: `C = value · G + blinding · H`.
///
/// `value` and `blinding` are decimal-string scalars in `F_l`. The
/// `babyjub-pedersen-v1` second generator `H` is fixed and pinned in
/// `specs/babyjub-pedersen.md`; this binding does not let the JS caller
/// supply a different `H`, deliberately — a wrong `H` would invalidate
/// the binding property silently.
///
/// **The caller is responsible for `blinding`.** Reusing it across
/// commitments to different values is a hiding-failure footgun
/// (documented in the spec). This binding does not sample randomness;
/// the JS-side caller should generate `blinding` via the browser's
/// `crypto.getRandomValues` (or equivalent) and convert to a decimal
/// string.
///
/// Returns the commitment point as decimal-string coordinates. A
/// malformed scalar comes back as a JS exception, not a panic.
#[wasm_bindgen]
pub fn pedersen_commit(value: &str, blinding: &str) -> Result<Point, JsError> {
    let v = babyjub::scalar_from_decimal(value)
        .map_err(|e| JsError::new(&format!("value: {e}")))?;
    let r = babyjub::scalar_from_decimal(blinding)
        .map_err(|e| JsError::new(&format!("blinding: {e}")))?;
    let c = babyjub::commit(v, r);
    Ok(babyjub::point_to_strings(&c).into())
}

/// Expose the protocol's fixed Pedersen `H` generator. Useful for
/// visualizations and audits that want to see `H` directly.
/// `H` is constant — same on every call — and pinned in
/// `specs/babyjub-pedersen.md`.
#[wasm_bindgen]
pub fn pedersen_h() -> Point {
    babyjub::point_to_strings(&babyjub::h_generator()).into()
}

/// A Baby Jubjub Schnorr signature in the boundary's wire form:
/// commitment point `R` as decimal-string coordinates, response scalar
/// `s` as a decimal string. All three are public — there is no
/// sensitive material in a signature.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct Signature {
    r_x: String,
    r_y: String,
    s: String,
}

#[wasm_bindgen]
impl Signature {
    /// Commitment-point `R.x` coordinate, base-10.
    #[wasm_bindgen(getter)]
    pub fn r_x(&self) -> String {
        self.r_x.clone()
    }

    /// Commitment-point `R.y` coordinate, base-10.
    #[wasm_bindgen(getter)]
    pub fn r_y(&self) -> String {
        self.r_y.clone()
    }

    /// Response scalar `s`, base-10.
    #[wasm_bindgen(getter)]
    pub fn s(&self) -> String {
        self.s.clone()
    }
}

/// Sign a single field-element message with the keypair derived from
/// `seed`. Deterministic — same `(seed, m)` always produces the same
/// signature. `m` is a base-10 decimal string interpreted as an
/// element of `F_p` (the base field, not the scalar field).
///
/// **The signature primitive signs a field element, not arbitrary
/// bytes.** A caller wanting to sign bytes hashes them to `F_p` first
/// — see `specs/babyjub-schnorr.md` for the rationale. The boundary
/// surface deliberately does not expose a byte-message variant.
///
/// `seed` length is enforced at the boundary (exactly 64 bytes). A
/// malformed `m` is a JS exception, not a panic.
#[wasm_bindgen]
pub fn schnorr_sign(seed: &[u8], m: &str) -> Result<Signature, JsError> {
    let bytes: [u8; 64] = seed
        .try_into()
        .map_err(|_| JsError::new("seed must be exactly 64 bytes"))?;
    let m_fq = m
        .parse::<babyjub::Fq>()
        .map_err(|_| JsError::new("m must be a non-negative base-10 integer"))?;
    // Reject leading signs explicitly, same hygiene rule the wire
    // decoder applies to scalars: `BigInt.toString()` on a non-negative
    // value never produces a sign, so a sign is a caller-side bug, not
    // a representation we want to silently wrap.
    if !m.bytes().all(|b| b.is_ascii_digit()) || m.is_empty() {
        return Err(JsError::new("m must be a non-negative base-10 integer"));
    }

    let (sk, pk) = babyjub::keypair_from_seed(&babyjub::Seed::from_bytes(bytes));
    let sig = babyjub::sign(&sk, &pk, m_fq);
    let r_strings = babyjub::point_to_strings(&sig.r);
    Ok(Signature {
        r_x: r_strings.x,
        r_y: r_strings.y,
        s: babyjub::scalar_to_decimal(&sig.s),
    })
}

/// Verify a Schnorr signature against a public key and message field
/// element. Returns `true` iff valid; `false` for any tamper. Malformed
/// inputs come back as a JS exception, distinguishing "invalid signature"
/// (returns `false`) from "garbage input" (throws).
///
/// `pk_x` / `pk_y` is the signer's public key. `r_x` / `r_y` + `s` is the
/// signature. Both points are decoded through the validating wire
/// decoder — off-curve or small-subgroup points fail at decode time,
/// before any signature math runs.
#[wasm_bindgen]
pub fn schnorr_verify(
    pk_x: &str,
    pk_y: &str,
    m: &str,
    r_x: &str,
    r_y: &str,
    s: &str,
) -> Result<bool, JsError> {
    let pk_point = babyjub::point_from_strings(pk_x, pk_y)
        .map_err(|e| JsError::new(&format!("pk: {e}")))?;
    let r_point = babyjub::point_from_strings(r_x, r_y)
        .map_err(|e| JsError::new(&format!("R: {e}")))?;
    let pk = babyjub::PublicKey::from_validated_point(pk_point);
    let s_scalar = babyjub::scalar_from_decimal(s)
        .map_err(|e| JsError::new(&format!("s: {e}")))?;
    if !m.bytes().all(|b| b.is_ascii_digit()) || m.is_empty() {
        return Err(JsError::new("m must be a non-negative base-10 integer"));
    }
    let m_fq = m
        .parse::<babyjub::Fq>()
        .map_err(|_| JsError::new("m must be a non-negative base-10 integer"))?;

    let sig = babyjub::Signature {
        r: r_point,
        s: s_scalar,
    };
    Ok(babyjub::verify(&pk, m_fq, &sig))
}

// --- encoding registry bindings ----------------------------------------
//
// One pair of exports per registered encoding: `encode_<name>` /
// `decode_<name>`. Adding a new encoding to the WASM surface means
// adding one dependency to `Cargo.toml` and one matching pair below;
// there is no global dispatcher because there is no global runtime
// registry (see `specs/encodings/README.md`).

use crypto::encoding::BytePayloadEncoding;
use crypto::encoding::FieldStream;
use ark_ff::PrimeField;

/// Helper: render a `FieldStream` as the boundary wire form — a
/// JS array of base-10 decimal strings.
fn stream_to_decimals(stream: &FieldStream) -> Vec<String> {
    stream
        .fields()
        .iter()
        .map(|f| f.into_bigint().to_string())
        .collect()
}

/// Helper: parse a JS array of decimal strings back into a
/// `FieldStream`. The arity is validated against the trait's
/// `FIELD_COUNT` by the caller via `validate_structural` (or via
/// `decode` itself, which rejects wrong arity).
fn decimals_to_stream(decimals: Vec<String>) -> Result<FieldStream, JsError> {
    let mut fields = Vec::with_capacity(decimals.len());
    for (i, d) in decimals.iter().enumerate() {
        if !d.bytes().all(|b| b.is_ascii_digit()) || d.is_empty() {
            return Err(JsError::new(&format!(
                "field {i}: must be a non-negative base-10 integer",
            )));
        }
        let f = d
            .parse::<crypto::babyjub::Fq>()
            .map_err(|_| JsError::new(&format!("field {i}: parse error")))?;
        fields.push(f);
    }
    Ok(FieldStream::from_vec(fields))
}

/// `text-utf8-v1` encoding-id, as a decimal string.
///
/// Constant — same value every call. Pinned in
/// `specs/encodings/text-utf8-v1.md`. Useful for boundary tests and
/// for any wire format that tags payloads with their encoding id.
#[wasm_bindgen]
pub fn text_utf8_v1_id() -> String {
    text_utf8_v1::TextUtf8V1::id().into_bigint().to_string()
}

/// Encode UTF-8 bytes via `text-utf8-v1`. Returns the field stream as
/// a JS array of decimal strings (always 9 elements).
///
/// Throws if `bytes` is longer than 248 bytes, or if `bytes` is not
/// valid UTF-8.
#[wasm_bindgen]
pub fn text_utf8_v1_encode(bytes: &[u8]) -> Result<Vec<String>, JsError> {
    let stream = text_utf8_v1::TextUtf8V1::encode(bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(stream_to_decimals(&stream))
}

/// Decode a `text-utf8-v1` field stream back to its UTF-8 bytes.
/// Input is a JS array of 9 decimal strings. Throws on any parse
/// error, structural invalidity (wrong arity, oversized length
/// prefix, chunk exceeds 31 bytes, non-zero padding past `f_0`), or
/// semantic invalidity (decoded bytes are not valid UTF-8).
#[wasm_bindgen]
pub fn text_utf8_v1_decode(stream: Vec<String>) -> Result<Vec<u8>, JsError> {
    let fs = decimals_to_stream(stream)?;
    text_utf8_v1::TextUtf8V1::decode(&fs).map_err(|e| JsError::new(&e.to_string()))
}

// --- poseidon hash bindings -------------------------------------------
//
// One pair of exports per Poseidon family — `_fixed` and `_sponge`.
// Both take decimal-string inputs and return a decimal-string output;
// `_fixed` can throw `ArityOutOfRange`. The two are different hash
// functions and produce different outputs on the same `(domain, inputs)`
// — the choice between them is the consumer's design-time call, pinned
// in the consumer's spec.

/// Helper: parse a single decimal string into an `Fq` field element,
/// rejecting leading signs / garbage to match the boundary's other
/// scalar parsers.
fn fq_from_decimal(s: &str, label: &str) -> Result<crypto::babyjub::Fq, JsError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(JsError::new(&format!(
            "{label}: must be a non-negative base-10 integer",
        )));
    }
    s.parse::<crypto::babyjub::Fq>()
        .map_err(|_| JsError::new(&format!("{label}: parse error")))
}

/// Helper: parse a JS array of decimal strings into a `Vec<Fq>` for
/// the input to a Poseidon hash. Used by both `poseidon_hash_fixed`
/// and `poseidon_hash_sponge`.
fn decimals_to_fields(inputs: Vec<String>) -> Result<Vec<crypto::babyjub::Fq>, JsError> {
    let mut fields = Vec::with_capacity(inputs.len());
    for (i, d) in inputs.iter().enumerate() {
        let label = format!("input[{i}]");
        fields.push(fq_from_decimal(d, &label)?);
    }
    Ok(fields)
}

/// Fixed-arity Poseidon hash. See `specs/poseidon-hash-fixed.md`.
///
/// `domain_tag` and each element of `inputs` are decimal-string field
/// elements. Output is a decimal-string field element. Throws on
/// malformed input or when the input length exceeds 11 (i.e. total
/// arity > 12). For variable-length or longer input, use
/// `poseidon_hash_sponge`.
#[wasm_bindgen]
pub fn poseidon_hash_fixed(
    domain_tag: &str,
    inputs: Vec<String>,
) -> Result<String, JsError> {
    use ark_ff::PrimeField;

    let d = fq_from_decimal(domain_tag, "domain_tag")?;
    let fields = decimals_to_fields(inputs)?;
    let h = crypto::poseidon::poseidon_hash_fixed(d, &fields)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(h.into_bigint().to_string())
}

/// Sponge Poseidon hash. See `specs/poseidon-hash-sponge.md`.
///
/// `domain_tag` and each element of `inputs` are decimal-string field
/// elements. Output is a decimal-string field element. Accepts inputs
/// of any length, including zero.
///
/// Produces a different hash than `poseidon_hash_fixed` on the same
/// `(domain_tag, inputs)`. The choice between them is pinned in the
/// consumer's spec.
#[wasm_bindgen]
pub fn poseidon_hash_sponge(
    domain_tag: &str,
    inputs: Vec<String>,
) -> Result<String, JsError> {
    use ark_ff::PrimeField;

    let d = fq_from_decimal(domain_tag, "domain_tag")?;
    let fields = decimals_to_fields(inputs)?;
    let h = crypto::poseidon::poseidon_hash_sponge(d, &fields);
    Ok(h.into_bigint().to_string())
}
