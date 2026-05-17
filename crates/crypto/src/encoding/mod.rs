//! Payload encoding: the registry interface.
//!
//! An *encoding* is a deterministic, fixed-arity mapping between some
//! input form (bytes, in this v1) and a sequence of BN254 field
//! elements. Encodings are the seam between application-level payloads
//! and the protocol's curve-shaped primitives (cipher, MAC, commitment,
//! signature, ZK predicate circuits) — every protocol operation that
//! "encrypts" or "commits to" a payload first runs it through an
//! encoding to produce the field-element stream those primitives
//! actually consume.
//!
//! ## Registry model
//!
//! The registry is a *pattern*, not a runtime table. An encoding
//! "exists in the registry" iff there is a Rust crate (in
//! `crates/encodings/`, or a third-party crate elsewhere) that
//! implements [`BytePayloadEncoding`] and ships alongside a canonical
//! spec doc in `specs/encodings/`. The encoding's identity is derived
//! from the spec doc's path; see [`id`]. There is no global mutable
//! map; if you want to decode an unknown encoding, you have to
//! statically depend on the crate that defines it.
//!
//! See [`specs/encodings/README.md`](../../../specs/encodings/README.md)
//! for the registry taxonomy, conformance rules, and the byte/typed
//! split.
//!
//! ## What this v1 commits to (and what it does not)
//!
//! [`BytePayloadEncoding`] is the **byte-input** half of the registry.
//! It handles encodings whose natural input is a byte slice: free-form
//! text, JSON, certificates, structurally-loose data with externally-
//! defined formats. For typed encodings (a `PaymentRecord` struct, a
//! `Vec<MerkleProof>`, etc.), a sibling `TypedPayloadEncoding<Input>`
//! trait will be added when the first typed use case is real. It's not
//! ready now because there's no consumer to push back on its shape.
//! Both traits will share the same id namespace and the same
//! [`FieldStream`] output; they're parallel, not nested.
//!
//! Every encoding (byte or typed) MUST be:
//! - **Deterministic** — same input always produces the same output.
//! - **Fixed-arity** — output [`FieldStream`] has the same
//!   `FIELD_COUNT` length every time. Variable-length payloads are
//!   handled by padding to a max (see `text-utf8-v1`).
//! - **Single-stream** — output is one [`FieldStream`], not multiple
//!   parallel streams. Multi-stream and point-bearing encodings would
//!   need a different trait.
//!
//! See `specs/encodings/README.md` for the full rationale.

mod error;
mod field_stream;
pub mod id;

pub use error::EncodingError;
pub use field_stream::FieldStream;

use crate::babyjub::Fq;

/// A byte-input encoding: bytes ↔ a fixed-arity stream of field
/// elements.
///
/// Implementations live in `crates/encodings/<name>/` (or third-party
/// crates elsewhere). Each implementation:
///
/// - Has a canonical spec at `specs/encodings/<name>-v<n>.md`.
/// - Derives its [`id`](BytePayloadEncoding::id) from that spec path
///   via [`crate::encoding::id::encoding_id`].
/// - Documents in its spec what semantic predicates are cheap to prove
///   over its [`FieldStream`] (length, hash equality, prefix, etc.).
///
/// ## Contracts
///
/// - `encode` and `decode` MUST round-trip for all inputs `encode`
///   accepts. That is: `decode(encode(b)?) == Ok(b)` for every `b`
///   that `encode` does not reject.
/// - `encode` MUST be deterministic. Same `&[u8]` always produces the
///   same [`FieldStream`].
/// - `encode` MUST produce a [`FieldStream`] of length exactly
///   [`FIELD_COUNT`](BytePayloadEncoding::FIELD_COUNT).
/// - `validate_structural` MUST be a strict subset of `decode`: any
///   stream where `decode` succeeds, `validate_structural` MUST
///   return `true`. (The reverse need not hold — `text-utf8-v1`'s
///   structural validator does not check UTF-8 validity, but `decode`
///   does.)
/// - `id` MUST be a constant determined by the encoding type, not by
///   any per-instance data. Two instances of the same encoding always
///   return the same id.
pub trait BytePayloadEncoding {
    /// Number of field elements every encoded payload of this
    /// encoding contains. Fixed at the encoding's design time and
    /// part of its identity.
    const FIELD_COUNT: usize;

    /// Encoding identifier — the field element that names this scheme
    /// at the wire level. Derived from the spec path via
    /// [`encoding_id`](id::encoding_id).
    fn id() -> Fq;

    /// Forward encoding: bytes → field stream.
    ///
    /// Returns `Err` if `input` violates the encoding's preconditions
    /// (too long, structurally invalid for this encoding, etc.). On
    /// `Ok`, the returned [`FieldStream`] has exactly `FIELD_COUNT`
    /// elements.
    fn encode(input: &[u8]) -> Result<FieldStream, EncodingError>;

    /// Reverse decoding: field stream → bytes.
    ///
    /// Returns `Err` if `stream` is not a valid instance of this
    /// encoding. "Valid" here is the **full** notion — including any
    /// semantic checks the encoding cares about (UTF-8 validity for
    /// `text-utf8-v1`, kv-pair well-formedness for a future
    /// `kv-pairs-v1`, etc.). For the cheaper structural-only check,
    /// use [`validate_structural`](Self::validate_structural).
    fn decode(stream: &FieldStream) -> Result<Vec<u8>, EncodingError>;

    /// Structural validity: cheap check that mirrors what an
    /// in-circuit validator would prove. Length, padding, chunk
    /// shape — *not* semantic well-formedness.
    ///
    /// MUST return `true` for any stream `decode` accepts. MAY return
    /// `true` for some streams `decode` rejects (those that are
    /// structurally well-formed but semantically invalid — e.g.
    /// `text-utf8-v1` field-streams that decode to non-UTF-8 bytes).
    fn validate_structural(stream: &FieldStream) -> bool;
}
