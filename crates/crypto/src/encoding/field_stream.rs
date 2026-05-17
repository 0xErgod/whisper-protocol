//! The shared output type for every encoding: a sequence of field
//! elements over the BN254 scalar field (= Baby Jubjub's base field).
//!
//! Every primitive that consumes encoded payloads downstream (stream
//! cipher, MAC, commitment hash, signature challenge, ZK predicates)
//! operates on a [`FieldStream`]. Keeping the type small and uniform
//! is what lets the primitives stay encoding-agnostic — they hash or
//! encrypt or commit to "n field elements," not to "a `PaymentRecord`"
//! or "UTF-8 bytes."

use crate::babyjub::Fq;

/// A fixed-arity sequence of field elements produced by an encoding.
///
/// Construction is via [`FieldStream::new`] (which checks the length
/// invariant) or via the inherent-conversion idiom from `Vec<Fq>`.
/// The inner vector is intentionally private: a `FieldStream` is a
/// produced-by-an-encoding value, not a free-form collection callers
/// should mutate.
///
/// Two streams are equal iff their elements are equal in order; the
/// encoding that produced them is *not* part of the equality. Callers
/// that need to compare under the same encoding should also compare
/// `encoding_id`s.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldStream {
    fields: Vec<Fq>,
}

impl FieldStream {
    /// Construct a `FieldStream` from a `Vec<Fq>` with no length check.
    ///
    /// Public for sibling encoding crates (`crates/encodings/*`)
    /// implementing [`BytePayloadEncoding`]: an encoding's `encode`
    /// method computes a `Vec<Fq>` of length `FIELD_COUNT` and wraps
    /// it here. Length conformance is the encoding's job; this
    /// constructor stays a thin newtype wrap.
    pub fn from_vec(fields: Vec<Fq>) -> Self {
        FieldStream { fields }
    }

    /// Number of field elements in the stream.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether the stream is empty. Conventional companion to `len`;
    /// in practice no real encoding produces an empty stream.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Borrow the underlying field elements.
    pub fn fields(&self) -> &[Fq] {
        &self.fields
    }

    /// Render the stream as a list of base-10 decimal strings — the
    /// wire form. Same convention as every other scalar/coordinate at
    /// the boundary.
    pub fn to_decimals(&self) -> Vec<String> {
        // `Fq` and `Fr` share the same `into_bigint().to_string()` shape;
        // `scalar_to_decimal` is the `Fr` version and isn't reusable.
        // For now, render directly via the bigint surface.
        self.fields
            .iter()
            .map(|f| {
                use ark_ff::PrimeField;
                f.into_bigint().to_string()
            })
            .collect()
    }
}

