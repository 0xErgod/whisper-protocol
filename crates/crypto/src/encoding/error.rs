//! Errors returned by encoding `encode` and `decode` methods.

use core::fmt;

/// Why an encode or decode call failed.
///
/// Variants are deliberately coarse — encodings differ enough that
/// fine-grained error taxonomies would either over-specialize the
/// shared error type or invite "Other(String)" sprawl. Each encoding's
/// spec doc names the conditions under which each variant fires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodingError {
    /// The input bytes violated a structural precondition of this
    /// encoding — too long, wrong size, malformed framing.
    InvalidInput(&'static str),
    /// The field stream has the wrong number of elements for this
    /// encoding. Mostly a defensive check at the boundary; encodings
    /// produce streams of the right size by construction internally.
    WrongFieldCount {
        expected: usize,
        actual: usize,
    },
    /// The field stream's structural invariants don't hold — padding
    /// is non-zero where it should be zero, chunk shape is wrong,
    /// length prefix is out of range, etc.
    StructuralInvalid(&'static str),
    /// The field stream is structurally valid but its semantic
    /// invariants don't hold — for `text-utf8-v1`, the bytes are
    /// structurally well-formed but aren't valid UTF-8.
    SemanticInvalid(&'static str),
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodingError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            EncodingError::WrongFieldCount { expected, actual } => {
                write!(f, "wrong field count: expected {expected}, got {actual}")
            }
            EncodingError::StructuralInvalid(msg) => {
                write!(f, "structurally invalid stream: {msg}")
            }
            EncodingError::SemanticInvalid(msg) => {
                write!(f, "semantically invalid stream: {msg}")
            }
        }
    }
}

impl std::error::Error for EncodingError {}
