//! Encoding-id derivation.
//!
//! An encoding's id is a field element in `Fq` derived from the
//! canonical path of its spec doc. Two-line rule:
//!
//! ```text
//! encoding_id = bytes_to_field_be(Blake2b-256(canonical_spec_path))
//! ```
//!
//! where `canonical_spec_path` is the repo-relative path to the
//! encoding's spec doc, exactly as it appears in the filesystem,
//! including the `-v<n>` suffix. For example:
//!
//! - `"specs/encodings/text-utf8-v1.md"` → encoding-id for
//!   `text-utf8-v1`.
//! - `"specs/encodings/kv-pairs-v1.md"` → encoding-id for
//!   `kv-pairs-v1`.
//!
//! ## Properties
//!
//! - **Self-certifying.** Anyone with the spec path can re-derive the
//!   id. No registry server, no central writer, no out-of-band
//!   lookup.
//! - **Collision-resistant.** Distinct paths produce distinct ids
//!   (with overwhelming probability — same security as the underlying
//!   hash).
//! - **Path-based, not content-based.** Editing the spec doc does NOT
//!   change the id. This is deliberate: it means an editorial
//!   improvement to the doc (typo fix, clarification, added
//!   examples) doesn't invalidate every payload encoded under that
//!   id. The trade is that the path is the load-bearing identifier;
//!   moving or renaming a spec doc silently mints a new encoding,
//!   which is why the `-v<n>` suffix discipline exists.
//!
//! ## Versioning discipline
//!
//! Every encoding's spec path MUST include a `-v<n>` suffix. A
//! breaking change to the encoding mints a new doc at `-v<n+1>` (and
//! a new crate at `crates/encodings/<name>-v<n+1>/`); the old doc
//! stays in place so old payloads remain decodable. Path-based id
//! makes this discipline necessary — it also makes it cheap, because
//! a new version is literally a new file.

use ark_ff::PrimeField;
use blake2::{digest::consts::U32, Blake2b, Digest};

use crate::babyjub::Fq;

/// Derive an encoding-id from its canonical spec-doc path.
///
/// The input is the repo-relative path string; case- and
/// punctuation-sensitive. The output is a field element in `Fq`
/// suitable for use as the encoding's wire-level identifier.
///
/// This is the function every conformant implementation (Rust, TS,
/// future circuit) MUST run on the same path string to land on the
/// same id.
pub fn encoding_id(canonical_spec_path: &str) -> Fq {
    let digest = Blake2b::<U32>::digest(canonical_spec_path.as_bytes());
    // Big-endian unsigned-integer interpretation, reduced mod p.
    // 256-bit input into a 254-bit field; the resulting bias is
    // negligible for a fixed identifier.
    Fq::from_be_bytes_mod_order(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Determinism: same path → same id, every time.
    #[test]
    fn id_is_deterministic() {
        let p = "specs/encodings/text-utf8-v1.md";
        assert_eq!(encoding_id(p), encoding_id(p));
    }

    /// Different paths → different ids (with overwhelming
    /// probability; same security as Blake2b-256).
    #[test]
    fn distinct_paths_yield_distinct_ids() {
        let a = encoding_id("specs/encodings/text-utf8-v1.md");
        let b = encoding_id("specs/encodings/text-utf8-v2.md");
        let c = encoding_id("specs/encodings/kv-pairs-v1.md");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    /// Case sensitivity: deliberate. Path strings are exact-match.
    #[test]
    fn id_is_case_sensitive() {
        let lo = encoding_id("specs/encodings/text-utf8-v1.md");
        let hi = encoding_id("specs/encodings/Text-Utf8-V1.md");
        assert_ne!(lo, hi);
    }
}
