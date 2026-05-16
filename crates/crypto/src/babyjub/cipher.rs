//! Poseidon-based stream cipher over field-element streams.
//!
//! `encrypt(key, plaintext) = [plaintext_i + Poseidon(cipher_domain, key, i)]_i`
//! `decrypt(key, ciphertext) = [ciphertext_i - Poseidon(cipher_domain, key, i)]_i`
//!
//! Same shape in and out: a 9-element plaintext stream produces a
//! 9-element ciphertext stream. The cipher operates per-element via
//! field-addition (mod `p`), not bitwise XOR — the arithmetic form is
//! ZK-native (one constraint per element instead of one per bit) and
//! matches the encoding's field-shaped output exactly.
//!
//! ## Construction
//!
//! For each position `i`:
//!
//! ```text
//! keystream_i = Poseidon_hash_fixed(cipher_domain, [key, i_as_field])
//! ciphertext_i = plaintext_i + keystream_i     (mod p)
//! plaintext_i  = ciphertext_i - keystream_i    (mod p)
//! ```
//!
//! The counter `i` is encoded as `Fq::from(i as u64)` — a small
//! non-negative integer in the base field. The full Poseidon call is
//! arity 3 (domain + key + counter), independent of stream length.
//!
//! ## Properties
//!
//! - **Symmetric** — `decrypt(key, encrypt(key, p)) == p` for every
//!   key and every plaintext. The defining property of any cipher.
//! - **Per-element addressable keystream** — `keystream_i` depends
//!   only on `(key, i)`, not on prior or subsequent elements. A
//!   future ZK predicate that wants to prove "the i-th plaintext
//!   element equals X given the i-th ciphertext element" reads
//!   exactly one keystream slot, no chain to follow.
//! - **Length-preserving** — `|ciphertext| == |plaintext|`.
//!
//! ## What this construction does NOT defend against
//!
//! - **Keystream reuse across messages.** If two plaintexts are
//!   encrypted under the same `key`, the same keystream is produced
//!   for each position. `c1_i - c2_i = p1_i - p2_i` reveals
//!   plaintext relationships. The cipher does NOT carry a per-message
//!   nonce of its own; key uniqueness per message is the **caller's
//!   responsibility** and the canonical way to enforce it is via the
//!   KDF: derive a fresh key per envelope by including an envelope
//!   identifier in the KDF context (see
//!   `specs/babyjub-kdf.md`).
//!
//!   A nonce-bearing variant (`Poseidon(cipher_domain, key, nonce,
//!   i)`) is a separate scheme and would mint its own spec. For the
//!   envelope use case where keys are already per-message, the extra
//!   nonce input is redundant cost.
//!
//! - **Tampering.** A stream cipher provides confidentiality, not
//!   integrity. An attacker who knows or guesses `plaintext_i` can
//!   tamper with `ciphertext_i` to flip the plaintext to any chosen
//!   value. Integrity is the MAC's job; the envelope construction
//!   pairs this cipher with `babyjub-mac` for that reason.
//!
//! - **Bit-level confidentiality.** The cipher hides
//!   *field-element values*, not *bit patterns within values*. An
//!   attacker who knows `plaintext_i ∈ {0, 1}` still can't tell
//!   which from `ciphertext_i` alone, but a bit-flipping
//!   chosen-plaintext attack against a known-bit-pattern target
//!   would have a different shape than for an XOR-based cipher.
//!   Field-arithmetic is the right level for our use case
//!   (encrypted encoded streams); bit-level is something
//!   byte-oriented ciphers do and we don't need.

use crate::poseidon::{domain_tag, poseidon_hash_fixed};

use super::config::Fq;

/// Domain tag for the cipher's keystream hash. Pinned in
/// `specs/babyjub-cipher.md`; changing it changes every
/// ciphertext.
pub const CIPHER_DOMAIN: &str = "babyjub-stream-cipher";

/// Compute the keystream element for position `i`. Internal helper;
/// callers use `encrypt`/`decrypt`.
fn keystream_at(key: Fq, i: usize) -> Fq {
    poseidon_hash_fixed(
        domain_tag(CIPHER_DOMAIN),
        &[key, Fq::from(i as u64)],
    )
    .expect("arity 3 is always in range")
}

/// Encrypt a plaintext stream by adding the per-position Poseidon
/// keystream to each element, mod `p`.
///
/// Same shape in and out — a length-`n` plaintext produces a
/// length-`n` ciphertext. No size cap; the cipher iterates per
/// element and each Poseidon call is fixed-arity.
pub fn encrypt(key: Fq, plaintext: &[Fq]) -> Vec<Fq> {
    plaintext
        .iter()
        .enumerate()
        .map(|(i, p)| *p + keystream_at(key, i))
        .collect()
}

/// Decrypt a ciphertext stream by subtracting the same keystream.
///
/// `decrypt(key, encrypt(key, p)) == p` for every key and plaintext.
/// Same shape in and out.
pub fn decrypt(key: Fq, ciphertext: &[Fq]) -> Vec<Fq> {
    ciphertext
        .iter()
        .enumerate()
        .map(|(i, c)| *c - keystream_at(key, i))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::AdditiveGroup;

    /// Round-trip: `decrypt(key, encrypt(key, p)) == p`. The defining
    /// property; everything else builds on it.
    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let key = Fq::from(42u64);
        let plaintext = vec![
            Fq::from(0u64),
            Fq::from(100u64),
            Fq::from(99999u64),
            Fq::from(7u64),
        ];
        let ciphertext = encrypt(key, &plaintext);
        let recovered = decrypt(key, &ciphertext);
        assert_eq!(recovered, plaintext);
    }

    /// Round-trip on the empty stream. Length-zero is a valid edge
    /// case — the empty plaintext encrypts to the empty ciphertext.
    #[test]
    fn empty_stream_roundtrips() {
        let key = Fq::from(1u64);
        let ciphertext = encrypt(key, &[]);
        assert!(ciphertext.is_empty());
        let recovered = decrypt(key, &ciphertext);
        assert!(recovered.is_empty());
    }

    /// Length is preserved: `|ciphertext| == |plaintext|`. The
    /// cipher does not add overhead.
    #[test]
    fn length_is_preserved() {
        let key = Fq::from(7u64);
        for n in [0usize, 1, 9, 100] {
            let plaintext: Vec<Fq> = (0..n as u64).map(Fq::from).collect();
            let ciphertext = encrypt(key, &plaintext);
            assert_eq!(ciphertext.len(), n);
        }
    }

    /// Determinism: same `(key, plaintext)` always produces the same
    /// ciphertext. Foundational.
    #[test]
    fn encrypt_is_deterministic() {
        let key = Fq::from(42u64);
        let plaintext = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        assert_eq!(encrypt(key, &plaintext), encrypt(key, &plaintext));
    }

    /// Different keys produce different ciphertexts (for non-trivial
    /// plaintexts). If two keys produced identical ciphertexts for a
    /// non-trivial plaintext, the cipher wouldn't be cipher-ing
    /// anything.
    #[test]
    fn different_keys_produce_different_ciphertexts() {
        let plaintext = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        let c1 = encrypt(Fq::from(1u64), &plaintext);
        let c2 = encrypt(Fq::from(2u64), &plaintext);
        assert_ne!(c1, c2);
    }

    /// The per-position keystream is position-dependent: encrypting
    /// `[x]` and `[x, x]` produces ciphertexts whose first elements
    /// agree (both use `keystream_0`), but the second slot of the
    /// longer ciphertext uses `keystream_1`, distinct from
    /// `keystream_0`. Pins per-position addressability.
    #[test]
    fn keystream_is_position_dependent() {
        let key = Fq::from(99u64);
        let c1 = encrypt(key, &[Fq::from(5u64)]);
        let c2 = encrypt(key, &[Fq::from(5u64), Fq::from(5u64)]);
        assert_eq!(c1[0], c2[0], "position 0 keystream is shared");
        assert_ne!(c1[0], c2[1], "position 1 keystream is distinct from position 0");
    }

    /// Decrypting under the WRONG key produces garbage, not the
    /// plaintext. (Decryption never errors — it always returns
    /// *something* of the right length. That's expected for a stream
    /// cipher without integrity; the MAC's job to detect this case.)
    #[test]
    fn decrypt_under_wrong_key_is_garbage() {
        let plaintext = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        let ciphertext = encrypt(Fq::from(1u64), &plaintext);
        let recovered = decrypt(Fq::from(2u64), &ciphertext);
        assert_ne!(recovered, plaintext);
    }

    /// All-zero plaintext: ciphertext IS the keystream. Pins the
    /// edge case where the cipher's output is just the keystream
    /// directly, which is useful as a "what's the keystream for this
    /// key?" probe for tests and audits.
    #[test]
    fn all_zero_plaintext_encrypts_to_keystream() {
        let key = Fq::from(123u64);
        let plaintext = vec![Fq::ZERO; 5];
        let ciphertext = encrypt(key, &plaintext);
        for (i, c) in ciphertext.iter().enumerate() {
            assert_eq!(*c, keystream_at(key, i));
        }
    }

    /// Long stream round-trips correctly. The cipher has no internal
    /// size limit (unlike the Schnorr message hash or KDF context);
    /// each Poseidon call is independent.
    #[test]
    fn long_stream_roundtrips() {
        let key = Fq::from(7u64);
        let plaintext: Vec<Fq> = (0..256u64).map(|i| Fq::from(i * i + 1)).collect();
        let ciphertext = encrypt(key, &plaintext);
        let recovered = decrypt(key, &ciphertext);
        assert_eq!(recovered, plaintext);
    }
}
