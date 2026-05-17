//! Poseidon-sponge keyed MAC over field-element streams.
//!
//! `mac(key, message) = Poseidon-sponge(mac_domain, [key, ...message])`
//! `verify(key, message, tag) = (mac(key, message) == tag)`
//!
//! The MAC takes a symmetric key (one `Fq` element, typically the
//! output of `babyjub-kdf` under the `envelope-mac-key` role) and a
//! field-element stream of any length, and produces one `Fq` tag.
//!
//! ## Construction
//!
//! ```text
//! tag = poseidon_hash_sponge(mac_domain, [key, m_0, m_1, ..., m_{n-1}])
//! ```
//!
//! The key is absorbed as the *first* rate-slot input, after the
//! domain tag (which the sponge folds into capacity at
//! initialization). An attacker without the key cannot compute the
//! correct tag for any message: the sponge's pre-image resistance
//! reduces breaking the MAC to inverting Poseidon, which is the
//! same hardness the rest of the protocol relies on.
//!
//! ## Properties
//!
//! - **Variable-length input.** Sponge absorption — no length cap on
//!   the message. The empty message is valid (produces a per-key
//!   constant).
//! - **Fixed-size output.** One `Fq` element. Always. The tag is
//!   the *hash* of the keyed absorption — same shape regardless of
//!   message length.
//! - **Deterministic.** `mac(key, m) == mac(key, m)` always. The
//!   sponge has no internal randomness.
//! - **Key-binding.** Different keys produce different tags for the
//!   same message with overwhelming probability (`~2⁻²⁵⁴`
//!   collision per pair).
//! - **Message-binding.** Different messages under the same key
//!   produce different tags with overwhelming probability.
//!
//! ## What this construction does NOT defend against
//!
//! - **Confidentiality.** A MAC authenticates; it does not encrypt.
//!   The message is fed in plaintext. The envelope construction
//!   handles confidentiality with `babyjub-cipher` and pairs the
//!   ciphertext with this MAC (encrypt-then-MAC).
//!
//! - **Replay.** A valid `(message, tag)` pair stays valid forever.
//!   The caller binds replay-protection material (envelope id,
//!   counter, recipient index) into the *key* via the KDF context,
//!   so a tag minted for envelope 42 cannot be replayed against
//!   envelope 43 — the keys differ.
//!
//! - **Length-extension on the message.** Not a sponge weakness for
//!   this construction (the output is the squeeze, not an
//!   intermediate state), but worth pinning: an attacker who sees
//!   `(m, tag)` cannot produce `tag'` for `m || extra` without the
//!   key. This is what distinguishes a keyed sponge MAC from a raw
//!   Merkle-Damgård HMAC concern.

use crate::poseidon::{domain_tag, poseidon_hash_sponge};

use super::config::Fq;

/// Domain tag for the MAC's sponge hash. Pinned in
/// `specs/babyjub-mac.md`; changing it invalidates every tag in
/// existence.
pub const MAC_DOMAIN: &str = "babyjub-mac";

/// Compute a MAC tag for `message` under `key`.
///
/// Construction: `Poseidon-sponge(mac_domain, [key, ...message])`.
/// No length cap on `message`; the empty message is valid and
/// produces a per-key constant tag.
pub fn mac(key: Fq, message: &[Fq]) -> Fq {
    let mut input = Vec::with_capacity(1 + message.len());
    input.push(key);
    input.extend_from_slice(message);
    poseidon_hash_sponge(domain_tag(MAC_DOMAIN), &input)
}

/// Verify a tag against a message under a key. Returns `true` iff
/// the tag is correct.
///
/// Equality is checked on the field element directly — `Fq`'s
/// `PartialEq` is a fixed-time comparison on the canonical limbs.
/// (The hash itself dominates the cost anyway, so timing leaks
/// from the comparison are not the threat model concern; the
/// concern is "is the tag right.")
pub fn verify(key: Fq, message: &[Fq], tag: Fq) -> bool {
    mac(key, message) == tag
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: a tag minted via `mac` verifies via `verify`. The
    /// defining property.
    #[test]
    fn mac_then_verify_accepts() {
        let key = Fq::from(42u64);
        let message = vec![Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        let tag = mac(key, &message);
        assert!(verify(key, &message, tag));
    }

    /// Determinism: same `(key, message)` always produces the same
    /// tag.
    #[test]
    fn mac_is_deterministic() {
        let key = Fq::from(42u64);
        let message = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        assert_eq!(mac(key, &message), mac(key, &message));
    }

    /// Empty message is valid; produces a per-key constant tag.
    #[test]
    fn empty_message_is_valid() {
        let key = Fq::from(7u64);
        let tag = mac(key, &[]);
        assert!(verify(key, &[], tag));
    }

    /// Different keys produce different tags for the same message.
    #[test]
    fn different_keys_produce_different_tags() {
        let message = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        let t1 = mac(Fq::from(1u64), &message);
        let t2 = mac(Fq::from(2u64), &message);
        assert_ne!(t1, t2);
    }

    /// Different messages under the same key produce different
    /// tags.
    #[test]
    fn different_messages_produce_different_tags() {
        let key = Fq::from(42u64);
        let t1 = mac(key, &[Fq::from(1u64)]);
        let t2 = mac(key, &[Fq::from(2u64)]);
        assert_ne!(t1, t2);
    }

    /// A truncated message produces a different tag than the full
    /// message. Pins length-binding (a sponge property, but worth
    /// asserting at this layer).
    #[test]
    fn truncation_changes_tag() {
        let key = Fq::from(42u64);
        let full = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        let truncated = &full[..2];
        assert_ne!(mac(key, &full), mac(key, truncated));
    }

    /// Verify rejects the right tag under the wrong key.
    #[test]
    fn verify_rejects_wrong_key() {
        let message = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        let tag = mac(Fq::from(1u64), &message);
        assert!(!verify(Fq::from(2u64), &message, tag));
    }

    /// Verify rejects a tag for a tampered message under the right
    /// key — the integrity property.
    #[test]
    fn verify_rejects_tampered_message() {
        let key = Fq::from(42u64);
        let message = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        let tag = mac(key, &message);
        let tampered = [Fq::from(1u64), Fq::from(2u64), Fq::from(4u64)];
        assert!(!verify(key, &tampered, tag));
    }

    /// Long-message round-trip. Pins the no-length-cap contract.
    #[test]
    fn long_message_roundtrips() {
        let key = Fq::from(7u64);
        let message: Vec<Fq> = (0..256u64).map(Fq::from).collect();
        let tag = mac(key, &message);
        assert!(verify(key, &message, tag));
    }
}
