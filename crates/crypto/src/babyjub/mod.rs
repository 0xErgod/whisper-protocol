//! Baby Jubjub: the twisted Edwards curve over the BN254 scalar field, in the
//! ERC-2494 / circomlib dialect.
//!
//! This module is the algebraic substrate for the protocol's keypairs,
//! commitments, key agreement, and signatures. It deliberately exposes only the
//! curve *as a group* — keypairs, ECDH, commitments, and signatures are built
//! in sibling modules on top of what is re-exported here.

mod cipher;
mod config;
mod curve;
mod ecdh;
mod kdf;
mod keypair;
mod pedersen;
mod schnorr;
mod wire;

pub use cipher::{decrypt, encrypt, CIPHER_DOMAIN};
pub use config::{BabyJubConfig, EdwardsAffine, EdwardsProjective, Fq, Fr};
pub use curve::{generator, is_in_prime_subgroup, is_on_curve, mul, IDENTITY};
pub use ecdh::shared_secret;
pub use kdf::{derive as kdf_derive, KDF_DOMAIN, MAX_CONTEXT_LEN as KDF_MAX_CONTEXT_LEN};
pub use keypair::{keypair_from_seed, PublicKey, SecretKey, Seed, KEYPAIR_DOMAIN};
pub use pedersen::{
    commit, derive_g_at, derive_h, g_generator, h_generator, G_DOMAIN, H_DOMAIN,
};
pub use schnorr::{
    sign, verify, SchnorrError, Signature, CHALLENGE_DOMAIN, MAX_MESSAGE_LEN, MESSAGE_DOMAIN,
    NONCE_DOMAIN,
};
pub use wire::{
    point_from_strings, point_to_strings, scalar_from_decimal, scalar_to_decimal, PointStrings,
    WireError,
};
