use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::env_keys::CharacterKey;

const INFO: &[u8] = b"sui-secret-sharing-poc-v1";

#[derive(Debug, Serialize, Deserialize)]
pub struct LocalEnvelope {
    pub protocol: String,
    pub sender: String,
    pub recipient: String,
    pub encryption_scheme: String,
    pub eph_pubkey_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

pub fn encrypt_for_recipient(
    sender: &CharacterKey,
    recipient: &CharacterKey,
    plaintext: &[u8],
) -> Result<LocalEnvelope> {
    let eph_secret = StaticSecret::random_from_rng(OsRng);
    let eph_public = PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&recipient.x25519_public_key);
    let sender_address = sender.sui_address_hex();
    let recipient_address = recipient.sui_address_hex();
    let key = derive_aead_key(shared.as_bytes(), &sender_address, &recipient_address)?;
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .context("encrypting plaintext")?;

    Ok(LocalEnvelope {
        protocol: "sui-secret-sharing-poc-v1".to_owned(),
        sender: sender_address,
        recipient: recipient_address,
        encryption_scheme: "x25519-ed25519-derived+hkdf-sha256+chacha20poly1305".to_owned(),
        eph_pubkey_hex: hex::encode(eph_public.as_bytes()),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

pub fn decrypt_for_recipient(recipient: &CharacterKey, envelope_json: &str) -> Result<Vec<u8>> {
    let envelope: LocalEnvelope =
        serde_json::from_str(envelope_json).context("parsing envelope")?;
    let eph_pubkey = parse_public_key(&envelope.eph_pubkey_hex)?;
    let nonce_bytes = hex::decode(&envelope.nonce_hex).context("decoding nonce hex")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = hex::decode(&envelope.ciphertext_hex).context("decoding ciphertext hex")?;
    let shared = recipient.x25519_private_key.diffie_hellman(&eph_pubkey);
    let key = derive_aead_key(shared.as_bytes(), &envelope.sender, &envelope.recipient)?;
    let cipher = ChaCha20Poly1305::new(&key);
    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .context("decrypting envelope")
}

fn derive_aead_key(shared: &[u8; 32], sender: &str, recipient: &str) -> Result<Key> {
    let salt = format!("{sender}->{recipient}");
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), shared);
    let mut out = [0u8; 32];
    hk.expand(INFO, &mut out)
        .map_err(|_| anyhow::anyhow!("expanding HKDF key"))?;
    Ok(*Key::from_slice(&out))
}

fn parse_public_key(hex_value: &str) -> Result<PublicKey> {
    let bytes = hex::decode(hex_value).context("decoding public key hex")?;
    let key: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("expected 32-byte public key, got {}", bytes.len())
    })?;
    Ok(PublicKey::from(key))
}
