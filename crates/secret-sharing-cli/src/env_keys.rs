use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha2::Digest;
use sha2::Sha512;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone, Copy, Debug)]
pub enum Character {
    Alice,
    Bob,
    Charlie,
}

impl Character {
    fn env_prefix(self) -> &'static str {
        match self {
            Character::Alice => "ALICE",
            Character::Bob => "BOB",
            Character::Charlie => "CHARLIE",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Character::Alice => "Alice",
            Character::Bob => "Bob",
            Character::Charlie => "Charlie",
        }
    }
}

pub struct CharacterKey {
    pub name: &'static str,
    pub ed25519_public_key: [u8; 32],
    pub sui_address: [u8; 32],
    pub x25519_private_key: StaticSecret,
    pub x25519_public_key: PublicKey,
}

#[derive(Debug, Serialize)]
pub struct PublicKeySummary {
    pub name: &'static str,
    pub sui_address: String,
    pub ed25519_public_key_hex: String,
    pub ed25519_private_key_source: &'static str,
    pub x25519_public_key_hex: String,
    pub encryption_scheme: &'static str,
}

impl CharacterKey {
    pub fn sui_address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.sui_address))
    }

    pub fn public_summary(&self) -> PublicKeySummary {
        PublicKeySummary {
            name: self.name,
            sui_address: self.sui_address_hex(),
            ed25519_public_key_hex: hex::encode(self.ed25519_public_key),
            ed25519_private_key_source: ".env",
            x25519_public_key_hex: hex::encode(self.x25519_public_key.as_bytes()),
            encryption_scheme: "x25519-from-ed25519",
        }
    }
}

pub fn load_character(character: Character) -> Result<CharacterKey> {
    let env_name = format!("{}_ED25519_PRIVATE_KEY", character.env_prefix());
    let raw = std::env::var(&env_name).with_context(|| {
        format!("missing {env_name}; copy .env.example to .env and add a local dev key")
    })?;
    let seed = parse_32_byte_key(&raw).with_context(|| format!("invalid {env_name}"))?;
    let ed25519_public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let sui_address = sui_ed25519_address(&ed25519_public_key);
    let x25519_private_key = ed25519_seed_to_x25519_private_key(&seed);
    let x25519_public_key = PublicKey::from(&x25519_private_key);

    Ok(CharacterKey {
        name: character.display_name(),
        ed25519_public_key,
        sui_address,
        x25519_private_key,
        x25519_public_key,
    })
}

pub fn generate_env_template() -> String {
    let mut out = String::from("# Local dev keys. Do not use with real funds.\n");
    for name in ["ALICE", "BOB", "CHARLIE"] {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        out.push_str(&format!(
            "{name}_ED25519_PRIVATE_KEY=0x{}\n",
            hex::encode(seed)
        ));
    }
    out
}

fn parse_32_byte_key(raw: &str) -> Result<[u8; 32]> {
    let trimmed = raw.trim();
    let decoded = if let Some(hex) = trimmed.strip_prefix("0x") {
        hex::decode(hex)?
    } else if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(trimmed)?
    } else {
        BASE64_STANDARD.decode(trimmed)?
    };

    if decoded.len() != 32 {
        bail!("expected 32-byte Ed25519 seed, got {} bytes", decoded.len());
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn ed25519_seed_to_x25519_private_key(seed: &[u8; 32]) -> StaticSecret {
    let digest = Sha512::digest(seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&digest[..32]);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    StaticSecret::from(scalar)
}

fn sui_ed25519_address(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid Blake2b output size");
    hasher.update(&[0x00]);
    hasher.update(public_key);
    let mut address = [0u8; 32];
    hasher
        .finalize_variable(&mut address)
        .expect("valid Blake2b output buffer");
    address
}
