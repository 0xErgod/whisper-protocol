use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::crypto::{LocalEnvelope, decrypt_for_recipient};
use crate::env_keys::CharacterKey;

const MODULE: &str = "secret_sharing";
const CLOCK_ID: &str = "0x6";

pub fn register_key(key: &CharacterKey) -> Result<String> {
    let package = package_id()?;
    let output = sui_json([
        "client",
        "call",
        "--package",
        &package,
        "--module",
        MODULE,
        "--function",
        "register_encryption_key",
        "--args",
        &package,
        &hex_arg(b"ed25519"),
        &hex_arg(&key.ed25519_public_key),
        &hex_arg(b"x25519-from-ed25519"),
        &hex_arg(key.x25519_public_key.as_bytes()),
        "1",
        CLOCK_ID,
        "--sender",
        &key.sui_address_hex(),
        "--gas-budget",
        "10000000",
        "--json",
    ])?;
    Ok(output["digest"]
        .as_str()
        .unwrap_or("<missing digest>")
        .to_owned())
}

pub fn post_envelope(
    sender: &CharacterKey,
    recipient: &CharacterKey,
    envelope: &LocalEnvelope,
) -> Result<String> {
    let package = package_id()?;
    let output = sui_json([
        "client",
        "call",
        "--package",
        &package,
        "--module",
        MODULE,
        "--function",
        "post_envelope",
        "--args",
        &package,
        &recipient.sui_address_hex(),
        &hex_arg(b"text_secret_v1"),
        "1",
        &hex_prefixed(&envelope.eph_pubkey_hex),
        "0x00",
        &hex_prefixed(&envelope.nonce_hex),
        &hex_prefixed(&envelope.ciphertext_hex),
        CLOCK_ID,
        "--sender",
        &sender.sui_address_hex(),
        "--gas-budget",
        "10000000",
        "--json",
    ])?;

    find_created_object(&output, &format!("{package}::{MODULE}::EncryptedEnvelope"))
        .context("published transaction did not create an EncryptedEnvelope")
}

pub fn inbox(key: &CharacterKey) -> Result<Vec<String>> {
    let package = package_id()?;
    let objects = sui_json(["client", "objects", &key.sui_address_hex(), "--json"])?;
    let Some(array) = objects.as_array() else {
        bail!("unexpected objects response");
    };

    let mut rendered = Vec::new();
    for object in array {
        if !is_envelope_object(object, &package) {
            continue;
        }
        let Some(contents) = object["data"]["Move"]["contents"].as_array() else {
            rendered.push("unknown object: unreadable object contents".to_owned());
            continue;
        };
        let bytes = values_to_bytes(contents)?;
        let decoded = decode_envelope_contents(&bytes)?;
        let envelope = LocalEnvelope {
            protocol: "sui-secret-sharing-poc-v1".to_owned(),
            sender: decoded.sender,
            recipient: decoded.recipient,
            encryption_scheme: "x25519-ed25519-derived+hkdf-sha256+chacha20poly1305".to_owned(),
            eph_pubkey_hex: hex::encode(decoded.eph_pubkey),
            nonce_hex: hex::encode(decoded.nonce),
            ciphertext_hex: hex::encode(decoded.ciphertext),
        };
        let envelope_json = serde_json::to_string(&envelope)?;
        match decrypt_for_recipient(key, &envelope_json) {
            Ok(plaintext) => rendered.push(format!(
                "{}: {}",
                decoded.object_id,
                String::from_utf8_lossy(&plaintext)
            )),
            Err(_) => rendered.push(format!("{}: <locked>", decoded.object_id)),
        }
    }

    if rendered.is_empty() {
        rendered.push("No encrypted envelopes owned by this character.".to_owned());
    }

    Ok(rendered)
}

fn package_id() -> Result<String> {
    std::env::var("SUI_PACKAGE_ID")
        .context("missing SUI_PACKAGE_ID in .env; publish the package and set it")
}

fn sui_json<const N: usize>(args: [&str; N]) -> Result<Value> {
    let output = Command::new("sui")
        .args(args)
        .output()
        .context("running sui CLI")?;
    if !output.status.success() {
        bail!(
            "sui CLI failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8(output.stdout).context("sui CLI stdout was not UTF-8")?;
    serde_json::from_str(&stdout).with_context(|| format!("parsing sui JSON output: {stdout}"))
}

fn hex_arg(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn hex_prefixed(hex: &str) -> String {
    if hex.starts_with("0x") {
        hex.to_owned()
    } else {
        format!("0x{hex}")
    }
}

fn find_created_object(output: &Value, object_type: &str) -> Option<String> {
    output["objectChanges"]
        .as_array()?
        .iter()
        .find(|change| {
            change["type"].as_str() == Some("created")
                && change["objectType"].as_str() == Some(object_type)
        })?
        .get("objectId")?
        .as_str()
        .map(ToOwned::to_owned)
}

fn is_envelope_object(object: &Value, package: &str) -> bool {
    let other = &object["data"]["Move"]["type_"]["Other"];
    other["address"].as_str() == Some(package.trim_start_matches("0x"))
        && other["module"].as_str() == Some(MODULE)
        && other["name"].as_str() == Some("EncryptedEnvelope")
}

fn values_to_bytes(values: &[Value]) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(values.len());
    for value in values {
        let byte = value
            .as_u64()
            .context("expected byte array value")?
            .try_into()
            .context("byte array value out of range")?;
        bytes.push(byte);
    }
    Ok(bytes)
}

struct DecodedEnvelope {
    object_id: String,
    sender: String,
    recipient: String,
    eph_pubkey: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn decode_envelope_contents(bytes: &[u8]) -> Result<DecodedEnvelope> {
    let mut cursor = Cursor { bytes, offset: 0 };
    let object_id = cursor.address_hex()?;
    let _game_id = cursor.address_hex()?;
    let sender = cursor.address_hex()?;
    let recipient = cursor.address_hex()?;
    let _schema = cursor.vector()?;
    let _key_version = cursor.u64()?;
    let eph_pubkey = cursor.vector()?;
    let _wrapped_key = cursor.vector()?;
    let nonce = cursor.vector()?;
    let ciphertext = cursor.vector()?;
    let _created_at_ms = cursor.u64()?;

    Ok(DecodedEnvelope {
        object_id,
        sender,
        recipient,
        eph_pubkey,
        nonce,
        ciphertext,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Cursor<'_> {
    fn take(&mut self, len: usize) -> Result<&[u8]> {
        let end = self
            .offset
            .checked_add(len)
            .context("BCS cursor overflow")?;
        if end > self.bytes.len() {
            bail!("BCS object ended unexpectedly");
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn address_hex(&mut self) -> Result<String> {
        Ok(format!("0x{}", hex::encode(self.take(32)?)))
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes: [u8; 8] = self.take(8)?.try_into().expect("slice length checked");
        Ok(u64::from_le_bytes(bytes))
    }

    fn vector(&mut self) -> Result<Vec<u8>> {
        let len = self.uleb128()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn uleb128(&mut self) -> Result<u64> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.take(1)?[0];
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                bail!("ULEB128 length is too large");
            }
        }
    }
}
