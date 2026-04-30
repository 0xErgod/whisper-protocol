mod crypto;
mod env_keys;
mod sui_cli;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use crypto::{decrypt_for_recipient, encrypt_for_recipient};
use env_keys::{Character, generate_env_template, load_character};
use sui_cli::{inbox, post_envelope, register_key};

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate local demo key material for .env.
    GenerateEnv,
    /// Print derived public protocol keys for a demo character.
    Keys {
        #[arg(value_enum)]
        character: CharacterArg,
    },
    /// Encrypt a text secret from one character to another.
    Encrypt {
        #[arg(value_enum)]
        from: CharacterArg,
        #[arg(value_enum)]
        to: CharacterArg,
        #[arg(long)]
        text: String,
    },
    /// Decrypt an envelope JSON using the selected character.
    Decrypt {
        #[arg(value_enum)]
        as_character: CharacterArg,
        #[arg(long)]
        envelope: String,
    },
    /// Register a character's derived encryption public key on local Sui.
    RegisterKey {
        #[arg(value_enum)]
        character: CharacterArg,
    },
    /// Encrypt and post a private text secret on local Sui.
    SendSecret {
        #[arg(value_enum)]
        from: CharacterArg,
        #[arg(value_enum)]
        to: CharacterArg,
        #[arg(long)]
        text: String,
    },
    /// List owned encrypted envelopes and try to decrypt them as a character.
    Inbox {
        #[arg(value_enum)]
        character: CharacterArg,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CharacterArg {
    Alice,
    Bob,
    Charlie,
}

impl From<CharacterArg> for Character {
    fn from(value: CharacterArg) -> Self {
        match value {
            CharacterArg::Alice => Character::Alice,
            CharacterArg::Bob => Character::Bob,
            CharacterArg::Charlie => Character::Charlie,
        }
    }
}

fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    match cli.command {
        Command::GenerateEnv => {
            println!("{}", generate_env_template());
        }
        Command::Keys { character } => {
            let key = load_character(character.into())?;
            println!("{}", serde_json::to_string_pretty(&key.public_summary())?);
        }
        Command::Encrypt { from, to, text } => {
            let sender = load_character(from.into())?;
            let recipient = load_character(to.into())?;
            let envelope = encrypt_for_recipient(&sender, &recipient, text.as_bytes())?;
            println!("{}", serde_json::to_string(&envelope)?);
        }
        Command::Decrypt {
            as_character,
            envelope,
        } => {
            let recipient = load_character(as_character.into())?;
            let plaintext = decrypt_for_recipient(&recipient, &envelope)?;
            println!("{}", String::from_utf8_lossy(&plaintext));
        }
        Command::RegisterKey { character } => {
            let key = load_character(character.into())?;
            let digest = register_key(&key)?;
            println!("{digest}");
        }
        Command::SendSecret { from, to, text } => {
            let sender = load_character(from.into())?;
            let recipient = load_character(to.into())?;
            let envelope = encrypt_for_recipient(&sender, &recipient, text.as_bytes())?;
            let object_id = post_envelope(&sender, &recipient, &envelope)?;
            println!("{object_id}");
        }
        Command::Inbox { character } => {
            let key = load_character(character.into())?;
            let items = inbox(&key)?;
            for item in items {
                println!("{item}");
            }
        }
    }

    Ok(())
}
