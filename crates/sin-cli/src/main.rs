//! `sin` — command-line admin for the SIn signer.
//!
//! Generate identities, mint a server challenge secret, and manage the
//! allowlist that gates access to your application.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rand::RngCore;
use sin_core::{Allowlist, Keypair, PublicKey};

#[derive(Parser)]
#[command(name = "sin", about = "Passwordless nostr/bitcoin-style sign-in admin", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a fresh identity (keypair). Prints the npub and nsec.
    Gen,

    /// Generate a random 32-byte server challenge secret (hex).
    Secret,

    /// Add (or update) a public key on the allowlist.
    Allow {
        /// The identity to permit, as `npub1...` or 64-char hex.
        key: String,
        /// Friendly label, e.g. "petter's laptop".
        #[arg(short, long)]
        label: String,
        /// Role string your app authorizes against.
        #[arg(short, long, default_value = "user")]
        role: String,
        /// Path to the allowlist file.
        #[arg(short, long, default_value = "allowlist.json")]
        file: PathBuf,
    },

    /// List the keys currently on the allowlist.
    List {
        #[arg(short, long, default_value = "allowlist.json")]
        file: PathBuf,
    },

    /// Remove a key from the allowlist.
    Revoke {
        /// The identity to remove, as `npub1...` or 64-char hex.
        key: String,
        #[arg(short, long, default_value = "allowlist.json")]
        file: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> sin_core::Result<()> {
    match cli.command {
        Command::Gen => {
            let kp = Keypair::generate();
            println!("npub (public, share with the server):");
            println!("  {}", kp.public_key().to_npub());
            println!("  {}", kp.public_key().to_hex());
            println!();
            println!("nsec (SECRET — store on the signing device only):");
            println!("  {}", kp.to_nsec());
        }
        Command::Secret => {
            let mut secret = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            println!("{}", hex::encode(secret));
        }
        Command::Allow {
            key,
            label,
            role,
            file,
        } => {
            let pk = parse_key(&key)?;
            let mut list = Allowlist::load(&file)?;
            let existed = list.allow(&pk, &label, &role).is_some();
            list.save(&file)?;
            println!(
                "{} {} ({role}) as \"{label}\"",
                if existed { "updated" } else { "allowed" },
                pk.to_npub()
            );
        }
        Command::List { file } => {
            let list = Allowlist::load(&file)?;
            if list.is_empty() {
                println!("(allowlist is empty)");
            }
            for (pk, entry) in list.iter() {
                println!("{}  {:<8}  {}", pk.to_npub(), entry.role, entry.label);
            }
        }
        Command::Revoke { key, file } => {
            let pk = parse_key(&key)?;
            let mut list = Allowlist::load(&file)?;
            if list.revoke(&pk) {
                list.save(&file)?;
                println!("revoked {}", pk.to_npub());
            } else {
                println!("{} was not on the allowlist", pk.to_npub());
            }
        }
    }
    Ok(())
}

/// Accept either an `npub1...` or a 64-character hex public key.
fn parse_key(input: &str) -> sin_core::Result<PublicKey> {
    let input = input.trim();
    if input.starts_with("npub1") {
        PublicKey::from_npub(input)
    } else {
        PublicKey::from_hex(input)
    }
}
