//! `sin` — command-line admin for the SIn signer.
//!
//! Generate identities, mint a server challenge secret, and manage the
//! allowlist that gates access to your application.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use rand::RngCore;
use sin_core::{Allowlist, ChallengeKey, Keypair, PublicKey, Verifier};

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

    /// Mint a challenge string for a client to sign (uses the server secret).
    Challenge {
        /// Server challenge secret, as hex (see `sin secret`).
        #[arg(short, long)]
        secret: String,
        /// Time-to-live in seconds.
        #[arg(short, long, default_value_t = 300)]
        ttl: u64,
        /// Override "now" (unix seconds); defaults to the system clock.
        #[arg(long)]
        now: Option<u64>,
    },

    /// Verify an Authorization token (read from stdin) against the allowlist.
    ///
    /// Prints the authenticated npub and role on success; exits non-zero on
    /// failure. The token is the full header value, e.g. `Nostr eyJ...`.
    Verify {
        /// Server challenge secret, as hex (must match the one used to mint).
        #[arg(short, long)]
        secret: String,
        /// The request URL the token must be bound to.
        #[arg(short, long)]
        url: String,
        /// The request method the token must be bound to.
        #[arg(short, long, default_value = "GET")]
        method: String,
        /// Path to the allowlist file.
        #[arg(short, long, default_value = "allowlist.json")]
        file: PathBuf,
        /// Allowed clock skew in seconds.
        #[arg(long, default_value_t = 60)]
        skew: i64,
        /// Override "now" (unix seconds); defaults to the system clock.
        #[arg(long)]
        now: Option<u64>,
    },
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the unix epoch")
        .as_secs()
}

fn decode_secret(hex_secret: &str) -> sin_core::Result<Vec<u8>> {
    hex::decode(hex_secret.trim())
        .map_err(|e| sin_core::Error::Key(format!("challenge secret is not valid hex: {e}")))
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
        Command::Challenge { secret, ttl, now } => {
            let challenge = ChallengeKey::new(decode_secret(&secret)?, ttl);
            let now = now.unwrap_or_else(now_unix);
            println!("{}", challenge.issue(now));
        }
        Command::Verify {
            secret,
            url,
            method,
            file,
            skew,
            now,
        } => {
            let mut token = String::new();
            std::io::stdin().read_to_string(&mut token)?;
            let challenge = ChallengeKey::new(decode_secret(&secret)?, 0);
            let verifier = Verifier::new(challenge, skew);
            let allowlist = Allowlist::load(&file)?;
            let now = now.unwrap_or_else(now_unix);
            let signin = verifier.verify(token.trim(), &method, &url, &allowlist, now)?;
            println!("OK {} {} \"{}\"", signin.pubkey.to_npub(), signin.role, signin.label);
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
