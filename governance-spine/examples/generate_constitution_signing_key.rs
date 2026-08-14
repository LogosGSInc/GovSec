//! A2 — one-time (or key-rotation) generator for the constitution-authoring
//! Ed25519 keypair. This is an OFFLINE release-signing identity, entirely
//! separate from any per-process CryptoEngine key and from A3's runtime
//! audit-signing identity — it exists only to sign the canonical
//! constitution document at release time; the running Sentinel process
//! never holds it.
//!
//! Deliberately writes OUTSIDE the repository and OUTSIDE any Docker/Podman
//! build context, and never prints private-key material — only paths,
//! permissions, and the public-key fingerprint.
//!
//! Usage: cargo run --example generate_constitution_signing_key

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn custody_dir() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME must be set");
    PathBuf::from(home).join(".logosgs").join("constitution-signing")
}

fn main() {
    let dir = custody_dir();

    // Output path is always $HOME/.logosgs/constitution-signing regardless
    // of current working directory — running this from inside the repo
    // (e.g. via `cargo run --example ...`) is safe; nothing is ever
    // written under the repo or a build context.
    fs::create_dir_all(&dir).expect("create custody dir");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod custody dir");

    let priv_path = dir.join("constitution-authority-ed25519.key");
    let pub_path = dir.join("constitution-authority-ed25519.pub");

    if priv_path.exists() || pub_path.exists() {
        eprintln!(
            "[REFUSED] A key already exists at {:?} — this tool does not \
             overwrite an existing signing identity. Move/back up the \
             existing key first if you intend to rotate it.",
            dir
        );
        std::process::exit(1);
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Raw 32-byte seed, matching CryptoEngine::from_bytes' expected format
    // elsewhere in this codebase — but this key is never loaded BY that
    // code path; it's a distinct, offline, authoring-only identity.
    {
        let mut f = fs::File::create(&priv_path).expect("create private key file");
        f.write_all(&signing_key.to_bytes()).expect("write private key");
        f.set_permissions(fs::Permissions::from_mode(0o600)).expect("chmod private key");
    }
    {
        let mut f = fs::File::create(&pub_path).expect("create public key file");
        f.write_all(&verifying_key.to_bytes()).expect("write public key");
        f.set_permissions(fs::Permissions::from_mode(0o600)).expect("chmod public key");
    }

    let pub_hex = hex::encode(verifying_key.to_bytes());

    // Must match constitution::public_key_fingerprint exactly (hash of the
    // HEX-ENCODED key string, not the raw bytes) — that's the formula
    // Sentinel actually logs at startup as `[CONSTITUTION] verified ...
    // signer_fingerprint=...`, and an operator needs to compare the two
    // values directly to confirm the pinned key matches what they
    // generated. (Previously hashed the raw bytes instead — a distinct
    // value from what the server logs for the identical key.)
    let fingerprint = {
        let digest = Sha256::digest(pub_hex.as_bytes());
        hex::encode(digest)[..16].to_string()
    };

    println!("Constitution-authority signing key generated.");
    println!("  private key path : {}", priv_path.display());
    println!("  public key path  : {}", pub_path.display());
    println!("  private key mode : 0600");
    println!("  public key mode  : 0600");
    println!("  public key (hex) : {pub_hex}");
    println!("  fingerprint      : {fingerprint}");
    println!();
    println!("Neither file is inside a git repository or a Docker/Podman build context.");
    println!("Only the public key hex above should be pinned into the release build.");
    println!("The private key must never be committed, containerized, or logged.");
}
