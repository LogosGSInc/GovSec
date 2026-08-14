//! A2 — signs a constitution JSON file with the offline constitution-
//! authoring key, producing a detached hex-encoded Ed25519 signature over
//! the EXACT raw bytes of the file (not a re-serialization through
//! `Constitution`/serde) — so what gets signed is byte-for-byte identical
//! to what gets verified at startup, with no canonicalization ambiguity.
//!
//! Usage:
//!   cargo run --example sign_constitution -- <constitution.json> [private-key-path]
//!
//! private-key-path defaults to
//!   $HOME/.logosgs/constitution-signing/constitution-authority-ed25519.key
//!
//! Writes <constitution.json>.sig next to the input file. Never prints
//! private-key material.

use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::path::PathBuf;

fn default_key_path() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME must be set");
    PathBuf::from(home)
        .join(".logosgs")
        .join("constitution-signing")
        .join("constitution-authority-ed25519.key")
}

fn main() {
    let mut args = std::env::args().skip(1);
    let doc_path = args.next().unwrap_or_else(|| {
        eprintln!("Usage: sign_constitution <constitution.json> [private-key-path]");
        std::process::exit(2);
    });
    let key_path = args.next().map(PathBuf::from).unwrap_or_else(default_key_path);

    let doc_bytes = fs::read(&doc_path).unwrap_or_else(|e| {
        eprintln!("[ERROR] could not read {doc_path}: {e}");
        std::process::exit(1);
    });
    // Fail closed on malformed JSON before signing something unparseable.
    if let Err(e) = serde_json::from_slice::<serde_json::Value>(&doc_bytes) {
        eprintln!("[ERROR] {doc_path} is not valid JSON, refusing to sign: {e}");
        std::process::exit(1);
    }

    let key_bytes = fs::read(&key_path).unwrap_or_else(|e| {
        eprintln!("[ERROR] could not read private key at {}: {e}", key_path.display());
        std::process::exit(1);
    });
    let key_array: [u8; 32] = key_bytes.as_slice().try_into().unwrap_or_else(|_| {
        eprintln!("[ERROR] private key at {} is not 32 bytes", key_path.display());
        std::process::exit(1);
    });
    let signing_key = SigningKey::from_bytes(&key_array);

    let signature = signing_key.sign(&doc_bytes);
    let sig_hex = hex::encode(signature.to_bytes());

    let sig_path = format!("{doc_path}.sig");
    fs::write(&sig_path, &sig_hex).unwrap_or_else(|e| {
        eprintln!("[ERROR] could not write signature to {sig_path}: {e}");
        std::process::exit(1);
    });

    println!("Signed {doc_path}");
    println!("  signature written to: {sig_path}");
    println!("  signature (hex)      : {sig_hex}");
    println!("  signer public key    : {}", key_path.with_extension("pub").display());
}
