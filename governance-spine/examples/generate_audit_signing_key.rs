//! A3 — one-time (or key-rotation) generator for the audit-signing Ed25519
//! keypair. This is the identity the RUNNING Sentinel process uses
//! continuously to sign every governance/audit event — entirely distinct
//! from A2's offline constitution-authoring key (which the running process
//! never holds) and from the operator-reset shared secret (not a signing
//! key at all). Three separate authorities, not one key wearing three hats.
//!
//! Unlike the constitution-authoring key, this key MUST be reachable by the
//! running container (mounted read-only — see governance-spine's compose
//! files) so the server can load it at every startup and keep signing
//! under the same identity across restarts. It still lives outside the
//! repo and outside any build context, and this tool never prints
//! private-key material — only paths, permissions, and the public-key
//! fingerprint.
//!
//! Usage: cargo run --example generate_audit_signing_key

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn custody_dir() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME must be set");
    PathBuf::from(home).join(".logosgs").join("audit-signing")
}

fn main() {
    let dir = custody_dir();

    // Output path is always $HOME/.logosgs/audit-signing regardless of
    // current working directory — running this from inside the repo (e.g.
    // via `cargo run --example ...`) is safe; nothing is ever written
    // under the repo or a build context. The operator is responsible for
    // bind-mounting the private key file (read-only) into the container.
    fs::create_dir_all(&dir).expect("create custody dir");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod custody dir");

    let priv_path = dir.join("audit-signing-ed25519.key");
    let pub_path = dir.join("audit-signing-ed25519.pub");

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

    // Raw 32-byte seed — the format CryptoEngine::from_bytes/
    // from_persisted_key_file expects. This key is loaded BY the running
    // server (unlike the A2 constitution-authoring key), so the file
    // layout is dictated by that loader.
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

    // Must match CryptoEngine::verifying_key_fingerprint() exactly (hash of
    // the HEX-ENCODED key string, not the raw bytes) — this is what
    // server.rs logs at startup as `[CRYPTO] audit-signing identity
    // loaded — fingerprint=...`, and an operator needs to be able to
    // compare the two values directly to confirm the mounted key is the
    // one they generated.
    let fingerprint = {
        let pub_hex = hex::encode(verifying_key.to_bytes());
        let digest = Sha256::digest(pub_hex.as_bytes());
        hex::encode(digest)[..16].to_string()
    };

    println!("Audit-signing key generated.");
    println!("  private key path : {}", priv_path.display());
    println!("  public key path  : {}", pub_path.display());
    println!("  private key mode : 0600");
    println!("  public key mode  : 0600");
    println!("  fingerprint      : {fingerprint}");
    println!();
    println!("Neither file is inside a git repository or a Docker/Podman build context.");
    println!("Bind-mount the PRIVATE key file read-only into the sentinel container at");
    println!("the path SENTOW_AUDIT_KEY_PATH resolves to (default: /app/audit-signing/audit-signing-ed25519.key).");
    println!("The private key must never be committed, containerized (baked into an image layer), or logged.");
}
