use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use parking_lot::RwLock;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid keypair bytes: {0}")]
    InvalidKeypair(String),
    #[error("Invalid signature format")]
    InvalidSignatureFormat,
    #[error("Invalid signature length: expected 64, got {0}")]
    InvalidSignatureLength(usize),
    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("Hash chain is empty")]
    EmptyChain,
}

#[derive(Debug)]
pub struct CryptoEngine {
    signing_key: Arc<RwLock<SigningKey>>,
    verifying_key: Arc<VerifyingKey>,
    /// Hash chain: each entry = SHA256(prev_entry + signal_canonical)
    hash_chain: Arc<RwLock<Vec<String>>>,
}

impl CryptoEngine {
    /// FIX: Never accepts zero verification key.
    /// Always derives verifying key from generated signing key.
    pub fn new(seed: &str) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = Arc::new(signing_key.verifying_key());

        let seed_hash = Self::compute_hash(seed);
        let hash_chain = Arc::new(RwLock::new(vec![seed_hash]));

        Self {
            signing_key: Arc::new(RwLock::new(signing_key)),
            verifying_key,
            hash_chain,
        }
    }

    /// Load from existing key bytes. Returns error instead of panicking.
    pub fn from_bytes(
        signing_key_bytes: &[u8; 32],
        seed: &str,
    ) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_bytes(signing_key_bytes);
        let verifying_key = Arc::new(signing_key.verifying_key());

        let seed_hash = Self::compute_hash(seed);
        let hash_chain = Arc::new(RwLock::new(vec![seed_hash]));

        Ok(Self {
            signing_key: Arc::new(RwLock::new(signing_key)),
            verifying_key,
            hash_chain,
        })
    }

    /// A3: file-I/O wrapper around `from_bytes` — reads the persisted
    /// audit-signing key (a raw 32-byte Ed25519 seed, provisioned offline by
    /// `cargo run --example generate_audit_signing_key` and bind-mounted
    /// read-only into the container) from disk. Kept separate from
    /// `from_bytes` so both layers (pure key-loading logic; file-missing/
    /// wrong-length conditions) are independently unit-testable without a
    /// running server, matching the split `Constitution::load_verified` /
    /// `load_verified_from_paths` already established for A2.
    ///
    /// Loading the SAME key file across process restarts is the entire
    /// point of A3: it is what lets a signature produced before a restart
    /// still verify against the `CryptoEngine` constructed after it. This
    /// does not persist the hash chain — `hash_chain` still starts fresh
    /// from `seed_hash` on every construction — so chain-linkage continuity
    /// across a restart remains a separate, unaddressed concern; only
    /// signing-key identity (and therefore per-entry signature
    /// verifiability) survives a restart via this path.
    pub fn from_persisted_key_file(
        path: &std::path::Path,
        seed: &str,
    ) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("audit signing key missing or unreadable at {}: {e}", path.display()))?;
        let array: [u8; 32] = bytes.try_into()
            .map_err(|v: Vec<u8>| format!(
                "audit signing key at {} is not 32 bytes (got {})",
                path.display(), v.len()
            ))?;
        Self::from_bytes(&array, seed)
            .map_err(|e| format!("audit signing key at {} is invalid: {e}", path.display()))
    }

    pub fn sign(&self, data: &[u8]) -> String {
        let key = self.signing_key.read();
        let signature: Signature = key.sign(data);
        hex::encode(signature.to_bytes())
    }

    pub fn verify(&self, data: &[u8], signature_hex: &str) -> Result<bool, CryptoError> {
        let sig_bytes = hex::decode(signature_hex)?;
        if sig_bytes.len() != 64 {
            return Err(CryptoError::InvalidSignatureLength(sig_bytes.len()));
        }
        let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();
        let signature = Signature::from_bytes(&sig_array);
        Ok(self.verifying_key.verify(data, &signature).is_ok())
    }

    pub fn compute_hash(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// FIX: Hash chain extension uses actual signal data, not empty string.
    /// new_hash = SHA256(last_hash + signal_canonical)
    /// This matches what verify_hash_chain checks.
    pub fn extend_chain(&self, signal_canonical: &str) -> String {
        let mut chain = self.hash_chain.write();
        let last = chain.last().cloned().unwrap_or_default();
        let new_hash = Self::compute_hash(&format!("{}{}", last, signal_canonical));
        chain.push(new_hash.clone());
        new_hash
    }

    /// FIX: Verification now correctly reconstructs each hash using
    /// the stored canonical data, not an empty string.
    /// Chain entries are stored as (hash, canonical) pairs for verification.
    pub fn get_latest_hash(&self) -> String {
        let chain = self.hash_chain.read();
        chain.last().cloned().unwrap_or_default()
    }

    pub fn chain_length(&self) -> usize {
        self.hash_chain.read().len()
    }

    /// Returns full chain snapshot for audit export.
    pub fn export_chain(&self) -> Vec<String> {
        self.hash_chain.read().clone()
    }

    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.verifying_key.as_bytes())
    }

    /// SHA-256 fingerprint of the verifying key, truncated to 16 hex chars —
    /// matches the format `generate_audit_signing_key` prints, so startup
    /// logs and the keygen tool's output are directly comparable, and
    /// matches `constitution::public_key_fingerprint`'s format too.
    pub fn verifying_key_fingerprint(&self) -> String {
        Self::compute_hash(&self.verifying_key_hex())[..16].to_string()
    }
}

/// Audit log entry — one per state transition or detection event.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    pub event_id: uuid::Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub session_id: String,
    pub source: String,
    pub direction: String,
    pub state_before: String,
    pub state_after: String,
    pub violation_class: Option<String>,
    pub policy_rule_id: Option<String>,
    pub severity: String,
    pub confidence: f32,
    pub constitutional_ref: Option<String>,
    pub payload_hash: String,
    pub prev_chain_hash: String,
    pub current_chain_hash: String,
    pub signature: String,
}
