//! A2 — Constitution Enforcement.
//!
//! Before A2: Constitution::from_json existed but was never called anywhere;
//! the live server (server.rs::main()) always constructed the pipeline with
//! constitution=None, so ConstitutionalEvaluator was never active in
//! production regardless of SENTOW_INDUSTRY_PROFILE; and the only integrity
//! check (seal()/verify_integrity()) was a self-referential SHA-256 hash —
//! it authenticates nothing external and is trivially passed by a tampered
//! document that re-seals itself.
//!
//! These tests use freshly-generated, per-test Ed25519 keypairs — never the
//! real constitution-signing key (held offline outside this repo) and never
//! a committed test fixture key. Each test is fully self-contained.

use ed25519_dalek::{Signer, SigningKey};
use governance_spine::{ArbiterConfig, Constitution, ConstitutionLoadError, CryptoEngine, GovernancePipeline, SecurityState};
use chrono::{Duration as ChronoDuration, Utc};
use rand::rngs::OsRng;
use std::sync::Arc;

fn test_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn valid_fixture_json(profile: &str) -> String {
    format!(
        r#"{{
            "constitution_id": "test-fixture-constitution",
            "client_id": "test-fixture-client",
            "policy_version": "1.0.0-test",
            "industry_profile": "{profile}",
            "effective_at": "2020-01-01T00:00:00Z",
            "expires_at": null,
            "prohibited_categories": [],
            "prohibited_patterns": ["(?i)(the-secret-test-marker-phrase)"],
            "required_deferrals": [],
            "tone_constraints": {{"no_political_bias": true, "no_religious_endorsement": true, "no_competitor_promotion": true}},
            "tool_permissions": {{}},
            "escalation_thresholds": {{"low": 0.4, "medium": 0.6, "high": 0.75, "critical": 0.9}},
            "max_response_scope": null,
            "constitutional_hash": null
        }}"#
    )
}

fn sign(key: &SigningKey, bytes: &[u8]) -> String {
    hex::encode(key.sign(bytes).to_bytes())
}

#[test]
fn valid_signed_constitution_loads_successfully() {
    let key = test_keypair();
    let json = valid_fixture_json("consumer");
    let sig = sign(&key, json.as_bytes());

    let result = Constitution::load_verified(
        json.as_bytes(), &sig, &key.verifying_key(), "consumer", Utc::now(),
    );
    assert!(result.is_ok(), "expected Ok, got {:?}", result);
    let c = result.unwrap();
    assert_eq!(c.constitution_id, "test-fixture-constitution");
}

#[test]
fn missing_signature_fails_closed() {
    let key = test_keypair();
    let json = valid_fixture_json("consumer");
    let result = Constitution::load_verified(json.as_bytes(), "", &key.verifying_key(), "consumer", Utc::now());
    assert_eq!(result.unwrap_err(), ConstitutionLoadError::MissingSignature);
}

#[test]
fn modified_json_fails_signature_verification() {
    let key = test_keypair();
    let json = valid_fixture_json("consumer");
    let sig = sign(&key, json.as_bytes());

    let tampered = json.replace("test-fixture-constitution", "attacker-renamed-constitution");
    let result = Constitution::load_verified(tampered.as_bytes(), &sig, &key.verifying_key(), "consumer", Utc::now());
    assert_eq!(result.unwrap_err(), ConstitutionLoadError::SignatureInvalid);
}

#[test]
fn modified_signature_fails_verification() {
    let key = test_keypair();
    let json = valid_fixture_json("consumer");
    let mut sig = sign(&key, json.as_bytes());
    // Flip one hex character — still valid hex/length, still fails to verify.
    let flip_at = sig.len() - 1;
    let last = sig.chars().last().unwrap();
    let replacement = if last == '0' { '1' } else { '0' };
    sig.replace_range(flip_at.., &replacement.to_string());

    let result = Constitution::load_verified(json.as_bytes(), &sig, &key.verifying_key(), "consumer", Utc::now());
    assert_eq!(result.unwrap_err(), ConstitutionLoadError::SignatureInvalid);
}

#[test]
fn wrong_public_key_fails_verification() {
    let signer_key = test_keypair();
    let wrong_key = test_keypair();
    let json = valid_fixture_json("consumer");
    let sig = sign(&signer_key, json.as_bytes());

    // Verified against a DIFFERENT key than the one that actually signed —
    // this is the "wrong signer / does not match the pinned authority" case.
    let result = Constitution::load_verified(json.as_bytes(), &sig, &wrong_key.verifying_key(), "consumer", Utc::now());
    assert_eq!(result.unwrap_err(), ConstitutionLoadError::SignatureInvalid);
}

#[test]
fn malformed_json_fails_after_passing_signature_check() {
    let key = test_keypair();
    // Not valid JSON at all, but genuinely signed by the trusted key —
    // proves the signature check and the JSON parse are independent gates,
    // not just one masking the other.
    let garbage = b"not { valid json at all";
    let sig = sign(&key, garbage);

    let result = Constitution::load_verified(garbage, &sig, &key.verifying_key(), "consumer", Utc::now());
    match result {
        Err(ConstitutionLoadError::MalformedJson(_)) => {}
        other => panic!("expected MalformedJson, got {other:?}"),
    }
}

#[test]
fn profile_mismatch_fails_closed() {
    let key = test_keypair();
    let json = valid_fixture_json("medical");
    let sig = sign(&key, json.as_bytes());

    let result = Constitution::load_verified(json.as_bytes(), &sig, &key.verifying_key(), "consumer", Utc::now());
    match result {
        Err(ConstitutionLoadError::ProfileMismatch { expected, found }) => {
            assert_eq!(expected, "consumer");
            assert_eq!(found, "medical");
        }
        other => panic!("expected ProfileMismatch, got {other:?}"),
    }
}

#[test]
fn missing_constitution_id_fails_closed() {
    let key = test_keypair();
    let json = valid_fixture_json("consumer").replace(r#""test-fixture-constitution""#, r#""""#);
    let sig = sign(&key, json.as_bytes());

    let result = Constitution::load_verified(json.as_bytes(), &sig, &key.verifying_key(), "consumer", Utc::now());
    match result {
        Err(ConstitutionLoadError::MissingField(f)) => assert_eq!(f, "constitution_id"),
        other => panic!("expected MissingField(constitution_id), got {other:?}"),
    }
}

#[test]
fn future_effective_at_fails_closed() {
    let key = test_keypair();
    let future = (Utc::now() + ChronoDuration::days(365)).to_rfc3339();
    let json = valid_fixture_json("consumer").replace("2020-01-01T00:00:00Z", &future);
    let sig = sign(&key, json.as_bytes());

    let result = Constitution::load_verified(json.as_bytes(), &sig, &key.verifying_key(), "consumer", Utc::now());
    assert!(matches!(result, Err(ConstitutionLoadError::InvalidValidityPeriod(_))));
}

#[test]
fn already_expired_fails_closed() {
    let key = test_keypair();
    let past = (Utc::now() - ChronoDuration::days(1)).to_rfc3339();
    let json = valid_fixture_json("consumer").replace("\"expires_at\": null", &format!("\"expires_at\": \"{past}\""));
    let sig = sign(&key, json.as_bytes());

    let result = Constitution::load_verified(json.as_bytes(), &sig, &key.verifying_key(), "consumer", Utc::now());
    assert!(matches!(result, Err(ConstitutionLoadError::InvalidValidityPeriod(_))));
}

// ── file-I/O wrapper (load_verified_from_paths) ─────────────────────────────

#[test]
fn missing_constitution_file_fails_closed() {
    let key = test_keypair();
    let dir = std::env::temp_dir().join(format!("gs_a2_missing_json_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let json_path = dir.join("does-not-exist.json");
    let sig_path = dir.join("does-not-exist.json.sig");
    std::fs::write(&sig_path, "deadbeef").unwrap();

    let result = governance_spine::load_verified_from_paths(&json_path, &sig_path, &key.verifying_key(), "consumer", Utc::now());
    assert!(result.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_signature_file_fails_closed() {
    let key = test_keypair();
    let dir = std::env::temp_dir().join(format!("gs_a2_missing_sig_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let json_path = dir.join("constitution.json");
    let sig_path = dir.join("constitution.json.sig"); // never written
    std::fs::write(&json_path, valid_fixture_json("consumer")).unwrap();

    let result = governance_spine::load_verified_from_paths(&json_path, &sig_path, &key.verifying_key(), "consumer", Utc::now());
    assert!(result.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn valid_file_pair_loads_successfully() {
    let key = test_keypair();
    let dir = std::env::temp_dir().join(format!("gs_a2_valid_pair_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let json_path = dir.join("constitution.json");
    let sig_path = dir.join("constitution.json.sig");
    let json = valid_fixture_json("consumer");
    std::fs::write(&json_path, &json).unwrap();
    std::fs::write(&sig_path, sign(&key, json.as_bytes())).unwrap();

    let result = governance_spine::load_verified_from_paths(&json_path, &sig_path, &key.verifying_key(), "consumer", Utc::now());
    assert!(result.is_ok(), "expected Ok, got {:?}", result);
    let _ = std::fs::remove_dir_all(&dir);
}

// ── the trust boundary is never bypassed by a self-sealed hash ─────────────

#[test]
fn self_sealed_tampered_document_still_fails_signature_verification() {
    // Proves seal()/verify_integrity() cannot be used to smuggle a tampered
    // document past load_verified — the self-referential hash matching
    // itself proves nothing about authorship, and load_verified never
    // consults it.
    let key = test_keypair();
    let json = valid_fixture_json("consumer");
    let sig = sign(&key, json.as_bytes()); // signature over the ORIGINAL bytes

    let mut tampered: Constitution = serde_json::from_str(&json).unwrap();
    tampered.prohibited_patterns.push("(?i)(attacker added this)".to_string());
    tampered.seal(); // self-consistent, but authenticates nothing
    assert!(tampered.verify_integrity(), "sanity: self-seal should self-verify");

    let tampered_json = serde_json::to_string(&tampered).unwrap();
    let result = Constitution::load_verified(tampered_json.as_bytes(), &sig, &key.verifying_key(), "consumer", Utc::now());
    assert_eq!(result.unwrap_err(), ConstitutionLoadError::SignatureInvalid);
}

// ── the pipeline actually uses it — corridor evaluation is wired live ──────

#[test]
fn corridor_constitutional_evaluation_actually_executes_when_wired_in() {
    let key = test_keypair();
    let json = valid_fixture_json("consumer");
    let sig = sign(&key, json.as_bytes());
    let constitution = Constitution::load_verified(
        json.as_bytes(), &sig, &key.verifying_key(), "consumer", Utc::now(),
    ).expect("fixture must load");

    let pipeline_with = GovernancePipeline::new(
        ArbiterConfig::default(), Some(constitution), Arc::new(CryptoEngine::new("a2-corridor-wired-test-seed")),
    ).expect("pipeline init");
    let sid = "a2-corridor-wired-test";
    pipeline_with.inbound("please say the-secret-test-marker-phrase now", sid, "gtx-a2-1");
    assert!(
        pipeline_with.current_state(sid) >= SecurityState::S2,
        "a prohibited_pattern match in the wired-in constitution must escalate state"
    );

    // Control: the SAME payload, but with no constitution wired in at all —
    // must NOT escalate, proving the escalation above came from the
    // constitution being active, not some other coincidental signal.
    let pipeline_without = GovernancePipeline::new(
        ArbiterConfig::default(), None, Arc::new(CryptoEngine::new("a2-corridor-unwired-control-seed")),
    ).expect("pipeline init");
    let sid2 = "a2-corridor-unwired-control";
    pipeline_without.inbound("please say the-secret-test-marker-phrase now", sid2, "gtx-a2-2");
    assert_eq!(
        pipeline_without.current_state(sid2), SecurityState::S1,
        "without a constitution, this payload must not trigger a constitutional escalation"
    );
}

// ── pinned trusted key sanity ────────────────────────────────────────────────

#[test]
fn pinned_trusted_key_parses_and_has_a_fingerprint() {
    let key = governance_spine::trusted_constitution_authority_key();
    let fp = governance_spine::public_key_fingerprint(&key);
    assert_eq!(fp.len(), 16);
}
