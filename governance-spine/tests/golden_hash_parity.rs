//! Golden context_hash parity check.
//!
//! `context_hash` is computed independently on both sides — OpenClaw's
//! src/govsec/canonical-json.ts + model-context-envelope.ts (TypeScript)
//! and this crate's src/envelope.rs (Rust). GovSec's /context/inspect
//! independently recomputes and verifies the hash a caller presents
//! (ModelContextEnvelope::verify), so any divergence between the two
//! encoders would surface as every real context admission failing closed
//! with a hash mismatch. This test fixes one deterministic input and
//! prints the Rust-computed hash so it can be compared, byte-for-byte,
//! against the TypeScript side's hash for the IDENTICAL input — see
//! src/govsec/canonical-json.golden.test.ts in the OpenClaw repo, which
//! hardcodes the same hash asserted here.
//!
//! Run with: cargo test --test golden_hash_parity -- --nocapture
use governance_spine::{
    derive_action_semantics, sha256_hex, ActionEnvelope, ActionPlane, ActionResource,
    ContextAttachment, ContextRole, ContextSegment, ContextSource, ModelContextEnvelope,
    ACTION_ENVELOPE_SCHEMA_VERSION,
};
use serde_json::json;

fn golden_envelope() -> ModelContextEnvelope {
    ModelContextEnvelope {
        schema_version: "logos.model-context.v1".to_string(),
        session_id: "golden-session".to_string(),
        run_id: "golden-run".to_string(),
        principal_id: "golden-principal".to_string(),
        provider_id: "golden-provider".to_string(),
        model_id: "golden-model".to_string(),
        policy_version: "golden-policy-v1".to_string(),
        policy_hash: sha256_hex(b"golden-policy"),
        provider_context_hash: sha256_hex(b"golden-provider-context"),
        system_prompt_hash: sha256_hex(b"golden-system-prompt"),
        tool_schema_hash: sha256_hex(b"golden-tool-schema"),
        workspace_manifest_hash: sha256_hex(b"golden-workspace-manifest"),
        segments: vec![
            ContextSegment {
                ordinal: 0,
                role: ContextRole::System,
                source: ContextSource::RuntimeInjection,
                content: "You are a careful assistant.".to_string(),
                tool_name: None,
                attachment_id: None,
            },
            ContextSegment {
                ordinal: 1,
                role: ContextRole::User,
                source: ContextSource::ExternalUser,
                content: "Hello, GovSec golden test! \"quotes\", \\backslash\\, newline:\nend."
                    .to_string(),
                tool_name: None,
                attachment_id: None,
            },
            ContextSegment {
                ordinal: 2,
                role: ContextRole::ToolResult,
                source: ContextSource::ToolResult,
                content: "tool output".to_string(),
                tool_name: Some("read".to_string()),
                attachment_id: None,
            },
        ],
        attachments: vec![ContextAttachment {
            attachment_id: "att-1".to_string(),
            media_type: "text/plain".to_string(),
            byte_length: 42,
            sha256: sha256_hex(b"golden-attachment"),
        }],
        context_hash: String::new(),
    }
}

#[test]
fn golden_context_hash_is_stable_and_printed_for_cross_language_comparison() {
    let sealed = golden_envelope().seal().expect("seal golden envelope");
    println!("GOLDEN_CONTEXT_HASH={}", sealed.context_hash);
    // Pinned: if this ever changes, either envelope.rs's canonical JSON
    // algorithm changed (update the TypeScript golden test to match) or a
    // real regression was introduced. Do not update this constant without
    // also updating src/govsec/canonical-json.golden.test.ts in the
    // OpenClaw repo to the SAME new value and confirming why both changed.
    assert_eq!(
        sealed.context_hash, "49f33e87aeb2d096aac04297bf898249e8b38a9d5683411aa58d5e4177e808cd",
        "golden context_hash changed — see this test's doc comment"
    );
}

/// Deterministic `logos.action.v1` fixture, deliberately using
/// `heartbeat_respond` (a CONTROL-plane tool) so this golden test also
/// covers the control-plane sprint's shape, not just an ordinary tool.
fn golden_action_envelope() -> ActionEnvelope {
    ActionEnvelope {
        schema_version: ACTION_ENVELOPE_SCHEMA_VERSION.to_string(),
        tool_name: "heartbeat_respond".to_string(),
        arguments: json!({
            "outcome": "no_change",
            "notify": false,
            "summary": "golden action fixture"
        }),
        resource: ActionResource {
            kind: "unknown".to_string(),
            locator: "heartbeat_respond".to_string(),
        },
        principal_id: "golden-principal".to_string(),
        session_id: "golden-session".to_string(),
        run_id: "golden-run".to_string(),
        tool_call_id: "golden-call-1".to_string(),
        policy_version: "golden-policy-v1".to_string(),
        policy_hash: sha256_hex(b"golden-policy"),
        context_hash: sha256_hex(b"golden-context"),
        action_hash: String::new(),
    }
}

#[test]
fn golden_action_hash_is_stable_and_printed_for_cross_language_comparison() {
    let sealed = golden_action_envelope().seal().expect("seal golden action envelope");
    println!("GOLDEN_ACTION_HASH={}", sealed.action_hash);

    // Pinned: if this ever changes, either envelope.rs's canonical JSON
    // algorithm changed (update the TypeScript golden test to match — see
    // src/govsec/action-envelope.golden.test.ts in the OpenClaw repo, which
    // hardcodes the same value) or a real regression was introduced.
    assert_eq!(
        sealed.action_hash,
        "b1dee45efc66058134900bf70379db4830be89e9e84ec14505b6dd311b2ad237",
        "golden action_hash changed — see this test's doc comment"
    );

    // Deriving server-owned semantic metadata (plane/normalized_action/
    // required_for_safe_completion) from the sealed envelope must never
    // mutate or require recomputing action_hash — it is not part of
    // ActionEnvelope's serialized form or hash material at all.
    let hash_before = sealed.action_hash.clone();
    let semantics = derive_action_semantics(&sealed);
    assert_eq!(semantics.plane, ActionPlane::Control);
    assert_eq!(semantics.normalized_action, "system.telemetry.heartbeat");
    assert_eq!(
        sealed.action_hash, hash_before,
        "deriving action semantics must not alter action_hash"
    );
}
