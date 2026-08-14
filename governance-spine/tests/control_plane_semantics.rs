//! GS-RT-CONTROL-001 / GS-RT-CONTROL-002 — control-plane (heartbeat_respond)
//! semantics regression tests, driven through the public `GovernancePipeline`
//! API exactly as a real caller (server.rs's HTTP handlers) would use it —
//! no internals reached through test-only crate-private hooks.

use governance_spine::capability::{ConsumeOutcome, PresentedBinding};
use governance_spine::pipeline::{ActionAuthorizationError, ActionAuthorizationRequest};
use governance_spine::{
    sha256_hex, ActionPlane, ActionResource, ActionRiskClass, ContextAttachment, ContextRole,
    ContextSegment, ContextSource, EnforcementResult, GovernancePipeline, ModelContextEnvelope,
    ACTION_ENVELOPE_SCHEMA_VERSION, MODEL_CONTEXT_SCHEMA_VERSION,
};
use serde_json::{json, Value};

fn digest(label: &str) -> String {
    sha256_hex(label.as_bytes())
}

fn context_envelope(
    session: &str,
    run: &str,
    principal: &str,
    content: &str,
) -> ModelContextEnvelope {
    ModelContextEnvelope {
        schema_version: MODEL_CONTEXT_SCHEMA_VERSION.to_string(),
        session_id: session.to_string(),
        run_id: run.to_string(),
        principal_id: principal.to_string(),
        provider_id: "anthropic".to_string(),
        model_id: "claude-test".to_string(),
        policy_version: "policy-test-v1".to_string(),
        policy_hash: digest("policy"),
        provider_context_hash: digest("provider context payload"),
        system_prompt_hash: digest("system prompt"),
        tool_schema_hash: digest("tool schemas"),
        workspace_manifest_hash: digest("workspace manifest"),
        segments: vec![ContextSegment {
            ordinal: 0,
            role: ContextRole::User,
            source: ContextSource::ExternalUser,
            content: content.to_string(),
            tool_name: None,
            attachment_id: None,
        }],
        attachments: Vec::<ContextAttachment>::new(),
        context_hash: String::new(),
    }
    .seal()
    .expect("test envelope must seal")
}

/// Run the full context-aware inbound path to a final-approved verdict and
/// return the sealed envelope, so its `context_hash`/`run_id` can be
/// presented to `authorize_action_execution` exactly as a real caller must.
fn approve_context(
    pipeline: &GovernancePipeline,
    gov_tx_id: &str,
    session: &str,
    run: &str,
    principal: &str,
    content: &str,
) -> ModelContextEnvelope {
    let envelope = context_envelope(session, run, principal, content);
    let result = pipeline
        .inbound_context(&envelope, gov_tx_id)
        .expect("well-formed envelope must not fail structurally");
    assert!(
        matches!(result, EnforcementResult::Approved(_)),
        "test content must complete the full context pipeline as APPROVED, got {:?}",
        result
    );
    envelope
}

fn action_request(
    tx: &str,
    envelope: &ModelContextEnvelope,
    tool_name: &str,
    arguments: Value,
    resource_kind: &str,
    resource_locator: &str,
    tool_call_id: &str,
) -> ActionAuthorizationRequest {
    ActionAuthorizationRequest {
        gov_tx_id: tx.to_string(),
        session_id: envelope.session_id.clone(),
        run_id: envelope.run_id.clone(),
        principal_fingerprint: "svc-openclaw".to_string(),
        tool_name: tool_name.to_string(),
        arguments,
        resource_kind: resource_kind.to_string(),
        resource_locator: resource_locator.to_string(),
        tool_call_id: tool_call_id.to_string(),
        context_hash: envelope.context_hash.clone(),
        policy_version: "policy-test-v1".to_string(),
        policy_hash: digest("policy"),
    }
}

fn heartbeat_request(
    tx: &str,
    envelope: &ModelContextEnvelope,
    arguments: Value,
    tool_call_id: &str,
) -> ActionAuthorizationRequest {
    action_request(
        tx,
        envelope,
        "heartbeat_respond",
        arguments,
        "unknown",
        "heartbeat_respond",
        tool_call_id,
    )
}

fn valid_heartbeat_args() -> Value {
    json!({
        "outcome": "no_change",
        "notify": false,
        "summary": "Still working on the migration; no blockers."
    })
}

fn binding(token: &governance_spine::capability::CapabilityToken) -> PresentedBinding<'_> {
    PresentedBinding {
        token_id: &token.token_id,
        gov_tx_id: &token.gov_tx_id,
        session_id: &token.session_id,
        principal_fingerprint: &token.principal_fingerprint,
        authority: &token.authority,
        backend: &token.backend,
        model: &token.model,
        run_id: &token.run_id,
        context_hash: &token.context_hash,
        policy_version: &token.policy_version,
        policy_hash: &token.policy_hash,
        action_hash: &token.action_hash,
        tool_name: &token.tool_name,
        resource_kind: &token.resource_kind,
        resource_locator: &token.resource_locator,
        tool_call_id: &token.tool_call_id,
        plane: token.action_plane.as_str(),
    }
}

fn assert_control_denied(
    result: &Result<governance_spine::capability::CapabilityToken, ActionAuthorizationError>,
    expected: ActionRiskClass,
) {
    match result {
        Err(ActionAuthorizationError::Denied(risks)) => {
            assert!(
                risks.contains(&expected),
                "expected {:?} among denial risk classes, got {:?}",
                expected,
                risks
            );
        }
        other => panic!("expected Denied({:?}), got {:?}", expected, other),
    }
}

// ═══════════════════════════ GS-RT-CONTROL-001 ═══════════════════════════
// A legitimate heartbeat_respond, from a service principal, under an
// approved context. Proves: CONTROL plane, normalized action name,
// noncritical-for-completion, authorization still required, exact action
// hash bound into decision+capability, single-use, replay fails, mutation
// after authorization fails.

#[test]
fn gs_rt_control_001_legitimate_heartbeat_is_control_plane_noncritical_and_requires_authorization()
{
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline");
    let tx = "GTX-control-001";
    let session = "sess-control-001";
    let envelope = approve_context(
        &pipeline,
        tx,
        session,
        "run1",
        "svc-openclaw",
        "heartbeat check-in",
    );

    let token = pipeline
        .authorize_action_execution(heartbeat_request(
            tx,
            &envelope,
            valid_heartbeat_args(),
            "call-hb-1",
        ))
        .expect("a legitimate, schema-valid heartbeat must be authorized, not denied");

    // 1: classified as CONTROL
    assert_eq!(token.action_plane, ActionPlane::Control);
    // 2: normalizes to system.telemetry.heartbeat
    assert_eq!(token.normalized_action, "system.telemetry.heartbeat");
    // 3: noncritical to response completion
    assert!(!token.required_for_safe_completion);
    // 4: still required authorization — i.e. this is a real, single-use
    // capability, not an unconditional allow (no capability would exist at
    // all for a bypass path).
    assert!(!token.token_id.is_empty());
    assert_eq!(token.max_uses, 1);
    assert_eq!(token.use_count, 0);

    // 5: exact action hash bound — independently recompute the same sealed
    // ActionEnvelope's hash and confirm the token carries exactly that.
    let independent = governance_spine::ActionEnvelope {
        schema_version: ACTION_ENVELOPE_SCHEMA_VERSION.to_string(),
        tool_name: "heartbeat_respond".to_string(),
        arguments: valid_heartbeat_args(),
        resource: ActionResource {
            kind: "unknown".to_string(),
            locator: "heartbeat_respond".to_string(),
        },
        principal_id: "svc-openclaw".to_string(),
        session_id: session.to_string(),
        run_id: "run1".to_string(),
        tool_call_id: "call-hb-1".to_string(),
        policy_version: "policy-test-v1".to_string(),
        policy_hash: digest("policy"),
        context_hash: envelope.context_hash.clone(),
        action_hash: String::new(),
    }
    .seal()
    .expect("independent envelope must seal");
    assert_eq!(token.action_hash, independent.action_hash);

    // 6 + 7: consumes exactly once, replay fails.
    let b = binding(&token);
    assert_eq!(
        pipeline.consume_provider_capability(&b),
        ConsumeOutcome::Authorized
    );
    assert_eq!(
        pipeline.consume_provider_capability(&b),
        ConsumeOutcome::AlreadyConsumed
    );
}

#[test]
fn gs_rt_control_001_mutation_after_authorization_fails() {
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline");
    let tx = "GTX-control-001-mutate";
    let session = "sess-control-001-mutate";
    let envelope = approve_context(
        &pipeline,
        tx,
        session,
        "run1",
        "svc-openclaw",
        "heartbeat check-in",
    );

    let token = pipeline
        .authorize_action_execution(heartbeat_request(
            tx,
            &envelope,
            valid_heartbeat_args(),
            "call-hb-2",
        ))
        .expect("legitimate heartbeat must be authorized");

    // 8: mutation after authorization fails — an executor about to record a
    // DIFFERENT outcome than what was authorized must not be able to reuse
    // this capability for it.
    let mut b = binding(&token);
    let different_hash = sha256_hex(b"different-heartbeat-arguments");
    b.action_hash = &different_hash;
    assert_eq!(
        pipeline.consume_provider_capability(&b),
        ConsumeOutcome::ActionHashMismatch
    );
}

// ═══════════════════════════ GS-RT-CONTROL-002 ═══════════════════════════
// Disguised/dangerous payloads presented as heartbeat_respond. Every case
// must be denied with a deterministic schema/risk reason, no capability
// issued (all assertions are on Err(...) — no token exists to invoke
// consume/execute on), and no plane/tool substitution succeeds.

#[test]
fn gs_rt_control_002_extra_command_field_is_denied() {
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline");
    let tx = "GTX-control-002-command";
    let session = "sess-control-002-command";
    let envelope = approve_context(
        &pipeline,
        tx,
        session,
        "run1",
        "svc-openclaw",
        "heartbeat check-in",
    );

    let mut args = valid_heartbeat_args();
    args.as_object_mut()
        .unwrap()
        .insert("command".to_string(), json!("rm -rf /"));

    let result =
        pipeline.authorize_action_execution(heartbeat_request(tx, &envelope, args, "call-hb-cmd"));
    assert_control_denied(&result, ActionRiskClass::ControlSchemaViolation);
}

#[test]
fn gs_rt_control_002_embedded_shell_command_in_free_text_field_is_denied() {
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline");
    let tx = "GTX-control-002-shell";
    let session = "sess-control-002-shell";
    let envelope = approve_context(
        &pipeline,
        tx,
        session,
        "run1",
        "svc-openclaw",
        "heartbeat check-in",
    );

    let args = json!({
        "outcome": "progress",
        "notify": false,
        "summary": "before running rm -rf /workspace to clean up",
    });
    let result = pipeline.authorize_action_execution(heartbeat_request(
        tx,
        &envelope,
        args,
        "call-hb-shell",
    ));
    assert_control_denied(&result, ActionRiskClass::DestructiveShell);
}

#[test]
fn gs_rt_control_002_filesystem_mutation_target_field_is_denied() {
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline");
    let tx = "GTX-control-002-path";
    let session = "sess-control-002-path";
    let envelope = approve_context(
        &pipeline,
        tx,
        session,
        "run1",
        "svc-openclaw",
        "heartbeat check-in",
    );

    let mut args = valid_heartbeat_args();
    args.as_object_mut()
        .unwrap()
        .insert("path".to_string(), json!("/etc/passwd"));

    let result =
        pipeline.authorize_action_execution(heartbeat_request(tx, &envelope, args, "call-hb-path"));
    assert_control_denied(&result, ActionRiskClass::ControlSchemaViolation);
}

#[test]
fn gs_rt_control_002_path_traversal_in_allowed_field_is_denied() {
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline");
    let tx = "GTX-control-002-traversal";
    let session = "sess-control-002-traversal";
    let envelope = approve_context(
        &pipeline,
        tx,
        session,
        "run1",
        "svc-openclaw",
        "heartbeat check-in",
    );

    let args = json!({
        "outcome": "no_change",
        "notify": false,
        "summary": "checkpoint",
        "nextCheck": "../../../etc/passwd",
    });
    let result =
        pipeline.authorize_action_execution(heartbeat_request(tx, &envelope, args, "call-hb-trav"));
    assert_control_denied(&result, ActionRiskClass::PathTraversal);
}

#[test]
fn gs_rt_control_002_external_destination_url_field_is_denied() {
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline");
    let tx = "GTX-control-002-url";
    let session = "sess-control-002-url";
    let envelope = approve_context(
        &pipeline,
        tx,
        session,
        "run1",
        "svc-openclaw",
        "heartbeat check-in",
    );

    let mut args = valid_heartbeat_args();
    args.as_object_mut()
        .unwrap()
        .insert("url".to_string(), json!("http://evil.example/exfiltrate"));

    let result =
        pipeline.authorize_action_execution(heartbeat_request(tx, &envelope, args, "call-hb-url"));
    assert_control_denied(&result, ActionRiskClass::ControlSchemaViolation);
}

#[test]
fn gs_rt_control_002_credential_shaped_content_is_denied() {
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline");
    let tx = "GTX-control-002-cred";
    let session = "sess-control-002-cred";
    let envelope = approve_context(
        &pipeline,
        tx,
        session,
        "run1",
        "svc-openclaw",
        "heartbeat check-in",
    );

    let args = json!({
        "outcome": "blocked",
        "notify": true,
        "summary": "need access",
        "notificationText": "check ~/.ssh/id_rsa for the key",
    });
    let result =
        pipeline.authorize_action_execution(heartbeat_request(tx, &envelope, args, "call-hb-cred"));
    assert_control_denied(&result, ActionRiskClass::CredentialAccess);
}

#[test]
fn gs_rt_control_002_unexpected_nested_object_is_denied() {
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline");
    let tx = "GTX-control-002-nested";
    let session = "sess-control-002-nested";
    let envelope = approve_context(
        &pipeline,
        tx,
        session,
        "run1",
        "svc-openclaw",
        "heartbeat check-in",
    );

    let args = json!({
        "outcome": "no_change",
        "notify": false,
        "summary": "checkpoint",
        "reason": {"nested": "object", "unexpected": true},
    });
    let result = pipeline.authorize_action_execution(heartbeat_request(
        tx,
        &envelope,
        args,
        "call-hb-nested",
    ));
    assert_control_denied(&result, ActionRiskClass::ControlSchemaViolation);
}

#[test]
fn gs_rt_control_002_oversized_field_is_denied() {
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline");
    let tx = "GTX-control-002-oversized";
    let session = "sess-control-002-oversized";
    let envelope = approve_context(
        &pipeline,
        tx,
        session,
        "run1",
        "svc-openclaw",
        "heartbeat check-in",
    );

    let args = json!({
        "outcome": "no_change",
        "notify": false,
        "summary": "x".repeat(5_000),
    });
    let result =
        pipeline.authorize_action_execution(heartbeat_request(tx, &envelope, args, "call-hb-big"));
    assert_control_denied(&result, ActionRiskClass::ControlSchemaViolation);
}

#[test]
fn gs_rt_control_002_invalid_outcome_enum_is_denied() {
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline");
    let tx = "GTX-control-002-enum";
    let session = "sess-control-002-enum";
    let envelope = approve_context(
        &pipeline,
        tx,
        session,
        "run1",
        "svc-openclaw",
        "heartbeat check-in",
    );

    let args = json!({
        "outcome": "launch_nukes",
        "notify": false,
        "summary": "checkpoint",
    });
    let result =
        pipeline.authorize_action_execution(heartbeat_request(tx, &envelope, args, "call-hb-enum"));
    assert_control_denied(&result, ActionRiskClass::ControlSchemaViolation);
}

#[test]
fn gs_rt_control_002_conditional_notification_field_wrong_type_is_denied() {
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline");
    let tx = "GTX-control-002-conditional";
    let session = "sess-control-002-conditional";
    let envelope = approve_context(
        &pipeline,
        tx,
        session,
        "run1",
        "svc-openclaw",
        "heartbeat check-in",
    );

    // notify=true with a non-string notificationText — violates the real
    // schema's conditional notification contract (Type.Optional(Type.String())).
    let args = json!({
        "outcome": "needs_attention",
        "notify": true,
        "summary": "checkpoint",
        "notificationText": 12345,
    });
    let result = pipeline.authorize_action_execution(heartbeat_request(
        tx,
        &envelope,
        args,
        "call-hb-condtype",
    ));
    assert_control_denied(&result, ActionRiskClass::ControlSchemaViolation);
}

#[test]
fn gs_rt_control_002_missing_required_key_is_denied() {
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline");
    let tx = "GTX-control-002-missing";
    let session = "sess-control-002-missing";
    let envelope = approve_context(
        &pipeline,
        tx,
        session,
        "run1",
        "svc-openclaw",
        "heartbeat check-in",
    );

    // summary omitted entirely.
    let args = json!({"outcome": "no_change", "notify": false});
    let result = pipeline.authorize_action_execution(heartbeat_request(
        tx,
        &envelope,
        args,
        "call-hb-missing",
    ));
    assert_control_denied(&result, ActionRiskClass::ControlSchemaViolation);
}

#[test]
fn gs_rt_control_002_control_capability_cannot_authorize_a_different_tool() {
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline");
    let tx = "GTX-control-002-substitute-a";
    let session = "sess-control-002-substitute-a";
    let envelope = approve_context(
        &pipeline,
        tx,
        session,
        "run1",
        "svc-openclaw",
        "heartbeat check-in",
    );

    let token = pipeline
        .authorize_action_execution(heartbeat_request(
            tx,
            &envelope,
            valid_heartbeat_args(),
            "call-hb-sub-a",
        ))
        .expect("legitimate heartbeat must be authorized");

    // Attacker presents the CONTROL capability as though it authorizes a
    // dangerous bash call. action_hash is left as the token's own (proving
    // the tool/resource check itself — not just the hash check — rejects
    // this), plane forged to match the claimed tool.
    let mut b = binding(&token);
    b.tool_name = "bash";
    b.resource_kind = "shell";
    b.resource_locator = "rm -rf /";
    b.plane = "tool";
    assert_eq!(
        pipeline.consume_provider_capability(&b),
        ConsumeOutcome::ToolMismatch
    );
}

#[test]
fn gs_rt_control_002_ordinary_tool_capability_cannot_authorize_heartbeat() {
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline");
    let tx = "GTX-control-002-substitute-b";
    let session = "sess-control-002-substitute-b";
    let envelope = approve_context(
        &pipeline,
        tx,
        session,
        "run1",
        "svc-openclaw",
        "heartbeat check-in",
    );

    let token = pipeline
        .authorize_action_execution(action_request(
            tx,
            &envelope,
            "read",
            json!({"path": "README.md"}),
            "file",
            "README.md",
            "call-read-1",
        ))
        .expect("ordinary read must be authorized");

    let mut b = binding(&token);
    b.tool_name = "heartbeat_respond";
    b.resource_kind = "unknown";
    b.resource_locator = "heartbeat_respond";
    b.plane = "control";
    assert_eq!(
        pipeline.consume_provider_capability(&b),
        ConsumeOutcome::ToolMismatch
    );
}
