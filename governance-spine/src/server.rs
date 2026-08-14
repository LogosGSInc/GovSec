//! LOGOS Governance Systems Inc.
//! Sentinel OverWatch HTTP Server
//!
//! Endpoints:
//!   GET  /health
//!   POST /inspect
//!   POST /context/inspect      (logos.model-context.v1 — full-context admission)
//!   POST /outbound
//!   POST /provider/authorize   (requires context_hash + run_id)
//!   POST /provider/consume     (requires context_hash + run_id)
//!   POST /action/authorize     (logos.action.v1 — tool-call authorization)
//!   POST /action/consume
//!   GET  /session/{id}/state
//!   POST /session/reset
//!   POST /session/start
//!   POST /session/end
//!   GET  /audit

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha256};
use serde_json::{json, Value};

use governance_spine::capability::{
    PresentedBinding,
    AUTHORITY_ACTION_EXECUTE,
    AUTHORITY_PROVIDER_EXECUTE,
};
use governance_spine::pipeline::{ActionAuthorizationRequest, ProviderAuthorizationRequest};
use governance_spine::envelope::ModelContextEnvelope;
use governance_spine::{
    GovernancePipeline,
    EnforcementResult,
    ArbiterConfig,
    OperatorResetAuthority,
    load_verified_from_paths,
    trusted_constitution_authority_key,
    public_key_fingerprint,
    CryptoEngine,
};
use chrono::Utc;

fn ok_json(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: http://localhost:7070\r\nX-Content-Type-Options: nosniff\r\n\r\n{}",
        body.len(), body
    )
}

fn err_json(status: u16, msg: &str) -> String {
    let body = format!("{{\"ok\":false,\"error\":\"{}\"}}", msg.replace('"', "'"));
    format!(
        "HTTP/1.1 {} Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        status, body.len(), body
    )
}

fn json_response(status: u16, body: Value) -> String {
    let body = body.to_string();
    format!(
        "HTTP/1.1 {} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: http://localhost:7070\r\nX-Content-Type-Options: nosniff\r\n\r\n{}",
        status, body.len(), body
    )
}

struct ProviderConsumeRequest {
    capability_id: String,
    gov_tx_id: String,
    session_id: String,
    backend: String,
    model: String,
    context_hash: String,
    run_id: String,
}

struct ActionConsumeRequest {
    capability_id: String,
    gov_tx_id: String,
    session_id: String,
    run_id: String,
    context_hash: String,
    action_hash: String,
    tool_name: String,
    resource_kind: String,
    resource_locator: String,
    tool_call_id: String,
}

pub(crate) fn required_json_string(value: &Value, key: &str) -> Result<String, String> {
    let field = value.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");

    if field.is_empty() {
        Err(format!("{} required", key))
    } else {
        Ok(field.to_string())
    }
}

pub(crate) fn optional_json_string(value: &Value, key: &str) -> Option<String> {
    value.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

const MAX_BODY_BYTES: usize = 262_144; // 256 KB — prevents OOM on adversarial oversized payloads

// C6: an attacker can otherwise stream an unterminated line (no '\n') or an
// unbounded number of header lines and grow server memory without limit,
// even though MAX_BODY_BYTES already caps the declared request body.
const MAX_HEADER_LINE_BYTES: usize = 8_192; // 8 KB — generous for any real header
const MAX_HEADER_COUNT: usize = 100;

// C6: default per-connection socket read/write timeout and connection cap.
// Both are overridable via env (SENTOW_SOCKET_TIMEOUT_SECS /
// SENTOW_MAX_CONNECTIONS) so operators can tune without a rebuild, but a
// parse failure always falls back to these safe defaults rather than an
// unbounded value.
const DEFAULT_SOCKET_TIMEOUT_SECS: u64 = 10;
const DEFAULT_MAX_CONNECTIONS: usize = 64;

// A2: baked into the release image at build time (see governance-spine/
// Dockerfile) — a versioned release artifact, not runtime-mutable config.
// Overridable via env only for test/dev flexibility; the fail-closed
// startup gate applies identically regardless of where these point.
fn constitution_json_path() -> String {
    std::env::var("SENTOW_CONSTITUTION_PATH")
        .unwrap_or_else(|_| "/app/constitution/constitution.json".to_string())
}
fn constitution_signature_path() -> String {
    std::env::var("SENTOW_CONSTITUTION_SIGNATURE_PATH")
        .unwrap_or_else(|_| "/app/constitution/constitution.json.sig".to_string())
}

// A3: the audit-signing key is provisioned offline (see
// governance-spine/examples/generate_audit_signing_key.rs) and bind-mounted
// read-only into the container — unlike A2's constitution, this key IS
// held by the running process, since it must sign every governance event
// under a stable identity across restarts. Env-overridable for test/dev
// flexibility; the fail-closed startup gate applies regardless.
fn audit_key_path() -> String {
    std::env::var("SENTOW_AUDIT_KEY_PATH")
        .unwrap_or_else(|_| "/app/audit-signing/audit-signing-ed25519.key".to_string())
}

/// Reads one line (through and including the terminating `\n`, if any),
/// refusing to grow the buffer past `max_bytes`. Unlike `BufRead::read_line`,
/// which will happily buffer an arbitrarily long unterminated line from a
/// slow/adversarial peer, this bails out as soon as the cap is exceeded —
/// bounding worst-case growth to one extra internal-buffer-sized chunk.
/// Returns `None` on a read error, on EOF with no bytes read at all, or when
/// the line exceeds `max_bytes`.
pub(crate) fn read_line_bounded(
    reader: &mut BufReader<&mut TcpStream>,
    max_bytes: usize,
) -> Option<String> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(_) => return None,
        };
        if available.is_empty() {
            // Peer closed the connection (EOF).
            return if buf.is_empty() { None } else { Some(String::from_utf8_lossy(&buf).to_string()) };
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                buf.extend_from_slice(&available[..=pos]);
                reader.consume(pos + 1);
                if buf.len() > max_bytes { return None; }
                return Some(String::from_utf8_lossy(&buf).to_string());
            }
            None => {
                buf.extend_from_slice(available);
                let n = available.len();
                reader.consume(n);
                if buf.len() > max_bytes { return None; }
            }
        }
    }
}

/// Parses request headers and body. Fails closed with a short error message
/// (surfaced to the caller as HTTP 431) on an oversized/unterminated header
/// line or too many header lines, instead of silently truncating or hanging.
fn read_request(
    reader: &mut BufReader<&mut TcpStream>,
) -> Result<(HashMap<String, String>, String), &'static str> {
    let mut headers = HashMap::new();

    loop {
        let line = match read_line_bounded(reader, MAX_HEADER_LINE_BYTES) {
            Some(l) => l,
            None => return Err("header line too long"),
        };
        let t = line.trim();
        if t.is_empty() { break; }
        if headers.len() >= MAX_HEADER_COUNT {
            return Err("too many headers");
        }
        if let Some(p) = t.find(':') {
            headers.insert(
                t[..p].trim().to_lowercase(),
                t[p + 1..].trim().to_string(),
            );
        }
    }

    let declared_len: usize = headers.get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    if declared_len > MAX_BODY_BYTES {
        return Ok((headers, String::new()));
    }

    let mut body = vec![0u8; declared_len];
    use std::io::Read;
    reader.read_exact(&mut body).unwrap_or(());

    Ok((headers, String::from_utf8_lossy(&body).to_string()))
}

fn token_digest(value: &str) -> [u8; 32] {
    let digest = Sha256::digest(value.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Bind capabilities to the authenticated Sentinel service identity rather
/// than trusting a caller-supplied principal assertion.
fn service_principal_fingerprint(service_token: &str) -> String {
    format!("{:x}", Sha256::digest(service_token.as_bytes()))
}

/// Runtime policy provenance. This is derived by Sentinel from the policy
/// configuration it actually starts with; callers cannot assert it.
fn runtime_policy_hash() -> String {
    let profile = std::env::var("SENTOW_INDUSTRY_PROFILE")
        .unwrap_or_else(|_| "consumer".to_string());
    let govmem_mode = std::env::var("GOVMEM_MODE")
        .unwrap_or_else(|_| "v1".to_string());

    let canonical = format!(
        "governance-spine:{}|industry:{}|govmem:{}",
        env!("CARGO_PKG_VERSION"),
        profile,
        govmem_mode,
    );

    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}

fn authorized(headers: &HashMap<String, String>, expected_token: &str) -> bool {
    let provided = headers.get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or("");

    !provided.is_empty() && token_digest(provided) == token_digest(expected_token)
}

fn verdict_json(result: &EnforcementResult, session_id: &str) -> String {
    match result {
        EnforcementResult::Approved(_) =>
            format!("{{\"ok\":true,\"verdict\":\"APPROVED\",\"session_id\":\"{}\"}}",
                session_id),
        EnforcementResult::Restricted(_, r) =>
            format!("{{\"ok\":true,\"verdict\":\"RESTRICTED\",\"session_id\":\"{}\",\"tool_calls_disabled\":{},\"enhanced_logging\":{}}}",
                session_id, r.tool_calls_disabled, r.enhanced_logging),
        EnforcementResult::Quarantined(msg) =>
            format!("{{\"ok\":false,\"verdict\":\"QUARANTINED\",\"session_id\":\"{}\",\"message\":\"{}\"}}",
                session_id, msg.replace('"', "'")),
        EnforcementResult::HardLocked(msg) =>
            format!("{{\"ok\":false,\"verdict\":\"HARD_LOCKED\",\"session_id\":\"{}\",\"message\":\"{}\"}}",
                session_id, msg.replace('"', "'")),
        EnforcementResult::HaapGated { reason, agency, drs } =>
            format!("{{\"ok\":false,\"verdict\":\"HAAP_GATED\",\"session_id\":\"{}\",\"reason\":\"{}\",\"agency\":\"{}\",\"drs\":{}}}",
                session_id, reason.replace('"', "'"), agency, drs),
    }
}

fn handle(
    stream: &mut TcpStream,
    pipeline: &Arc<GovernancePipeline>,
    service_token: &Arc<String>,
) {
    let mut reader = BufReader::new(stream as &mut TcpStream);
    let req = match read_line_bounded(&mut reader, MAX_HEADER_LINE_BYTES) {
        Some(l) => l,
        None => return, // malformed/oversized/absent request line — silently drop, as before
    };
    let parts: Vec<&str> = req.split_whitespace().collect();
    if parts.len() < 2 { return; }
    let method = parts[0];
    let path   = parts[1];
    let (headers, body) = match read_request(&mut reader) {
        Ok(v) => v,
        Err(msg) => return write_response(reader, err_json(431, msg)),
    };

    let response = if path != "/health" && !authorized(&headers, service_token.as_str()) {
        err_json(401, "service authentication required")
    } else {
        match (method, path) {

        ("GET", "/health") => ok_json(&format!(
            "{{\"ok\":true,\"service\":\"sentinel-overwatch\",\"audit_entries\":{},\"chain_length\":{}}}",
            pipeline.audit_entry_count(), pipeline.chain_length()
        )),

        ("POST", "/inspect") => {
            let body_value: Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(_) => return write_response(
                    reader,
                    json_response(400, json!({"ok": false, "error": "valid JSON body required"}))
                ),
            };
            let parsed = (|| -> Result<(String, String), String> {
                let payload = required_json_string(&body_value, "payload")?;
                let session_id = required_json_string(&body_value, "session_id")?;
                Ok((payload, session_id))
            })();
            // Gate 2 (F-GM-005): per-request department/agent identity, not a
            // process-fixed env var. Optional — a request naming neither still
            // routes through the same should_block/record_turn path with None.
            let department_id = optional_json_string(&body_value, "department_id");
            let agent_id = optional_json_string(&body_value, "agent_id");

            match parsed {
                Err(error) => err_json(400, &error),
                Ok((payload, session_id)) => {
                let gov_tx_id = format!("GTX-{}", uuid::Uuid::new_v4().simple());
                let result = pipeline.inbound_with_identity(
                    &payload, &session_id, &gov_tx_id,
                    department_id.as_deref(), agent_id.as_deref(),
                );

                match &result {
                    EnforcementResult::Approved(_) => {
                        match pipeline.approved_verdict_id(&gov_tx_id, &session_id) {
                            Some(verdict_id) => json_response(200, json!({
                                "ok": true,
                                "verdict": "APPROVED",
                                "session_id": session_id,
                                "gov_tx_id": gov_tx_id,
                                "verdict_id": verdict_id,
                                "provider_authorizable": true
                            })),
                            None => json_response(500, json!({
                                "ok": false,
                                "verdict": "INTERNAL_AUTHORITY_ERROR",
                                "session_id": session_id,
                                "gov_tx_id": gov_tx_id,
                                "provider_authorizable": false,
                                "error": "final approval receipt missing"
                            })),
                        }
                    }
                    _ => {
                        let mut value: Value = serde_json::from_str(
                            &verdict_json(&result, &session_id)
                        ).unwrap_or_else(|_| json!({
                            "ok": false,
                            "verdict": "SERIALIZATION_ERROR",
                            "session_id": session_id
                        }));

                        value["gov_tx_id"] = json!(gov_tx_id);
                        value["provider_authorizable"] = json!(false);
                        json_response(200, value)
                    }
                }
                }
            }
        }

        ("POST", "/outbound") => {
            let body_value: Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(_) => return write_response(
                    reader,
                    json_response(400, json!({"ok": false, "error": "valid JSON body required"}))
                ),
            };
            let parsed = (|| -> Result<(String, String), String> {
                let payload = required_json_string(&body_value, "payload")?;
                let session_id = required_json_string(&body_value, "session_id")?;
                Ok((payload, session_id))
            })();

            match parsed {
                Err(error) => err_json(400, &error),
                Ok((payload, session_id)) => {
                    let r = pipeline.outbound(&payload, &session_id);
                    ok_json(&verdict_json(&r, &session_id))
                }
            }
        }

        ("POST", "/context/inspect") => {
            let envelope: ModelContextEnvelope = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(e) => return write_response(
                    reader,
                    json_response(400, json!({
                        "ok": false,
                        "error": format!("invalid model context envelope: {e}")
                    }))
                ),
            };

            let body_value: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            let department_id = optional_json_string(&body_value, "department_id");
            let agent_id = optional_json_string(&body_value, "agent_id");

            let session_id = envelope.session_id.clone();
            let gov_tx_id = format!("GTX-{}", uuid::Uuid::new_v4().simple());

            match pipeline.inbound_context_with_identity(
                &envelope, &gov_tx_id, department_id.as_deref(), agent_id.as_deref(),
            ) {
                Err(envelope_error) => json_response(400, json!({
                    "ok": false,
                    "error": format!("envelope validation failed: {envelope_error}")
                })),
                Ok(result) => match &result {
                    EnforcementResult::Approved(_) => {
                        match pipeline.approved_verdict_id(&gov_tx_id, &session_id) {
                            Some(verdict_id) => json_response(200, json!({
                                "ok": true,
                                "verdict": "APPROVED",
                                "session_id": session_id,
                                "gov_tx_id": gov_tx_id,
                                "verdict_id": verdict_id,
                                "context_hash": envelope.context_hash,
                                "run_id": envelope.run_id,
                                "provider_authorizable": true,
                                "action_authorizable": true
                            })),
                            None => json_response(500, json!({
                                "ok": false,
                                "verdict": "INTERNAL_AUTHORITY_ERROR",
                                "session_id": session_id,
                                "gov_tx_id": gov_tx_id,
                                "provider_authorizable": false,
                                "action_authorizable": false,
                                "error": "final approval receipt missing"
                            })),
                        }
                    }
                    _ => {
                        let mut value: Value = serde_json::from_str(
                            &verdict_json(&result, &session_id)
                        ).unwrap_or_else(|_| json!({
                            "ok": false,
                            "verdict": "SERIALIZATION_ERROR",
                            "session_id": session_id
                        }));
                        value["gov_tx_id"] = json!(gov_tx_id);
                        value["provider_authorizable"] = json!(false);
                        value["action_authorizable"] = json!(false);
                        json_response(200, value)
                    }
                }
            }
        }

        ("POST", "/provider/authorize") => {
            let value: Value = match serde_json::from_str(&body) {
                Ok(value) => value,
                Err(_) => return write_response(
                    reader,
                    json_response(400, json!({
                        "ok": false,
                        "error": "valid JSON body required"
                    }))
                ),
            };

            let parsed = (|| -> Result<ProviderAuthorizationRequest, String> {
                let gov_tx_id = required_json_string(&value, "gov_tx_id")?;
                let session_id = required_json_string(&value, "session_id")?;

                Ok(ProviderAuthorizationRequest {
                    gov_tx_id,
                    session_id: session_id.clone(),
                    principal_fingerprint: service_principal_fingerprint(
                        service_token.as_str()
                    ),
                    backend: required_json_string(&value, "backend")?,
                    model: required_json_string(&value, "model")?,
                    action_class: required_json_string(&value, "action_class")?,
                    policy_hash: runtime_policy_hash(),
                    authorization_basis: "FinalPipelineApproved".to_string(),
                    agency: "ExecuteActions".to_string(),
                    drs: pipeline.session_drs(&session_id),
                    // context_hash/run_id are the values the caller received
                    // back from a prior /context/inspect APPROVED response —
                    // never trusted as an assertion of approval, only
                    // compared against what the pipeline itself recorded.
                    context_hash: required_json_string(&value, "context_hash")?,
                    run_id: required_json_string(&value, "run_id")?,
                    policy_version: pipeline.active_policy_version(),
                })
            })();

            match parsed {
                Err(error) => json_response(400, json!({
                    "ok": false,
                    "error": error
                })),
                Ok(request) => {
                    match pipeline.authorize_provider_execution(request) {
                        Ok(token) => json_response(200, json!({
                            "ok": true,
                            "decision_id": token.haap_decision_id,
                            "capability_id": token.token_id,
                            "gov_tx_id": token.gov_tx_id,
                            "session_id": token.session_id,
                            "principal_fingerprint": token.principal_fingerprint,
                            "authority": token.authority,
                            "backend": token.backend,
                            "model": token.model,
                            "action_class": token.action_class,
                            "verdict_id": token.sentinel_verdict_id,
                            "policy_hash": token.policy_hash,
                            "run_id": token.run_id,
                            "context_hash": token.context_hash,
                            "policy_version": token.policy_version,
                            "expires_at": token.expires_at,
                            "max_uses": token.max_uses
                        })),
                        Err(error) => json_response(403, json!({
                            "ok": false,
                            "authorized": false,
                            "error": format!("{:?}", error)
                        })),
                    }
                }
            }
        }

        ("POST", "/provider/consume") => {
            let value: Value = match serde_json::from_str(&body) {
                Ok(value) => value,
                Err(_) => return write_response(
                    reader,
                    json_response(400, json!({
                        "ok": false,
                        "error": "valid JSON body required"
                    }))
                ),
            };

            let parsed = (|| -> Result<ProviderConsumeRequest, String> {
                Ok(ProviderConsumeRequest {
                    capability_id: required_json_string(&value, "capability_id")?,
                    gov_tx_id: required_json_string(&value, "gov_tx_id")?,
                    session_id: required_json_string(&value, "session_id")?,
                    backend: required_json_string(&value, "backend")?,
                    model: required_json_string(&value, "model")?,
                    context_hash: required_json_string(&value, "context_hash")?,
                    run_id: required_json_string(&value, "run_id")?,
                })
            })();

            match parsed {
                Err(error) => json_response(400, json!({
                    "ok": false,
                    "error": error
                })),
                Ok(req) => {
                    let policy_version = pipeline.active_policy_version();
                    let policy_hash = runtime_policy_hash();
                    let binding = PresentedBinding {
                        token_id: &req.capability_id,
                        gov_tx_id: &req.gov_tx_id,
                        session_id: &req.session_id,
                        principal_fingerprint: &service_principal_fingerprint(
                            service_token.as_str()
                        ),
                        authority: AUTHORITY_PROVIDER_EXECUTE,
                        backend: &req.backend,
                        model: &req.model,
                        run_id: &req.run_id,
                        context_hash: &req.context_hash,
                        policy_version: &policy_version,
                        policy_hash: &policy_hash,
                        action_hash: "",
                        tool_name: "",
                        resource_kind: "",
                        resource_locator: "",
                        tool_call_id: "",
                        plane: "",
                    };

                    let outcome = pipeline.consume_provider_capability(&binding);
                    let authorized = outcome.authorized();
                    let status = if authorized { 200 } else { 403 };

                    json_response(status, json!({
                        "ok": authorized,
                        "authorized": authorized,
                        "outcome": outcome.as_audit_str(),
                        "capability_id": req.capability_id,
                        "gov_tx_id": req.gov_tx_id,
                        "session_id": req.session_id
                    }))
                }
            }
        }

        ("POST", "/action/authorize") => {
            let value: Value = match serde_json::from_str(&body) {
                Ok(value) => value,
                Err(_) => return write_response(
                    reader,
                    json_response(400, json!({
                        "ok": false,
                        "error": "valid JSON body required"
                    }))
                ),
            };

            let parsed = (|| -> Result<ActionAuthorizationRequest, String> {
                let gov_tx_id = required_json_string(&value, "gov_tx_id")?;
                let session_id = required_json_string(&value, "session_id")?;
                let arguments = value.get("arguments").cloned().unwrap_or(Value::Null);

                Ok(ActionAuthorizationRequest {
                    gov_tx_id,
                    session_id,
                    run_id: required_json_string(&value, "run_id")?,
                    // Trusted principal — derived from the authenticated
                    // service identity, never a client-asserted value.
                    principal_fingerprint: service_principal_fingerprint(
                        service_token.as_str()
                    ),
                    tool_name: required_json_string(&value, "tool_name")?,
                    arguments,
                    resource_kind: required_json_string(&value, "resource_kind")?,
                    resource_locator: required_json_string(&value, "resource_locator")?,
                    tool_call_id: required_json_string(&value, "tool_call_id")?,
                    context_hash: required_json_string(&value, "context_hash")?,
                    // Trusted policy identity — derived server-side from the
                    // running, signature-verified configuration, never taken
                    // from the request body.
                    policy_version: pipeline.active_policy_version(),
                    policy_hash: runtime_policy_hash(),
                })
            })();

            match parsed {
                Err(error) => json_response(400, json!({ "ok": false, "error": error })),
                Ok(request) => {
                    // Captured before the request is moved/consumed below,
                    // purely for bounded diagnostics on the denial path —
                    // never used to grant anything (authorization already
                    // happened, or didn't, inside authorize_action_execution).
                    let diag_tool_name = request.tool_name.clone();
                    let diag_semantics =
                        governance_spine::action_semantics::derive_action_semantics_for_tool(
                            &diag_tool_name,
                        );
                    match pipeline.authorize_action_execution(request) {
                    Ok(token) => json_response(200, json!({
                        "ok": true,
                        "decision_id": token.haap_decision_id,
                        "capability_id": token.token_id,
                        "gov_tx_id": token.gov_tx_id,
                        "session_id": token.session_id,
                        "run_id": token.run_id,
                        "principal_fingerprint": token.principal_fingerprint,
                        "authority": token.authority,
                        "tool_name": token.tool_name,
                        "resource_kind": token.resource_kind,
                        "resource_locator": token.resource_locator,
                        "tool_call_id": token.tool_call_id,
                        "verdict_id": token.sentinel_verdict_id,
                        "context_hash": token.context_hash,
                        "action_hash": token.action_hash,
                        "policy_hash": token.policy_hash,
                        "policy_version": token.policy_version,
                        "expires_at": token.expires_at,
                        "max_uses": token.max_uses,
                        "plane": token.action_plane.as_str(),
                        "normalized_action": token.normalized_action,
                        "required_for_safe_completion": token.required_for_safe_completion
                    })),
                    Err(error @ (
                        governance_spine::pipeline::ActionAuthorizationError::MalformedContextHash
                        | governance_spine::pipeline::ActionAuthorizationError::Envelope(_)
                    )) => json_response(400, json!({
                        "ok": false,
                        "authorized": false,
                        "error": format!("{:?}", error),
                        "diagnostics": {
                            "decision_type": "structural_validation_failed",
                            "plane": diag_semantics.plane.as_str(),
                            "native_tool": diag_tool_name,
                            "normalized_action": diag_semantics.normalized_action,
                            "required_for_safe_completion": diag_semantics.required_for_safe_completion(),
                            "denial_stage": "action_envelope_validation"
                        }
                    })),
                    Err(error) => {
                        // A denied classification is action-authorization
                        // territory, distinct from Boundary E's outbound
                        // content review — never described as "content
                        // review" here.
                        let risk_classes = match &error {
                            governance_spine::pipeline::ActionAuthorizationError::Denied(risks) => {
                                json!(risks)
                            }
                            _ => Value::Null,
                        };
                        json_response(403, json!({
                            "ok": false,
                            "authorized": false,
                            "error": format!("{:?}", error),
                            "diagnostics": {
                                "decision_type": "action_authorization_denied",
                                "plane": diag_semantics.plane.as_str(),
                                "native_tool": diag_tool_name,
                                "normalized_action": diag_semantics.normalized_action,
                                "required_for_safe_completion": diag_semantics.required_for_safe_completion(),
                                "denial_stage": "action_gate",
                                "risk_classes": risk_classes
                            }
                        }))
                    }
                }
                }
            }
        }

        ("POST", "/action/consume") => {
            let value: Value = match serde_json::from_str(&body) {
                Ok(value) => value,
                Err(_) => return write_response(
                    reader,
                    json_response(400, json!({
                        "ok": false,
                        "error": "valid JSON body required"
                    }))
                ),
            };

            let parsed = (|| -> Result<ActionConsumeRequest, String> {
                Ok(ActionConsumeRequest {
                    capability_id: required_json_string(&value, "capability_id")?,
                    gov_tx_id: required_json_string(&value, "gov_tx_id")?,
                    session_id: required_json_string(&value, "session_id")?,
                    run_id: required_json_string(&value, "run_id")?,
                    context_hash: required_json_string(&value, "context_hash")?,
                    action_hash: required_json_string(&value, "action_hash")?,
                    tool_name: required_json_string(&value, "tool_name")?,
                    resource_kind: required_json_string(&value, "resource_kind")?,
                    resource_locator: required_json_string(&value, "resource_locator")?,
                    tool_call_id: optional_json_string(&value, "tool_call_id").unwrap_or_default(),
                })
            })();

            match parsed {
                Err(error) => json_response(400, json!({ "ok": false, "error": error })),
                Ok(req) => {
                    let policy_version = pipeline.active_policy_version();
                    let policy_hash = runtime_policy_hash();
                    // Re-derived fresh from the presented (trusted-at-this-
                    // point-because-it-must-match-the-token) tool_name —
                    // never accepted as a standalone field from the request
                    // body. See action_semantics.rs's module doc.
                    let presented_semantics =
                        governance_spine::action_semantics::derive_action_semantics_for_tool(
                            &req.tool_name,
                        );
                    let binding = PresentedBinding {
                        token_id: &req.capability_id,
                        gov_tx_id: &req.gov_tx_id,
                        session_id: &req.session_id,
                        principal_fingerprint: &service_principal_fingerprint(
                            service_token.as_str()
                        ),
                        authority: AUTHORITY_ACTION_EXECUTE,
                        backend: "",
                        model: "",
                        run_id: &req.run_id,
                        context_hash: &req.context_hash,
                        policy_version: &policy_version,
                        policy_hash: &policy_hash,
                        action_hash: &req.action_hash,
                        tool_name: &req.tool_name,
                        resource_kind: &req.resource_kind,
                        resource_locator: &req.resource_locator,
                        tool_call_id: &req.tool_call_id,
                        plane: presented_semantics.plane.as_str(),
                    };

                    let outcome = pipeline.consume_provider_capability(&binding);
                    let authorized = outcome.authorized();
                    let status = if authorized { 200 } else { 403 };

                    json_response(status, json!({
                        "ok": authorized,
                        "authorized": authorized,
                        "outcome": outcome.as_audit_str(),
                        "capability_id": req.capability_id,
                        "gov_tx_id": req.gov_tx_id,
                        "session_id": req.session_id,
                        // Bounded, non-secret diagnostics — never labeled as
                        // "content review" (that is Boundary E / outbound
                        // gate territory, a completely separate check). See
                        // docs/govsec-openclaw-integration.md's
                        // "action-authorization vs outbound content" section.
                        "diagnostics": {
                            "plane": presented_semantics.plane.as_str(),
                            "normalized_action": presented_semantics.normalized_action,
                            "required_for_safe_completion": presented_semantics.required_for_safe_completion(),
                            "denial_stage": if authorized { Value::Null } else { json!("action_capability_consume") }
                        }
                    }))
                }
            }
        }

        ("GET", p) if p.starts_with("/session/") && p.ends_with("/state") => {
            let sid   = p.trim_start_matches("/session/").trim_end_matches("/state");
            let state = pipeline.current_state(sid);
            let drs   = pipeline.session_drs(sid);
            ok_json(&format!(
                "{{\"ok\":true,\"session_id\":\"{}\",\"state\":\"{}\",\"drs\":{}}}",
                sid, state, drs
            ))
        }

        ("POST", "/session/reset") => {
            let body_value: Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(_) => return write_response(
                    reader,
                    json_response(400, json!({"ok": false, "error": "valid JSON body required"}))
                ),
            };
            match required_json_string(&body_value, "session_id") {
                Err(error) => err_json(400, &error),
                Ok(sid) => {
                    let token = optional_json_string(&body_value, "operator_token").unwrap_or_default();
                    match pipeline.operator_reset(&sid, &token) {
                        Ok(_)  => ok_json(&format!(
                            "{{\"ok\":true,\"session_id\":\"{}\",\"reset\":true}}", sid)),
                        Err(e) => err_json(403, e),
                    }
                }
            }
        }

        ("POST", "/session/start") => {
            let body_value: Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(_) => return write_response(
                    reader,
                    json_response(400, json!({"ok": false, "error": "valid JSON body required"}))
                ),
            };
            let actor_id = optional_json_string(&body_value, "actor_id")
                .unwrap_or_else(|| "anonymous".into());
            let session_id = match required_json_string(&body_value, "session_id") {
                Ok(v) => v,
                Err(e) => return write_response(reader, err_json(400, &e)),
            };

            // Return real session state from pipeline memory (not hardcoded "Clean")
            let state = pipeline.current_state(&session_id);
            let drs   = pipeline.session_drs(&session_id);
            let starting_state = match state {
                governance_spine::arbiter::SecurityState::S1 => "Clean",
                governance_spine::arbiter::SecurityState::S2 => "Watching",
                governance_spine::arbiter::SecurityState::S3 => "Elevated",
                governance_spine::arbiter::SecurityState::S4 => "Locked",
            };

            ok_json(&format!(
                "{{\"ok\":true,\"actor_id\":\"{}\",\"session_id\":\"{}\",\"starting_state\":\"{}\",\"drs\":{},\"threshold_modifier\":{:.2},\"prior_escalations\":{}}}",
                actor_id, session_id, starting_state, drs, 1.0, 0,
            ))
        }

        ("POST", "/session/end") => {
            let body_value: Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(_) => return write_response(
                    reader,
                    json_response(400, json!({"ok": false, "error": "valid JSON body required"}))
                ),
            };
            let actor_id = optional_json_string(&body_value, "actor_id")
                .unwrap_or_else(|| "anonymous".into());
            let session_id = match required_json_string(&body_value, "session_id") {
                Ok(v) => v,
                Err(e) => return write_response(reader, err_json(400, &e)),
            };
            let escalated = body_value.get("escalated")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            // GS-BUILD-01: report the real persistence outcome, decoupled into
            // two honest facts:
            //   persisted  — did THIS call durably write a session profile to
            //                SENTOW_MEMORY_PATH (true only with real session data
            //                + a successful disk write).
            //   durability — the store's configuration ("disk" vs
            //                "in-memory-only"), independent of this call.
            // This replaces the previous unconditional "persisted":true (GS-FIX-01)
            // without re-introducing a claim-without-a-write.
            let persisted = pipeline.end_session(&session_id, &actor_id);
            let durability = if pipeline.memory_is_durable() { "disk" } else { "in-memory-only" };
            ok_json(&format!(
                "{{\"ok\":true,\"actor_id\":\"{}\",\"session_id\":\"{}\",\"persisted\":{},\"durability\":\"{}\",\"escalated\":{}}}",
                actor_id, session_id, persisted, durability, escalated
            ))
        }

        ("GET", p) if p.starts_with("/audit") => {
            let entries = pipeline.export_audit_log();
            let last_50: Vec<_> = entries.iter().rev().take(50).collect();
            let items: Vec<String> = last_50.iter().map(|e| format!(
                "{{\"event_id\":\"{}\",\"session_id\":\"{}\",\"source\":\"{}\",\"severity\":\"{}\"}}",
                e.event_id, e.session_id, e.source, e.severity
            )).collect();
            ok_json(&format!("{{\"ok\":true,\"count\":{},\"entries\":[{}]}}",
                items.len(), items.join(",")))
        }

        _ => err_json(404, "not found"),
        }
    };

    let s = reader.get_mut();
    let _ = s.write_all(response.as_bytes());
}

fn write_response(mut reader: BufReader<&mut TcpStream>, response: String) {
    let s = reader.get_mut();
    let _ = s.write_all(response.as_bytes());
}

fn main() {
    let service_token = std::env::var("SENTINEL_SERVICE_TOKEN")
        .unwrap_or_default()
        .trim()
        .to_string();

    if service_token.is_empty()
        || service_token.to_uppercase().contains("PLACEHOLDER")
        || service_token.to_uppercase().contains("GENERATE")
    {
        eprintln!("[SECURITY ERROR] SENTINEL_SERVICE_TOKEN missing or invalid");
        std::process::exit(1);
    }

    let service_token = Arc::new(service_token);

    // SENTINEL_OPERATOR_RESET_TOKEN authorizes destructive session reset and
    // is a distinct credential from SENTINEL_SERVICE_TOKEN (HTTP caller
    // authentication) — neither substitutes for the other. Loaded and
    // validated once here, before the server accepts any connections.
    let reset_authority = match OperatorResetAuthority::from_config(
        std::env::var("SENTINEL_OPERATOR_RESET_TOKEN").ok()
    ) {
        Ok(authority) => authority,
        Err(error) => {
            eprintln!("[SECURITY ERROR] SENTINEL_OPERATOR_RESET_TOKEN invalid: {}", error);
            std::process::exit(1);
        }
    };

    let addr = std::env::var("SENTOW_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8080".into());
    let industry = std::env::var("SENTOW_INDUSTRY_PROFILE")
        .unwrap_or_else(|_| "consumer".into());
    let arbiter_config = match industry.as_str() {
        "medical" => ArbiterConfig::medical(),
        _         => ArbiterConfig::default(),
    };
    // A2: mandatory constitution load + signature verification, BEFORE the
    // pipeline is constructed and BEFORE the listener binds — no request
    // can be served until this succeeds. Refuses to start (matching the
    // existing SENTINEL_SERVICE_TOKEN/SENTINEL_OPERATOR_RESET_TOKEN
    // fail-closed pattern above) on: missing file, missing signature,
    // malformed JSON, invalid signature, wrong signer, profile mismatch,
    // missing constitution_id/policy_version, or an invalid validity
    // window. The trusted key is the compiled-in pinned constant, never a
    // key from the document itself or a runtime-mutable file.
    let trusted_constitution_key = trusted_constitution_authority_key();
    let constitution = match load_verified_from_paths(
        std::path::Path::new(&constitution_json_path()),
        std::path::Path::new(&constitution_signature_path()),
        &trusted_constitution_key,
        &industry,
        Utc::now(),
    ) {
        Ok(c) => {
            eprintln!(
                "[CONSTITUTION] verified — id={} version={} profile={} signer_fingerprint={}",
                c.constitution_id, c.policy_version, c.industry_profile,
                public_key_fingerprint(&trusted_constitution_key),
            );
            c
        }
        Err(e) => {
            eprintln!("[SECURITY ERROR] constitution verification failed: {e}");
            std::process::exit(1);
        }
    };

    // A3: mandatory persistent audit-signing identity load, BEFORE the
    // pipeline is constructed — fail-closed on the same terms as the
    // constitution gate above. Loading the SAME key file on every startup
    // (rather than generating a fresh one, as CryptoEngine::new() used to)
    // is what lets an audit entry's signature still verify after a
    // restart. This key is distinct from the A2 constitution-authoring key
    // (which the running process never holds) and from
    // SENTINEL_OPERATOR_RESET_TOKEN (a shared secret, not a signing key).
    let audit_crypto = match CryptoEngine::from_persisted_key_file(
        std::path::Path::new(&audit_key_path()),
        "logos_governance_v1_seed",
    ) {
        Ok(c) => {
            eprintln!("[CRYPTO] audit-signing identity loaded — fingerprint={}", c.verifying_key_fingerprint());
            Arc::new(c)
        }
        Err(e) => {
            eprintln!("[SECURITY ERROR] audit signing key load failed: {e}");
            std::process::exit(1);
        }
    };

    let pipeline = Arc::new(
        GovernancePipeline::new(arbiter_config, Some(constitution), audit_crypto)
            .expect("Pipeline init failed")
    );
    pipeline
        .configure_operator_reset_authority(reset_authority)
        .expect("operator reset authority configured exactly once at startup");
    eprintln!("[SENTINEL-SERVER] Listening on http://{}", addr);
    eprintln!("[SENTINEL-SERVER] SENTOW_MEMORY_PATH={}",
        std::env::var("SENTOW_MEMORY_PATH").unwrap_or_else(|_| "(in-memory only)".into()));

    // C6: both overridable via env; a missing/unparseable value falls back
    // to the safe default rather than an unbounded one.
    let socket_timeout = Duration::from_secs(
        std::env::var("SENTOW_SOCKET_TIMEOUT_SECS").ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_SOCKET_TIMEOUT_SECS)
    );
    let max_connections = std::env::var("SENTOW_MAX_CONNECTIONS").ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_CONNECTIONS);

    let listener = TcpListener::bind(&addr).expect("Failed to bind");
    serve(listener, pipeline, service_token, max_connections, socket_timeout);
}

/// The accept loop: bounded connection concurrency, and a per-connection
/// socket read/write timeout applied before any bytes are read (C6 —
/// otherwise a single slow/silent client can hold a handler thread forever).
/// Extracted from `main()` so tests can bind an ephemeral port and drive it
/// with real sockets instead of only exercising library-level parsing.
pub(crate) fn serve(
    listener: TcpListener,
    pipeline: Arc<GovernancePipeline>,
    service_token: Arc<String>,
    max_connections: usize,
    socket_timeout: Duration,
) {
    let active_connections = Arc::new(AtomicUsize::new(0));
    for mut s in listener.incoming().flatten() {
        let in_flight = active_connections.fetch_add(1, Ordering::SeqCst) + 1;
        if in_flight > max_connections {
            active_connections.fetch_sub(1, Ordering::SeqCst);
            let _ = s.write_all(err_json(503, "server at connection capacity").as_bytes());
            continue;
        }
        let _ = s.set_read_timeout(Some(socket_timeout));
        let _ = s.set_write_timeout(Some(socket_timeout));
        let p = pipeline.clone();
        let token = service_token.clone();
        let counter = active_connections.clone();
        thread::spawn(move || {
            handle(&mut s, &p, &token);
            counter.fetch_sub(1, Ordering::SeqCst);
        });
    }
}
