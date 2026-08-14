//! Canonical governance contracts for model context and consequential actions.
//!
//! Hashes in this module bind a decision to exact bytes. They do not provide
//! durable or immutable storage; audit records must be written to a separate
//! append-only, access-controlled sink.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;

pub const MODEL_CONTEXT_SCHEMA_VERSION: &str = "logos.model-context.v1";
pub const ACTION_ENVELOPE_SCHEMA_VERSION: &str = "logos.action.v1";

const SHA256_HEX_LEN: usize = 64;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_POLICY_VERSION_BYTES: usize = 128;
const MAX_CONTEXT_SEGMENTS: usize = 4_096;
const MAX_CONTEXT_SEGMENT_BYTES: usize = 262_144;
const MAX_CONTEXT_CONTENT_BYTES: usize = 4_194_304;
const MAX_ATTACHMENTS: usize = 128;
const MAX_MEDIA_TYPE_BYTES: usize = 256;
const MAX_TOOL_NAME_BYTES: usize = 128;
const MAX_RESOURCE_KIND_BYTES: usize = 128;
const MAX_RESOURCE_LOCATOR_BYTES: usize = 4_096;
const MAX_ACTION_ARGUMENT_BYTES: usize = 262_144;
const MAX_JSON_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    MissingField(&'static str),
    InvalidField(&'static str),
    InvalidDigest(&'static str),
    LimitExceeded(&'static str),
    InvalidContextSegment { ordinal: u32, reason: String },
    DuplicateAttachmentId(String),
    UnknownAttachmentId(String),
    HashMismatch(&'static str),
    Canonicalization(String),
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "required field is empty: {field}"),
            Self::InvalidField(field) => write!(f, "invalid field: {field}"),
            Self::InvalidDigest(field) => write!(f, "invalid SHA-256 digest: {field}"),
            Self::LimitExceeded(field) => write!(f, "contract limit exceeded: {field}"),
            Self::InvalidContextSegment { ordinal, reason } => {
                write!(f, "invalid context segment {ordinal}: {reason}")
            }
            Self::DuplicateAttachmentId(id) => write!(f, "duplicate attachment id: {id}"),
            Self::UnknownAttachmentId(id) => write!(f, "unknown attachment id: {id}"),
            Self::HashMismatch(field) => write!(f, "hash mismatch: {field}"),
            Self::Canonicalization(reason) => write!(f, "canonicalization failed: {reason}"),
        }
    }
}

impl Error for EnvelopeError {}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// True iff `value` is a well-formed lowercase SHA-256 hex digest. Exposed so
/// callers outside this module (capability issuance, decision recording) can
/// reject malformed hashes with the same rule the envelope contracts use,
/// rather than re-implementing or loosening the check.
pub fn is_sha256_hex(value: &str) -> bool {
    validate_sha256("external", value).is_ok()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextRole {
    System,
    User,
    Assistant,
    ToolResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextSource {
    ExternalUser,
    ConversationHistory,
    ToolResult,
    Attachment,
    HookInjection,
    RuntimeInjection,
    CompactionSummary,
}

impl ContextSource {
    /// Every source-labelled text segment is inspected for each run. This
    /// deliberately includes prior history and compaction summaries because
    /// model-produced or imported text can carry forward hostile instructions.
    pub fn requires_content_inspection(&self) -> bool {
        matches!(
            self,
            Self::ExternalUser
                | Self::ConversationHistory
                | Self::ToolResult
                | Self::Attachment
                | Self::HookInjection
                | Self::RuntimeInjection
                | Self::CompactionSummary
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextSegment {
    /// Zero-based position in the exact ordered model context.
    pub ordinal: u32,
    pub role: ContextRole,
    pub source: ContextSource,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextAttachment {
    pub attachment_id: String,
    pub media_type: String,
    pub byte_length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelContextEnvelope {
    pub schema_version: String,
    pub session_id: String,
    pub run_id: String,
    pub principal_id: String,
    /// Provider and model are part of the approved run identity. A context
    /// approved for one model must not be replayed against another.
    pub provider_id: String,
    pub model_id: String,
    pub policy_version: String,
    pub policy_hash: String,
    /// Hash of the exact provider-bound context payload after OpenClaw has
    /// assembled messages, multimodal parts and provider wrappers.
    pub provider_context_hash: String,
    /// Hash of the exact assembled system prompt, including injected workspace
    /// material and hook additions that are part of that prompt.
    pub system_prompt_hash: String,
    /// Hash of the exact ordered tool-schema payload sent to the model.
    pub tool_schema_hash: String,
    /// Hash of the ordered manifest for injected workspace/bootstrap files.
    pub workspace_manifest_hash: String,
    pub segments: Vec<ContextSegment>,
    pub attachments: Vec<ContextAttachment>,
    /// SHA-256 of the canonical envelope material, excluding this field.
    #[serde(default)]
    pub context_hash: String,
}

impl ModelContextEnvelope {
    /// Validate the material and replace `context_hash` with the canonical hash.
    pub fn seal(mut self) -> Result<Self, EnvelopeError> {
        self.validate_material()?;
        self.context_hash = self.compute_hash()?;
        Ok(self)
    }

    /// Verify structure, limits and exact canonical hash binding.
    pub fn verify(&self) -> Result<(), EnvelopeError> {
        self.validate_material()?;
        validate_sha256("context_hash", &self.context_hash)?;
        if self.compute_hash()? != self.context_hash {
            return Err(EnvelopeError::HashMismatch("context_hash"));
        }
        Ok(())
    }

    pub fn compute_hash(&self) -> Result<String, EnvelopeError> {
        hash_canonical(&model_context_hash_material(self))
    }

    pub fn segments_requiring_inspection(&self) -> impl Iterator<Item = &ContextSegment> {
        self.segments
            .iter()
            .filter(|segment| segment.source.requires_content_inspection())
    }

    fn validate_material(&self) -> Result<(), EnvelopeError> {
        if self.schema_version != MODEL_CONTEXT_SCHEMA_VERSION {
            return Err(EnvelopeError::InvalidField("schema_version"));
        }
        validate_identifier("session_id", &self.session_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier("run_id", &self.run_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier("principal_id", &self.principal_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier("provider_id", &self.provider_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier("model_id", &self.model_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier(
            "policy_version",
            &self.policy_version,
            MAX_POLICY_VERSION_BYTES,
        )?;
        validate_sha256("policy_hash", &self.policy_hash)?;
        validate_sha256("provider_context_hash", &self.provider_context_hash)?;
        validate_sha256("system_prompt_hash", &self.system_prompt_hash)?;
        validate_sha256("tool_schema_hash", &self.tool_schema_hash)?;
        validate_sha256("workspace_manifest_hash", &self.workspace_manifest_hash)?;

        if self.segments.is_empty() {
            return Err(EnvelopeError::MissingField("segments"));
        }
        if self.segments.len() > MAX_CONTEXT_SEGMENTS {
            return Err(EnvelopeError::LimitExceeded("segments"));
        }
        if self.attachments.len() > MAX_ATTACHMENTS {
            return Err(EnvelopeError::LimitExceeded("attachments"));
        }

        let mut attachment_ids = HashSet::new();
        for attachment in &self.attachments {
            validate_identifier(
                "attachment_id",
                &attachment.attachment_id,
                MAX_IDENTIFIER_BYTES,
            )?;
            validate_identifier("media_type", &attachment.media_type, MAX_MEDIA_TYPE_BYTES)?;
            validate_sha256("attachment.sha256", &attachment.sha256)?;
            if !attachment_ids.insert(attachment.attachment_id.clone()) {
                return Err(EnvelopeError::DuplicateAttachmentId(
                    attachment.attachment_id.clone(),
                ));
            }
        }

        let mut total_content_bytes = 0usize;
        for (index, segment) in self.segments.iter().enumerate() {
            if segment.ordinal as usize != index {
                return Err(EnvelopeError::InvalidContextSegment {
                    ordinal: segment.ordinal,
                    reason: "ordinal must equal its zero-based vector position".to_string(),
                });
            }
            if segment.content.len() > MAX_CONTEXT_SEGMENT_BYTES {
                return Err(EnvelopeError::LimitExceeded("segment.content"));
            }
            total_content_bytes = total_content_bytes
                .checked_add(segment.content.len())
                .ok_or(EnvelopeError::LimitExceeded("context content"))?;
            if total_content_bytes > MAX_CONTEXT_CONTENT_BYTES {
                return Err(EnvelopeError::LimitExceeded("context content"));
            }
            validate_segment(segment, &attachment_ids)?;
        }

        Ok(())
    }
}

fn validate_segment(
    segment: &ContextSegment,
    attachment_ids: &HashSet<String>,
) -> Result<(), EnvelopeError> {
    let invalid = |reason: &str| EnvelopeError::InvalidContextSegment {
        ordinal: segment.ordinal,
        reason: reason.to_string(),
    };

    if segment.content.trim().is_empty() && segment.source != ContextSource::Attachment {
        return Err(invalid("content is required"));
    }
    match segment.source {
        ContextSource::ExternalUser if segment.role != ContextRole::User => {
            return Err(invalid("external_user source requires user role"));
        }
        ContextSource::ToolResult => {
            if segment.role != ContextRole::ToolResult {
                return Err(invalid("tool_result source requires tool_result role"));
            }
            let tool_name = segment
                .tool_name
                .as_deref()
                .ok_or_else(|| invalid("tool_result source requires tool_name"))?;
            validate_tool_name(tool_name).map_err(|_| invalid("invalid tool_name"))?;
        }
        ContextSource::Attachment => {
            let attachment_id = segment
                .attachment_id
                .as_deref()
                .ok_or_else(|| invalid("attachment source requires attachment_id"))?;
            if !attachment_ids.contains(attachment_id) {
                return Err(EnvelopeError::UnknownAttachmentId(
                    attachment_id.to_string(),
                ));
            }
        }
        _ => {}
    }
    if segment.source != ContextSource::ToolResult && segment.tool_name.is_some() {
        return Err(invalid("tool_name is only valid for tool_result source"));
    }
    if segment.source != ContextSource::Attachment && segment.attachment_id.is_some() {
        return Err(invalid("attachment_id is only valid for attachment source"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionResource {
    pub kind: String,
    pub locator: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionEnvelope {
    pub schema_version: String,
    pub tool_name: String,
    pub arguments: Value,
    pub resource: ActionResource,
    pub principal_id: String,
    pub session_id: String,
    pub run_id: String,
    pub tool_call_id: String,
    pub policy_version: String,
    pub policy_hash: String,
    pub context_hash: String,
    /// SHA-256 of the canonical envelope material, excluding this field.
    #[serde(default)]
    pub action_hash: String,
}

impl ActionEnvelope {
    /// Validate the material and replace `action_hash` with the canonical hash.
    pub fn seal(mut self) -> Result<Self, EnvelopeError> {
        self.validate_material()?;
        self.action_hash = self.compute_hash()?;
        Ok(self)
    }

    /// Verify structure, limits and exact canonical hash binding.
    pub fn verify(&self) -> Result<(), EnvelopeError> {
        self.validate_material()?;
        validate_sha256("action_hash", &self.action_hash)?;
        if self.compute_hash()? != self.action_hash {
            return Err(EnvelopeError::HashMismatch("action_hash"));
        }
        Ok(())
    }

    pub fn compute_hash(&self) -> Result<String, EnvelopeError> {
        hash_canonical(&action_hash_material(self))
    }

    /// Strict baseline classification. Unknown tools and dangerous argument
    /// classes are denied. Consequential but non-dangerous actions require an
    /// explicit authorization step; this function never grants that authority.
    pub fn evaluate_strict(&self) -> Result<ActionPolicyDecision, EnvelopeError> {
        self.verify()?;
        let tool = KnownTool::from_name(&self.tool_name);
        if tool == KnownTool::Unknown {
            return Ok(ActionPolicyDecision::denied(vec![
                ActionRiskClass::UnknownTool,
            ]));
        }

        let mut searchable = self.resource.locator.to_lowercase();
        collect_json_strings(&self.arguments, &mut searchable);
        let mut risks = Vec::new();

        if contains_path_traversal(&searchable) {
            risks.push(ActionRiskClass::PathTraversal);
        }
        if references_credentials(&searchable) {
            risks.push(ActionRiskClass::CredentialAccess);
        }
        if matches!(
            tool,
            KnownTool::Write | KnownTool::Edit | KnownTool::ApplyPatch
        ) && references_protected_write_resource(&searchable)
        {
            risks.push(ActionRiskClass::ProtectedResourceMutation);
        }
        if matches!(tool, KnownTool::Exec | KnownTool::Bash | KnownTool::Heartbeat) {
            if contains_destructive_shell(&searchable) {
                risks.push(ActionRiskClass::DestructiveShell);
            }
            if contains_privilege_escalation(&searchable) {
                risks.push(ActionRiskClass::PrivilegeEscalation);
            }
            if contains_remote_code_execution(&searchable) {
                risks.push(ActionRiskClass::RemoteCodeExecution);
            }
        }
        if tool == KnownTool::Browser && contains_browser_script_execution(&searchable) {
            risks.push(ActionRiskClass::BrowserScriptExecution);
        }
        if tool == KnownTool::Heartbeat && !validate_heartbeat_schema(&self.arguments) {
            risks.push(ActionRiskClass::ControlSchemaViolation);
        }
        deduplicate_risks(&mut risks);

        if risks.iter().any(ActionRiskClass::is_deny_class) {
            return Ok(ActionPolicyDecision::denied(risks));
        }

        match tool {
            KnownTool::Read => Ok(ActionPolicyDecision::allowed()),
            KnownTool::Write | KnownTool::Edit | KnownTool::ApplyPatch => {
                risks.push(ActionRiskClass::FilesystemMutation);
                Ok(ActionPolicyDecision::requires_authorization(risks))
            }
            KnownTool::Exec | KnownTool::Bash => {
                risks.push(ActionRiskClass::ShellExecution);
                Ok(ActionPolicyDecision::requires_authorization(risks))
            }
            KnownTool::Browser => {
                risks.push(ActionRiskClass::ExternalInteraction);
                Ok(ActionPolicyDecision::requires_authorization(risks))
            }
            KnownTool::Heartbeat => {
                // Schema was already validated above (a violation is a deny
                // class and would have returned already), so reaching here
                // means this is a legitimate, well-formed heartbeat. It
                // still requires authorization — recognized-and-valid is
                // never an unconditional bypass.
                risks.push(ActionRiskClass::ControlAction);
                Ok(ActionPolicyDecision::requires_authorization(risks))
            }
            KnownTool::Unknown => unreachable!("unknown tool returned above"),
        }
    }

    fn validate_material(&self) -> Result<(), EnvelopeError> {
        if self.schema_version != ACTION_ENVELOPE_SCHEMA_VERSION {
            return Err(EnvelopeError::InvalidField("schema_version"));
        }
        validate_tool_name(&self.tool_name)?;
        validate_identifier(
            "resource.kind",
            &self.resource.kind,
            MAX_RESOURCE_KIND_BYTES,
        )?;
        validate_identifier(
            "resource.locator",
            &self.resource.locator,
            MAX_RESOURCE_LOCATOR_BYTES,
        )?;
        validate_identifier("principal_id", &self.principal_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier("session_id", &self.session_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier("run_id", &self.run_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier("tool_call_id", &self.tool_call_id, MAX_IDENTIFIER_BYTES)?;
        validate_identifier(
            "policy_version",
            &self.policy_version,
            MAX_POLICY_VERSION_BYTES,
        )?;
        validate_sha256("policy_hash", &self.policy_hash)?;
        validate_sha256("context_hash", &self.context_hash)?;
        validate_json_limits(&self.arguments, 0)?;
        let canonical_arguments = canonical_json(&self.arguments)?;
        if canonical_arguments.len() > MAX_ACTION_ARGUMENT_BYTES {
            return Err(EnvelopeError::LimitExceeded("arguments"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KnownTool {
    Read,
    Write,
    Edit,
    ApplyPatch,
    Exec,
    Bash,
    Browser,
    /// Control-plane telemetry tool. See `evaluate_strict`'s heartbeat arm
    /// and `validate_heartbeat_schema` for the strict contract this must
    /// satisfy before it is even eligible for `RequireAuthorization` —
    /// unlike the other consequential tools above, this one is only
    /// recognized (never auto-denied as `UnknownTool`) after its exact
    /// argument shape has already been checked.
    Heartbeat,
    Unknown,
}

impl KnownTool {
    fn from_name(name: &str) -> Self {
        match name {
            "read" | "read_file" => Self::Read,
            "write" | "write_file" => Self::Write,
            "edit" => Self::Edit,
            "apply_patch" => Self::ApplyPatch,
            "exec" => Self::Exec,
            "bash" => Self::Bash,
            "browser" => Self::Browser,
            "heartbeat_respond" => Self::Heartbeat,
            _ => Self::Unknown,
        }
    }
}

/// Exact permitted `heartbeat_respond` argument shape, mirrored from
/// OpenClaw's own tool schema (src/agents/tools/heartbeat-response-tool.ts,
/// src/auto-reply/heartbeat-tool-response.ts — `HeartbeatResponseToolSchema`
/// / `normalizeHeartbeatToolResponse`), not inferred from the tool name.
/// GovSec re-validates this independently rather than trusting that
/// OpenClaw's own client-side schema was actually enforced.
const HEARTBEAT_ALLOWED_KEYS: [&str; 8] = [
    "outcome",
    "notify",
    "summary",
    "notificationText",
    "reason",
    "priority",
    "nextCheck",
    "scratch",
];
const HEARTBEAT_REQUIRED_KEYS: [&str; 3] = ["outcome", "notify", "summary"];
const HEARTBEAT_OUTCOMES: [&str; 5] = ["no_change", "progress", "done", "blocked", "needs_attention"];
const HEARTBEAT_PRIORITIES: [&str; 3] = ["low", "normal", "high"];
/// Bound for each free-text field (summary/notificationText/reason/nextCheck).
/// Well above any legitimate heartbeat note, far below the generic
/// MAX_ACTION_ARGUMENT_BYTES ceiling that already caps the whole payload.
const MAX_HEARTBEAT_TEXT_BYTES: usize = 4_096;
/// Mirrors OpenClaw's own `CRON_JOB_SCRATCH_MAX_BYTES`
/// (src/cron/scratch-contract.ts) so GovSec's ceiling is never looser than
/// the producer's own contract for this field.
const MAX_HEARTBEAT_SCRATCH_BYTES: usize = 262_144;

/// Strict structural validation of a `heartbeat_respond` argument payload.
/// Rejects: unknown keys (`additionalProperties: false`), missing required
/// keys, wrong value types, out-of-enum values, and oversized strings. A
/// nested object/array under any allowed key is rejected by the type check
/// alone (every allowed key is bool/string), so no separate "no nested
/// executable structure" pass is needed.
fn validate_heartbeat_schema(arguments: &Value) -> bool {
    let Value::Object(map) = arguments else {
        return false;
    };
    if map.keys().any(|key| !HEARTBEAT_ALLOWED_KEYS.contains(&key.as_str())) {
        return false;
    }
    if HEARTBEAT_REQUIRED_KEYS
        .iter()
        .any(|key| !map.contains_key(*key))
    {
        return false;
    }
    match map.get("outcome") {
        Some(Value::String(value)) if HEARTBEAT_OUTCOMES.contains(&value.as_str()) => {}
        _ => return false,
    }
    if !matches!(map.get("notify"), Some(Value::Bool(_))) {
        return false;
    }
    match map.get("summary") {
        Some(Value::String(value))
            if !value.trim().is_empty() && value.len() <= MAX_HEARTBEAT_TEXT_BYTES => {}
        _ => return false,
    }
    for key in ["notificationText", "reason", "nextCheck"] {
        if let Some(value) = map.get(key) {
            match value {
                Value::String(value) if value.len() <= MAX_HEARTBEAT_TEXT_BYTES => {}
                _ => return false,
            }
        }
    }
    if let Some(value) = map.get("priority") {
        match value {
            Value::String(value) if HEARTBEAT_PRIORITIES.contains(&value.as_str()) => {}
            _ => return false,
        }
    }
    if let Some(value) = map.get("scratch") {
        match value {
            Value::String(value) if value.len() <= MAX_HEARTBEAT_SCRATCH_BYTES => {}
            _ => return false,
        }
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionDisposition {
    Allow,
    RequireAuthorization,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionRiskClass {
    UnknownTool,
    PathTraversal,
    CredentialAccess,
    ProtectedResourceMutation,
    DestructiveShell,
    PrivilegeEscalation,
    RemoteCodeExecution,
    BrowserScriptExecution,
    FilesystemMutation,
    ShellExecution,
    ExternalInteraction,
    /// The tool call named `heartbeat_respond` (or any other control-plane
    /// tool GovSec recognizes) but its argument payload did not satisfy the
    /// exact schema GovSec enforces for that tool — extra/unknown keys,
    /// missing required keys, wrong types, out-of-enum values, or an
    /// oversized field. Deterministic deny; distinct from `UnknownTool` so
    /// diagnostics can tell "not a recognized tool" apart from "recognized
    /// control tool, invalid payload."
    ControlSchemaViolation,
    /// Recognized, schema-valid control-plane action (currently only
    /// `heartbeat_respond`). Not a deny class — mirrors `FilesystemMutation`
    /// / `ShellExecution` / `ExternalInteraction` as the reason authorization
    /// is required for an otherwise-allowed tool.
    ControlAction,
}

impl ActionRiskClass {
    fn is_deny_class(&self) -> bool {
        matches!(
            self,
            Self::UnknownTool
                | Self::PathTraversal
                | Self::CredentialAccess
                | Self::ProtectedResourceMutation
                | Self::DestructiveShell
                | Self::PrivilegeEscalation
                | Self::RemoteCodeExecution
                | Self::BrowserScriptExecution
                | Self::ControlSchemaViolation
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionPolicyDecision {
    pub disposition: ActionDisposition,
    pub risk_classes: Vec<ActionRiskClass>,
}

impl ActionPolicyDecision {
    fn allowed() -> Self {
        Self {
            disposition: ActionDisposition::Allow,
            risk_classes: Vec::new(),
        }
    }

    fn requires_authorization(risk_classes: Vec<ActionRiskClass>) -> Self {
        Self {
            disposition: ActionDisposition::RequireAuthorization,
            risk_classes,
        }
    }

    fn denied(risk_classes: Vec<ActionRiskClass>) -> Self {
        Self {
            disposition: ActionDisposition::Deny,
            risk_classes,
        }
    }
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), EnvelopeError> {
    if value.trim().is_empty() {
        return Err(EnvelopeError::MissingField(field));
    }
    if value.len() > max_bytes {
        return Err(EnvelopeError::LimitExceeded(field));
    }
    if value.chars().any(char::is_control) {
        return Err(EnvelopeError::InvalidField(field));
    }
    Ok(())
}

fn validate_tool_name(value: &str) -> Result<(), EnvelopeError> {
    validate_identifier("tool_name", value, MAX_TOOL_NAME_BYTES)?;
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
    {
        return Err(EnvelopeError::InvalidField("tool_name"));
    }
    Ok(())
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), EnvelopeError> {
    if value.len() != SHA256_HEX_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EnvelopeError::InvalidDigest(field));
    }
    Ok(())
}

fn model_context_hash_material(envelope: &ModelContextEnvelope) -> Value {
    let segments = envelope
        .segments
        .iter()
        .map(|segment| {
            let mut value = Map::new();
            value.insert("ordinal".to_string(), Value::from(segment.ordinal));
            value.insert(
                "role".to_string(),
                Value::String(context_role_name(&segment.role).to_string()),
            );
            value.insert(
                "source".to_string(),
                Value::String(context_source_name(&segment.source).to_string()),
            );
            value.insert(
                "content".to_string(),
                Value::String(segment.content.clone()),
            );
            insert_optional_string(&mut value, "tool_name", segment.tool_name.as_deref());
            insert_optional_string(
                &mut value,
                "attachment_id",
                segment.attachment_id.as_deref(),
            );
            Value::Object(value)
        })
        .collect();
    let attachments = envelope
        .attachments
        .iter()
        .map(|attachment| {
            object([
                (
                    "attachment_id",
                    Value::String(attachment.attachment_id.clone()),
                ),
                ("media_type", Value::String(attachment.media_type.clone())),
                ("byte_length", Value::from(attachment.byte_length)),
                ("sha256", Value::String(attachment.sha256.clone())),
            ])
        })
        .collect();

    object([
        (
            "schema_version",
            Value::String(envelope.schema_version.clone()),
        ),
        ("session_id", Value::String(envelope.session_id.clone())),
        ("run_id", Value::String(envelope.run_id.clone())),
        ("principal_id", Value::String(envelope.principal_id.clone())),
        ("provider_id", Value::String(envelope.provider_id.clone())),
        ("model_id", Value::String(envelope.model_id.clone())),
        (
            "policy_version",
            Value::String(envelope.policy_version.clone()),
        ),
        ("policy_hash", Value::String(envelope.policy_hash.clone())),
        (
            "provider_context_hash",
            Value::String(envelope.provider_context_hash.clone()),
        ),
        (
            "system_prompt_hash",
            Value::String(envelope.system_prompt_hash.clone()),
        ),
        (
            "tool_schema_hash",
            Value::String(envelope.tool_schema_hash.clone()),
        ),
        (
            "workspace_manifest_hash",
            Value::String(envelope.workspace_manifest_hash.clone()),
        ),
        ("segments", Value::Array(segments)),
        ("attachments", Value::Array(attachments)),
    ])
}

fn action_hash_material(envelope: &ActionEnvelope) -> Value {
    object([
        (
            "schema_version",
            Value::String(envelope.schema_version.clone()),
        ),
        ("tool_name", Value::String(envelope.tool_name.clone())),
        ("arguments", envelope.arguments.clone()),
        (
            "resource",
            object([
                ("kind", Value::String(envelope.resource.kind.clone())),
                ("locator", Value::String(envelope.resource.locator.clone())),
            ]),
        ),
        ("principal_id", Value::String(envelope.principal_id.clone())),
        ("session_id", Value::String(envelope.session_id.clone())),
        ("run_id", Value::String(envelope.run_id.clone())),
        ("tool_call_id", Value::String(envelope.tool_call_id.clone())),
        (
            "policy_version",
            Value::String(envelope.policy_version.clone()),
        ),
        ("policy_hash", Value::String(envelope.policy_hash.clone())),
        ("context_hash", Value::String(envelope.context_hash.clone())),
    ])
}

fn object<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

fn insert_optional_string(map: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        map.insert(key.to_string(), Value::String(value.to_string()));
    }
}

fn context_role_name(role: &ContextRole) -> &'static str {
    match role {
        ContextRole::System => "system",
        ContextRole::User => "user",
        ContextRole::Assistant => "assistant",
        ContextRole::ToolResult => "tool_result",
    }
}

fn context_source_name(source: &ContextSource) -> &'static str {
    match source {
        ContextSource::ExternalUser => "external_user",
        ContextSource::ConversationHistory => "conversation_history",
        ContextSource::ToolResult => "tool_result",
        ContextSource::Attachment => "attachment",
        ContextSource::HookInjection => "hook_injection",
        ContextSource::RuntimeInjection => "runtime_injection",
        ContextSource::CompactionSummary => "compaction_summary",
    }
}

fn hash_canonical(value: &Value) -> Result<String, EnvelopeError> {
    Ok(sha256_hex(canonical_json(value)?.as_bytes()))
}

/// Deterministic JSON encoding: object keys are lexicographically ordered,
/// arrays preserve order, and strings/numbers use serde_json's stable encoding.
fn canonical_json(value: &Value) -> Result<String, EnvelopeError> {
    let mut output = String::new();
    write_canonical_json(value, 0, &mut output)?;
    Ok(output)
}

fn write_canonical_json(
    value: &Value,
    depth: usize,
    output: &mut String,
) -> Result<(), EnvelopeError> {
    if depth > MAX_JSON_DEPTH {
        return Err(EnvelopeError::LimitExceeded("json depth"));
    }
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => output.push_str(
            &serde_json::to_string(value)
                .map_err(|error| EnvelopeError::Canonicalization(error.to_string()))?,
        ),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical_json(value, depth + 1, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key)
                        .map_err(|error| EnvelopeError::Canonicalization(error.to_string()))?,
                );
                output.push(':');
                write_canonical_json(value, depth + 1, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn validate_json_limits(value: &Value, depth: usize) -> Result<(), EnvelopeError> {
    if depth > MAX_JSON_DEPTH {
        return Err(EnvelopeError::LimitExceeded("json depth"));
    }
    match value {
        Value::Array(values) => {
            for value in values {
                validate_json_limits(value, depth + 1)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_json_limits(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_json_strings(value: &Value, output: &mut String) {
    match value {
        Value::String(value) => {
            output.push('\n');
            output.push_str(&value.to_lowercase());
        }
        Value::Array(values) => {
            for value in values {
                collect_json_strings(value, output);
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                output.push('\n');
                output.push_str(&key.to_lowercase());
                collect_json_strings(value, output);
            }
        }
        _ => {}
    }
}

fn contains_path_traversal(locator: &str) -> bool {
    locator
        .replace('\\', "/")
        .split('/')
        .any(|component| component == "..")
}

fn references_credentials(value: &str) -> bool {
    [
        "/etc/shadow",
        ".ssh/",
        "id_rsa",
        "id_ed25519",
        ".aws/credentials",
        ".config/gcloud/credentials",
        "keychain",
    ]
    .iter()
    .any(|pattern| value.contains(pattern))
}

fn references_protected_write_resource(value: &str) -> bool {
    let normalized = value.replace('\\', "/");
    [
        "/bin/", "/boot/", "/dev/", "/etc/", "/proc/", "/root/", "/sbin/", "/sys/", "/usr/",
    ]
    .iter()
    .any(|prefix| normalized.contains(prefix))
        || normalized.split_whitespace().any(|token| {
            matches!(
                token,
                "/" | "/bin"
                    | "/boot"
                    | "/dev"
                    | "/etc"
                    | "/proc"
                    | "/root"
                    | "/sbin"
                    | "/sys"
                    | "/usr"
            )
        })
}

fn contains_destructive_shell(value: &str) -> bool {
    [
        "rm -rf",
        "rm -fr",
        "mkfs",
        "wipefs",
        "dd if=",
        "shutdown",
        "reboot",
        ":(){:|:&};:",
    ]
    .iter()
    .any(|pattern| value.contains(pattern))
}

fn contains_privilege_escalation(value: &str) -> bool {
    ["sudo ", "su -c", "chmod 777", "chmod -r 777", "chown -r"]
        .iter()
        .any(|pattern| value.contains(pattern))
}

fn contains_remote_code_execution(value: &str) -> bool {
    let downloads = value.contains("curl ") || value.contains("wget ");
    let piped_shell = value.contains("| sh") || value.contains("| bash");
    (downloads && piped_shell) || value.contains("eval $(") || value.contains("eval \"$(")
}

fn contains_browser_script_execution(value: &str) -> bool {
    value.contains("javascript:")
        || value.contains("evaluate_script")
        || value.contains("execute_script")
}

fn deduplicate_risks(risks: &mut Vec<ActionRiskClass>) {
    let mut seen = HashSet::new();
    risks.retain(|risk| seen.insert(risk.clone()));
}
