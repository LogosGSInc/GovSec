//! LOGOS Governance Systems Inc. — Provider Execution Capability (v3)
//!
//! v3 closes the seven self-contained defects the authority-model review found
//! in v2. All are properties v2's tests did not encode, therefore did not prove:
//!
//!   1. principal + authority now CHECKED at consume (v2 signed them, never
//!      verified the presenter — a capability-theft hole).
//!   2. max_uses now SIGNED (v2 left an authority field outside the signature).
//!   3. expiry uses >= (v2's > left the token valid at exactly expires_at).
//!   4. record_decision is FALLIBLE -> Result (v2's String could not express
//!      persistence failure, so "recorded iff authorized" was unfalsifiable).
//!   5. decision IDEMPOTENCY per (gov_tx_id, authority): identical retry returns
//!      the existing decision; conflicting scope errors (v2 minted two).
//!   6. issuance is ONE-LOCK atomic across decision-mark + capability-insert
//!      (v2 used two guards; a panic between them stranded state).
//!   7. field VALIDATION rejects empties and non-positive TTL (v2 signed empties).
//!
//! record_decision is pub(crate): only in-crate authority (HAAP) may write the
//! ledger. External holders of a CapabilityStore cannot manufacture decisions.

use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::action_semantics::ActionPlane;
use crate::crypto::CryptoEngine;
use crate::envelope::is_sha256_hex;

pub const AUTHORITY_PROVIDER_EXECUTE: &str = "provider.execute";
/// Consequential tool-call authority, bound to a model-context capability by
/// `context_hash` and to an exact proposed tool call by `action_hash`.
pub const AUTHORITY_ACTION_EXECUTE: &str = "action.execute";

// ═══ ERRORS ════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    /// A required field was empty. Carries the field name.
    EmptyField(&'static str),
    /// A field that must be a SHA-256 hex digest was not one. Carries the field name.
    MalformedDigest(&'static str),
    /// TTL configured <= 0.
    InvalidTtl,
    /// Same gov_tx_id + authority already has a decision with DIFFERENT scope.
    TransactionScopeConflict,
    /// Authority string was neither provider.execute nor action.execute.
    WrongAuthority,
}

// ═══ DECISION LEDGER ═══════════════════════════════════════════════════════

/// Input to record_decision. A struct (not positional args) so scope is named,
/// validated as a unit, and extensible without churning call sites.
#[derive(Debug, Clone)]
pub struct DecisionRequest {
    pub gov_tx_id: String,
    pub session_id: String,
    pub principal_fingerprint: String,
    pub authority: String,
    pub backend: String,
    pub model: String,
    pub action_class: String,
    pub sentinel_verdict_id: String,
    pub policy_hash: String,
    /// Which authorization path produced this (e.g. "BelowRiskThreshold",
    /// "IntentTokenVerified"). Persisted so provenance is auditable; the
    /// wrapper fills it from the HaapVerdict.
    pub authorization_basis: String,
    pub agency: String,
    pub drs: u8,
    /// Run identifier this decision is scoped to. Required for both
    /// authorities — a provider or action capability must not be usable
    /// under a different run than the one GovSec actually evaluated.
    pub run_id: String,
    /// The approved `ModelContextEnvelope.context_hash` this decision traces
    /// back to. Required for both authorities — closes the gap where a
    /// caller could request a capability for content GovSec never inspected.
    pub context_hash: String,
    /// Signed policy identity active at decision time. Required for both
    /// authorities so a policy rollback/rotation invalidates outstanding
    /// capabilities rather than silently carrying the old authorization.
    pub policy_version: String,
    /// `AUTHORITY_ACTION_EXECUTE` only: the sealed `ActionEnvelope.action_hash`.
    /// Empty for `AUTHORITY_PROVIDER_EXECUTE`.
    pub action_hash: String,
    /// `AUTHORITY_ACTION_EXECUTE` only: exact tool name. Empty otherwise.
    pub tool_name: String,
    /// `AUTHORITY_ACTION_EXECUTE` only: normalized resource kind. Empty otherwise.
    pub resource_kind: String,
    /// `AUTHORITY_ACTION_EXECUTE` only: normalized resource locator. Empty otherwise.
    pub resource_locator: String,
    /// `AUTHORITY_ACTION_EXECUTE` only: the originating model tool-call id. Empty otherwise.
    pub tool_call_id: String,
    /// `AUTHORITY_ACTION_EXECUTE` only: server-derived action plane (see
    /// `action_semantics::derive_action_semantics`). Never caller-supplied —
    /// callers of `record_decision` (in-crate only; see the module doc)
    /// must derive this from the same sealed envelope that produced
    /// `action_hash`/`tool_name`, never accept it from a request body.
    /// `ActionPlane::Tool` for `AUTHORITY_PROVIDER_EXECUTE` (unused there).
    pub action_plane: ActionPlane,
    /// `AUTHORITY_ACTION_EXECUTE` only: server-derived normalized action
    /// name (e.g. `system.telemetry.heartbeat`). Empty for
    /// `AUTHORITY_PROVIDER_EXECUTE`.
    pub normalized_action: String,
    /// `AUTHORITY_ACTION_EXECUTE` only: server-derived completion
    /// criticality. `true` for `AUTHORITY_PROVIDER_EXECUTE` (unused there;
    /// `true` is the historical, always-required default every non-action
    /// authority has implicitly had).
    pub required_for_safe_completion: bool,
}

impl DecisionRequest {
    fn validate(&self) -> Result<(), CapabilityError> {
        macro_rules! nonempty {
            ($f:expr, $name:literal) => {
                if $f.trim().is_empty() { return Err(CapabilityError::EmptyField($name)); }
            };
        }
        nonempty!(self.gov_tx_id, "gov_tx_id");
        nonempty!(self.session_id, "session_id");
        nonempty!(self.principal_fingerprint, "principal_fingerprint");
        nonempty!(self.sentinel_verdict_id, "sentinel_verdict_id");
        nonempty!(self.policy_hash, "policy_hash");
        nonempty!(self.run_id, "run_id");
        nonempty!(self.context_hash, "context_hash");
        nonempty!(self.policy_version, "policy_version");
        if !is_sha256_hex(&self.context_hash) {
            return Err(CapabilityError::MalformedDigest("context_hash"));
        }
        if !is_sha256_hex(&self.policy_hash) {
            return Err(CapabilityError::MalformedDigest("policy_hash"));
        }

        match self.authority.as_str() {
            AUTHORITY_PROVIDER_EXECUTE => {
                nonempty!(self.backend, "backend");
                nonempty!(self.model, "model");
                nonempty!(self.action_class, "action_class");
            }
            AUTHORITY_ACTION_EXECUTE => {
                nonempty!(self.action_hash, "action_hash");
                nonempty!(self.tool_name, "tool_name");
                nonempty!(self.resource_kind, "resource_kind");
                nonempty!(self.resource_locator, "resource_locator");
                nonempty!(self.tool_call_id, "tool_call_id");
                nonempty!(self.normalized_action, "normalized_action");
                if !is_sha256_hex(&self.action_hash) {
                    return Err(CapabilityError::MalformedDigest("action_hash"));
                }
            }
            _ => return Err(CapabilityError::WrongAuthority),
        }
        Ok(())
    }
    /// The scope that must match for an idempotent retry to be accepted.
    fn same_scope(&self, d: &Decision) -> bool {
        d.session_id == self.session_id
            && d.principal_fingerprint == self.principal_fingerprint
            && d.backend == self.backend
            && d.model == self.model
            && d.action_class == self.action_class
            && d.run_id == self.run_id
            && d.context_hash == self.context_hash
            && d.policy_version == self.policy_version
            && d.action_hash == self.action_hash
            && d.tool_name == self.tool_name
            && d.resource_kind == self.resource_kind
            && d.resource_locator == self.resource_locator
            && d.tool_call_id == self.tool_call_id
            && d.action_plane == self.action_plane
            && d.normalized_action == self.normalized_action
            && d.required_for_safe_completion == self.required_for_safe_completion
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub decision_id: String,
    pub gov_tx_id: String,
    pub session_id: String,
    pub principal_fingerprint: String,
    pub authority: String,
    pub backend: String,
    pub model: String,
    pub action_class: String,
    pub sentinel_verdict_id: String,
    pub policy_hash: String,
    pub authorization_basis: String,
    pub agency: String,
    pub drs: u8,
    pub authorized_at: DateTime<Utc>,
    pub issued: bool,
    pub run_id: String,
    pub context_hash: String,
    pub policy_version: String,
    pub action_hash: String,
    pub tool_name: String,
    pub resource_kind: String,
    pub resource_locator: String,
    pub tool_call_id: String,
    pub action_plane: ActionPlane,
    pub normalized_action: String,
    pub required_for_safe_completion: bool,
}

// Boxing Issued(CapabilityToken) would shave the enum's stack size but
// changes IssueOutcome's shape at every construction/match site — this is
// the decision-bound signed capability-token type this sprint's work
// centers on, not a local edit to apply on a size hint alone. Deferred for
// a deliberate call, not silently fixed or silently ignored.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueOutcome {
    Issued(CapabilityToken),
    DecisionNotFound,
    AlreadyIssued,
}

// ═══ CAPABILITY TOKEN ══════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    pub token_id: String,
    pub haap_decision_id: String,
    pub gov_tx_id: String,
    pub session_id: String,
    pub principal_fingerprint: String,
    pub authority: String,
    pub backend: String,
    pub model: String,
    pub action_class: String,
    pub sentinel_verdict_id: String,
    pub policy_hash: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_uses: u32,
    pub use_count: u32,
    pub signature: String,
    pub run_id: String,
    pub context_hash: String,
    pub policy_version: String,
    pub action_hash: String,
    pub tool_name: String,
    pub resource_kind: String,
    pub resource_locator: String,
    pub tool_call_id: String,
    /// Server-derived, never caller-supplied (see `DecisionRequest::action_plane`).
    /// Included in `canonical()` so post-issuance tampering with any of
    /// these three fields invalidates the signature exactly like tampering
    /// with `max_uses` already does.
    pub action_plane: ActionPlane,
    pub normalized_action: String,
    pub required_for_safe_completion: bool,
}

impl CapabilityToken {
    /// Canonical signed form. Every authority-bearing field is present —
    /// INCLUDING max_uses (changing it changes authority). use_count is the
    /// only mutable field and is deliberately excluded.
    pub fn canonical(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.token_id,
            self.haap_decision_id,
            self.gov_tx_id,
            self.session_id,
            self.principal_fingerprint,
            self.authority,
            self.backend,
            self.model,
            self.action_class,
            self.sentinel_verdict_id,
            self.policy_hash,
            self.issued_at.timestamp(),
            self.expires_at.timestamp(),
            self.max_uses,
            self.run_id,
            self.context_hash,
            self.policy_version,
            self.action_hash,
            self.tool_name,
            self.resource_kind,
            self.resource_locator,
            self.tool_call_id,
            self.action_plane.as_str(),
            self.normalized_action,
            self.required_for_safe_completion,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeOutcome {
    Authorized,
    NotFound,
    SignatureInvalid,
    AlreadyConsumed,
    Expired,
    TransactionMismatch,
    SessionMismatch,
    PrincipalMismatch,
    AuthorityMismatch,
    BackendMismatch,
    ModelMismatch,
    RunMismatch,
    ContextHashMismatch,
    PolicyVersionMismatch,
    PolicyHashMismatch,
    ActionHashMismatch,
    ToolMismatch,
    ResourceMismatch,
    ToolCallIdMismatch,
    /// The capability's server-derived `action_plane` does not match the
    /// plane re-derived from the presented `tool_name` at consumption time.
    /// By construction this cannot fire when `ToolMismatch` would not also
    /// fire (plane is a pure function of `tool_name`) — it exists as an
    /// explicit, independently-checked guarantee that a CONTROL capability
    /// can never authorize a TOOL/USER/GOVERNANCE action or vice versa,
    /// rather than relying solely on the tool-name check to imply it.
    PlaneMismatch,
}

impl ConsumeOutcome {
    pub fn authorized(&self) -> bool { matches!(self, ConsumeOutcome::Authorized) }
    pub fn as_audit_str(&self) -> &'static str {
        match self {
            ConsumeOutcome::Authorized          => "CAPABILITY_CONSUMED",
            ConsumeOutcome::NotFound            => "CAPABILITY_NOT_FOUND",
            ConsumeOutcome::SignatureInvalid    => "CAPABILITY_SIGNATURE_INVALID",
            ConsumeOutcome::AlreadyConsumed     => "CAPABILITY_REPLAY_REJECTED",
            ConsumeOutcome::Expired             => "CAPABILITY_EXPIRED",
            ConsumeOutcome::TransactionMismatch => "CAPABILITY_TX_MISMATCH",
            ConsumeOutcome::SessionMismatch     => "CAPABILITY_SESSION_MISMATCH",
            ConsumeOutcome::PrincipalMismatch   => "CAPABILITY_PRINCIPAL_MISMATCH",
            ConsumeOutcome::AuthorityMismatch   => "CAPABILITY_AUTHORITY_MISMATCH",
            ConsumeOutcome::BackendMismatch     => "CAPABILITY_BACKEND_MISMATCH",
            ConsumeOutcome::ModelMismatch       => "CAPABILITY_MODEL_MISMATCH",
            ConsumeOutcome::RunMismatch            => "CAPABILITY_RUN_MISMATCH",
            ConsumeOutcome::ContextHashMismatch     => "CAPABILITY_CONTEXT_HASH_MISMATCH",
            ConsumeOutcome::PolicyVersionMismatch   => "CAPABILITY_POLICY_VERSION_MISMATCH",
            ConsumeOutcome::PolicyHashMismatch      => "CAPABILITY_POLICY_HASH_MISMATCH",
            ConsumeOutcome::ActionHashMismatch      => "CAPABILITY_ACTION_HASH_MISMATCH",
            ConsumeOutcome::ToolMismatch            => "CAPABILITY_TOOL_MISMATCH",
            ConsumeOutcome::ResourceMismatch        => "CAPABILITY_RESOURCE_MISMATCH",
            ConsumeOutcome::ToolCallIdMismatch      => "CAPABILITY_TOOL_CALL_ID_MISMATCH",
            ConsumeOutcome::PlaneMismatch           => "CAPABILITY_PLANE_MISMATCH",
        }
    }
}

/// What the adapter presents at consume. Includes principal + authority so
/// consume verifies WHO is presenting, not just what scope is claimed.
/// `action_hash`/`tool_name`/`resource_kind`/`resource_locator`/`tool_call_id`
/// are only compared when the token's authority is `AUTHORITY_ACTION_EXECUTE`;
/// provider-execute callers pass empty strings for them.
pub struct PresentedBinding<'a> {
    pub token_id: &'a str,
    pub gov_tx_id: &'a str,
    pub session_id: &'a str,
    pub principal_fingerprint: &'a str,
    pub authority: &'a str,
    pub backend: &'a str,
    pub model: &'a str,
    pub run_id: &'a str,
    pub context_hash: &'a str,
    pub policy_version: &'a str,
    pub policy_hash: &'a str,
    pub action_hash: &'a str,
    pub tool_name: &'a str,
    pub resource_kind: &'a str,
    pub resource_locator: &'a str,
    pub tool_call_id: &'a str,
    /// Only compared when the token's authority is `AUTHORITY_ACTION_EXECUTE`.
    /// Callers must derive this the same way issuance did — from
    /// `action_semantics::derive_action_semantics_for_tool(tool_name)` on the
    /// presented `tool_name` — never accept it as a standalone client value.
    pub plane: &'a str,
}

// ═══ STORE — one lock over all three maps ══════════════════════════════════

struct CapabilityState {
    decisions: HashMap<String, Decision>,
    capabilities: HashMap<String, CapabilityToken>,
    /// (gov_tx_id|authority) -> decision_id, for idempotency + conflict.
    decision_by_tx: HashMap<String, String>,
}

#[derive(Clone)]
pub struct CapabilityStore {
    state: Arc<RwLock<CapabilityState>>,
    crypto: Arc<CryptoEngine>,
    default_ttl_secs: i64,
}

fn tx_key(gov_tx_id: &str, authority: &str) -> String {
    format!("{}|{}", gov_tx_id, authority)
}

impl CapabilityStore {
    pub fn new(crypto: Arc<CryptoEngine>) -> Self {
        Self {
            state: Arc::new(RwLock::new(CapabilityState {
                decisions: HashMap::new(),
                capabilities: HashMap::new(),
                decision_by_tx: HashMap::new(),
            })),
            crypto,
            default_ttl_secs: 30,
        }
    }

    /// TTL must be positive. Fallible so a misconfiguration fails loud.
    pub fn with_ttl_secs(mut self, ttl: i64) -> Result<Self, CapabilityError> {
        if ttl <= 0 { return Err(CapabilityError::InvalidTtl); }
        self.default_ttl_secs = ttl;
        Ok(self)
    }

    /// Persist an authorized decision. pub(crate): only in-crate authority may
    /// write the ledger. Fallible, validated, idempotent per (gov_tx_id,authority).
    ///
    ///   - identical retry (same scope)      -> Ok(existing decision_id)
    ///   - same tx+authority, different scope -> Err(TransactionScopeConflict)
    ///   - empty field / wrong authority      -> Err(...)
    pub(crate) fn record_decision(&self, req: DecisionRequest)
        -> Result<String, CapabilityError>
    {
        req.validate()?;
        let key = tx_key(&req.gov_tx_id, &req.authority);

        let mut st = self.state.write();

        if let Some(existing_id) = st.decision_by_tx.get(&key).cloned() {
            let existing = st.decisions.get(&existing_id)
                .expect("index/decision invariant");
            if req.same_scope(existing) {
                return Ok(existing_id); // idempotent retry
            }
            return Err(CapabilityError::TransactionScopeConflict);
        }

        let decision_id = format!("DEC-{}", uuid::Uuid::new_v4().simple());
        let decision = Decision {
            decision_id: decision_id.clone(),
            gov_tx_id: req.gov_tx_id,
            session_id: req.session_id,
            principal_fingerprint: req.principal_fingerprint,
            authority: req.authority,
            backend: req.backend,
            model: req.model,
            action_class: req.action_class,
            sentinel_verdict_id: req.sentinel_verdict_id,
            policy_hash: req.policy_hash,
            authorization_basis: req.authorization_basis,
            agency: req.agency,
            drs: req.drs,
            authorized_at: Utc::now(),
            issued: false,
            run_id: req.run_id,
            context_hash: req.context_hash,
            policy_version: req.policy_version,
            action_hash: req.action_hash,
            tool_name: req.tool_name,
            resource_kind: req.resource_kind,
            resource_locator: req.resource_locator,
            tool_call_id: req.tool_call_id,
            action_plane: req.action_plane,
            normalized_action: req.normalized_action,
            required_for_safe_completion: req.required_for_safe_completion,
        };
        st.decisions.insert(decision_id.clone(), decision);
        st.decision_by_tx.insert(key, decision_id.clone());
        Ok(decision_id)
    }

    /// Issue a capability FROM a decision. Scope read from the decision; caller
    /// scope never consulted. Decision-mark + capability-insert under ONE guard.
    pub fn issue_after_authorization(&self, decision_id: &str) -> IssueOutcome {
        let mut st = self.state.write();

        let decision = match st.decisions.get(decision_id) {
            Some(d) => d.clone(),
            None => return IssueOutcome::DecisionNotFound,
        };
        if decision.issued {
            return IssueOutcome::AlreadyIssued;
        }

        let token_id = format!("CAP-{}", uuid::Uuid::new_v4().simple());
        let issued_at = Utc::now();
        let expires_at = issued_at + Duration::seconds(self.default_ttl_secs);

        let mut token = CapabilityToken {
            token_id: token_id.clone(),
            haap_decision_id: decision.decision_id.clone(),
            gov_tx_id: decision.gov_tx_id.clone(),
            session_id: decision.session_id.clone(),
            principal_fingerprint: decision.principal_fingerprint.clone(),
            authority: decision.authority.clone(),
            backend: decision.backend.clone(),
            model: decision.model.clone(),
            action_class: decision.action_class.clone(),
            sentinel_verdict_id: decision.sentinel_verdict_id.clone(),
            policy_hash: decision.policy_hash.clone(),
            issued_at,
            expires_at,
            max_uses: 1,
            use_count: 0,
            signature: String::new(),
            run_id: decision.run_id.clone(),
            context_hash: decision.context_hash.clone(),
            policy_version: decision.policy_version.clone(),
            action_hash: decision.action_hash.clone(),
            tool_name: decision.tool_name.clone(),
            resource_kind: decision.resource_kind.clone(),
            resource_locator: decision.resource_locator.clone(),
            tool_call_id: decision.tool_call_id.clone(),
            action_plane: decision.action_plane,
            normalized_action: decision.normalized_action.clone(),
            required_for_safe_completion: decision.required_for_safe_completion,
        };
        token.signature = self.crypto.sign(token.canonical().as_bytes());

        // Both writes under the same guard: mark issued AND insert capability.
        st.decisions.get_mut(decision_id).unwrap().issued = true;
        st.capabilities.insert(token_id, token.clone());
        IssueOutcome::Issued(token)
    }

    /// Atomic verify-and-burn. One write guard over the whole check-then-mark.
    pub fn consume(&self, p: &PresentedBinding) -> ConsumeOutcome {
        let mut st = self.state.write();
        let token = match st.capabilities.get_mut(p.token_id) {
            Some(t) => t,
            None => return ConsumeOutcome::NotFound,
        };

        // Authenticity first — over the STORED canonical form (covers max_uses).
        let canonical = token.canonical();
        if !self.crypto.verify(canonical.as_bytes(), &token.signature).unwrap_or(false) {
            return ConsumeOutcome::SignatureInvalid;
        }

        // Exhaustion (replay) before mutation.
        if token.use_count >= token.max_uses { return ConsumeOutcome::AlreadyConsumed; }
        // Expiry: valid strictly before expires_at.
        if Utc::now() >= token.expires_at { return ConsumeOutcome::Expired; }

        // Authority + WHO, then scope.
        let known_authority = matches!(
            token.authority.as_str(),
            AUTHORITY_PROVIDER_EXECUTE | AUTHORITY_ACTION_EXECUTE
        );
        if !known_authority || token.authority != p.authority {
            return ConsumeOutcome::AuthorityMismatch;
        }
        if token.principal_fingerprint != p.principal_fingerprint {
            return ConsumeOutcome::PrincipalMismatch;
        }
        if token.gov_tx_id  != p.gov_tx_id  { return ConsumeOutcome::TransactionMismatch; }
        if token.session_id != p.session_id { return ConsumeOutcome::SessionMismatch; }
        if token.run_id     != p.run_id     { return ConsumeOutcome::RunMismatch; }
        if token.context_hash != p.context_hash { return ConsumeOutcome::ContextHashMismatch; }
        if token.policy_version != p.policy_version { return ConsumeOutcome::PolicyVersionMismatch; }
        if token.policy_hash != p.policy_hash { return ConsumeOutcome::PolicyHashMismatch; }
        if token.backend    != p.backend    { return ConsumeOutcome::BackendMismatch; }
        if token.model      != p.model      { return ConsumeOutcome::ModelMismatch; }
        if token.authority == AUTHORITY_ACTION_EXECUTE {
            if token.action_hash != p.action_hash { return ConsumeOutcome::ActionHashMismatch; }
            if token.tool_name   != p.tool_name   { return ConsumeOutcome::ToolMismatch; }
            if token.resource_kind != p.resource_kind || token.resource_locator != p.resource_locator {
                return ConsumeOutcome::ResourceMismatch;
            }
            if token.tool_call_id != p.tool_call_id { return ConsumeOutcome::ToolCallIdMismatch; }
            if token.action_plane.as_str() != p.plane { return ConsumeOutcome::PlaneMismatch; }
        }

        token.use_count += 1;
        ConsumeOutcome::Authorized
    }

    pub fn prune_expired(&self) -> usize {
        let mut st = self.state.write();
        let before = st.capabilities.len();
        st.capabilities.retain(|_, t| Utc::now() < t.expires_at);
        before - st.capabilities.len()
    }

    // ── test-only introspection/tampering, to prove signed-field integrity ──
    #[cfg(test)]
    pub(crate) fn mutate_stored_token(&self, token_id: &str,
                                      f: impl FnOnce(&mut CapabilityToken)) {
        let mut st = self.state.write();
        if let Some(t) = st.capabilities.get_mut(token_id) { f(t); }
    }
}

// ═══ TESTS ═════════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    fn store() -> CapabilityStore {
        CapabilityStore::new(Arc::new(CryptoEngine::new("logos_capability_test_seed")))
    }

    fn req(tx: &str) -> DecisionRequest {
        DecisionRequest {
            gov_tx_id: tx.into(),
            session_id: "sess1".into(),
            principal_fingerprint: "fpADMIN00000000".into(),
            authority: AUTHORITY_PROVIDER_EXECUTE.into(),
            backend: "groq".into(),
            model: "llama-3.3-70b-versatile".into(),
            action_class: "chat".into(),
            sentinel_verdict_id: "sv1".into(),
            policy_hash: "d".repeat(64),
            authorization_basis: "BelowRiskThreshold".into(),
            agency: "L2".into(),
            drs: 20,
            run_id: "run1".into(),
            context_hash: "c".repeat(64),
            policy_version: "policy-v1".into(),
            action_hash: String::new(),
            tool_name: String::new(),
            resource_kind: String::new(),
            resource_locator: String::new(),
            tool_call_id: String::new(),
            action_plane: ActionPlane::Tool,
            normalized_action: String::new(),
            required_for_safe_completion: true,
        }
    }

    fn action_req(tx: &str) -> DecisionRequest {
        DecisionRequest {
            gov_tx_id: tx.into(),
            session_id: "sess1".into(),
            principal_fingerprint: "fpADMIN00000000".into(),
            authority: AUTHORITY_ACTION_EXECUTE.into(),
            backend: String::new(),
            model: String::new(),
            action_class: "tool:bash".into(),
            sentinel_verdict_id: "sv1".into(),
            policy_hash: "d".repeat(64),
            authorization_basis: "RequireAuthorization".into(),
            agency: "L2".into(),
            drs: 20,
            run_id: "run1".into(),
            context_hash: "c".repeat(64),
            policy_version: "policy-v1".into(),
            action_hash: "a".repeat(64),
            tool_name: "bash".into(),
            resource_kind: "shell".into(),
            resource_locator: "echo hi".into(),
            tool_call_id: "call1".into(),
            action_plane: ActionPlane::Tool,
            normalized_action: "tool.bash".into(),
            required_for_safe_completion: true,
        }
    }

    fn heartbeat_req(tx: &str) -> DecisionRequest {
        DecisionRequest {
            gov_tx_id: tx.into(),
            session_id: "sess1".into(),
            principal_fingerprint: "fpADMIN00000000".into(),
            authority: AUTHORITY_ACTION_EXECUTE.into(),
            backend: String::new(),
            model: String::new(),
            action_class: "tool:heartbeat_respond".into(),
            sentinel_verdict_id: "sv1".into(),
            policy_hash: "d".repeat(64),
            authorization_basis: "RequireAuthorization".into(),
            agency: "L2".into(),
            drs: 20,
            run_id: "run1".into(),
            context_hash: "c".repeat(64),
            policy_version: "policy-v1".into(),
            action_hash: "b".repeat(64),
            tool_name: "heartbeat_respond".into(),
            resource_kind: "unknown".into(),
            resource_locator: "heartbeat_respond".into(),
            tool_call_id: "call-hb-1".into(),
            action_plane: ActionPlane::Control,
            normalized_action: "system.telemetry.heartbeat".into(),
            required_for_safe_completion: false,
        }
    }

    fn cap(s: &CapabilityStore) -> CapabilityToken {
        let did = s.record_decision(req("tx1")).expect("record");
        match s.issue_after_authorization(&did) {
            IssueOutcome::Issued(c) => c,
            o => panic!("expected Issued, got {:?}", o),
        }
    }

    fn action_cap(s: &CapabilityStore) -> CapabilityToken {
        let did = s.record_decision(action_req("tx-action-1")).expect("record");
        match s.issue_after_authorization(&did) {
            IssueOutcome::Issued(c) => c,
            o => panic!("expected Issued, got {:?}", o),
        }
    }

    fn heartbeat_cap(s: &CapabilityStore) -> CapabilityToken {
        let did = s.record_decision(heartbeat_req("tx-heartbeat-1")).expect("record");
        match s.issue_after_authorization(&did) {
            IssueOutcome::Issued(c) => c,
            o => panic!("expected Issued, got {:?}", o),
        }
    }

    fn good_binding<'a>(t: &'a CapabilityToken) -> PresentedBinding<'a> {
        PresentedBinding {
            token_id: &t.token_id, gov_tx_id: &t.gov_tx_id,
            session_id: &t.session_id, principal_fingerprint: &t.principal_fingerprint,
            authority: &t.authority, backend: &t.backend, model: &t.model,
            run_id: &t.run_id, context_hash: &t.context_hash, policy_version: &t.policy_version,
            policy_hash: &t.policy_hash,
            action_hash: &t.action_hash, tool_name: &t.tool_name,
            resource_kind: &t.resource_kind, resource_locator: &t.resource_locator,
            tool_call_id: &t.tool_call_id,
            plane: t.action_plane.as_str(),
        }
    }

    // ── existing properties, retained ──
    #[test] fn happy_path_consumes_once() {
        let s = store(); let c = cap(&s);
        assert_eq!(s.consume(&good_binding(&c)), ConsumeOutcome::Authorized);
    }
    #[test] fn replay_rejected() {
        let s = store(); let c = cap(&s);
        assert_eq!(s.consume(&good_binding(&c)), ConsumeOutcome::Authorized);
        assert_eq!(s.consume(&good_binding(&c)), ConsumeOutcome::AlreadyConsumed);
    }
    #[test] fn backend_mismatch() {
        let s = store(); let c = cap(&s);
        let mut b = good_binding(&c); b.backend = "anthropic";
        assert_eq!(s.consume(&b), ConsumeOutcome::BackendMismatch);
    }
    #[test] fn model_mismatch() {
        let s = store(); let c = cap(&s);
        let mut b = good_binding(&c); b.model = "gpt-4o";
        assert_eq!(s.consume(&b), ConsumeOutcome::ModelMismatch);
    }
    #[test] fn transaction_mismatch() {
        let s = store(); let c = cap(&s);
        let mut b = good_binding(&c); b.gov_tx_id = "tx2";
        assert_eq!(s.consume(&b), ConsumeOutcome::TransactionMismatch);
    }
    #[test] fn issuance_requires_real_decision() {
        assert_eq!(store().issue_after_authorization("DEC-nope"),
                   IssueOutcome::DecisionNotFound);
    }
    #[test] fn scope_from_decision_not_caller() {
        let s = store(); let c = cap(&s);
        assert_eq!(c.backend, "groq");
        assert_eq!(c.model, "llama-3.3-70b-versatile");
        assert!(!c.haap_decision_id.is_empty());
    }

    // ── NEW: session mismatch ──
    #[test] fn session_mismatch() {
        let s = store(); let c = cap(&s);
        let mut b = good_binding(&c); b.session_id = "sessX";
        assert_eq!(s.consume(&b), ConsumeOutcome::SessionMismatch);
    }

    // ── A1: a durable session_id (reused across many turns, not one-per-turn)
    // must not degrade capability isolation — each turn's token is still
    // scoped by its own gov_tx_id and remains independently single-use.
    #[test] fn same_session_multiple_turns_each_capability_independent() {
        let s = store();
        let sid = "sess1"; // matches req()'s hardcoded session_id — one durable conversation
        let c1 = { let did = s.record_decision(req("tx-turn-1")).expect("record"); match s.issue_after_authorization(&did) { IssueOutcome::Issued(c) => c, o => panic!("expected Issued, got {:?}", o) } };
        let c2 = { let did = s.record_decision(req("tx-turn-2")).expect("record"); match s.issue_after_authorization(&did) { IssueOutcome::Issued(c) => c, o => panic!("expected Issued, got {:?}", o) } };
        let c3 = { let did = s.record_decision(req("tx-turn-3")).expect("record"); match s.issue_after_authorization(&did) { IssueOutcome::Issued(c) => c, o => panic!("expected Issued, got {:?}", o) } };

        // All three belong to the SAME session_id — proving durable reuse
        // across turns doesn't require distinct sessions per token.
        assert_eq!(c1.session_id, sid);
        assert_eq!(c2.session_id, sid);
        assert_eq!(c3.session_id, sid);

        // Each is independently consumable exactly once, regardless of order
        // or how many other turns share the same session_id.
        assert_eq!(s.consume(&good_binding(&c2)), ConsumeOutcome::Authorized);
        assert_eq!(s.consume(&good_binding(&c1)), ConsumeOutcome::Authorized);
        assert_eq!(s.consume(&good_binding(&c3)), ConsumeOutcome::Authorized);

        // Replaying an earlier turn's token after later turns have already
        // been consumed must still be rejected as AlreadyConsumed, not
        // silently accepted because the session_id is "still current."
        assert_eq!(s.consume(&good_binding(&c1)), ConsumeOutcome::AlreadyConsumed);
    }

    // ── NEW: principal mismatch (the capability-theft fix) ──
    #[test] fn principal_mismatch_rejected() {
        let s = store(); let c = cap(&s);
        let mut b = good_binding(&c); b.principal_fingerprint = "fpATTACKER00000";
        assert_eq!(s.consume(&b), ConsumeOutcome::PrincipalMismatch);
    }

    // ── NEW: authority mismatch ──
    #[test] fn authority_mismatch_rejected() {
        let s = store(); let c = cap(&s);
        let mut b = good_binding(&c); b.authority = "provider.admin";
        assert_eq!(s.consume(&b), ConsumeOutcome::AuthorityMismatch);
    }

    // ── NEW: context/run/policy binding (model-context wiring) ──
    #[test] fn run_mismatch_rejected() {
        let s = store(); let c = cap(&s);
        let mut b = good_binding(&c); b.run_id = "run-other";
        assert_eq!(s.consume(&b), ConsumeOutcome::RunMismatch);
    }
    #[test] fn context_hash_mismatch_rejected() {
        let s = store(); let c = cap(&s);
        let other = "f".repeat(64);
        let mut b = good_binding(&c); b.context_hash = &other;
        assert_eq!(s.consume(&b), ConsumeOutcome::ContextHashMismatch);
    }
    #[test] fn policy_version_mismatch_rejected() {
        let s = store(); let c = cap(&s);
        let mut b = good_binding(&c); b.policy_version = "policy-v2";
        assert_eq!(s.consume(&b), ConsumeOutcome::PolicyVersionMismatch);
    }
    #[test] fn policy_hash_mismatch_rejected() {
        let s = store(); let c = cap(&s);
        let other = "e".repeat(64);
        let mut b = good_binding(&c); b.policy_hash = &other;
        assert_eq!(s.consume(&b), ConsumeOutcome::PolicyHashMismatch);
    }
    #[test] fn missing_context_hash_rejected() {
        let s = store();
        let mut r = req("tx1"); r.context_hash = "".into();
        assert_eq!(s.record_decision(r).err(), Some(CapabilityError::EmptyField("context_hash")));
    }
    #[test] fn malformed_context_hash_rejected() {
        let s = store();
        let mut r = req("tx1"); r.context_hash = "not-a-hash".into();
        assert_eq!(s.record_decision(r).err(), Some(CapabilityError::MalformedDigest("context_hash")));
    }

    // ── NEW: action-authority binding (tool-call wiring) ──
    #[test] fn action_capability_binds_action_hash_tool_and_resource() {
        let s = store(); let c = action_cap(&s);
        assert_eq!(c.authority, AUTHORITY_ACTION_EXECUTE);
        assert_eq!(s.consume(&good_binding(&c)), ConsumeOutcome::Authorized);
    }
    #[test] fn action_hash_mismatch_rejected() {
        let s = store(); let c = action_cap(&s);
        let other = "b".repeat(64);
        let mut b = good_binding(&c); b.action_hash = &other;
        assert_eq!(s.consume(&b), ConsumeOutcome::ActionHashMismatch);
    }
    #[test] fn tool_mismatch_rejected() {
        let s = store(); let c = action_cap(&s);
        let mut b = good_binding(&c); b.tool_name = "write";
        assert_eq!(s.consume(&b), ConsumeOutcome::ToolMismatch);
    }
    #[test] fn resource_mismatch_rejected() {
        let s = store(); let c = action_cap(&s);
        let mut b = good_binding(&c); b.resource_locator = "rm -rf /";
        assert_eq!(s.consume(&b), ConsumeOutcome::ResourceMismatch);
    }
    #[test] fn tool_call_id_mismatch_rejected() {
        let s = store(); let c = action_cap(&s);
        let mut b = good_binding(&c); b.tool_call_id = "call-other";
        assert_eq!(s.consume(&b), ConsumeOutcome::ToolCallIdMismatch);
    }
    #[test] fn action_replay_rejected() {
        let s = store(); let c = action_cap(&s);
        assert_eq!(s.consume(&good_binding(&c)), ConsumeOutcome::Authorized);
        assert_eq!(s.consume(&good_binding(&c)), ConsumeOutcome::AlreadyConsumed);
    }
    #[test] fn action_requires_action_fields() {
        let s = store();
        let mut r = action_req("tx-a1"); r.tool_name = "".into();
        assert_eq!(s.record_decision(r).err(), Some(CapabilityError::EmptyField("tool_name")));
        let mut r2 = action_req("tx-a1"); r2.action_hash = "not-a-hash".into();
        assert_eq!(s.record_decision(r2).err(), Some(CapabilityError::MalformedDigest("action_hash")));
    }
    // ── NEW: action-plane / completion-criticality binding ──
    #[test] fn heartbeat_capability_binds_control_plane_and_noncritical() {
        let s = store(); let c = heartbeat_cap(&s);
        assert_eq!(c.authority, AUTHORITY_ACTION_EXECUTE);
        assert_eq!(c.action_plane, ActionPlane::Control);
        assert_eq!(c.normalized_action, "system.telemetry.heartbeat");
        assert!(!c.required_for_safe_completion);
        assert_eq!(s.consume(&good_binding(&c)), ConsumeOutcome::Authorized);
    }
    #[test] fn ordinary_action_capability_binds_tool_plane_and_required() {
        let s = store(); let c = action_cap(&s);
        assert_eq!(c.action_plane, ActionPlane::Tool);
        assert!(c.required_for_safe_completion);
    }
    #[test] fn plane_mismatch_rejected() {
        let s = store(); let c = heartbeat_cap(&s);
        let mut b = good_binding(&c); b.plane = "tool";
        assert_eq!(s.consume(&b), ConsumeOutcome::PlaneMismatch);
    }
    #[test] fn control_capability_cannot_be_presented_as_tool_plane_for_a_different_tool() {
        // A CONTROL (heartbeat) capability presented against a different
        // tool's identity (tool_name AND plane both changed, simulating an
        // attacker trying to launder it as an ordinary tool capability)
        // must fail — and specifically on ToolMismatch first, since tool
        // identity is checked before plane.
        let s = store(); let c = heartbeat_cap(&s);
        let mut b = good_binding(&c);
        b.tool_name = "bash";
        b.plane = "tool";
        assert_eq!(s.consume(&b), ConsumeOutcome::ToolMismatch);
    }
    #[test] fn semantics_tampering_invalidates_signature() {
        let s = store(); let c = heartbeat_cap(&s);
        // Flip required_for_safe_completion without re-signing: canonical()
        // now differs from what was signed, exactly like max_uses tampering.
        s.mutate_stored_token(&c.token_id, |t| t.required_for_safe_completion = true);
        assert_eq!(s.consume(&good_binding(&c)), ConsumeOutcome::SignatureInvalid);
    }
    #[test] fn plane_tampering_invalidates_signature() {
        let s = store(); let c = heartbeat_cap(&s);
        s.mutate_stored_token(&c.token_id, |t| t.action_plane = ActionPlane::Tool);
        assert_eq!(s.consume(&good_binding(&c)), ConsumeOutcome::SignatureInvalid);
    }

    #[test] fn provider_and_action_decisions_coexist_under_same_gov_tx_id() {
        // tx_key is (gov_tx_id, authority) — the same transaction may carry
        // both a provider-execute and an action-execute decision.
        let s = store();
        let provider_id = s.record_decision(req("tx-shared")).unwrap();
        let mut a = action_req("tx-shared");
        a.gov_tx_id = "tx-shared".into();
        let action_id = s.record_decision(a).unwrap();
        assert_ne!(provider_id, action_id);
    }
    #[test] fn action_conflicting_tool_same_tx_errors() {
        let s = store();
        s.record_decision(action_req("tx-a2")).unwrap();
        let mut r = action_req("tx-a2"); r.tool_name = "write".into();
        assert_eq!(s.record_decision(r).err(),
                   Some(CapabilityError::TransactionScopeConflict));
    }

    // ── NEW: signature corruption ──
    #[test] fn corrupted_signature_rejected() {
        let s = store(); let c = cap(&s);
        s.mutate_stored_token(&c.token_id, |t| t.signature = "deadbeef".into());
        assert_eq!(s.consume(&good_binding(&c)), ConsumeOutcome::SignatureInvalid);
    }

    // ── NEW: max_uses tampering is caught because max_uses is signed ──
    #[test] fn max_uses_tampering_rejected() {
        let s = store(); let c = cap(&s);
        // Inflate stored max_uses without re-signing. canonical() now differs
        // from what was signed -> signature verification must fail.
        s.mutate_stored_token(&c.token_id, |t| t.max_uses = 1000);
        assert_eq!(s.consume(&good_binding(&c)), ConsumeOutcome::SignatureInvalid);
    }

    // ── NEW: expiry uses >= ──
    #[test] fn expired_token_rejected() {
        let s = store(); let c = cap(&s);
        s.mutate_stored_token(&c.token_id, |t| {
            t.expires_at = Utc::now() - Duration::seconds(1);
            // re-sign so it's the EXPIRY, not the signature, that rejects
            t.signature = s.crypto.sign(t.canonical().as_bytes());
        });
        assert_eq!(s.consume(&good_binding(&c)), ConsumeOutcome::Expired);
    }

    // ── NEW: TTL validation ──
    #[test] fn nonpositive_ttl_rejected() {
        let c = Arc::new(CryptoEngine::new("logos_capability_test_seed"));
        assert_eq!(CapabilityStore::new(c.clone()).with_ttl_secs(0).err(),
                   Some(CapabilityError::InvalidTtl));
        assert_eq!(CapabilityStore::new(c).with_ttl_secs(-5).err(),
                   Some(CapabilityError::InvalidTtl));
    }

    // ── NEW: field validation ──
    #[test] fn empty_fields_rejected() {
        let s = store();
        let mut r = req("tx1"); r.model = "".into();
        assert_eq!(s.record_decision(r).err(), Some(CapabilityError::EmptyField("model")));
        let mut r2 = req("tx1"); r2.gov_tx_id = "  ".into();
        assert_eq!(s.record_decision(r2).err(), Some(CapabilityError::EmptyField("gov_tx_id")));
    }
    #[test] fn wrong_authority_rejected() {
        let s = store();
        let mut r = req("tx1"); r.authority = "provider.admin".into();
        assert_eq!(s.record_decision(r).err(), Some(CapabilityError::WrongAuthority));
    }

    // ── NEW: decision idempotency ──
    #[test] fn identical_retry_returns_same_decision() {
        let s = store();
        let a = s.record_decision(req("tx1")).unwrap();
        let b = s.record_decision(req("tx1")).unwrap(); // identical scope
        assert_eq!(a, b, "identical retry must be idempotent");
    }
    #[test] fn conflicting_backend_same_tx_errors() {
        let s = store();
        s.record_decision(req("tx1")).unwrap();
        let mut r = req("tx1"); r.backend = "openai".into(); r.model = "gpt-4o".into();
        assert_eq!(s.record_decision(r).err(),
                   Some(CapabilityError::TransactionScopeConflict));
    }
    #[test] fn conflicting_session_same_tx_errors() {
        let s = store();
        s.record_decision(req("tx1")).unwrap();
        let mut r = req("tx1"); r.session_id = "sessOTHER".into();
        assert_eq!(s.record_decision(r).err(),
                   Some(CapabilityError::TransactionScopeConflict));
    }

    // ── retained: the primary concurrency proofs ──
    #[test] fn concurrent_consume_is_single_use() {
        let s = store(); let c = cap(&s);
        const N: usize = 64;
        let ok = Arc::new(AtomicUsize::new(0));
        let rej = Arc::new(AtomicUsize::new(0));
        let mut h = Vec::new();
        for _ in 0..N {
            let (s, c, ok, rej) = (s.clone(), c.clone(), ok.clone(), rej.clone());
            h.push(thread::spawn(move || {
                let b = good_binding(&c);
                match s.consume(&b) {
                    ConsumeOutcome::Authorized => { ok.fetch_add(1, Ordering::SeqCst); }
                    _ => { rej.fetch_add(1, Ordering::SeqCst); }
                }
            }));
        }
        for x in h { x.join().unwrap(); }
        assert_eq!(ok.load(Ordering::SeqCst), 1);
        assert_eq!(rej.load(Ordering::SeqCst), N - 1);
    }
    #[test] fn concurrent_issuance_is_single_capability() {
        let s = store();
        let did = s.record_decision(req("tx1")).unwrap();
        const N: usize = 64;
        let iss = Arc::new(AtomicUsize::new(0));
        let den = Arc::new(AtomicUsize::new(0));
        let mut h = Vec::new();
        for _ in 0..N {
            let (s, did, iss, den) = (s.clone(), did.clone(), iss.clone(), den.clone());
            h.push(thread::spawn(move || {
                match s.issue_after_authorization(&did) {
                    IssueOutcome::Issued(_) => { iss.fetch_add(1, Ordering::SeqCst); }
                    _ => { den.fetch_add(1, Ordering::SeqCst); }
                }
            }));
        }
        for x in h { x.join().unwrap(); }
        assert_eq!(iss.load(Ordering::SeqCst), 1);
        assert_eq!(den.load(Ordering::SeqCst), N - 1);
    }

    // ── NEW: concurrent idempotent record — one decision under contention ──
    #[test] fn concurrent_identical_record_is_single_decision() {
        let s = store();
        const N: usize = 64;
        let mut h = Vec::new();
        for _ in 0..N {
            let s = s.clone();
            h.push(thread::spawn(move || s.record_decision(req("tx1")).unwrap()));
        }
        let ids: std::collections::HashSet<String> =
            h.into_iter().map(|x| x.join().unwrap()).collect();
        assert_eq!(ids.len(), 1, "all identical retries must collapse to one decision");
    }
}
