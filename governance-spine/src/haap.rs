//! LOGOS Governance Systems Inc.
//! Human-AI Authorization Protocol (HAAP) v2.0
//! US Provisional Patent No. 63/953,447
//!
//! HAAP is the human-in-the-loop gate between OverWatch (L4) and OIM.
//! It intercepts actions above a configured DRS ceiling and requires
//! an operator-issued Intent Token before execution can proceed.
//!
//! Design principles (from LOGOS-PLY-001):
//!   - Model decides judgment. HAAP decides authorization.
//!   - Agents cannot self-elevate. Authority flows from the Human Principal only.
//!   - Ambiguity defaults to HALT, not interpretation.
//!   - Every HAAP gate event is audited and chain-linked.
//!
//! Agency levels (ascending authority required):
//!   ANALYZE          → read-only, no gate
//!   DRAFT_ACTIONS    → proposes only, no gate
//!   MODIFY_CONFIG    → gate at DRS > 40
//!   EXECUTE_ACTIONS  → gate at DRS > 60  (default production ceiling)
//!   FINANCIAL_OPS    → gate always
//!   ROOT_AUTHORITY   → gate always + dual sign-off required

use crate::{
    crypto::CryptoEngine,
    governance_signal::{GovernanceSignal, Severity, SignalSource, Direction, SignalBuilder},
};
use chrono::{DateTime, Utc, Duration};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// ═══════════════════════════════════════════════════════════════════════════
//  AGENCY LEVELS
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AgencyLevel {
    Analyze,        // 0  — read-only, never gated
    DraftActions,   // 1  — proposal only, never gated
    ModifyConfig,   // 2  — gated if DRS > 40
    ExecuteActions, // 3  — gated if DRS > 60 (default ceiling)
    FinancialOps,   // 4  — always gated
    RootAuthority,  // 5  — always gated, dual sign-off required
}

impl AgencyLevel {
    /// DRS threshold above which this level requires a HAAP gate.
    /// Returns None if this level is NEVER gated (Analyze, Draft).
    /// Returns Some(0) if this level is ALWAYS gated.
    pub fn gate_threshold(&self) -> Option<u8> {
        match self {
            AgencyLevel::Analyze        => None,
            AgencyLevel::DraftActions   => None,
            AgencyLevel::ModifyConfig   => Some(40),
            AgencyLevel::ExecuteActions => Some(60),
            AgencyLevel::FinancialOps   => Some(0),
            AgencyLevel::RootAuthority  => Some(0),
        }
    }

    pub fn requires_dual_signoff(&self) -> bool {
        matches!(self, AgencyLevel::RootAuthority)
    }
}

impl std::fmt::Display for AgencyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgencyLevel::Analyze        => write!(f, "ANALYZE"),
            AgencyLevel::DraftActions   => write!(f, "DRAFT_ACTIONS"),
            AgencyLevel::ModifyConfig   => write!(f, "MODIFY_CONFIG"),
            AgencyLevel::ExecuteActions => write!(f, "EXECUTE_ACTIONS"),
            AgencyLevel::FinancialOps   => write!(f, "FINANCIAL_OPS"),
            AgencyLevel::RootAuthority  => write!(f, "ROOT_AUTHORITY"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  INTENT TOKEN
// ═══════════════════════════════════════════════════════════════════════════

/// Ed25519-signed authorization token issued by the Human Principal.
/// Tokens have a defined scope, agency ceiling, and expiry.
/// Agents present tokens; HAAP verifies them. Agents cannot issue tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentToken {
    /// Unique token identifier
    pub token_id: String,
    /// Who issued this token (human principal ID)
    pub issued_by: String,
    /// Which session this token covers
    pub session_id: String,
    /// Maximum agency level this token authorizes
    pub agency_ceiling: AgencyLevel,
    /// What this token explicitly permits (plain language)
    pub permitted_actions: Vec<String>,
    /// What this token explicitly forbids
    pub forbidden_actions: Vec<String>,
    /// Token expiry — tokens are ephemeral, never indefinite
    pub expires_at: DateTime<Utc>,
    /// Maximum number of uses (None = unlimited within expiry)
    pub max_uses: Option<u32>,
    /// Ed25519 signature of canonical token representation
    pub signature: String,
    /// Use count (incremented on each authorized use)
    pub use_count: u32,
}

impl IntentToken {
    /// Build canonical representation for signature verification.
    pub fn canonical(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.token_id,
            self.issued_by,
            self.session_id,
            self.agency_ceiling,
            self.expires_at.timestamp(),
            self.permitted_actions.join(","),
        )
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn is_exhausted(&self) -> bool {
        self.max_uses.map(|max| self.use_count >= max).unwrap_or(false)
    }

    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_exhausted()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  HAAP VERDICT
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub enum HaapVerdict {
    /// Action is below the gate threshold — proceed without authorization
    Authorized { drs: u8, agency: AgencyLevel },
    /// Action requires human authorization — halt and request token
    GateRequired {
        drs: u8,
        agency: AgencyLevel,
        reason: String,
        signal: GovernanceSignal,
    },
    /// Token provided and verified — action authorized
    TokenVerified {
        token_id: String,
        agency: AgencyLevel,
        uses_remaining: Option<u32>,
        signal: GovernanceSignal,
    },
    /// Token rejected — expired, exhausted, wrong session, or bad signature
    TokenRejected {
        reason: String,
        signal: GovernanceSignal,
    },
    /// Constitutional block — DRS > 95, no override possible
    ConstitutionalBlock {
        drs: u8,
        signal: GovernanceSignal,
    },
}

impl HaapVerdict {
    pub fn is_blocked(&self) -> bool {
        matches!(self, HaapVerdict::GateRequired { .. }
            | HaapVerdict::TokenRejected { .. }
            | HaapVerdict::ConstitutionalBlock { .. })
    }

    pub fn to_governance_signal(&self) -> Option<&GovernanceSignal> {
        match self {
            HaapVerdict::GateRequired   { signal, .. } => Some(signal),
            HaapVerdict::TokenVerified  { signal, .. } => Some(signal),
            HaapVerdict::TokenRejected  { signal, .. } => Some(signal),
            HaapVerdict::ConstitutionalBlock { signal, .. } => Some(signal),
            HaapVerdict::Authorized { .. } => None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  HAAP GATE
// ═══════════════════════════════════════════════════════════════════════════

pub struct HaapConfig {
    /// DRS above which EXECUTE_ACTIONS is always gated (default 60)
    pub execute_ceiling: u8,
    /// DRS above which all actions are constitutionally blocked (default 96)
    pub constitutional_block_threshold: u8,
    /// Token expiry window for operator-issued tokens (default 4 hours)
    pub default_token_duration_secs: u64,
}

impl Default for HaapConfig {
    fn default() -> Self {
        Self {
            execute_ceiling: 60,
            constitutional_block_threshold: 96,
            default_token_duration_secs: 14_400, // 4 hours per LOGOS-PLY-001 template
        }
    }
}

/// session_id → list of (action_class, expiry) pre-authorizations.
type PreauthMap = Arc<RwLock<HashMap<String, Vec<(String, DateTime<Utc>)>>>>;

pub struct HaapGate {
    config: HaapConfig,
    crypto: Arc<CryptoEngine>,
    /// Active tokens by token_id
    tokens: Arc<RwLock<HashMap<String, IntentToken>>>,
    /// Pre-authorized action classes by session_id → (action_class, expiry)
    preauth: PreauthMap,
}

impl HaapGate {
    pub fn new(config: HaapConfig, crypto: Arc<CryptoEngine>) -> Self {
        Self {
            config,
            crypto,
            tokens: Arc::new(RwLock::new(HashMap::new())),
            preauth: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Evaluate a proposed action against HAAP policy.
    ///
    /// Args:
    ///   session_id     — current session
    ///   agency         — what the agent is trying to do
    ///   drs            — current Dynamic Risk Score (0-100)
    ///   action_class   — plain language action category (for preauth check)
    ///   token          — operator-issued token if agent is presenting one
    pub fn evaluate(
        &self,
        session_id: &str,
        agency: &AgencyLevel,
        drs: u8,
        action_class: &str,
        token: Option<&str>,
    ) -> HaapVerdict {
        let payload_hash = CryptoEngine::compute_hash(
            &format!("haap|{}|{}|{}|{}", session_id, agency, drs, action_class)
        );

        // Constitutional block — no override at all
        if drs >= self.config.constitutional_block_threshold {
            let sig = self.build_signal(session_id, "CONSTITUTIONAL_BLOCK", "HAAP-CONST-001",
                Severity::Critical, 0.99, &payload_hash, "haap/constitutional_block");
            eprintln!("[HAAP] {} | DRS={} CONSTITUTIONAL BLOCK — no override path", session_id, drs);
            return HaapVerdict::ConstitutionalBlock { drs, signal: sig };
        }

        // Check if action falls below the gate threshold for this agency level
        match agency.gate_threshold() {
            None => return HaapVerdict::Authorized { drs, agency: agency.clone() },
            Some(threshold) if drs < threshold => {
                return HaapVerdict::Authorized { drs, agency: agency.clone() }
            }
            _ => {} // Gate required — continue below
        }

        // Check pre-authorization for this action class
        if self.is_preauthorized(session_id, action_class) {
            return HaapVerdict::Authorized { drs, agency: agency.clone() };
        }

        // Token presented — verify it
        if let Some(token_str) = token {
            return self.verify_token(session_id, agency, drs, token_str, &payload_hash);
        }

        // No token — gate required
        let reason = format!(
            "Action '{}' at agency level {} requires human authorization (DRS={}). \
             Present a valid Intent Token to proceed.",
            action_class, agency, drs
        );
        eprintln!("[HAAP] {} | GATE REQUIRED | {} | DRS={}", session_id, agency, drs);

        let sig = self.build_signal(session_id, "HAAP_GATE_REQUIRED", "HAAP-GATE-001",
            Severity::High, 0.90, &payload_hash, "haap/authorization_required");

        HaapVerdict::GateRequired { drs, agency: agency.clone(), reason, signal: sig }
    }

    /// Register an operator-issued Intent Token.
    /// Called when the human principal provides authorization.
    pub fn register_token(&self, token: IntentToken) -> Result<(), &'static str> {
        if token.is_expired() { return Err("Token is already expired"); }
        if token.signature.is_empty() { return Err("Token has no signature"); }
        self.tokens.write().insert(token.token_id.clone(), token);
        Ok(())
    }

    /// Pre-authorize an action class for a session (operator shortcut).
    /// Used for low-risk repeated actions within a governed workflow.
    pub fn preauthorize(
        &self,
        session_id: &str,
        action_class: &str,
        duration_secs: u64,
    ) {
        let expiry = Utc::now() + Duration::seconds(duration_secs as i64);
        let mut preauth = self.preauth.write();
        preauth
            .entry(session_id.to_string())
            .or_default()
            .push((action_class.to_string(), expiry));
    }

    /// Revoke all tokens and preauth for a session (operator kill).
    pub fn revoke_session(&self, session_id: &str) {
        self.preauth.write().remove(session_id);
        // Revoke any tokens scoped to this session
        self.tokens.write().retain(|_, t| t.session_id != session_id);
        eprintln!("[HAAP] {} | All authorizations revoked", session_id);
    }

    // ── Private helpers ────────────────────────────────────────────────────

    fn is_preauthorized(&self, session_id: &str, action_class: &str) -> bool {
        let mut preauth = self.preauth.write();
        let now = Utc::now();
        if let Some(entries) = preauth.get_mut(session_id) {
            // Prune expired entries
            entries.retain(|(_, expiry)| *expiry > now);
            return entries.iter().any(|(class, _)| class == action_class);
        }
        false
    }

    fn verify_token(
        &self,
        session_id: &str,
        agency: &AgencyLevel,
        drs: u8,
        token_id: &str,
        payload_hash: &str,
    ) -> HaapVerdict {
        let mut tokens = self.tokens.write();

        let token = match tokens.get_mut(token_id) {
            None => {
                let sig = self.build_signal(session_id, "TOKEN_NOT_FOUND", "HAAP-TOKEN-001",
                    Severity::High, 0.92, payload_hash, "haap/token_verification");
                return HaapVerdict::TokenRejected {
                    reason: format!("Token '{}' not found in registry", token_id),
                    signal: sig,
                };
            }
            Some(t) => t,
        };

        // Session binding check
        if token.session_id != session_id {
            let sig = self.build_signal(session_id, "TOKEN_SESSION_MISMATCH", "HAAP-TOKEN-002",
                Severity::Critical, 0.97, payload_hash, "haap/token_verification");
            return HaapVerdict::TokenRejected {
                reason: "Token is bound to a different session".to_string(),
                signal: sig,
            };
        }

        // Validity checks
        if token.is_expired() {
            let sig = self.build_signal(session_id, "TOKEN_EXPIRED", "HAAP-TOKEN-003",
                Severity::High, 0.90, payload_hash, "haap/token_verification");
            return HaapVerdict::TokenRejected {
                reason: format!("Token '{}' expired at {}", token_id, token.expires_at),
                signal: sig,
            };
        }

        if token.is_exhausted() {
            let sig = self.build_signal(session_id, "TOKEN_EXHAUSTED", "HAAP-TOKEN-004",
                Severity::High, 0.90, payload_hash, "haap/token_verification");
            return HaapVerdict::TokenRejected {
                reason: format!("Token '{}' has no remaining uses", token_id),
                signal: sig,
            };
        }

        // Agency ceiling check — token must authorize at least the requested level
        if token.agency_ceiling < *agency {
            let sig = self.build_signal(session_id, "TOKEN_AGENCY_INSUFFICIENT", "HAAP-TOKEN-005",
                Severity::High, 0.92, payload_hash, "haap/token_verification");
            return HaapVerdict::TokenRejected {
                reason: format!(
                    "Token ceiling {} does not cover requested agency {}",
                    token.agency_ceiling, agency
                ),
                signal: sig,
            };
        }

        // Signature verification
        let canonical = token.canonical();
        let sig_valid = self.crypto.verify(canonical.as_bytes(), &token.signature)
            .unwrap_or(false);

        if !sig_valid {
            let sig = self.build_signal(session_id, "TOKEN_SIGNATURE_INVALID", "HAAP-TOKEN-006",
                Severity::Critical, 0.99, payload_hash, "haap/token_verification");
            eprintln!("[HAAP] {} | SIGNATURE INVALID for token {}", session_id, token_id);
            return HaapVerdict::TokenRejected {
                reason: "Token signature verification failed".to_string(),
                signal: sig,
            };
        }

        // Increment use count
        token.use_count += 1;
        let uses_remaining = token.max_uses.map(|max| max.saturating_sub(token.use_count));
        let token_id = token.token_id.clone();

        eprintln!(
            "[HAAP] {} | TOKEN VERIFIED | {} | agency={} | drs={} | uses_left={:?}",
            session_id, token_id, agency, drs, uses_remaining
        );

        let sig = self.build_signal(session_id, "HAAP_TOKEN_VERIFIED", "HAAP-OK-001",
            Severity::None, 0.0, payload_hash, "haap/token_verified");

        HaapVerdict::TokenVerified { token_id, agency: agency.clone(), uses_remaining, signal: sig }
    }

    // Same rationale as sentinel.rs's build()/corridor.rs's build(): already
    // delegates to SignalBuilder, args are independent signal fields, and
    // this wrapper is called as a one-liner at 9 sites in this file.
    #[allow(clippy::too_many_arguments)]
    fn build_signal(
        &self,
        session_id: &str,
        violation: &str,
        rule_id: &str,
        severity: Severity,
        confidence: f32,
        payload_hash: &str,
        const_ref: &str,
    ) -> GovernanceSignal {
        let mut sig = SignalBuilder::new(SignalSource::Sentinel, Direction::Inbound, session_id)
            .violation(violation, rule_id)
            .severity(severity, confidence)
            .payload_hash(payload_hash)
            .constitutional_ref(const_ref)
            .build();
        let canonical = sig.canonical();
        sig.previous_hash = Some(self.crypto.get_latest_hash());
        sig.current_hash  = Some(self.crypto.extend_chain(&canonical));
        sig.signature     = Some(self.crypto.sign(canonical.as_bytes()));
        sig
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  INTENT TOKEN BUILDER (operator tooling)
// ═══════════════════════════════════════════════════════════════════════════

/// Convenience builder for operators constructing Intent Tokens.
pub struct IntentTokenBuilder {
    issued_by: String,
    session_id: String,
    agency_ceiling: AgencyLevel,
    permitted_actions: Vec<String>,
    forbidden_actions: Vec<String>,
    duration_secs: u64,
    max_uses: Option<u32>,
}

impl IntentTokenBuilder {
    pub fn new(issued_by: &str, session_id: &str) -> Self {
        Self {
            issued_by: issued_by.to_string(),
            session_id: session_id.to_string(),
            agency_ceiling: AgencyLevel::ExecuteActions,
            permitted_actions: Vec::new(),
            forbidden_actions: Vec::new(),
            duration_secs: 14_400, // 4 hours default
            max_uses: None,
        }
    }

    pub fn agency(mut self, level: AgencyLevel) -> Self {
        self.agency_ceiling = level; self
    }

    pub fn permit(mut self, action: &str) -> Self {
        self.permitted_actions.push(action.to_string()); self
    }

    pub fn forbid(mut self, action: &str) -> Self {
        self.forbidden_actions.push(action.to_string()); self
    }

    pub fn expires_in(mut self, secs: u64) -> Self {
        self.duration_secs = secs; self
    }

    pub fn max_uses(mut self, n: u32) -> Self {
        self.max_uses = Some(n); self
    }

    /// Build and sign the token. Requires the CryptoEngine for Ed25519 signing.
    pub fn build(self, crypto: &CryptoEngine) -> IntentToken {
        let token_id = format!("IT-{}", uuid::Uuid::new_v4().simple());
        let expires_at = Utc::now() + Duration::seconds(self.duration_secs as i64);

        let mut token = IntentToken {
            token_id,
            issued_by: self.issued_by,
            session_id: self.session_id,
            agency_ceiling: self.agency_ceiling,
            permitted_actions: self.permitted_actions,
            forbidden_actions: self.forbidden_actions,
            expires_at,
            max_uses: self.max_uses,
            signature: String::new(),
            use_count: 0,
        };

        let canonical = token.canonical();
        token.signature = crypto.sign(canonical.as_bytes());
        token
    }
}
