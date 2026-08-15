//! GovSec Evidence Plane v1.
//!
//! The evidence plane is deliberately separate from authorization. It records
//! what the runtime decided; it never grants authority and never substitutes
//! for the capability checks in `pipeline`/`capability`.
//!
//! Evidence events are append-only, hash-linked, and Ed25519-signed with the
//! same `CryptoEngine` identity supplied to the governed pipeline. Raw prompts,
//! tool arguments, and resource locators are not stored by this module.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;

use crate::capability::{
    CapabilityToken, ConsumeOutcome, PresentedBinding, AUTHORITY_ACTION_EXECUTE,
};
use crate::constitution::Constitution;
use crate::crypto::CryptoEngine;
use crate::envelope::ModelContextEnvelope;
use crate::pipeline::{
    ActionAuthorizationError, ActionAuthorizationRequest, EnforcementResult, GovernancePipeline,
    ProviderAuthorizationError, ProviderAuthorizationRequest,
};
use crate::ArbiterConfig;

pub const EVIDENCE_SCHEMA_VERSION: &str = "logos.govsec-evidence.v1";
pub const EVIDENCE_CHECKPOINT_SCHEMA_VERSION: &str = "logos.govsec-evidence-checkpoint.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceEventType {
    ContextApproved,
    ContextRefused,
    ProviderAuthorized,
    ProviderRefused,
    ActionAuthorized,
    ActionRefused,
    CapabilityConsumed,
    CapabilityRejected,
}

impl EvidenceEventType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContextApproved => "CONTEXT_APPROVED",
            Self::ContextRefused => "CONTEXT_REFUSED",
            Self::ProviderAuthorized => "PROVIDER_AUTHORIZED",
            Self::ProviderRefused => "PROVIDER_REFUSED",
            Self::ActionAuthorized => "ACTION_AUTHORIZED",
            Self::ActionRefused => "ACTION_REFUSED",
            Self::CapabilityConsumed => "CAPABILITY_CONSUMED",
            Self::CapabilityRejected => "CAPABILITY_REJECTED",
        }
    }
}

/// Bounded execution evidence. The plane intentionally excludes raw prompt
/// text, model output, tool arguments, credentials, and raw resource locators.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePayload {
    pub gov_tx_id: Option<String>,
    pub session_id: Option<String>,
    pub run_id: Option<String>,
    pub principal_fingerprint: Option<String>,
    pub authority: Option<String>,
    pub context_hash: Option<String>,
    pub decision_id: Option<String>,
    pub capability_id: Option<String>,
    pub action_hash: Option<String>,
    pub tool_name: Option<String>,
    pub resource_kind: Option<String>,
    /// SHA-256 of the resource locator, never the raw locator.
    pub resource_locator_hash: Option<String>,
    pub tool_call_id: Option<String>,
    pub policy_version: Option<String>,
    pub policy_hash: Option<String>,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEvent {
    pub schema_version: String,
    pub epoch_id: String,
    pub epoch_parent_hash: Option<String>,
    pub sequence: u64,
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: EvidenceEventType,
    pub payload: EvidencePayload,
    pub previous_event_hash: String,
    pub event_hash: String,
    pub signer_fingerprint: String,
    pub signer_public_key: String,
    pub signature: String,
}

impl EvidenceEvent {
    fn hash_material(&self) -> String {
        canonical_event_material(self)
    }

    pub fn recompute_hash(&self) -> String {
        CryptoEngine::compute_hash(&self.hash_material())
    }

    pub fn verify_signature(&self) -> bool {
        verify_signature_hex(
            &self.signer_public_key,
            self.event_hash.as_bytes(),
            &self.signature,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceCheckpoint {
    pub schema_version: String,
    pub epoch_id: String,
    pub last_sequence: u64,
    pub head_hash: String,
    pub signer_fingerprint: String,
    pub signer_public_key: String,
    pub created_at: DateTime<Utc>,
    pub checkpoint_hash: String,
    pub signature: String,
}

impl EvidenceCheckpoint {
    fn hash_material(&self) -> String {
        canonical_checkpoint_material(
            &self.schema_version,
            &self.epoch_id,
            self.last_sequence,
            &self.head_hash,
            &self.signer_fingerprint,
            &self.signer_public_key,
            self.created_at,
        )
    }

    pub fn recompute_hash(&self) -> String {
        CryptoEngine::compute_hash(&self.hash_material())
    }

    pub fn verify(&self) -> bool {
        if self.schema_version != EVIDENCE_CHECKPOINT_SCHEMA_VERSION {
            return false;
        }
        let Some(fingerprint) = signer_fingerprint(&self.signer_public_key) else {
            return false;
        };
        if fingerprint != self.signer_fingerprint {
            return false;
        }
        if self.recompute_hash() != self.checkpoint_hash {
            return false;
        }
        verify_signature_hex(
            &self.signer_public_key,
            self.checkpoint_hash.as_bytes(),
            &self.signature,
        )
    }
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[error("evidence sink {sink} failed: {message}")]
pub struct EvidenceSinkError {
    pub sink: String,
    pub message: String,
}

pub trait EvidenceSink: Send + Sync {
    fn name(&self) -> &str;
    fn write(&self, event: &EvidenceEvent) -> Result<(), EvidenceSinkError>;
}

#[derive(Default)]
pub struct MemoryEvidenceSink {
    events: RwLock<Vec<EvidenceEvent>>,
}

impl MemoryEvidenceSink {
    pub fn snapshot(&self) -> Vec<EvidenceEvent> {
        self.events.read().clone()
    }
}

impl EvidenceSink for MemoryEvidenceSink {
    fn name(&self) -> &str {
        "memory"
    }

    fn write(&self, event: &EvidenceEvent) -> Result<(), EvidenceSinkError> {
        self.events.write().push(event.clone());
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceSinkStatus {
    NotConfigured,
    Delivered { sink: String },
    Deferred { sink: String, error: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceAppendReceipt {
    pub event_id: String,
    pub event_hash: String,
    pub sequence: u64,
    pub sink_status: EvidenceSinkStatus,
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum EvidenceVerificationError {
    #[error("evidence checkpoint is invalid")]
    InvalidCheckpoint,
    #[error("checkpoint signer does not match the configured runtime signing identity")]
    CheckpointSignerMismatch,
    #[error("unsupported evidence schema at sequence {sequence}")]
    SchemaMismatch { sequence: u64 },
    #[error("mixed evidence epochs in one snapshot")]
    MixedEpoch,
    #[error("mixed evidence signers in one snapshot")]
    MixedSigner,
    #[error("signer fingerprint does not match embedded public key")]
    SignerFingerprintMismatch,
    #[error("invalid evidence sequence: expected {expected}, got {actual}")]
    InvalidSequence { expected: u64, actual: u64 },
    #[error("evidence chain parent mismatch at sequence {sequence}")]
    ParentMismatch { sequence: u64 },
    #[error("evidence hash mismatch at sequence {sequence}")]
    HashMismatch { sequence: u64 },
    #[error("evidence signature invalid at sequence {sequence}")]
    SignatureInvalid { sequence: u64 },
}

struct EvidenceState {
    epoch_id: String,
    epoch_parent_hash: Option<String>,
    head_hash: String,
    next_sequence: u64,
    events: Vec<EvidenceEvent>,
    pending_sink: VecDeque<EvidenceEvent>,
}

#[derive(Clone)]
pub struct EvidencePlane {
    crypto: Arc<CryptoEngine>,
    sink: Option<Arc<dyn EvidenceSink>>,
    state: Arc<Mutex<EvidenceState>>,
}

impl EvidencePlane {
    pub fn new(crypto: Arc<CryptoEngine>, sink: Option<Arc<dyn EvidenceSink>>) -> Self {
        Self::with_parent_hash(crypto, None, sink)
    }

    fn with_parent_hash(
        crypto: Arc<CryptoEngine>,
        epoch_parent_hash: Option<String>,
        sink: Option<Arc<dyn EvidenceSink>>,
    ) -> Self {
        let epoch_id = format!("EVP-{}", uuid::Uuid::new_v4().simple());
        let signer = crypto.verifying_key_fingerprint();
        let head_hash = epoch_parent_hash.clone().unwrap_or_else(|| {
            CryptoEngine::compute_hash(&format!(
                "{}|GENESIS|{}|{}",
                EVIDENCE_SCHEMA_VERSION, epoch_id, signer
            ))
        });
        Self {
            crypto,
            sink,
            state: Arc::new(Mutex::new(EvidenceState {
                epoch_id,
                epoch_parent_hash,
                head_hash,
                next_sequence: 1,
                events: Vec::new(),
                pending_sink: VecDeque::new(),
            })),
        }
    }

    pub fn from_checkpoint(
        crypto: Arc<CryptoEngine>,
        checkpoint: &EvidenceCheckpoint,
        sink: Option<Arc<dyn EvidenceSink>>,
    ) -> Result<Self, EvidenceVerificationError> {
        if !checkpoint.verify() {
            return Err(EvidenceVerificationError::InvalidCheckpoint);
        }
        if checkpoint.signer_public_key != crypto.verifying_key_hex()
            || checkpoint.signer_fingerprint != crypto.verifying_key_fingerprint()
        {
            return Err(EvidenceVerificationError::CheckpointSignerMismatch);
        }
        Ok(Self::with_parent_hash(
            crypto,
            Some(checkpoint.head_hash.clone()),
            sink,
        ))
    }

    pub fn append(
        &self,
        event_type: EvidenceEventType,
        payload: EvidencePayload,
    ) -> EvidenceAppendReceipt {
        let mut state = self.state.lock();
        let sequence = state.next_sequence;
        let timestamp = Utc::now();
        let event_id = format!("EVE-{}", uuid::Uuid::new_v4().simple());
        let previous_event_hash = state.head_hash.clone();
        let signer_fingerprint = self.crypto.verifying_key_fingerprint();
        let signer_public_key = self.crypto.verifying_key_hex();

        let mut event = EvidenceEvent {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
            epoch_id: state.epoch_id.clone(),
            epoch_parent_hash: state.epoch_parent_hash.clone(),
            sequence,
            event_id: event_id.clone(),
            timestamp,
            event_type,
            payload,
            previous_event_hash,
            event_hash: String::new(),
            signer_fingerprint,
            signer_public_key,
            signature: String::new(),
        };

        let material = canonical_event_material(&event);
        let event_hash = CryptoEngine::compute_hash(&material);
        event.signature = self.crypto.sign(event_hash.as_bytes());
        event.event_hash = event_hash.clone();

        state.events.push(event.clone());
        state.head_hash = event_hash.clone();
        state.next_sequence += 1;

        let sink_status = match &self.sink {
            None => EvidenceSinkStatus::NotConfigured,
            Some(sink) if !state.pending_sink.is_empty() => {
                // Preserve append order at the external sink. Once one event
                // is deferred, later events join the same FIFO instead of
                // racing ahead if the sink happens to recover between calls.
                state.pending_sink.push_back(event);
                EvidenceSinkStatus::Deferred {
                    sink: sink.name().to_string(),
                    error: "prior deferred evidence pending".to_string(),
                }
            }
            Some(sink) => match sink.write(&event) {
                Ok(()) => EvidenceSinkStatus::Delivered {
                    sink: sink.name().to_string(),
                },
                Err(error) => {
                    state.pending_sink.push_back(event);
                    EvidenceSinkStatus::Deferred {
                        sink: sink.name().to_string(),
                        error: error.to_string(),
                    }
                }
            },
        };

        EvidenceAppendReceipt {
            event_id,
            event_hash,
            sequence,
            sink_status,
        }
    }

    pub fn snapshot(&self) -> Vec<EvidenceEvent> {
        self.state.lock().events.clone()
    }

    pub fn len(&self) -> usize {
        self.state.lock().events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.state.lock().events.is_empty()
    }

    pub fn epoch_id(&self) -> String {
        self.state.lock().epoch_id.clone()
    }

    pub fn pending_sink_count(&self) -> usize {
        self.state.lock().pending_sink.len()
    }

    /// Retry deferred sink writes in original chain order. Stops on the first
    /// failure so an external append-only sink never observes reordering.
    pub fn flush_pending(&self) -> Result<usize, EvidenceSinkError> {
        let sink = match &self.sink {
            Some(sink) => Arc::clone(sink),
            None => return Ok(0),
        };
        let mut state = self.state.lock();
        let mut delivered = 0usize;
        while let Some(event) = state.pending_sink.front().cloned() {
            sink.write(&event)?;
            state.pending_sink.pop_front();
            delivered += 1;
        }
        Ok(delivered)
    }

    pub fn checkpoint(&self) -> EvidenceCheckpoint {
        let state = self.state.lock();
        let created_at = Utc::now();
        let signer_fingerprint = self.crypto.verifying_key_fingerprint();
        let signer_public_key = self.crypto.verifying_key_hex();
        let last_sequence = state.next_sequence.saturating_sub(1);
        let material = canonical_checkpoint_material(
            EVIDENCE_CHECKPOINT_SCHEMA_VERSION,
            &state.epoch_id,
            last_sequence,
            &state.head_hash,
            &signer_fingerprint,
            &signer_public_key,
            created_at,
        );
        let checkpoint_hash = CryptoEngine::compute_hash(&material);
        let signature = self.crypto.sign(checkpoint_hash.as_bytes());
        EvidenceCheckpoint {
            schema_version: EVIDENCE_CHECKPOINT_SCHEMA_VERSION.to_string(),
            epoch_id: state.epoch_id.clone(),
            last_sequence,
            head_hash: state.head_hash.clone(),
            signer_fingerprint,
            signer_public_key,
            created_at,
            checkpoint_hash,
            signature,
        }
    }

    pub fn verify_snapshot(events: &[EvidenceEvent]) -> Result<(), EvidenceVerificationError> {
        let Some(first) = events.first() else {
            return Ok(());
        };
        let epoch_id = &first.epoch_id;
        let epoch_parent_hash = &first.epoch_parent_hash;
        let signer_public_key = &first.signer_public_key;
        let signer_fp = signer_fingerprint(signer_public_key)
            .ok_or(EvidenceVerificationError::SignerFingerprintMismatch)?;
        if signer_fp != first.signer_fingerprint {
            return Err(EvidenceVerificationError::SignerFingerprintMismatch);
        }

        let mut previous_hash = epoch_parent_hash.clone().unwrap_or_else(|| {
            CryptoEngine::compute_hash(&format!(
                "{}|GENESIS|{}|{}",
                EVIDENCE_SCHEMA_VERSION, epoch_id, signer_fp
            ))
        });

        for (index, event) in events.iter().enumerate() {
            let expected_sequence = index as u64 + 1;
            if event.schema_version != EVIDENCE_SCHEMA_VERSION {
                return Err(EvidenceVerificationError::SchemaMismatch {
                    sequence: event.sequence,
                });
            }
            if &event.epoch_id != epoch_id || &event.epoch_parent_hash != epoch_parent_hash {
                return Err(EvidenceVerificationError::MixedEpoch);
            }
            if &event.signer_public_key != signer_public_key
                || event.signer_fingerprint != signer_fp
            {
                return Err(EvidenceVerificationError::MixedSigner);
            }
            if event.sequence != expected_sequence {
                return Err(EvidenceVerificationError::InvalidSequence {
                    expected: expected_sequence,
                    actual: event.sequence,
                });
            }
            if event.previous_event_hash != previous_hash {
                return Err(EvidenceVerificationError::ParentMismatch {
                    sequence: event.sequence,
                });
            }
            if event.recompute_hash() != event.event_hash {
                return Err(EvidenceVerificationError::HashMismatch {
                    sequence: event.sequence,
                });
            }
            if !event.verify_signature() {
                return Err(EvidenceVerificationError::SignatureInvalid {
                    sequence: event.sequence,
                });
            }
            previous_hash = event.event_hash.clone();
        }
        Ok(())
    }

    /// Verify an epoch snapshot against a signed checkpoint for that same
    /// epoch. This catches tail truncation in addition to the interior
    /// deletion/reordering checks performed by `verify_snapshot`.
    pub fn verify_snapshot_against_checkpoint(
        events: &[EvidenceEvent],
        checkpoint: &EvidenceCheckpoint,
    ) -> Result<(), EvidenceVerificationError> {
        if !checkpoint.verify() {
            return Err(EvidenceVerificationError::InvalidCheckpoint);
        }
        Self::verify_snapshot(events)?;

        let Some(last) = events.last() else {
            if checkpoint.last_sequence == 0 {
                return Ok(());
            }
            return Err(EvidenceVerificationError::InvalidSequence {
                expected: checkpoint.last_sequence,
                actual: 0,
            });
        };

        if last.epoch_id != checkpoint.epoch_id {
            return Err(EvidenceVerificationError::MixedEpoch);
        }
        if last.signer_public_key != checkpoint.signer_public_key
            || last.signer_fingerprint != checkpoint.signer_fingerprint
        {
            return Err(EvidenceVerificationError::MixedSigner);
        }
        if last.sequence != checkpoint.last_sequence {
            return Err(EvidenceVerificationError::InvalidSequence {
                expected: checkpoint.last_sequence,
                actual: last.sequence,
            });
        }
        if last.event_hash != checkpoint.head_hash {
            return Err(EvidenceVerificationError::ParentMismatch {
                sequence: last.sequence,
            });
        }
        Ok(())
    }
}

/// Decorator that records execution evidence without moving authorization
/// logic out of `GovernancePipeline`. The inner pipeline still makes every
/// governance decision; this wrapper only observes the returned result.
pub struct EvidenceGovernedPipeline {
    pipeline: GovernancePipeline,
    evidence: EvidencePlane,
}

impl EvidenceGovernedPipeline {
    pub fn new(
        arbiter_config: ArbiterConfig,
        constitution: Option<Constitution>,
        crypto: Arc<CryptoEngine>,
        sink: Option<Arc<dyn EvidenceSink>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let pipeline = GovernancePipeline::new(arbiter_config, constitution, Arc::clone(&crypto))?;
        let evidence = EvidencePlane::new(crypto, sink);
        Ok(Self { pipeline, evidence })
    }

    pub fn from_checkpoint(
        arbiter_config: ArbiterConfig,
        constitution: Option<Constitution>,
        crypto: Arc<CryptoEngine>,
        checkpoint: &EvidenceCheckpoint,
        sink: Option<Arc<dyn EvidenceSink>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let pipeline = GovernancePipeline::new(arbiter_config, constitution, Arc::clone(&crypto))?;
        let evidence = EvidencePlane::from_checkpoint(crypto, checkpoint, sink)?;
        Ok(Self { pipeline, evidence })
    }

    pub fn default_for_test() -> Result<Self, Box<dyn std::error::Error>> {
        let crypto = Arc::new(CryptoEngine::new("govsec_evidence_test"));
        Self::new(ArbiterConfig::default(), None, crypto, None)
    }

    pub fn inbound_context(
        &self,
        envelope: &ModelContextEnvelope,
        gov_tx_id: &str,
    ) -> Result<EnforcementResult, crate::envelope::EnvelopeError> {
        self.inbound_context_with_identity(envelope, gov_tx_id, None, None)
    }

    pub fn inbound_context_with_identity(
        &self,
        envelope: &ModelContextEnvelope,
        gov_tx_id: &str,
        department_id: Option<&str>,
        agent_id: Option<&str>,
    ) -> Result<EnforcementResult, crate::envelope::EnvelopeError> {
        let result = self.pipeline.inbound_context_with_identity(
            envelope,
            gov_tx_id,
            department_id,
            agent_id,
        );
        let (event_type, outcome) = match &result {
            Ok(EnforcementResult::Approved(_)) => {
                (EvidenceEventType::ContextApproved, "APPROVED".to_string())
            }
            Ok(other) => (
                EvidenceEventType::ContextRefused,
                enforcement_outcome(other).to_string(),
            ),
            Err(_) => (
                EvidenceEventType::ContextRefused,
                "STRUCTURAL_VALIDATION_FAILED".to_string(),
            ),
        };
        self.evidence.append(
            event_type,
            EvidencePayload {
                gov_tx_id: Some(gov_tx_id.to_string()),
                session_id: Some(envelope.session_id.clone()),
                run_id: Some(envelope.run_id.clone()),
                context_hash: Some(envelope.context_hash.clone()),
                policy_version: Some(envelope.policy_version.clone()),
                policy_hash: Some(envelope.policy_hash.clone()),
                outcome,
                ..EvidencePayload::default()
            },
        );
        result
    }

    pub fn authorize_provider_execution(
        &self,
        req: ProviderAuthorizationRequest,
    ) -> Result<CapabilityToken, ProviderAuthorizationError> {
        let evidence_req = req.clone();
        let result = self.pipeline.authorize_provider_execution(req);
        match &result {
            Ok(token) => {
                self.evidence.append(
                    EvidenceEventType::ProviderAuthorized,
                    payload_from_token(token, "AUTHORIZED"),
                );
            }
            Err(error) => {
                self.evidence.append(
                    EvidenceEventType::ProviderRefused,
                    EvidencePayload {
                        gov_tx_id: Some(evidence_req.gov_tx_id),
                        session_id: Some(evidence_req.session_id),
                        run_id: Some(evidence_req.run_id),
                        principal_fingerprint: Some(evidence_req.principal_fingerprint),
                        authority: Some("provider.execute".to_string()),
                        context_hash: Some(evidence_req.context_hash),
                        policy_version: Some(evidence_req.policy_version),
                        policy_hash: Some(evidence_req.policy_hash),
                        outcome: format!("{:?}", error),
                        ..EvidencePayload::default()
                    },
                );
            }
        }
        result
    }

    pub fn authorize_action_execution(
        &self,
        req: ActionAuthorizationRequest,
    ) -> Result<CapabilityToken, ActionAuthorizationError> {
        let evidence_req = req.clone();
        let result = self.pipeline.authorize_action_execution(req);
        match &result {
            Ok(token) => {
                self.evidence.append(
                    EvidenceEventType::ActionAuthorized,
                    payload_from_token(token, "AUTHORIZED"),
                );
            }
            Err(error) => {
                self.evidence.append(
                    EvidenceEventType::ActionRefused,
                    EvidencePayload {
                        gov_tx_id: Some(evidence_req.gov_tx_id),
                        session_id: Some(evidence_req.session_id),
                        run_id: Some(evidence_req.run_id),
                        principal_fingerprint: Some(evidence_req.principal_fingerprint),
                        authority: Some(AUTHORITY_ACTION_EXECUTE.to_string()),
                        context_hash: Some(evidence_req.context_hash),
                        tool_name: Some(evidence_req.tool_name),
                        resource_kind: Some(evidence_req.resource_kind),
                        resource_locator_hash: Some(CryptoEngine::compute_hash(
                            &evidence_req.resource_locator,
                        )),
                        tool_call_id: Some(evidence_req.tool_call_id),
                        policy_version: Some(evidence_req.policy_version),
                        policy_hash: Some(evidence_req.policy_hash),
                        outcome: format!("{:?}", error),
                        ..EvidencePayload::default()
                    },
                );
            }
        }
        result
    }

    pub fn consume_provider_capability(&self, binding: &PresentedBinding<'_>) -> ConsumeOutcome {
        let outcome = self.pipeline.consume_provider_capability(binding);
        let event_type = if outcome.authorized() {
            EvidenceEventType::CapabilityConsumed
        } else {
            EvidenceEventType::CapabilityRejected
        };
        self.evidence.append(
            event_type,
            EvidencePayload {
                gov_tx_id: Some(binding.gov_tx_id.to_string()),
                session_id: Some(binding.session_id.to_string()),
                run_id: Some(binding.run_id.to_string()),
                principal_fingerprint: Some(binding.principal_fingerprint.to_string()),
                authority: Some(binding.authority.to_string()),
                context_hash: Some(binding.context_hash.to_string()),
                capability_id: Some(binding.token_id.to_string()),
                action_hash: nonempty(binding.action_hash),
                tool_name: nonempty(binding.tool_name),
                resource_kind: nonempty(binding.resource_kind),
                resource_locator_hash: if binding.resource_locator.is_empty() {
                    None
                } else {
                    Some(CryptoEngine::compute_hash(binding.resource_locator))
                },
                tool_call_id: nonempty(binding.tool_call_id),
                policy_version: Some(binding.policy_version.to_string()),
                policy_hash: Some(binding.policy_hash.to_string()),
                outcome: outcome.as_audit_str().to_string(),
                ..EvidencePayload::default()
            },
        );
        outcome
    }

    pub fn evidence(&self) -> &EvidencePlane {
        &self.evidence
    }

    pub fn pipeline(&self) -> &GovernancePipeline {
        &self.pipeline
    }
}

impl std::ops::Deref for EvidenceGovernedPipeline {
    type Target = GovernancePipeline;

    fn deref(&self) -> &Self::Target {
        &self.pipeline
    }
}

fn payload_from_token(token: &CapabilityToken, outcome: &str) -> EvidencePayload {
    EvidencePayload {
        gov_tx_id: Some(token.gov_tx_id.clone()),
        session_id: Some(token.session_id.clone()),
        run_id: Some(token.run_id.clone()),
        principal_fingerprint: Some(token.principal_fingerprint.clone()),
        authority: Some(token.authority.clone()),
        context_hash: Some(token.context_hash.clone()),
        decision_id: Some(token.haap_decision_id.clone()),
        capability_id: Some(token.token_id.clone()),
        action_hash: nonempty(&token.action_hash),
        tool_name: nonempty(&token.tool_name),
        resource_kind: nonempty(&token.resource_kind),
        resource_locator_hash: if token.resource_locator.is_empty() {
            None
        } else {
            Some(CryptoEngine::compute_hash(&token.resource_locator))
        },
        tool_call_id: nonempty(&token.tool_call_id),
        policy_version: Some(token.policy_version.clone()),
        policy_hash: Some(token.policy_hash.clone()),
        outcome: outcome.to_string(),
    }
}

fn enforcement_outcome(result: &EnforcementResult) -> &'static str {
    match result {
        EnforcementResult::Approved(_) => "APPROVED",
        EnforcementResult::Restricted(_, _) => "RESTRICTED",
        EnforcementResult::Quarantined(_) => "QUARANTINED",
        EnforcementResult::HardLocked(_) => "HARD_LOCKED",
        EnforcementResult::HaapGated { .. } => "HAAP_GATED",
    }
}

fn nonempty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn signer_fingerprint(public_key_hex: &str) -> Option<String> {
    let bytes = hex::decode(public_key_hex).ok()?;
    let key_bytes: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&key_bytes).ok()?;
    Some(CryptoEngine::compute_hash(public_key_hex)[..16].to_string())
}

fn verify_signature_hex(public_key_hex: &str, data: &[u8], signature_hex: &str) -> bool {
    let key_bytes = match hex::decode(public_key_hex)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
    {
        Some(bytes) => bytes,
        None => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&key_bytes) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let signature_bytes = match hex::decode(signature_hex)
        .ok()
        .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
    {
        Some(bytes) => bytes,
        None => return false,
    };
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key.verify(data, &signature).is_ok()
}

fn canonical_event_material(event: &EvidenceEvent) -> String {
    let payload = &event.payload;
    let fields = [
        enc(&event.schema_version),
        enc(&event.epoch_id),
        enc_opt(event.epoch_parent_hash.as_deref()),
        event.sequence.to_string(),
        enc(&event.event_id),
        event
            .timestamp
            .timestamp_nanos_opt()
            .unwrap_or(0)
            .to_string(),
        event.event_type.as_str().to_string(),
        enc_opt(payload.gov_tx_id.as_deref()),
        enc_opt(payload.session_id.as_deref()),
        enc_opt(payload.run_id.as_deref()),
        enc_opt(payload.principal_fingerprint.as_deref()),
        enc_opt(payload.authority.as_deref()),
        enc_opt(payload.context_hash.as_deref()),
        enc_opt(payload.decision_id.as_deref()),
        enc_opt(payload.capability_id.as_deref()),
        enc_opt(payload.action_hash.as_deref()),
        enc_opt(payload.tool_name.as_deref()),
        enc_opt(payload.resource_kind.as_deref()),
        enc_opt(payload.resource_locator_hash.as_deref()),
        enc_opt(payload.tool_call_id.as_deref()),
        enc_opt(payload.policy_version.as_deref()),
        enc_opt(payload.policy_hash.as_deref()),
        enc(&payload.outcome),
        enc(&event.previous_event_hash),
        enc(&event.signer_fingerprint),
        enc(&event.signer_public_key),
    ];
    fields.join("|")
}

fn canonical_checkpoint_material(
    schema_version: &str,
    epoch_id: &str,
    last_sequence: u64,
    head_hash: &str,
    signer_fingerprint: &str,
    signer_public_key: &str,
    created_at: DateTime<Utc>,
) -> String {
    [
        enc(schema_version),
        enc(epoch_id),
        last_sequence.to_string(),
        enc(head_hash),
        enc(signer_fingerprint),
        enc(signer_public_key),
        created_at.timestamp_nanos_opt().unwrap_or(0).to_string(),
    ]
    .join("|")
}

fn enc(value: &str) -> String {
    hex::encode(value.as_bytes())
}

fn enc_opt(value: Option<&str>) -> String {
    match value {
        Some(value) => format!("1{}", enc(value)),
        None => "0".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{
        sha256_hex, ContextAttachment, ContextRole, ContextSegment, ContextSource,
        MODEL_CONTEXT_SCHEMA_VERSION,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    struct ToggleSink {
        fail: AtomicBool,
        events: RwLock<Vec<EvidenceEvent>>,
    }

    impl ToggleSink {
        fn new(fail: bool) -> Self {
            Self {
                fail: AtomicBool::new(fail),
                events: RwLock::new(Vec::new()),
            }
        }
    }

    impl EvidenceSink for ToggleSink {
        fn name(&self) -> &str {
            "toggle"
        }

        fn write(&self, event: &EvidenceEvent) -> Result<(), EvidenceSinkError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(EvidenceSinkError {
                    sink: self.name().to_string(),
                    message: "simulated outage".to_string(),
                });
            }
            self.events.write().push(event.clone());
            Ok(())
        }
    }

    fn payload(label: &str) -> EvidencePayload {
        EvidencePayload {
            gov_tx_id: Some(format!("GTX-{label}")),
            session_id: Some("sess-evidence".to_string()),
            run_id: Some("run-evidence".to_string()),
            context_hash: Some(sha256_hex(label.as_bytes())),
            outcome: label.to_string(),
            ..EvidencePayload::default()
        }
    }

    #[test]
    fn chain_and_signatures_verify() {
        let crypto = Arc::new(CryptoEngine::new("evidence-chain"));
        let plane = EvidencePlane::new(crypto, None);
        plane.append(EvidenceEventType::ContextApproved, payload("one"));
        plane.append(EvidenceEventType::ActionAuthorized, payload("two"));
        plane.append(EvidenceEventType::CapabilityConsumed, payload("three"));

        let events = plane.snapshot();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[2].previous_event_hash, events[1].event_hash);
        assert_eq!(EvidencePlane::verify_snapshot(&events), Ok(()));
    }

    #[test]
    fn mutation_is_detected() {
        let crypto = Arc::new(CryptoEngine::new("evidence-mutation"));
        let plane = EvidencePlane::new(crypto, None);
        plane.append(EvidenceEventType::ActionAuthorized, payload("authorized"));
        let mut events = plane.snapshot();
        events[0].payload.outcome = "tampered".to_string();

        assert!(matches!(
            EvidencePlane::verify_snapshot(&events),
            Err(EvidenceVerificationError::HashMismatch { sequence: 1 })
        ));
    }

    #[test]
    fn deletion_and_reordering_are_detected() {
        let crypto = Arc::new(CryptoEngine::new("evidence-order"));
        let plane = EvidencePlane::new(crypto, None);
        for label in ["one", "two", "three"] {
            plane.append(EvidenceEventType::ActionAuthorized, payload(label));
        }

        let events = plane.snapshot();
        let deleted = vec![events[0].clone(), events[2].clone()];
        assert!(EvidencePlane::verify_snapshot(&deleted).is_err());

        let reordered = vec![events[1].clone(), events[0].clone(), events[2].clone()];
        assert!(EvidencePlane::verify_snapshot(&reordered).is_err());
    }

    #[test]
    fn signed_checkpoint_links_a_new_epoch() {
        let crypto = Arc::new(CryptoEngine::new("evidence-checkpoint"));
        let first = EvidencePlane::new(Arc::clone(&crypto), None);
        first.append(EvidenceEventType::ContextApproved, payload("first"));
        let checkpoint = first.checkpoint();
        assert!(checkpoint.verify());

        let second = EvidencePlane::from_checkpoint(crypto, &checkpoint, None)
            .expect("valid checkpoint should resume");
        second.append(EvidenceEventType::ActionAuthorized, payload("second"));
        let events = second.snapshot();
        assert_eq!(events[0].epoch_parent_hash, Some(checkpoint.head_hash));
        assert_eq!(EvidencePlane::verify_snapshot(&events), Ok(()));
    }

    #[test]
    fn sink_failure_keeps_local_evidence_and_retries_in_order() {
        let crypto = Arc::new(CryptoEngine::new("evidence-sink"));
        let sink = Arc::new(ToggleSink::new(true));
        let sink_dyn: Arc<dyn EvidenceSink> = sink.clone();
        let plane = EvidencePlane::new(crypto, Some(sink_dyn));

        let first = plane.append(EvidenceEventType::ActionAuthorized, payload("one"));
        assert!(matches!(
            first.sink_status,
            EvidenceSinkStatus::Deferred { .. }
        ));
        let second = plane.append(EvidenceEventType::ActionAuthorized, payload("two"));
        assert!(matches!(
            second.sink_status,
            EvidenceSinkStatus::Deferred { .. }
        ));
        assert_eq!(plane.snapshot().len(), 2);
        assert_eq!(plane.pending_sink_count(), 2);

        sink.fail.store(false, Ordering::SeqCst);
        assert_eq!(plane.flush_pending().expect("sink recovery"), 2);
        assert_eq!(plane.pending_sink_count(), 0);
        let delivered = sink.events.read();
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0].sequence, 1);
        assert_eq!(delivered[1].sequence, 2);
    }

    #[test]
    fn signed_checkpoint_detects_tail_truncation() {
        let crypto = Arc::new(CryptoEngine::new("evidence-tail"));
        let plane = EvidencePlane::new(crypto, None);
        for label in ["one", "two", "three"] {
            plane.append(EvidenceEventType::ActionAuthorized, payload(label));
        }
        let checkpoint = plane.checkpoint();
        let mut truncated = plane.snapshot();
        truncated.pop();

        assert!(matches!(
            EvidencePlane::verify_snapshot_against_checkpoint(&truncated, &checkpoint),
            Err(EvidenceVerificationError::InvalidSequence {
                expected: 3,
                actual: 2
            })
        ));
    }

    #[test]
    fn serialized_evidence_does_not_expose_raw_resource_locator() {
        let crypto = Arc::new(CryptoEngine::new("evidence-resource-redaction"));
        let plane = EvidencePlane::new(crypto, None);
        plane.append(
            EvidenceEventType::ActionAuthorized,
            EvidencePayload {
                resource_locator_hash: Some(CryptoEngine::compute_hash("customer/3817")),
                outcome: "AUTHORIZED".to_string(),
                ..EvidencePayload::default()
            },
        );

        let encoded = serde_json::to_string(&plane.snapshot()).expect("serialize evidence");
        assert!(!encoded.contains("customer/3817"));
        assert!(encoded.contains(&CryptoEngine::compute_hash("customer/3817")));
    }

    fn test_context() -> ModelContextEnvelope {
        ModelContextEnvelope {
            schema_version: MODEL_CONTEXT_SCHEMA_VERSION.to_string(),
            session_id: "sess-wrapper".to_string(),
            run_id: "run-wrapper".to_string(),
            principal_id: "test-principal".to_string(),
            provider_id: "test-provider".to_string(),
            model_id: "test-model".to_string(),
            policy_version: "policy-test-v1".to_string(),
            policy_hash: sha256_hex(b"policy"),
            provider_context_hash: sha256_hex(b"provider-context"),
            system_prompt_hash: sha256_hex(b"system-prompt"),
            tool_schema_hash: sha256_hex(b"tool-schema"),
            workspace_manifest_hash: sha256_hex(b"workspace-manifest"),
            segments: vec![ContextSegment {
                ordinal: 0,
                role: ContextRole::User,
                source: ContextSource::ExternalUser,
                content: "hello".to_string(),
                tool_name: None,
                attachment_id: None,
            }],
            attachments: Vec::<ContextAttachment>::new(),
            context_hash: String::new(),
        }
        .seal()
        .expect("test context seals")
    }

    #[test]
    fn wrapper_records_context_action_consume_and_replay() {
        let governed = EvidenceGovernedPipeline::default_for_test().expect("pipeline");
        let envelope = test_context();
        let context_result = governed
            .inbound_context(&envelope, "GTX-context-wrapper")
            .expect("valid context envelope");
        assert!(matches!(context_result, EnforcementResult::Approved(_)));

        let request = ActionAuthorizationRequest {
            gov_tx_id: "GTX-action-wrapper".to_string(),
            session_id: envelope.session_id.clone(),
            run_id: envelope.run_id.clone(),
            principal_fingerprint: "trusted-wrapper".to_string(),
            tool_name: "write".to_string(),
            arguments: serde_json::json!({"value":"synthetic"}),
            resource_kind: "record".to_string(),
            resource_locator: "customer/3817".to_string(),
            tool_call_id: "call-wrapper-1".to_string(),
            context_hash: envelope.context_hash.clone(),
            policy_version: "policy-test-v1".to_string(),
            policy_hash: sha256_hex(b"policy"),
        };
        let token = governed
            .authorize_action_execution(request)
            .expect("action capability");

        let binding = PresentedBinding {
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
        };

        assert_eq!(
            governed.consume_provider_capability(&binding),
            ConsumeOutcome::Authorized
        );
        assert_eq!(
            governed.consume_provider_capability(&binding),
            ConsumeOutcome::AlreadyConsumed
        );

        let events = governed.evidence().snapshot();
        assert_eq!(
            events
                .iter()
                .map(|event| event.event_type)
                .collect::<Vec<_>>(),
            vec![
                EvidenceEventType::ContextApproved,
                EvidenceEventType::ActionAuthorized,
                EvidenceEventType::CapabilityConsumed,
                EvidenceEventType::CapabilityRejected,
            ]
        );
        assert_eq!(events[3].payload.outcome, "CAPABILITY_REPLAY_REJECTED");
        assert_eq!(EvidencePlane::verify_snapshot(&events), Ok(()));
    }
}
