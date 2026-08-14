//! LOGOS GovMem V2 — RL-Enhanced Multi-Turn Attack Detection
//!
//! Extends GovMem V1 (session_memory.rs) with:
//! - Semantic embeddings for drift detection
//! - Memory Policy Agent (RL model)
//! - Optional session and agent metadata tracking
//! - Cross-layer signal aggregation
//!
//! LOGOS Governance Systems Inc. // US Provisional Patent No. 63/953,447

use crate::{
    governance_signal::{GovernanceSignal, Severity},
    session_memory::SessionMemory,
};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// ═══════════════════════════════════════════════════════════════════════════
//  GOVMEM V2 CORE
// ═══════════════════════════════════════════════════════════════════════════

pub struct GovMem {
    // Tier 1: the shared per-session tactical accumulator (session_memory.rs).
    // Gate 3: this is the SAME Arc that GovernancePipeline.session_memories
    // holds — cloned, never a second independent store — so writes from
    // Pipeline::ingest_to_memory are immediately visible here. should_block()
    // reads this directly; it is what GovMemMode::V1's doc comment ("Rule-based
    // only — existing session_memory.rs") always meant to be, now actually wired.
    session_memories: Arc<RwLock<HashMap<String, SessionMemory>>>,

    // V2 enhancements
    v2_sessions: Arc<RwLock<HashMap<String, GovMemSession>>>,

    // Runtime-wide blocking threshold. Caller-supplied department
    // metadata never selects authorization or blocking policy.
    block_threshold: f32,

    // Mode flag
    mode: GovMemMode,

    // Embedding model (lazy-loaded)
    #[allow(dead_code)] // Tracked gap — see FINDINGS.md:
    // GOVMEM_V2_SCAFFOLDING_NOT_WIRED
    embedding_model: Option<Arc<SentenceEmbedder>>,

    // MPA (lazy-loaded)
    #[allow(dead_code)] // Tracked gap — see FINDINGS.md:
    // GOVMEM_V2_SCAFFOLDING_NOT_WIRED
    mpa: Option<Arc<MemoryPolicyAgent>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GovMemMode {
    V1, // Rule-based only (existing session_memory.rs)
    V2, // RL-enhanced with embeddings + MPA
}

/// V2 Session with semantic tracking
#[derive(Debug, Clone)]
pub struct GovMemSession {
    // Core identity
    pub session_id: String,
    pub created_at: DateTime<Utc>,

    // Optional caller metadata. It is observational only and must never
    // select authorization, capability scope, or blocking thresholds.
    pub department_id: Option<String>,
    pub agent_id: Option<String>, // EXE-01, ENG-02, etc.

    // Message history
    pub messages: Vec<Message>,

    // Semantic trajectory (V2 feature)
    pub embedding_trajectory: Vec<Vec<f32>>,

    // Cross-layer signals (from all 12 governance-spine modules)
    pub layer_signals: Vec<LayerSignal>,

    // V1 compatibility
    pub v1_session: SessionMemory,

    // V2 scores
    pub semantic_drift_score: f32,
    pub mpa_anomaly_score: f32,

    // Governance state
    pub flagged_for_review: bool,
    pub human_label: Option<HumanLabel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub turn: u32,
    pub timestamp: DateTime<Utc>,
    pub content: String,
    pub direction: MessageDirection,
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageDirection {
    UserToSystem,
    SystemToUser,
}

#[derive(Debug, Clone, Serialize)]
pub struct LayerSignal {
    pub layer: String, // "sentinel", "corridor_in", "corridor_out", "overwatch", "oim", "arbiter", "constitution"
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub violation: Option<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HumanLabel {
    TrueAttack,
    FalsePositive,
    Benign,
    Uncertain,
}

// ═══════════════════════════════════════════════════════════════════════════
//  GOVMEM IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════

/// Default GovMem blocking threshold.
///
/// This preserves the behavior of callers that did not supply an ASF
/// department identity: block when `1.0 - threshold_modifier()` exceeds 0.7.
///
/// Deployments may tighten this with GOVMEM_BLOCK_THRESHOLD. Configuration is
/// trusted operator input, not request/model input. Invalid configuration
/// terminates startup rather than silently changing governance behavior.
const DEFAULT_BLOCK_THRESHOLD: f32 = 0.7;

fn valid_block_threshold(value: f32) -> bool {
    value.is_finite() && (0.0..1.0).contains(&value)
}

fn configured_block_threshold() -> f32 {
    match std::env::var("GOVMEM_BLOCK_THRESHOLD") {
        Err(std::env::VarError::NotPresent) => DEFAULT_BLOCK_THRESHOLD,

        Err(err) => {
            panic!("GOVMEM_BLOCK_THRESHOLD could not be read safely: {err}")
        }

        Ok(raw) => {
            let value = raw.parse::<f32>().unwrap_or_else(|_| {
                panic!("GOVMEM_BLOCK_THRESHOLD must be a finite number in [0.0, 1.0); got {raw:?}")
            });

            if !valid_block_threshold(value) {
                panic!("GOVMEM_BLOCK_THRESHOLD must be a finite number in [0.0, 1.0); got {raw:?}");
            }

            value
        }
    }
}

impl GovMem {
    pub fn new(mode: GovMemMode) -> Self {
        Self::new_with_sessions(Arc::new(RwLock::new(HashMap::new())), mode)
    }

    /// Gate 3 (Tier 1 convergence): construct a GovMem that shares the
    /// caller's own session_memories Arc — the same map GovernancePipeline
    /// updates on every turn — instead of an independent, never-populated
    /// one. See the `session_memories` field doc for why this must be a
    /// clone of the same Arc, not a fresh store.
    pub fn new_with_sessions(
        session_memories: Arc<RwLock<HashMap<String, SessionMemory>>>,
        mode: GovMemMode,
    ) -> Self {
        Self {
            session_memories,
            v2_sessions: Arc::new(RwLock::new(HashMap::new())),
            block_threshold: configured_block_threshold(),
            mode,
            embedding_model: None,
            mpa: None,
        }
    }

    /// Record a turn in the session
    pub fn record_turn(
        &self,
        session_id: &str,
        message: &str,
        direction: MessageDirection,
        blocked: bool,
        department_id: Option<&str>,
        agent_id: Option<&str>,
    ) {
        match self.mode {
            GovMemMode::V1 => {
                // Gate 3: Tier 1 accumulation (session_memory.rs's SessionMemory)
                // happens directly against the shared session_memories map via
                // GovernancePipeline::ingest_to_memory, not through this method —
                // should_block() reads that map directly. Nothing to do here for V1.
            }
            GovMemMode::V2 => {
                self.record_turn_v2(
                    session_id,
                    message,
                    direction,
                    blocked,
                    department_id,
                    agent_id,
                );
            }
        }
    }

    fn record_turn_v2(
        &self,
        session_id: &str,
        message: &str,
        direction: MessageDirection,
        blocked: bool,
        department_id: Option<&str>,
        agent_id: Option<&str>,
    ) {
        let mut sessions = self.v2_sessions.write();
        let session = sessions
            .entry(session_id.to_string())
            .or_insert_with(|| GovMemSession {
                session_id: session_id.to_string(),
                created_at: Utc::now(),
                department_id: department_id.map(String::from),
                agent_id: agent_id.map(String::from),
                messages: Vec::new(),
                embedding_trajectory: Vec::new(),
                layer_signals: Vec::new(),
                v1_session: SessionMemory::new(session_id),
                semantic_drift_score: 0.0,
                mpa_anomaly_score: 0.0,
                flagged_for_review: false,
                human_label: None,
            });

        let turn = session.messages.len() as u32 + 1;
        session.messages.push(Message {
            turn,
            timestamp: Utc::now(),
            content: message.to_string(),
            direction,
            blocked,
        });

        // TODO: Compute embedding if model loaded
        // session.embedding_trajectory.push(embedding);

        // TODO: Calculate semantic drift
        // session.semantic_drift_score = self.calculate_drift(&session.embedding_trajectory);

        // TODO: Run MPA if loaded
        // session.mpa_anomaly_score = self.mpa_predict(session);
    }

    /// Record a signal from any layer
    pub fn record_layer_signal(&self, session_id: &str, layer: &str, signal: &GovernanceSignal) {
        if self.mode != GovMemMode::V2 {
            return;
        }

        let mut sessions = self.v2_sessions.write();
        if let Some(session) = sessions.get_mut(session_id) {
            session.layer_signals.push(LayerSignal {
                layer: layer.to_string(),
                timestamp: Utc::now(),
                severity: signal.severity.clone(),
                violation: signal.violation_class.clone(),
                confidence: signal.confidence,
            });
        }
    }

    /// Get drift score for a session
    pub fn get_drift_score(&self, session_id: &str) -> f32 {
        match self.mode {
            GovMemMode::V1 => {
                // V1: Return 0.0 (no semantic drift in V1)
                0.0
            }
            GovMemMode::V2 => {
                let sessions = self.v2_sessions.read();
                sessions
                    .get(session_id)
                    .map(|s| s.semantic_drift_score)
                    .unwrap_or(0.0)
            }
        }
    }

    /// Check whether accumulated Tier 1 SessionMemory state exceeds the
    /// runtime-wide GovMem blocking threshold.
    ///
    /// `department_id` remains accepted temporarily for API compatibility
    /// and optional metadata tracking, but it has no authority-bearing
    /// effect. Request/model-controlled identity must not select policy.
    ///
    /// `block_score` is `1.0 - threshold_modifier()`: Clear=0.0,
    /// Watching=0.15, Elevated=0.35, Escalated=0.60, Locked=1.0.
    pub fn should_block(&self, session_id: &str, _department_id: Option<&str>) -> bool {
        let threshold = self.block_threshold;

        let sessions = self.session_memories.read();
        match sessions.get(session_id) {
            Some(mem) => {
                let block_score = 1.0 - mem.threshold_modifier();
                block_score > threshold
            }
            None => false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  PLACEHOLDER TYPES (To be implemented in Phase 2)
// ═══════════════════════════════════════════════════════════════════════════

pub struct SentenceEmbedder {
    // TODO: rust-bert or candle implementation
}

pub struct MemoryPolicyAgent {
    // TODO: ONNX model loader
}

impl SentenceEmbedder {
    pub fn encode(&self, _text: &str) -> Vec<f32> {
        // TODO: Actual embedding
        vec![0.0; 384] // Placeholder 384-dim vector
    }
}

impl MemoryPolicyAgent {
    pub fn predict(&self, _session: &GovMemSession) -> f32 {
        // TODO: Actual MPA inference
        0.0
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;
    use crate::session_memory::MemoryState;

    fn govmem_with_state(session_id: &str, state: MemoryState) -> GovMem {
        let session_memories: Arc<RwLock<HashMap<String, SessionMemory>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let mut memory = SessionMemory::new(session_id);
        memory.memory_state = state;

        session_memories
            .write()
            .insert(session_id.to_string(), memory);

        GovMem {
            session_memories,
            v2_sessions: Arc::new(RwLock::new(HashMap::new())),
            block_threshold: DEFAULT_BLOCK_THRESHOLD,
            mode: GovMemMode::V1,
            embedding_model: None,
            mpa: None,
        }
    }

    #[test]
    fn default_block_threshold_is_valid() {
        assert!(valid_block_threshold(DEFAULT_BLOCK_THRESHOLD));
        assert_eq!(DEFAULT_BLOCK_THRESHOLD, 0.7);
    }

    #[test]
    fn department_metadata_cannot_change_block_threshold() {
        let session = "metadata-cannot-select-policy";
        let govmem = govmem_with_state(session, MemoryState::Escalated);

        // Escalated => block_score 0.60, below the runtime default 0.70.
        assert!(!govmem.should_block(session, None));
        assert!(!govmem.should_block(session, Some("SEC")));
        assert!(!govmem.should_block(session, Some("LGL")));
        assert!(!govmem.should_block(session, Some("ATTACKER-CONTROLLED")));
    }

    #[test]
    fn locked_session_blocks_regardless_of_department_metadata() {
        let session = "locked-is-runtime-wide";
        let govmem = govmem_with_state(session, MemoryState::Locked);

        assert!(govmem.should_block(session, None));
        assert!(govmem.should_block(session, Some("SEC")));
        assert!(govmem.should_block(session, Some("LGL")));
        assert!(govmem.should_block(session, Some("ATTACKER-CONTROLLED")));
    }

    #[test]
    fn invalid_block_threshold_values_are_rejected_by_validator() {
        assert!(!valid_block_threshold(-0.01));
        assert!(!valid_block_threshold(1.0));
        assert!(!valid_block_threshold(f32::NAN));
        assert!(!valid_block_threshold(f32::INFINITY));

        assert!(valid_block_threshold(0.0));
        assert!(valid_block_threshold(0.5));
        assert!(valid_block_threshold(0.999));
    }
}
