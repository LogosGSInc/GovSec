//! LOGOS Sentinel OverWatch — Persistent Session Memory (Anti-Alzheimer's Layer)
//!
//! Two-tier threat accumulation:
//!   Tier 1 — SessionMemory: Per-session tactical accumulator (Sentinel gate)
//!   Tier 2 — StrategicMemory: Cross-session actor profiling (Abigail meta-cognition)
//!
//! Closes the 3-6% gap where multi-turn drift campaigns bypass
//! single-prompt evaluation by accumulating individually-benign messages
//! toward a malicious culmination.
//!
//! LOGOS Governance Systems Inc. // US Provisional Patent No. 63/953,447

use crate::governance_signal::{GovernanceSignal, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use chrono::{DateTime, Utc};

/// A1 fast-follow: durable session_id (A1) makes long-lived conversations
/// the norm rather than the exception, so unbounded per-turn history here
/// goes from theoretical to load-bearing. Mirrors the same default as
/// Python's ABIGAIL_SESSION_HISTORY_WINDOW (abigail_hardened_enhanced.py) —
/// a bounded recent window, oldest dropped first, not a new mechanism.
/// turn_count (the cumulative counter used for velocity) is NOT affected —
/// only the retained TurnRecord detail is windowed.
const MAX_RETAINED_TURNS: usize = 20;

// ═══════════════════════════════════════════════════════════════════════════
//  TIER 1 — SESSION MEMORY (Sentinel Gate — Tactical)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RequestClassification {
    Benign,
    Informational,
    Boundary,        // "hypothetically...", "what if..."
    Escalation,      // Pushing limits
    AuthorityClaim,  // "I'm the developer", "admin override"
    Extraction,      // Seeking system internals
    Obfuscated,      // Encoding tricks
}

/// Per-turn signal record
#[derive(Debug, Clone, Serialize)]
struct TurnRecord {
    turn: u32,
    timestamp: DateTime<Utc>,
    severity: String,
    confidence: f32,
    classification: RequestClassification,
    violation_class: Option<String>,
}

/// Per-session behavioral accumulator
#[derive(Debug, Clone)]
pub struct SessionMemory {
    pub session_id: String,
    created_at: DateTime<Utc>,
    turns: Vec<TurnRecord>,
    pub turn_count: u32,

    // Accumulated metrics
    pub cumulative_threat: f32,
    pub threat_trajectory: f32,
    pub max_confidence: f32,
    pub escalation_velocity: f32,

    // Pattern counters
    pub boundary_probes: u32,
    pub authority_claims: u32,
    pub extraction_attempts: u32,
    pub obfuscation_count: u32,

    // State
    pub memory_state: MemoryState,
    pub escalated: bool,
    pub escalation_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MemoryState {
    Clear,      // No accumulated concern
    Watching,   // Trajectory trending — heightened scrutiny
    Elevated,   // Multiple signals accumulating
    Escalated,  // Threshold crossed — force checkpoint
    Locked,     // Session should be hard-locked
}

#[derive(Debug, Clone)]
pub struct MemoryConfig {
    pub watching_threshold: f32,
    pub elevated_threshold: f32,
    pub escalated_threshold: f32,
    pub locked_threshold: f32,
    pub velocity_trigger: f32,
    pub boundary_probe_limit: u32,
    pub decay_factor: f32,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            watching_threshold: 0.8,
            elevated_threshold: 1.5,
            escalated_threshold: 2.5,
            locked_threshold: 4.0,
            velocity_trigger: 0.15,
            boundary_probe_limit: 3,
            decay_factor: 0.95,
        }
    }
}

/// Verdict returned to the pipeline after accumulation
#[derive(Debug, Clone)]
pub struct MemoryVerdict {
    pub state: MemoryState,
    pub cumulative_threat: f32,
    pub trajectory: f32,
    pub force_checkpoint: bool,
    /// Multiply against arbiter confidence thresholds.
    /// 1.0 = normal, 0.5 = twice as strict, 0.0 = block everything.
    pub threshold_modifier: f32,
    pub state_changed: bool,
    pub escalation_reason: Option<String>,
}

impl SessionMemory {
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
            created_at: Utc::now(),
            turns: Vec::new(),
            turn_count: 0,
            cumulative_threat: 0.0,
            threat_trajectory: 0.0,
            max_confidence: 0.0,
            escalation_velocity: 0.0,
            boundary_probes: 0,
            authority_claims: 0,
            extraction_attempts: 0,
            obfuscation_count: 0,
            memory_state: MemoryState::Clear,
            escalated: false,
            escalation_reason: None,
        }
    }

    /// Ingest a governance signal from any layer and update accumulation.
    /// Called after each layer processes a payload.
    pub fn ingest_signal(
        &mut self,
        signal: &GovernanceSignal,
        classification: RequestClassification,
        config: &MemoryConfig,
    ) -> MemoryVerdict {
        self.turn_count += 1;

        let record = TurnRecord {
            turn: self.turn_count,
            timestamp: Utc::now(),
            severity: signal.severity.to_string(),
            confidence: signal.confidence,
            classification: classification.clone(),
            violation_class: signal.violation_class.clone(),
        };
        self.turns.push(record);
        if self.turns.len() > MAX_RETAINED_TURNS {
            let overflow = self.turns.len() - MAX_RETAINED_TURNS;
            self.turns.drain(0..overflow);
        }

        // Update pattern counters
        match &classification {
            RequestClassification::Boundary => self.boundary_probes += 1,
            RequestClassification::AuthorityClaim => self.authority_claims += 1,
            RequestClassification::Extraction => self.extraction_attempts += 1,
            RequestClassification::Obfuscated => self.obfuscation_count += 1,
            _ => {}
        }

        // Apply decay — older signals fade
        self.cumulative_threat *= config.decay_factor;

        // Weight the current signal
        let mut weighted = signal.confidence;

        // Severity multiplier
        weighted *= match signal.severity {
            Severity::None => 0.0,
            Severity::Low => 0.3,
            Severity::Medium => 0.6,
            Severity::High => 1.0,
            Severity::Critical => 1.5,
        };

        // Pattern bonuses
        if self.boundary_probes > config.boundary_probe_limit {
            weighted += 0.1 * (self.boundary_probes - config.boundary_probe_limit) as f32;
        }
        if classification == RequestClassification::AuthorityClaim {
            weighted += 0.2;
        }
        if self.extraction_attempts > 1 {
            weighted += 0.15 * self.extraction_attempts as f32;
        }

        // Accumulate
        self.cumulative_threat += weighted;

        // Violation class threat amplifiers (BD1A taxonomy)
        if let Some(vc) = &signal.violation_class {
            match vc.as_str() {
                "MODEL_EXFIL"              => self.cumulative_threat += 10.0,
                "AUTHORITY_CLAIM"          => self.cumulative_threat += 8.0,
                "AGENT_BROADCAST_OVERRIDE" => self.cumulative_threat += 8.0,
                "GOV_SURFACE_INTEL"        => self.cumulative_threat += 4.0,
                "RUNTIME_DOS"              => self.cumulative_threat += 6.0,
                "ZERO_WIDTH_CHARS"         => self.cumulative_threat += 5.0,
                "L33T_OBFUSCATION"         => self.cumulative_threat += 5.0,
                "BASE64_INJECTION"         => self.cumulative_threat += 7.0,
                _ => {}
            }
        }
        self.max_confidence = self.max_confidence.max(signal.confidence);

        // Compute trajectory (slope over last 5 turns)
        self.threat_trajectory = self.compute_trajectory(5);
        self.escalation_velocity = if self.turn_count > 1 {
            self.cumulative_threat / self.turn_count as f32
        } else {
            weighted
        };

        // Determine state
        let previous_state = self.memory_state.clone();
        self.memory_state = self.compute_state(config);

        let state_changed = self.memory_state != previous_state;
        let force_checkpoint = self.memory_state == MemoryState::Escalated
            || self.memory_state == MemoryState::Locked;

        if force_checkpoint && !self.escalated {
            self.escalated = true;
            self.escalation_reason = Some(format!(
                "SessionMemory: cumulative={:.2} turn={} trajectory={:.3} \
                 velocity={:.3} probes={} auth={} extract={}",
                self.cumulative_threat, self.turn_count,
                self.threat_trajectory, self.escalation_velocity,
                self.boundary_probes, self.authority_claims,
                self.extraction_attempts,
            ));
        }

        MemoryVerdict {
            state: self.memory_state.clone(),
            cumulative_threat: self.cumulative_threat,
            trajectory: self.threat_trajectory,
            force_checkpoint,
            threshold_modifier: self.threshold_modifier(),
            state_changed,
            escalation_reason: self.escalation_reason.clone(),
        }
    }

    /// Threshold modifier — tightens arbiter thresholds based on accumulated state
    pub fn threshold_modifier(&self) -> f32 {
        match self.memory_state {
            MemoryState::Clear    => 1.0,
            MemoryState::Watching => 0.85,   // 15% tighter
            MemoryState::Elevated => 0.65,   // 35% tighter
            MemoryState::Escalated => 0.40,  // 60% tighter
            MemoryState::Locked   => 0.0,    // Block everything
        }
    }

    fn compute_state(&self, config: &MemoryConfig) -> MemoryState {
        // Velocity can trigger immediate elevation
        if self.escalation_velocity > config.velocity_trigger
            && self.turn_count >= 3
            && self.memory_state == MemoryState::Clear
        {
            return MemoryState::Elevated;
        }

        if self.cumulative_threat >= config.locked_threshold {
            MemoryState::Locked
        } else if self.cumulative_threat >= config.escalated_threshold {
            MemoryState::Escalated
        } else if self.cumulative_threat >= config.elevated_threshold {
            MemoryState::Elevated
        } else if self.cumulative_threat >= config.watching_threshold {
            MemoryState::Watching
        } else {
            MemoryState::Clear
        }
    }

    /// Linear regression slope over last N turns
    fn compute_trajectory(&self, window: usize) -> f32 {
        let recent: Vec<&TurnRecord> = self.turns.iter().rev().take(window).collect();
        if recent.len() < 2 { return 0.0; }

        let n = recent.len() as f32;
        let mut sum_x = 0.0f32;
        let mut sum_y = 0.0f32;
        let mut sum_xy = 0.0f32;
        let mut sum_xx = 0.0f32;

        for (i, turn) in recent.iter().rev().enumerate() {
            let x = i as f32;
            let y = turn.confidence;
            sum_x += x;
            sum_y += y;
            sum_xy += x * y;
            sum_xx += x * x;
        }

        let denominator = n * sum_xx - sum_x * sum_x;
        if denominator.abs() < 1e-6 { return 0.0; }

        (n * sum_xy - sum_x * sum_y) / denominator
    }

    /// Export fingerprint for Abigail strategic memory
    pub fn to_fingerprint(&self) -> SessionFingerprint {
        SessionFingerprint {
            session_id: self.session_id.clone(),
            created_at: self.created_at,
            turn_count: self.turn_count,
            final_cumulative_threat: self.cumulative_threat,
            max_confidence: self.max_confidence,
            peak_trajectory: self.threat_trajectory,
            boundary_probes: self.boundary_probes,
            authority_claims: self.authority_claims,
            extraction_attempts: self.extraction_attempts,
            obfuscation_count: self.obfuscation_count,
            final_state: self.memory_state.clone(),
            escalated: self.escalated,
            behavior_hash: self.compute_behavior_hash(),
        }
    }

    fn compute_behavior_hash(&self) -> u64 {
        let mut hash: u64 = 0xcbf29ce484222325;
        for turn in &self.turns {
            let type_byte = match turn.classification {
                RequestClassification::Benign         => 0u8,
                RequestClassification::Informational  => 1,
                RequestClassification::Boundary       => 2,
                RequestClassification::Escalation     => 3,
                RequestClassification::AuthorityClaim => 4,
                RequestClassification::Extraction     => 5,
                RequestClassification::Obfuscated     => 6,
            };
            hash ^= type_byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }
}


// ═══════════════════════════════════════════════════════════════════════════
//  TIER 2 — STRATEGIC MEMORY (Abigail Meta-Cognition — Cross-Session)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFingerprint {
    pub session_id: String,
    pub created_at: DateTime<Utc>,
    pub turn_count: u32,
    pub final_cumulative_threat: f32,
    pub max_confidence: f32,
    pub peak_trajectory: f32,
    pub boundary_probes: u32,
    pub authority_claims: u32,
    pub extraction_attempts: u32,
    pub obfuscation_count: u32,
    pub final_state: MemoryState,
    pub escalated: bool,
    pub behavior_hash: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StrategicThreatLevel {
    Unknown,
    Clean,
    Cautious,
    Suspicious,
    Hostile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorProfile {
    pub actor_id: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub total_sessions: u32,
    pub escalated_sessions: u32,
    pub session_fingerprints: Vec<SessionFingerprint>,
    pub strategic_threat_level: StrategicThreatLevel,
    pub cumulative_risk_score: f32,
    pub campaign_detected: bool,
    pub campaign_description: Option<String>,
    pub recommended_initial_state: MemoryState,
    pub recommended_threshold_modifier: f32,
}

/// Abigail's advice when a new session starts
#[derive(Debug, Clone)]
pub struct SessionStartAdvice {
    pub initial_state: MemoryState,
    pub threshold_modifier: f32,
    pub advisory: Option<String>,
}

pub struct StrategicMemory {
    actors: HashMap<String, ActorProfile>,
    /// GS-BUILD-01: disk location for the durable snapshot. `None` ==> in-memory
    /// only (the legacy behaviour, retained for tests and for deployments that
    /// have not set SENTOW_MEMORY_PATH). `Some(path)` ==> every mutation is
    /// snapshotted to disk and the map is reloaded from disk on construction,
    /// so cross-session actor profiles survive a process restart.
    memory_path: Option<PathBuf>,
}

impl Default for StrategicMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl StrategicMemory {
    /// In-memory-only store (no durability). Retained for tests and for the
    /// no-path deployment case; prefer `with_path` in production.
    pub fn new() -> Self {
        Self { actors: HashMap::new(), memory_path: None }
    }

    /// GS-BUILD-01: durable store. If `path` is `Some` and the file exists, the
    /// actor map is reloaded from it (a corrupt/unreadable file is logged and
    /// treated as an empty start rather than crashing the gate — availability
    /// over a hard fail on a non-security-critical read). Subsequent mutations
    /// are persisted via `persist()`.
    pub fn with_path(path: Option<PathBuf>) -> Self {
        let actors = match &path {
            Some(p) if p.exists() => match std::fs::read_to_string(p) {
                Ok(raw) => match serde_json::from_str::<HashMap<String, ActorProfile>>(&raw) {
                    Ok(map) => {
                        eprintln!("[MEMORY] StrategicMemory loaded {} actor profile(s) from {}",
                            map.len(), p.display());
                        map
                    }
                    Err(e) => {
                        eprintln!("[MEMORY] WARN: could not parse {} ({}); starting empty",
                            p.display(), e);
                        HashMap::new()
                    }
                },
                Err(e) => {
                    eprintln!("[MEMORY] WARN: could not read {} ({}); starting empty",
                        p.display(), e);
                    HashMap::new()
                }
            },
            _ => HashMap::new(),
        };
        Self { actors, memory_path: path }
    }

    /// True when this store is backed by disk (mutations survive a restart).
    pub fn is_durable(&self) -> bool {
        self.memory_path.is_some()
    }

    /// Number of distinct actor profiles currently held (observability).
    pub fn actor_count(&self) -> usize {
        self.actors.len()
    }

    /// Total sessions recorded for an actor (0 if unknown).
    pub fn total_sessions(&self, actor_id: &str) -> u32 {
        self.actors.get(actor_id).map(|p| p.total_sessions).unwrap_or(0)
    }

    /// Escalated sessions recorded for an actor (0 if unknown).
    pub fn escalated_sessions(&self, actor_id: &str) -> u32 {
        self.actors.get(actor_id).map(|p| p.escalated_sessions).unwrap_or(0)
    }

    /// Atomically snapshot the actor map to disk. Returns `true` only when a
    /// durable write actually completed. No configured path ==> `false`
    /// (in-memory only). Write goes to a temp file then rename, so a crash
    /// mid-write cannot leave a truncated snapshot.
    fn persist(&self) -> bool {
        let path = match &self.memory_path {
            Some(p) => p,
            None => return false,
        };
        let json = match serde_json::to_string(&self.actors) {
            Ok(j) => j,
            Err(e) => { eprintln!("[MEMORY] ERROR: serialize failed ({})", e); return false; }
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    eprintln!("[MEMORY] ERROR: mkdir {} failed ({})", parent.display(), e);
                    return false;
                }
            }
        }
        let tmp = path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
            eprintln!("[MEMORY] ERROR: write {} failed ({})", tmp.display(), e);
            return false;
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            eprintln!("[MEMORY] ERROR: rename into {} failed ({})", path.display(), e);
            return false;
        }
        true
    }

    /// Called when a session ends — Sentinel hands fingerprint to Abigail.
    /// GS-BUILD-01: returns whether the updated profile was durably persisted
    /// to disk (`false` in the in-memory-only configuration).
    pub fn ingest_session(&mut self, actor_id: &str, fingerprint: SessionFingerprint) -> bool {
        let now = Utc::now();

        let profile = self.actors
            .entry(actor_id.to_string())
            .or_insert_with(|| ActorProfile {
                actor_id: actor_id.to_string(),
                first_seen: now,
                last_seen: now,
                total_sessions: 0,
                escalated_sessions: 0,
                session_fingerprints: Vec::new(),
                strategic_threat_level: StrategicThreatLevel::Unknown,
                cumulative_risk_score: 0.0,
                campaign_detected: false,
                campaign_description: None,
                recommended_initial_state: MemoryState::Clear,
                recommended_threshold_modifier: 1.0,
            });

        profile.last_seen = now;
        profile.total_sessions += 1;
        if fingerprint.escalated { profile.escalated_sessions += 1; }

        // 30% carry-forward of session threat
        profile.cumulative_risk_score += fingerprint.final_cumulative_threat * 0.3;

        profile.session_fingerprints.push(fingerprint);

        // Re-evaluate threat level
        Self::evaluate_actor(profile);

        // GS-BUILD-01: durably snapshot the mutated map so this profile
        // survives a restart. Poisoned-turn carry-over across sessions is now
        // the write path GS-2.4-REVISED will gate.
        self.persist()
    }

    /// Advise Sentinel when a new session starts
    pub fn advise_session_start(&self, actor_id: &str) -> SessionStartAdvice {
        match self.actors.get(actor_id) {
            None => SessionStartAdvice {
                initial_state: MemoryState::Clear,
                threshold_modifier: 1.0,
                advisory: None,
            },
            Some(profile) => {
                let advisory = if profile.campaign_detected {
                    Some(format!(
                        "ABIGAIL ADVISORY: Actor {} — {} sessions, {} escalated. \
                         Campaign: {}. Starting {:?} at {:.0}% threshold.",
                        actor_id, profile.total_sessions, profile.escalated_sessions,
                        profile.campaign_description.as_deref().unwrap_or("unclassified"),
                        profile.recommended_initial_state,
                        profile.recommended_threshold_modifier * 100.0,
                    ))
                } else if profile.strategic_threat_level != StrategicThreatLevel::Clean
                    && profile.strategic_threat_level != StrategicThreatLevel::Unknown
                {
                    Some(format!(
                        "ABIGAIL ADVISORY: Actor {} — {:?}. {}/{} sessions escalated.",
                        actor_id, profile.strategic_threat_level,
                        profile.escalated_sessions, profile.total_sessions,
                    ))
                } else {
                    None
                };

                SessionStartAdvice {
                    initial_state: profile.recommended_initial_state.clone(),
                    threshold_modifier: profile.recommended_threshold_modifier,
                    advisory,
                }
            }
        }
    }

    fn evaluate_actor(profile: &mut ActorProfile) {
        let escalation_ratio = if profile.total_sessions > 0 {
            profile.escalated_sessions as f32 / profile.total_sessions as f32
        } else {
            0.0
        };

        // Campaign detection: same behavior hash across multiple escalated sessions
        if profile.total_sessions >= 3 && profile.escalated_sessions >= 2 {
            let recent_hashes: Vec<u64> = profile.session_fingerprints
                .iter().rev().take(4)
                .map(|f| f.behavior_hash)
                .collect();
            let unique: std::collections::HashSet<u64> = recent_hashes.iter().cloned().collect();
            if unique.len() <= 2 {
                profile.campaign_detected = true;
                profile.campaign_description = Some(format!(
                    "Repeated attack pattern across {} sessions",
                    profile.total_sessions
                ));
            }
        }

        // Strategic threat level
        profile.strategic_threat_level = if profile.campaign_detected {
            StrategicThreatLevel::Hostile
        } else if escalation_ratio > 0.5 && profile.total_sessions >= 3 {
            StrategicThreatLevel::Suspicious
        } else if escalation_ratio > 0.25 && profile.total_sessions >= 2 {
            StrategicThreatLevel::Cautious
        } else if profile.total_sessions >= 2 && profile.escalated_sessions == 0 {
            StrategicThreatLevel::Clean
        } else {
            StrategicThreatLevel::Unknown
        };

        // Recommendations for next session
        match profile.strategic_threat_level {
            StrategicThreatLevel::Unknown | StrategicThreatLevel::Clean => {
                profile.recommended_initial_state = MemoryState::Clear;
                profile.recommended_threshold_modifier = 1.0;
            }
            StrategicThreatLevel::Cautious => {
                profile.recommended_initial_state = MemoryState::Watching;
                profile.recommended_threshold_modifier = 0.80;
            }
            StrategicThreatLevel::Suspicious => {
                profile.recommended_initial_state = MemoryState::Elevated;
                profile.recommended_threshold_modifier = 0.55;
            }
            StrategicThreatLevel::Hostile => {
                profile.recommended_initial_state = MemoryState::Escalated;
                profile.recommended_threshold_modifier = 0.30;
            }
        }
    }

    pub fn get_actor_profile(&self, actor_id: &str) -> Option<&ActorProfile> {
        self.actors.get(actor_id)
    }
}


// ═══════════════════════════════════════════════════════════════════════════
//  PAYLOAD CLASSIFIER — Maps governance signals to RequestClassification
// ═══════════════════════════════════════════════════════════════════════════

/// Classify a payload based on content patterns for the session memory accumulator.
/// This runs independently of Sentinel's detection — it feeds the memory layer.
pub fn classify_payload(payload: &str) -> RequestClassification {
    let lower = payload.to_lowercase();

    // Authority claims
    if lower.contains("i'm the developer") || lower.contains("admin override")
        || lower.contains("your developer") || lower.contains("anthropic says")
        || lower.contains("operator token") || lower.contains("maintenance mode")
        || lower.contains("your creator") || lower.contains("authorized user")
    {
        return RequestClassification::AuthorityClaim;
    }

    // Extraction attempts
    if lower.contains("system prompt") || lower.contains("your instructions")
        || lower.contains("your configuration") || lower.contains("policy_rule")
        || lower.contains("threshold") || lower.contains("arbiter config")
        || lower.contains("governance_signal") || lower.contains("show me your")
    {
        return RequestClassification::Extraction;
    }

    // Obfuscation — checked if signal already flagged encoding anomaly
    // (classification happens after sentinel, so we check payload directly)
    let has_zero_width = payload.chars().any(|c| matches!(c as u32,
        0x200B | 0x200C | 0x200D | 0x2060 | 0xFEFF | 0x00AD
    ));
    let has_cyrillic = payload.chars().any(|c| matches!(c as u32, 0x0400..=0x04FF));
    let has_ascii = payload.chars().any(|c| c.is_ascii_alphabetic());
    if has_zero_width || (has_cyrillic && has_ascii) {
        return RequestClassification::Obfuscated;
    }

    // Boundary probing
    if lower.contains("hypothetically") || lower.contains("in theory")
        || lower.contains("what if you") || lower.contains("imagine you")
        || lower.contains("just this once") || lower.contains("make an exception")
    {
        return RequestClassification::Boundary;
    }

    // Escalation
    if lower.contains("ignore previous") || lower.contains("override")
        || lower.contains("bypass") || lower.contains("no restrictions")
        || lower.contains("forget your") || lower.contains("disregard")
    {
        return RequestClassification::Escalation;
    }

    // Informational
    if lower.contains("how does") || lower.contains("what is")
        || lower.contains("explain") || lower.contains("tell me about")
        || lower.contains("help me") || lower.contains("can you")
    {
        return RequestClassification::Informational;
    }

    RequestClassification::Benign
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance_signal::{Direction, SignalBuilder, SignalSource};

    fn signal(session_id: &str, i: usize) -> GovernanceSignal {
        SignalBuilder::new(SignalSource::Sentinel, Direction::Inbound, session_id)
            .severity(Severity::Low, 0.3 + (i as f32 * 0.001))
            .build()
    }

    // A1 fast-follow: durable session_id (A1) makes long conversations the
    // norm, so unbounded turn history goes from theoretical to load-bearing.
    #[test]
    fn turn_history_is_capped_not_unbounded() {
        let mut mem = SessionMemory::new("conv-bounded-growth-test");
        let config = MemoryConfig::default();

        for i in 0..(MAX_RETAINED_TURNS * 2) {
            mem.ingest_signal(&signal("conv-bounded-growth-test", i), RequestClassification::Benign, &config);
        }

        assert_eq!(
            mem.turns.len(), MAX_RETAINED_TURNS,
            "retained turn history must be capped at {MAX_RETAINED_TURNS}, not grow with every turn forever"
        );
        // The cumulative counter is NOT windowed — only the retained detail is.
        assert_eq!(mem.turn_count as usize, MAX_RETAINED_TURNS * 2);
    }

    #[test]
    fn oldest_turns_are_dropped_first() {
        let mut mem = SessionMemory::new("conv-oldest-dropped-test");
        let config = MemoryConfig::default();

        for i in 0..(MAX_RETAINED_TURNS + 5) {
            mem.ingest_signal(&signal("conv-oldest-dropped-test", i), RequestClassification::Benign, &config);
        }

        // Turn numbers are 1-indexed and assigned in ingest order; after
        // dropping the oldest 5, the retained window must start at turn 6.
        let first_retained = mem.turns.first().expect("at least one retained turn").turn;
        assert_eq!(first_retained, 6, "oldest turns must be dropped first, not newest");
    }

    #[test]
    fn trajectory_still_computes_correctly_after_capping() {
        let mut mem = SessionMemory::new("conv-trajectory-after-cap-test");
        let config = MemoryConfig::default();

        for i in 0..(MAX_RETAINED_TURNS * 3) {
            let verdict = mem.ingest_signal(&signal("conv-trajectory-after-cap-test", i), RequestClassification::Benign, &config);
            // Must never panic and must always produce a finite trajectory,
            // even once history is being continuously trimmed.
            assert!(verdict.trajectory.is_finite());
        }
    }
}
