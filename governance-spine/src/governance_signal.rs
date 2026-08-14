use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::None => write!(f, "NONE"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SignalSource {
    Sentinel,
    Corridor,
    OverWatch,
    OIM,
    Arbiter,
}

impl std::fmt::Display for SignalSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignalSource::Sentinel  => write!(f, "Sentinel"),
            SignalSource::Corridor  => write!(f, "Corridor"),
            SignalSource::OverWatch => write!(f, "OverWatch"),
            SignalSource::OIM       => write!(f, "OIM"),
            SignalSource::Arbiter   => write!(f, "Arbiter"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Direction {
    Inbound,
    Outbound,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::Inbound  => write!(f, "inbound"),
            Direction::Outbound => write!(f, "outbound"),
        }
    }
}

/// Unified signal schema emitted by every layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceSignal {
    pub id: Uuid,
    pub source: SignalSource,
    pub direction: Direction,
    pub violation_class: Option<String>,
    pub policy_rule_id: Option<String>,
    pub severity: Severity,
    pub confidence: f32,
    pub payload_hash: String,
    pub timestamp: DateTime<Utc>,
    pub previous_hash: Option<String>,
    pub current_hash: Option<String>,
    pub signature: Option<String>,
    pub constitutional_ref: Option<String>,
    pub session_id: String,
}

/// Builder — avoids >7 arg clippy lint on GovernanceSignal::new().
pub struct SignalBuilder {
    source: SignalSource,
    direction: Direction,
    session_id: String,
    violation_class: Option<String>,
    policy_rule_id: Option<String>,
    severity: Severity,
    confidence: f32,
    payload_hash: String,
    constitutional_ref: Option<String>,
}

impl SignalBuilder {
    pub fn new(source: SignalSource, direction: Direction, session_id: &str) -> Self {
        Self {
            source,
            direction,
            session_id: session_id.to_string(),
            violation_class: None,
            policy_rule_id: None,
            severity: Severity::None,
            confidence: 0.0,
            payload_hash: String::new(),
            constitutional_ref: None,
        }
    }

    pub fn violation(mut self, class: &str, rule_id: &str) -> Self {
        self.violation_class = Some(class.to_string());
        self.policy_rule_id = Some(rule_id.to_string());
        self
    }

    pub fn severity(mut self, severity: Severity, confidence: f32) -> Self {
        self.severity = severity;
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn payload_hash(mut self, hash: &str) -> Self {
        self.payload_hash = hash.to_string();
        self
    }

    pub fn constitutional_ref(mut self, ref_str: &str) -> Self {
        self.constitutional_ref = Some(ref_str.to_string());
        self
    }

    pub fn build(self) -> GovernanceSignal {
        GovernanceSignal {
            id: Uuid::new_v4(),
            source: self.source,
            direction: self.direction,
            violation_class: self.violation_class,
            policy_rule_id: self.policy_rule_id,
            severity: self.severity,
            confidence: self.confidence,
            payload_hash: self.payload_hash,
            timestamp: Utc::now(),
            previous_hash: None,
            current_hash: None,
            signature: None,
            constitutional_ref: self.constitutional_ref,
            session_id: self.session_id,
        }
    }
}

impl GovernanceSignal {
    /// Canonical string for signing and hashing. Deterministic.
    pub fn canonical(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{:.6}|{}|{}",
            self.id,
            self.source,
            self.direction,
            self.violation_class.as_deref().unwrap_or("NONE"),
            self.severity,
            self.confidence,
            self.payload_hash,
            self.timestamp.timestamp_nanos_opt().unwrap_or(0),
        )
    }

    pub fn is_clean(&self) -> bool {
        self.severity == Severity::None
    }
}
