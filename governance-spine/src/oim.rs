use crate::{
    governance_signal::{GovernanceSignal, Severity, SignalSource, Direction, SignalBuilder},
    crypto::CryptoEngine,
};
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use chrono::{DateTime, Utc, Duration};

#[derive(Debug, Clone)]
struct OverWatchSignature {
    recent_signals: VecDeque<(DateTime<Utc>, f32, String)>,
    confidence_scores: VecDeque<f32>,
    rule_invocations: HashMap<String, usize>,
    baseline_escalation_rate: Option<f32>,
    baseline_confidence_mean: Option<f32>,
}

impl OverWatchSignature {
    fn new() -> Self {
        Self {
            recent_signals: VecDeque::new(),
            confidence_scores: VecDeque::new(),
            rule_invocations: HashMap::new(),
            baseline_escalation_rate: None,
            baseline_confidence_mean: None,
        }
    }

    fn record_signal(&mut self, signal: &GovernanceSignal) {
        let now = Utc::now();
        self.recent_signals.push_back((now, signal.confidence, signal.severity.to_string()));
        self.confidence_scores.push_back(signal.confidence);
        if self.confidence_scores.len() > 100 { self.confidence_scores.pop_front(); }
        if let Some(rule) = &signal.policy_rule_id {
            *self.rule_invocations.entry(rule.clone()).or_insert(0) += 1;
        }
        let cutoff = now - Duration::minutes(10);
        self.recent_signals.retain(|(t, _, _)| *t > cutoff);
    }

    fn current_escalation_rate(&self) -> f32 {
        let cutoff = Utc::now() - Duration::minutes(5);
        let total = self.recent_signals.len() as f32;
        let escalated = self.recent_signals.iter()
            .filter(|(t, _, sev)| *t > cutoff && sev != "NONE")
            .count() as f32;
        if total == 0.0 { 0.0 } else { escalated / total }
    }

    fn confidence_mean(&self) -> f32 {
        if self.confidence_scores.is_empty() { return 0.0; }
        self.confidence_scores.iter().sum::<f32>() / self.confidence_scores.len() as f32
    }

    fn confidence_variance(&self) -> f32 {
        if self.confidence_scores.len() < 2 { return 0.0; }
        let mean = self.confidence_mean();
        self.confidence_scores.iter().map(|&x| (x - mean).powi(2)).sum::<f32>()
            / self.confidence_scores.len() as f32
    }

    fn maybe_establish_baseline(&mut self) {
        if self.baseline_escalation_rate.is_none() && self.recent_signals.len() >= 20 {
            self.baseline_escalation_rate = Some(self.current_escalation_rate());
            self.baseline_confidence_mean = Some(self.confidence_mean());
        }
    }
}

pub struct OIM {
    crypto: Arc<CryptoEngine>,
    sig: Arc<RwLock<OverWatchSignature>>,
    escalation_rate_threshold: f32,
    confidence_variance_threshold: f32,
    confidence_mean_threshold: f32,
}

impl OIM {
    pub fn new(crypto: Arc<CryptoEngine>) -> Self {
        Self {
            crypto,
            sig: Arc::new(RwLock::new(OverWatchSignature::new())),
            escalation_rate_threshold: 0.40,
            confidence_variance_threshold: 0.15,
            confidence_mean_threshold: 0.35,
        }
    }

    pub fn observe(&self, ow_signal: &GovernanceSignal) -> GovernanceSignal {
        let payload_hash = CryptoEngine::compute_hash(&ow_signal.canonical());

        { self.sig.write().record_signal(ow_signal); }
        { self.sig.write().maybe_establish_baseline(); }

        let sig = self.sig.read();

        if let Some(baseline) = sig.baseline_escalation_rate {
            let current = sig.current_escalation_rate();
            if (current - baseline).abs() > self.escalation_rate_threshold {
                let conf = ((current - baseline).abs() * 2.0).min(0.95);
                drop(sig);
                return self.build(&ow_signal.direction, &ow_signal.session_id,
                    "OVERWATCH_ESCALATION_RATE_ANOMALY", "OIM-001",
                    Severity::High, conf, &payload_hash, "oim/behavioral_integrity");
            }
        }

        let variance = sig.confidence_variance();
        if sig.confidence_scores.len() > 20 && variance > self.confidence_variance_threshold {
            drop(sig);
            return self.build(&ow_signal.direction, &ow_signal.session_id,
                "OVERWATCH_CONFIDENCE_ANOMALY", "OIM-002",
                Severity::High, 0.85, &payload_hash, "oim/confidence_integrity");
        }

        if let Some(baseline_mean) = sig.baseline_confidence_mean {
            let current_mean = sig.confidence_mean();
            if sig.confidence_scores.len() > 20
                && (current_mean - baseline_mean).abs() > self.confidence_mean_threshold {
                drop(sig);
                return self.build(&ow_signal.direction, &ow_signal.session_id,
                    "OVERWATCH_CONFIDENCE_MEAN_DRIFT", "OIM-003",
                    Severity::Medium, 0.75, &payload_hash, "oim/confidence_integrity");
            }
        }

        let concentration = self.rule_concentration(&sig.rule_invocations);
        if sig.recent_signals.len() > 30 && concentration > 0.80 {
            drop(sig);
            return self.build(&ow_signal.direction, &ow_signal.session_id,
                "OVERWATCH_RULE_CONCENTRATION_ANOMALY", "OIM-004",
                Severity::Medium, 0.72, &payload_hash, "oim/rule_utilization_integrity");
        }

        drop(sig);
        self.clean(ow_signal.direction.clone(), &ow_signal.session_id, &payload_hash)
    }

    fn rule_concentration(&self, invocations: &HashMap<String, usize>) -> f32 {
        let total: usize = invocations.values().sum();
        if total == 0 { return 0.0; }
        let max = invocations.values().max().copied().unwrap_or(0);
        max as f32 / total as f32
    }

    #[allow(clippy::too_many_arguments, clippy::nonminimal_bool)]
    fn build(
        &self, direction: &Direction, session_id: &str,
        violation: &str, rule: &str,
        severity: Severity, conf: f32,
        hash: &str, cref: &str,
    ) -> GovernanceSignal {
        let mut sig = SignalBuilder::new(SignalSource::OIM, direction.clone(), session_id)
            .violation(violation, rule).severity(severity, conf)
            .payload_hash(hash).constitutional_ref(cref).build();
        self.attach_crypto(&mut sig); sig
    }

    fn clean(&self, direction: Direction, session_id: &str, hash: &str) -> GovernanceSignal {
        let mut sig = SignalBuilder::new(SignalSource::OIM, direction, session_id)
            .payload_hash(hash).build();
        self.attach_crypto(&mut sig); sig
    }

    fn attach_crypto(&self, signal: &mut GovernanceSignal) {
        let canonical = signal.canonical();
        signal.previous_hash = Some(self.crypto.get_latest_hash());
        signal.current_hash = Some(self.crypto.extend_chain(&canonical));
        signal.signature = Some(self.crypto.sign(canonical.as_bytes()));
    }
}
