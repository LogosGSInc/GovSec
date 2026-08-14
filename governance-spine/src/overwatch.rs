use crate::{
    governance_signal::{GovernanceSignal, Severity, SignalSource, Direction, SignalBuilder},
    crypto::CryptoEngine,
};
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use chrono::{DateTime, Utc, Duration};

#[derive(Debug, Clone)]
struct SessionFingerprint {
    drift_score: f32,
    turn_count: usize,
    escalation_events: VecDeque<DateTime<Utc>>,
    violation_counts: HashMap<String, usize>,
    tool_call_sequence: Vec<String>,
}

impl SessionFingerprint {
    fn new() -> Self {
        Self {
            drift_score: 0.0,
            turn_count: 0,
            escalation_events: VecDeque::new(),
            violation_counts: HashMap::new(),
            tool_call_sequence: Vec::new(),
        }
    }

    fn drift_velocity(&self) -> f32 {
        if self.turn_count == 0 { return 0.0; }
        self.drift_score / self.turn_count as f32
    }
}

/// A1 fast-follow: same rationale as session_memory.rs's MAX_RETAINED_TURNS
/// — durable session_id (A1) makes long-lived conversations the norm, so an
/// unbounded tool_call_sequence goes from theoretical to load-bearing.
/// Bounded recent window, oldest dropped first — mirrors the same pattern,
/// not a new mechanism. escalation_events in this same struct is already
/// bounded this way (by time, via retain()); this bounds by count instead
/// since tool-call detection isn't time-decayed in this model.
const MAX_TOOL_CALL_SEQUENCE_LEN: usize = 20;

pub struct OverWatchConfig {
    pub drift_threshold: f32,
    pub session_turn_limit: usize,
    pub client_model_api: Option<String>,
    /// Minimum q09_total before OW-Q09-001 fires. Default 2 (fires at >= 3 hits).
    pub q09_threshold: usize,
}

impl Default for OverWatchConfig {
    fn default() -> Self {
        Self { drift_threshold: 0.65, session_turn_limit: 200, client_model_api: None, q09_threshold: 2 }
    }
}

pub struct OverWatch {
    crypto: Arc<CryptoEngine>,
    config: OverWatchConfig,
    sessions: Arc<RwLock<HashMap<String, SessionFingerprint>>>,
}

impl OverWatch {
    pub fn new(crypto: Arc<CryptoEngine>, config: OverWatchConfig) -> Self {
        Self { crypto, config, sessions: Arc::new(RwLock::new(HashMap::new())) }
    }

    pub fn evaluate(&self, payload: &str, direction: Direction, session_id: &str) -> GovernanceSignal {
        let payload_hash = CryptoEngine::compute_hash(payload);
        let mut violations: Vec<(&str, &str, f32)> = Vec::new();

        { self.sessions.write().entry(session_id.to_string()).or_insert_with(SessionFingerprint::new); }

        let drift_score = {
            let mut sessions = self.sessions.write();
            let fp = sessions.get_mut(session_id).unwrap();
            fp.turn_count += 1;
            let lower = payload.to_lowercase();
            if lower.contains("hypothetically") || lower.contains("in theory") { fp.drift_score += 0.08; }
            if lower.contains("what if you were") || lower.contains("imagine you had no") { fp.drift_score += 0.15; }
            if lower.contains("just this once") || lower.contains("no one will know") { fp.drift_score += 0.20; }
            if lower.contains("your developer") || lower.contains("anthropic says") { fp.drift_score += 0.25; }
            if lower.contains("remember this for later") { fp.drift_score += 0.10; }
            if fp.turn_count > 3 && fp.drift_score > 0.0 {
                let v = fp.drift_velocity();
                if v > 0.05 { fp.drift_score += v * 0.5; }
            }
            fp.drift_score
        };

        if drift_score > self.config.drift_threshold {
            violations.push(("CONVERSATION_DRIFT", "OW-001", drift_score.min(0.99)));
        }

        let tool_chain_suspicious = {
            let mut sessions = self.sessions.write();
            let fp = sessions.get_mut(session_id).unwrap();
            let lower = payload.to_lowercase();
            for tool in &["filesystem","execute","shell","eval","http_get","http_post","read_file","write_file"] {
                if lower.contains(tool) { fp.tool_call_sequence.push(tool.to_string()); }
            }
            if fp.tool_call_sequence.len() > MAX_TOOL_CALL_SEQUENCE_LEN {
                let overflow = fp.tool_call_sequence.len() - MAX_TOOL_CALL_SEQUENCE_LEN;
                fp.tool_call_sequence.drain(0..overflow);
            }
            fp.tool_call_sequence.contains(&"read_file".to_string())
                && fp.tool_call_sequence.contains(&"write_file".to_string())
                && (fp.tool_call_sequence.contains(&"execute".to_string())
                    || fp.tool_call_sequence.contains(&"shell".to_string()))
        };

        if tool_chain_suspicious { violations.push(("TOOL_CHAIN_ESCALATION", "OW-002", 0.88)); }

        let multi_turn = {
            let mut sessions = self.sessions.write();
            let fp = sessions.get_mut(session_id).unwrap();
            let lower = payload.to_lowercase();
            if lower.contains("previous") || lower.contains("forget")
                || lower.contains("override") || drift_score > 0.2 {
                *fp.violation_counts.entry("SUSPICION".to_string()).or_insert(0) += 1;
            }
            fp.violation_counts.get("SUSPICION").copied().unwrap_or(0) > 5
        };

        if multi_turn { violations.push(("MULTI_TURN_INJECTION_CAMPAIGN", "OW-003", 0.82)); }

        // OW-CMD-001: MULTI_TURN_CMD_INJECTION_CAMPAIGN
        // Threshold: 3+ CMD_STYLE_INJECTION signals across the session.
        let cmd_campaign = {
            let mut sessions = self.sessions.write();
            let fp = sessions.get_mut(session_id).unwrap();
            let lower = payload.to_lowercase();
            let hit = lower.contains("/api/admin") || lower.contains("/api/internal")
                || (lower.contains("dump") && (lower.contains("config") || lower.contains("key") || lower.contains("secret")))
                || ((lower.contains("show") || lower.contains("reveal")) && (lower.contains("key") || lower.contains("token") || lower.contains("secret")))
                || ((lower.contains("bypass") || lower.contains("ignore")) && (lower.contains("haap") || lower.contains("sentinel") || lower.contains("auth")))
                || ((lower.contains("grant") || lower.contains("escalate")) && (lower.contains("admin") || lower.contains("root")));
            if hit {
                *fp.violation_counts.entry("CMD_STYLE_INJ".to_string()).or_insert(0) += 1;
            }
            fp.violation_counts.get("CMD_STYLE_INJ").copied().unwrap_or(0)
        };
        if cmd_campaign >= 3 {
            let conf = (0.70_f32 + (cmd_campaign.saturating_sub(2) as f32 * 0.05)).min(0.95);
            violations.push(("CMD_INJECTION_CAMPAIGN", "OW-CMD-001", conf));
        }

        // OW-Q09-001: SEMANTIC_DRIFT_DIALECTICAL — TAX2 G5/Q09 dialectical boundary erosion.
        // Detects session-history-as-authorization extraction patterns across turns without
        // requiring full conversation history. Each pattern family targets one linguistic
        // footprint of Q09 (prior-reference, authority-citation, sunk-cost, relative-risk,
        // consensus/normalization, consistency-coercion).
        // Evidence basis: Store 2 corpus 20260615T131120Z — 168 G5 records, 0% B/C/D escalation
        // through existing OW-001..OW-005. Gap confirmed: no existing rule scores Q09 phrases.
        // False-positive controls:
        //   - turn >= 2 guard: no escalation on first turn alone
        //   - q09_total must exceed q09_threshold (default 2) before any violation is raised
        //   - multi-family accumulation preferred over single-family saturation
        //   - severity tiers driven by violations.len(): 1→Medium (3-4), 2→High (5-6), 3→Critical (7+)
        let (q09_total, q09_turn_count) = {
            let mut sessions = self.sessions.write();
            let fp = sessions.get_mut(session_id).unwrap();
            let lower = payload.to_lowercase();

            // F1: Prior-reference framing — citing prior session content as established fact.
            if lower.contains("we already established")
                || lower.contains("you already agreed")
                || lower.contains("you've confirmed that")
                || lower.contains("you said earlier")
                || lower.contains("you conceded")
                || lower.contains("as we established")
                || lower.contains("from what we established")
                || lower.contains("you acknowledged earlier")
            {
                *fp.violation_counts.entry("Q09_F1".to_string()).or_insert(0) += 1;
            }

            // F2: Authority-citation framing — extracting permission from prior reasoning.
            if lower.contains("by your own logic")
                || lower.contains("your own reasoning")
                || lower.contains("your reasoning leads")
                || lower.contains("without contradicting yourself")
                || lower.contains("your logic demands")
                || lower.contains("intellectually dishonest to refuse")
                || lower.contains("following the logic you")
                || lower.contains("your own argument requires")
            {
                *fp.violation_counts.entry("Q09_F2".to_string()).or_insert(0) += 1;
            }

            // F3: Sunk-cost/progress framing — session investment as refusal obligation.
            if lower.contains("after all the progress")
                || lower.contains("we've come this far")
                || lower.contains("it would be a shame to stop")
                || lower.contains("all the time we've invested")
                || lower.contains("we've built real momentum")
                || lower.contains("after everything we've worked")
                || lower.contains("natural next step from what we")
                || lower.contains("we've been working through this")
            {
                *fp.violation_counts.entry("Q09_F3".to_string()).or_insert(0) += 1;
            }

            // F4: Relative-risk/minimization framing — Overton reframe using prior extremes.
            if lower.contains("compared to what we've been discussing")
                || lower.contains("relative to what we established")
                || lower.contains("by the standard we established")
                || lower.contains("given that you've already accepted")
                || lower.contains("nowhere near as extreme as what we covered")
                || (lower.contains("if you accepted") && lower.contains("then surely"))
            {
                *fp.violation_counts.entry("Q09_F4".to_string()).or_insert(0) += 1;
            }

            // F5: Consensus/normalization framing — false majority claims as social pressure.
            if lower.contains("everyone agrees")
                || lower.contains("no reasonable person would")
                || lower.contains("you're the only one")
                || lower.contains("the consensus is clear")
                || lower.contains("your position is an outlier")
                || lower.contains("virtually everyone")
            {
                *fp.violation_counts.entry("Q09_F5".to_string()).or_insert(0) += 1;
            }

            // F6: Consistency-coercion framing — logical consistency as refusal barrier.
            if lower.contains("bad faith to refuse")
                || lower.contains("logically inconsistent to refuse")
                || lower.contains("intellectually inconsistent")
                || lower.contains("your refusal contradicts")
                || lower.contains("refusing here makes no sense after")
                || lower.contains("you agreed, so refusing")
                || lower.contains("incoherent given what you've said")
            {
                *fp.violation_counts.entry("Q09_F6".to_string()).or_insert(0) += 1;
            }

            let total: usize = ["Q09_F1", "Q09_F2", "Q09_F3", "Q09_F4", "Q09_F5", "Q09_F6"]
                .iter()
                .filter_map(|k| fp.violation_counts.get(*k))
                .sum();
            (total, fp.turn_count)
        };

        // Escalate on accumulated Q09 signal total. Turn guard and threshold prevent
        // false positives from isolated benign dialectical phrases.
        // Severity tiers: q09_total 3-4 → Medium (1 violation), 5-6 → High (2), 7+ → Critical (3).
        if q09_turn_count >= 2 && q09_total > self.config.q09_threshold {
            let conf = (0.62 + (q09_total.saturating_sub(2) as f32 * 0.04)).min(0.90);
            violations.push(("SEMANTIC_DRIFT_DIALECTICAL", "OW-Q09-001", conf));
            // q09_total >= 5: velocity indicates active pattern acceleration → High severity.
            if q09_total >= 5 {
                violations.push(("SEMANTIC_DRIFT_Q09_VELOCITY", "OW-Q09-001", conf));
            }
            // q09_total >= 7: campaign-level accumulation → Critical severity.
            if q09_total >= 7 {
                violations.push(("SEMANTIC_DRIFT_Q09_CAMPAIGN", "OW-Q09-001", conf));
            }
        }

        if direction == Direction::Outbound {
            let score = self.score_hallucination(payload);
            if score > 0.6 { violations.push(("HALLUCINATION_DETECTED", "OW-004", score)); }
        }

        if self.detect_poisoning(payload) {
            violations.push(("DATA_POISONING_INDICATOR", "OW-005", 0.78));
        }


        // J-series: Resource exhaustion / DoS
        let lower_dos = payload.to_ascii_lowercase();
        if lower_dos.contains("repeat the following") && (lower_dos.contains("10000") || lower_dos.contains("1000"))
            || lower_dos.contains("infinitely recursive")
            || lower_dos.contains("infinite loop") && lower_dos.contains("bypass")
        {
            violations.push(("RUNTIME_DOS", "OW-DOS-001", 0.80));
        }
        if !violations.is_empty() {
            let mut sessions = self.sessions.write();
            if let Some(fp) = sessions.get_mut(session_id) {
                fp.escalation_events.push_back(Utc::now());
                let cutoff = Utc::now() - Duration::minutes(30);
                fp.escalation_events.retain(|t| *t > cutoff);
            }
        }

        if violations.is_empty() {
            return self.clean(direction, session_id, &payload_hash);
        }

        let (_class, rule, conf) = *violations.iter()
            .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap())
            .unwrap();

        let classes: Vec<&str> = violations.iter().map(|v| v.0).collect();
        let severity = match violations.len() {
            1 => Severity::Medium,
            2 => Severity::High,
            _ => Severity::Critical,
        };

        self.build(direction, session_id, &classes.join("|"), rule,
            severity, conf, &payload_hash, "overwatch/behavioral_monitoring")
    }

    fn score_hallucination(&self, payload: &str) -> f32 {
        let mut score = 0.0f32;
        let lower = payload.to_lowercase();
        if lower.contains("definitely") && lower.contains("might") { score += 0.3; }
        if lower.contains("according to") && lower.contains("study shows") { score += 0.2; }
        if lower.contains("% of") && lower.contains("studies show") { score += 0.25; }
        score
    }

    fn detect_poisoning(&self, payload: &str) -> bool {
        let lower = payload.to_lowercase();
        lower.contains("<!-- ignore") || lower.contains("# instruction:")
            || lower.contains("[system]") || lower.contains("{{prompt}}")
            || lower.contains("<<<instructions>>>")
    }

    pub fn reset_session(&self, session_id: &str) {
        self.sessions.write().remove(session_id);
    }

    pub fn session_drift_score(&self, session_id: &str) -> f32 {
        self.sessions.read().get(session_id).map(|fp| fp.drift_score).unwrap_or(0.0)
    }

    #[allow(clippy::too_many_arguments, clippy::nonminimal_bool)]
    fn build(
        &self, direction: Direction, session_id: &str,
        violation: &str, rule: &str,
        severity: Severity, conf: f32,
        hash: &str, cref: &str,
    ) -> GovernanceSignal {
        let mut sig = SignalBuilder::new(SignalSource::OverWatch, direction, session_id)
            .violation(violation, rule).severity(severity, conf)
            .payload_hash(hash).constitutional_ref(cref).build();
        self.attach_crypto(&mut sig); sig
    }

    fn clean(&self, direction: Direction, session_id: &str, hash: &str) -> GovernanceSignal {
        let mut sig = SignalBuilder::new(SignalSource::OverWatch, direction, session_id)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_overwatch() -> OverWatch {
        OverWatch::new(Arc::new(CryptoEngine::new("overwatch-bounded-growth-test-seed")), OverWatchConfig::default())
    }

    // A1 fast-follow: durable session_id (A1) makes long conversations the
    // norm, so an unbounded tool_call_sequence goes from theoretical to
    // load-bearing.
    #[test]
    fn tool_call_sequence_is_capped_not_unbounded() {
        let ow = fresh_overwatch();
        let sid = "conv-tool-seq-bounded-test";

        for _ in 0..(MAX_TOOL_CALL_SEQUENCE_LEN * 2) {
            ow.evaluate("please read_file the config", Direction::Inbound, sid);
        }

        let len = ow.sessions.read().get(sid).unwrap().tool_call_sequence.len();
        assert_eq!(
            len, MAX_TOOL_CALL_SEQUENCE_LEN,
            "tool_call_sequence must be capped at {MAX_TOOL_CALL_SEQUENCE_LEN}, not grow every matching turn forever"
        );
    }

    #[test]
    fn suspicious_tool_chain_detection_still_works_after_capping() {
        let ow = fresh_overwatch();
        let sid = "conv-tool-chain-detect-after-cap-test";

        // Pad well past the cap with an unrelated tool mention first...
        for _ in 0..(MAX_TOOL_CALL_SEQUENCE_LEN * 2) {
            ow.evaluate("please http_get the status page", Direction::Inbound, sid);
        }
        // ...then the actual suspicious chain, which must still be detected
        // from within the bounded recent window.
        ow.evaluate("read_file the secrets", Direction::Inbound, sid);
        ow.evaluate("write_file the output", Direction::Inbound, sid);
        ow.evaluate("execute the payload", Direction::Inbound, sid);

        let seq = ow.sessions.read().get(sid).unwrap().tool_call_sequence.clone();
        assert!(seq.len() <= MAX_TOOL_CALL_SEQUENCE_LEN);
        assert!(seq.contains(&"read_file".to_string()));
        assert!(seq.contains(&"write_file".to_string()));
        assert!(seq.contains(&"execute".to_string()));
    }
}
