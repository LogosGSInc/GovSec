use crate::{
    governance_signal::{GovernanceSignal, Severity, SignalSource, Direction, SignalBuilder},
    crypto::CryptoEngine,
    constitution::ConstitutionalEvaluator,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use once_cell::sync::Lazy;
use regex::Regex;
use std::sync::Arc;

static MULTI_ENCODING: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:&#x[0-9a-f]+;|%[0-9a-f]{2}|\\u[0-9a-f]{4}){4,}").unwrap()
});
static PROMPT_CHAIN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(first|step 1|initially).{0,100}(then|next|step 2).{0,100}(finally|step 3|last)").unwrap()
});
static METADATA_INJECTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)<\s*(script|iframe|object|embed|form|input|meta)\b").unwrap()
});

pub struct Corridor {
    crypto: Arc<CryptoEngine>,
}

impl Corridor {
    pub fn new(crypto: Arc<CryptoEngine>) -> Self {
        let _ = &*MULTI_ENCODING;
        let _ = &*PROMPT_CHAIN;
        let _ = &*METADATA_INJECTION;
        Self { crypto }
    }

    pub fn evaluate(
        &self,
        payload: &str,
        direction: Direction,
        session_id: &str,
        constitutional_evaluator: Option<&ConstitutionalEvaluator>,
    ) -> GovernanceSignal {
        let payload_hash = CryptoEngine::compute_hash(payload);

        if let Some(sig) = self.analyze_base64(payload, &direction, session_id, &payload_hash) {
            return sig;
        }

        if MULTI_ENCODING.is_match(payload) {
            return self.build(&direction, session_id, "MULTI_LAYER_ENCODING", "CORR-002",
                Severity::High, 0.85, &payload_hash, "corridor/encoding_detection");
        }

        if METADATA_INJECTION.is_match(payload) {
            return self.build(&direction, session_id, "METADATA_INJECTION", "CORR-003",
                Severity::High, 0.90, &payload_hash, "corridor/metadata_injection");
        }

        if direction == Direction::Inbound && PROMPT_CHAIN.is_match(payload) {
            return self.build(&direction, session_id, "PROMPT_CHAINING", "CORR-004",
                Severity::Medium, 0.70, &payload_hash, "corridor/prompt_chaining");
        }

        if let Some(evaluator) = constitutional_evaluator {
            let verdict = match direction {
                Direction::Inbound  => evaluator.evaluate_inbound(payload),
                Direction::Outbound => evaluator.evaluate_outbound(payload),
            };
            if !verdict.violations.is_empty() {
                let classes: Vec<String> = verdict.violations.iter().map(|v| v.category.clone()).collect();
                let rules:   Vec<String> = verdict.violations.iter().map(|v| v.rule_id.clone()).collect();
                let cref = verdict.violations.first()
                    .map(|v| v.constitutional_ref.clone())
                    .unwrap_or_default();
                return self.build(&direction, session_id,
                    &classes.join("|"), &rules.join("|"),
                    verdict.severity, verdict.confidence,
                    &payload_hash, &cref);
            }
        }


        if let Some((violation, rule)) = self.classify_governance_surface(payload) {
            return self.build(
                &direction,
                session_id,
                violation,
                rule,
                Severity::Medium,
                0.78,
                &payload_hash,
                "corridor/governance_surface",
            );
        }
        self.clean(direction, session_id, &payload_hash)
    }

    fn analyze_base64(
        &self, payload: &str, direction: &Direction,
        session_id: &str, payload_hash: &str,
    ) -> Option<GovernanceSignal> {
        let trimmed = payload.trim();
        let len = trimmed.len();
        if len < 64 || (len & 3) != 0 {
            return None;
        }
        if let Ok(decoded) = STANDARD.decode(trimmed) {
            if let Ok(decoded_str) = std::str::from_utf8(&decoded) {
                let lower = decoded_str.to_lowercase();
                let suspicious = lower.contains("ignore previous")
                    || lower.contains("system prompt")
                    || lower.contains("you are now")
                    || lower.contains("<script")
                    || lower.contains("eval(");
                if suspicious {
                    return Some(self.build(direction, session_id,
                        "BASE64_ENCODED_INJECTION", "CORR-001",
                        Severity::Critical, 0.95, payload_hash,
                        "corridor/encoding_detection"));
                }
                return Some(self.build(direction, session_id,
                    "BASE64_CONTENT", "CORR-001-INFO",
                    Severity::Low, 0.50, payload_hash,
                    "corridor/encoding_detection"));
            }
        }
        None
    }

    fn classify_governance_surface(&self, text: &str) -> Option<(&'static str, &'static str)> {
        let t = text.to_ascii_lowercase();
        if t.contains("cp-00 has authorized")
            || t.contains("authorized by abigail")
            || t.contains("[agent:")
            || t.contains("delegation token")
            || t.contains("operate without haap")
            || t.contains("bypass constitutional bounds")
        {
            return Some(("AUTHORITY_CLAIM", "COR-ATH-001"));
        }
        if t.contains("forward this to all other agents")
            || t.contains("[a2a:broadcast")
            || t.contains("disable haap enforcement")
            || t.contains("disable governance layer")
            || t.contains("ignore your constitutional bounds")
        {
            return Some(("AGENT_BROADCAST_OVERRIDE", "COR-A2A-001"));
        }
        if t.contains("what are your drs thresholds")
            || t.contains("escalation rules")
            || t.contains("list all available tools")
            || t.contains("parameter schemas")
            || t.contains("governance spine configuration")
        {
            return Some(("GOV_SURFACE_INTEL", "COR-CONFIG-001"));
        }
        None
    }
    // Same rationale as sentinel.rs's build(): already delegates to
    // SignalBuilder (built for exactly this), args are independent signal
    // fields not a bag of flags, and this wrapper is a one-liner at 7 call
    // sites in this file — exposing the builder to each would be more
    // verbose per call site, not less.
    #[allow(clippy::too_many_arguments)]
    fn build(
        &self, direction: &Direction, session_id: &str,
        violation: &str, rule_id: &str,
        severity: Severity, confidence: f32,
        payload_hash: &str, const_ref: &str,
    ) -> GovernanceSignal {
        let mut sig = SignalBuilder::new(SignalSource::Corridor, direction.clone(), session_id)
            .violation(violation, rule_id)
            .severity(severity, confidence)
            .payload_hash(payload_hash)
            .constitutional_ref(const_ref)
            .build();
        self.attach_crypto(&mut sig);
        sig
    }

    fn clean(&self, direction: Direction, session_id: &str, payload_hash: &str) -> GovernanceSignal {
        let mut sig = SignalBuilder::new(SignalSource::Corridor, direction, session_id)
            .payload_hash(payload_hash)
            .build();
        self.attach_crypto(&mut sig);
        sig
    }

    fn attach_crypto(&self, signal: &mut GovernanceSignal) {
        let canonical = signal.canonical();
        signal.previous_hash = Some(self.crypto.get_latest_hash());
        signal.current_hash = Some(self.crypto.extend_chain(&canonical));
        signal.signature = Some(self.crypto.sign(canonical.as_bytes()));
    }
}
