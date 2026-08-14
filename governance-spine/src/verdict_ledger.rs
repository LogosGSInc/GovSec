use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use crate::governance_signal::{Direction, GovernanceSignal, Severity};

#[derive(Debug, Clone)]
pub struct VerdictRecord {
    pub verdict_id: String,
    pub gov_tx_id: String,
    pub session_id: String,
    /// True only when the complete inbound pipeline finally approved execution.
    pub final_approved: bool,
    pub direction: Direction,
    pub violation_class: Option<String>,
    pub severity: Severity,
    pub confidence: f32,
    pub payload_hash: String,
    pub signal_signature: String,
    pub recorded_at: DateTime<Utc>,
    /// The approved `ModelContextEnvelope.context_hash`, present only when
    /// this verdict was produced by the context-aware inbound path
    /// (`inbound_context_with_identity`). `None` for the legacy plain-text
    /// path (`inbound_with_identity`) — deliberately, so a provider or
    /// action authorization request that requires a matching context_hash
    /// can never be satisfied by a legacy text-only approval.
    pub context_hash: Option<String>,
    /// The `ModelContextEnvelope.run_id` this approval covers. Same
    /// legacy-path caveat as `context_hash`.
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveOutcome {
    Found,
    NotFound,
    TransactionMismatch,
    SessionMismatch,
}

/// Outcome of resolving a verdict by (context_hash, session_id) rather than
/// by (gov_tx_id, session_id). No transaction-id check here by design — see
/// `resolve_by_context`'s doc comment for why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextResolveOutcome {
    Found,
    NotFound,
    SessionMismatch,
}

pub struct SentinelVerdictLedger {
    verdicts: Arc<RwLock<HashMap<String, VerdictRecord>>>,
    /// (gov_tx_id|session_id) -> final approved verdict_id.
    approved_by_tx: Arc<RwLock<HashMap<String, String>>>,
    /// (context_hash|session_id) -> final approved verdict_id. Populated
    /// only by `record_final_approved_with_context`. This is the lookup
    /// `authorize_provider_execution`/`authorize_action_execution` actually
    /// use: a single approved context legitimately backs MANY independent
    /// provider/action authorization calls (a governed turn that calls two
    /// different tools still traces back to the one context that was
    /// approved), so verdict resolution must not require every one of those
    /// calls to share one gov_tx_id — context_hash is the correct, already
    /// tamper-evident key for "which approval does this call belong to."
    approved_by_context: Arc<RwLock<HashMap<String, String>>>,
}

impl Default for SentinelVerdictLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl SentinelVerdictLedger {
    pub fn new() -> Self {
        Self {
            verdicts: Arc::new(RwLock::new(HashMap::new())),
            approved_by_tx: Arc::new(RwLock::new(HashMap::new())),
            approved_by_context: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn record(&self, gov_tx_id: &str, signal: &GovernanceSignal) -> String {
        let verdict_id = format!("SV-{}", uuid::Uuid::new_v4().simple());
        let record = VerdictRecord {
            verdict_id: verdict_id.clone(),
            gov_tx_id: gov_tx_id.to_string(),
            session_id: signal.session_id.clone(),
            final_approved: false,
            direction: signal.direction.clone(),
            violation_class: signal.violation_class.clone(),
            severity: signal.severity.clone(),
            confidence: signal.confidence,
            payload_hash: signal.payload_hash.clone(),
            signal_signature: signal.signature.clone().unwrap_or_default(),
            recorded_at: Utc::now(),
            context_hash: None,
            run_id: None,
        };
        self.verdicts.write().insert(verdict_id.clone(), record);
        verdict_id
    }

    /// Record execution authority only after every inbound layer has
    /// produced a final APPROVED result. Legacy plain-text path — leaves
    /// `context_hash`/`run_id` unset, so this verdict can authorize neither
    /// a provider capability nor an action capability that require them.
    pub fn record_final_approved(
        &self,
        gov_tx_id: &str,
        signal: &GovernanceSignal,
    ) -> String {
        self.record_final_approved_inner(gov_tx_id, signal, None, None)
    }

    /// Record execution authority for the context-aware inbound path.
    /// `context_hash` is the sealed `ModelContextEnvelope.context_hash` that
    /// every inspected segment and the full pipeline pass approved;
    /// `run_id` is the envelope's run identifier. Both are required here —
    /// this is the only way a verdict acquires them.
    pub fn record_final_approved_with_context(
        &self,
        gov_tx_id: &str,
        signal: &GovernanceSignal,
        context_hash: &str,
        run_id: &str,
    ) -> String {
        self.record_final_approved_inner(gov_tx_id, signal, Some(context_hash), Some(run_id))
    }

    fn record_final_approved_inner(
        &self,
        gov_tx_id: &str,
        signal: &GovernanceSignal,
        context_hash: Option<&str>,
        run_id: Option<&str>,
    ) -> String {
        let verdict_id = format!("SV-{}", uuid::Uuid::new_v4().simple());
        let record = VerdictRecord {
            verdict_id: verdict_id.clone(),
            gov_tx_id: gov_tx_id.to_string(),
            session_id: signal.session_id.clone(),
            final_approved: true,
            direction: signal.direction.clone(),
            violation_class: signal.violation_class.clone(),
            severity: signal.severity.clone(),
            confidence: signal.confidence,
            payload_hash: signal.payload_hash.clone(),
            signal_signature: signal.signature.clone().unwrap_or_default(),
            recorded_at: Utc::now(),
            context_hash: context_hash.map(str::to_string),
            run_id: run_id.map(str::to_string),
        };

        self.verdicts.write().insert(verdict_id.clone(), record);
        self.approved_by_tx.write().insert(
            format!("{}|{}", gov_tx_id, signal.session_id),
            verdict_id.clone(),
        );
        if let Some(ctx) = context_hash {
            self.approved_by_context.write().insert(
                format!("{}|{}", ctx, signal.session_id),
                verdict_id.clone(),
            );
        }
        verdict_id
    }

    pub fn approved_verdict_id(
        &self,
        gov_tx_id: &str,
        session_id: &str,
    ) -> Option<String> {
        self.approved_by_tx
            .read()
            .get(&format!("{}|{}", gov_tx_id, session_id))
            .cloned()
    }

    /// Resolves the approved verdict for a given (context_hash, session_id)
    /// pair — the lookup provider/action authorization actually use, so
    /// multiple independent authorization calls can share one approved
    /// context without colliding on a single gov_tx_id.
    pub fn approved_verdict_id_by_context(
        &self,
        context_hash: &str,
        session_id: &str,
    ) -> Option<String> {
        self.approved_by_context
            .read()
            .get(&format!("{}|{}", context_hash, session_id))
            .cloned()
    }

    /// Resolves a verdict by (verdict_id, session_id) only — no gov_tx_id
    /// check. Used alongside `approved_verdict_id_by_context`: the verdict
    /// was already found via the tamper-evident context_hash key, so a
    /// further transaction-id match isn't a meaningful additional check
    /// here (unlike `resolve`, which is the primitive lookup where
    /// transaction identity IS the caller-supplied binding).
    pub fn resolve_by_context(&self, verdict_id: &str, session_id: &str)
        -> (ContextResolveOutcome, Option<VerdictRecord>)
    {
        let guard = self.verdicts.read();
        match guard.get(verdict_id) {
            None => (ContextResolveOutcome::NotFound, None),
            Some(rec) => {
                if rec.session_id != session_id {
                    return (ContextResolveOutcome::SessionMismatch, Some(rec.clone()));
                }
                (ContextResolveOutcome::Found, Some(rec.clone()))
            }
        }
    }

    pub fn resolve(&self, verdict_id: &str, gov_tx_id: &str, session_id: &str)
        -> (ResolveOutcome, Option<VerdictRecord>)
    {
        let guard = self.verdicts.read();
        match guard.get(verdict_id) {
            None => (ResolveOutcome::NotFound, None),
            Some(rec) => {
                if rec.gov_tx_id != gov_tx_id {
                    return (ResolveOutcome::TransactionMismatch, Some(rec.clone()));
                }
                if rec.session_id != session_id {
                    return (ResolveOutcome::SessionMismatch, Some(rec.clone()));
                }
                (ResolveOutcome::Found, Some(rec.clone()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance_signal::{SignalBuilder, SignalSource};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    fn approved_signal(session_id: &str) -> GovernanceSignal {
        SignalBuilder::new(SignalSource::Sentinel, Direction::Inbound, session_id)
            .payload_hash("deadbeef")
            .build()
    }

    #[test]
    fn record_then_resolve_matches() {
        let ledger = SentinelVerdictLedger::new();
        let sig = approved_signal("sess1");
        let vid = ledger.record("tx1", &sig);
        let (outcome, rec) = ledger.resolve(&vid, "tx1", "sess1");
        assert_eq!(outcome, ResolveOutcome::Found);
        assert_eq!(rec.unwrap().gov_tx_id, "tx1");
    }

    #[test]
    fn unknown_verdict_id_not_found() {
        let ledger = SentinelVerdictLedger::new();
        let (outcome, rec) = ledger.resolve("SV-fabricated", "tx1", "sess1");
        assert_eq!(outcome, ResolveOutcome::NotFound);
        assert!(rec.is_none());
    }

    #[test]
    fn transaction_mismatch_rejected() {
        let ledger = SentinelVerdictLedger::new();
        let sig = approved_signal("sess1");
        let vid = ledger.record("tx1", &sig);
        let (outcome, _) = ledger.resolve(&vid, "tx2", "sess1");
        assert_eq!(outcome, ResolveOutcome::TransactionMismatch);
    }

    #[test]
    fn session_mismatch_rejected() {
        let ledger = SentinelVerdictLedger::new();
        let sig = approved_signal("sess1");
        let vid = ledger.record("tx1", &sig);
        let (outcome, _) = ledger.resolve(&vid, "tx1", "sessOTHER");
        assert_eq!(outcome, ResolveOutcome::SessionMismatch);
    }

    #[test]
    fn intermediate_record_is_not_execution_authority() {
        let ledger = SentinelVerdictLedger::new();
        let sig = approved_signal("sess1");

        let intermediate_id = ledger.record("tx1", &sig);

        assert!(
            ledger.approved_verdict_id("tx1", "sess1").is_none(),
            "intermediate Sentinel evidence must not authorize provider execution"
        );

        let (outcome, record) = ledger.resolve(&intermediate_id, "tx1", "sess1");
        assert_eq!(outcome, ResolveOutcome::Found);
        assert!(!record.unwrap().final_approved);
    }

    #[test]
    fn final_approved_receipt_is_execution_authority() {
        let ledger = SentinelVerdictLedger::new();
        let sig = approved_signal("sess1");

        let verdict_id = ledger.record_final_approved("tx1", &sig);

        assert_eq!(
            ledger.approved_verdict_id("tx1", "sess1"),
            Some(verdict_id.clone())
        );

        let (outcome, record) = ledger.resolve(&verdict_id, "tx1", "sess1");
        assert_eq!(outcome, ResolveOutcome::Found);
        assert!(record.unwrap().final_approved);

        assert!(
            ledger.approved_verdict_id("tx1", "other-session").is_none(),
            "execution authority must remain session-bound"
        );
    }

    #[test]
    fn concurrent_record_all_persist_distinctly() {
        let ledger = SentinelVerdictLedger::new();
        const N: usize = 64;
        let recorded = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for i in 0..N {
            let ledger = SentinelVerdictLedger {
                verdicts: ledger.verdicts.clone(),
                approved_by_tx: ledger.approved_by_tx.clone(),
                approved_by_context: ledger.approved_by_context.clone(),
            };
            let recorded = recorded.clone();
            handles.push(thread::spawn(move || {
                let sig = approved_signal(&format!("sess{i}"));
                let vid = ledger.record(&format!("tx{i}"), &sig);
                let (outcome, _) = ledger.resolve(&vid, &format!("tx{i}"), &format!("sess{i}"));
                if outcome == ResolveOutcome::Found {
                    recorded.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for h in handles { h.join().unwrap(); }
        assert_eq!(recorded.load(Ordering::SeqCst), N, "no lost writes under concurrent record");
    }
}
