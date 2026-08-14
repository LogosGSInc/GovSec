//! Gate 3 — Tier 1 (SessionMemory) convergence red tests.
//!
//! Before this gate, GovMem::should_block() read v2_sessions'
//! semantic_drift_score/mpa_anomaly_score — permanent 0.0 placeholders,
//! gated behind GovMemMode::V2, which nothing in this deployment ever sets.
//! Meanwhile the REAL per-session threat accumulator (SessionMemory, in
//! session_memory.rs) already lived in GovernancePipeline.session_memories
//! and drove the arbiter's threshold_modifier — but should_block() never
//! looked at it. T01 proves should_block() now reads that real accumulator.

use governance_spine::govmem::{GovMem, GovMemMode};
use governance_spine::session_memory::{
    MemoryConfig, RequestClassification, SessionMemory,
};
use governance_spine::governance_signal::{Direction, Severity, SignalBuilder, SignalSource};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// Mirrors the helper `session_memory.rs`'s own tests use (see
/// governance-spine/src/session_memory.rs:738) and the shape of the real
/// signal GovernancePipeline::ingest_to_memory feeds in.
fn escalation_signal(session_id: &str) -> governance_spine::GovernanceSignal {
    SignalBuilder::new(SignalSource::Sentinel, Direction::Inbound, session_id)
        .severity(Severity::High, 0.9)
        .build()
}

#[test]
fn t01_should_block_returns_true_when_threshold_exceeded() {
    // Build the shared session_memories map — the same type and the same
    // Arc-sharing pattern GovernancePipeline::new() now uses (see
    // pipeline.rs: session_memories constructed before GovMem, cloned into
    // both, not two independent stores).
    let session_memories: Arc<RwLock<HashMap<String, SessionMemory>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let session_id = "t01-tier1-convergence";
    let config = MemoryConfig::default();

    // Drive SessionMemory to Escalated state directly via ingest_signal,
    // mirroring how GovernancePipeline::ingest_to_memory calls it
    // (pipeline.rs's ingest_to_memory — real classification, real signal).
    {
        let mut memories = session_memories.write();
        let mem = memories
            .entry(session_id.to_string())
            .or_insert_with(|| SessionMemory::new(session_id));

        // escalated_threshold defaults to 2.5 cumulative_threat; High severity
        // (multiplier 1.0) at confidence 0.9 with decay 0.95 crosses it by the
        // 3rd-4th call. Loop generously — the setup assertion below is what
        // actually proves we got there, not this iteration count.
        for _ in 0..6 {
            mem.ingest_signal(&escalation_signal(session_id), RequestClassification::Escalation, &config);
        }

        // Setup assertion: confirm we actually reached a state whose
        // threshold_modifier is <= 0.40 (Escalated or Locked) BEFORE
        // asserting anything about GovMem — a passing acceptance assertion
        // below must be caused by this, not by an unrelated default.
        let modifier = mem.threshold_modifier();
        assert!(
            modifier <= 0.40,
            "test setup failed: session must be Escalated (threshold_modifier <= 0.40), got {modifier}"
        );
    }

    // Gate 3: GovMem shares this exact Arc, not a copy of the map.
    let gm = GovMem::new_with_sessions(Arc::clone(&session_memories), GovMemMode::V1);

    // SEC's registry threshold is 0.5. Escalated => block_score 0.60 > 0.5.
    assert!(
        gm.should_block(session_id, Some("SEC")),
        "should_block must return true for SEC session in Escalated state"
    );
}

#[test]
fn t01b_should_block_false_when_below_threshold() {
    // Companion to T01: a session that never accumulates any threat must
    // not block, for any department — guards against a should_block that's
    // unconditionally true regardless of session state.
    let session_memories: Arc<RwLock<HashMap<String, SessionMemory>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let session_id = "t01b-clear-session";

    session_memories
        .write()
        .insert(session_id.to_string(), SessionMemory::new(session_id));

    let gm = GovMem::new_with_sessions(Arc::clone(&session_memories), GovMemMode::V1);

    assert!(
        !gm.should_block(session_id, Some("SEC")),
        "a Clear session (no signals ingested) must not block, even under SEC's strict 0.5 threshold"
    );
}

#[test]
fn t01c_unknown_session_does_not_block() {
    // A session_id GovMem has never seen (no entry in session_memories at
    // all) must not block — absence is not evidence of threat.
    let session_memories: Arc<RwLock<HashMap<String, SessionMemory>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let gm = GovMem::new_with_sessions(Arc::clone(&session_memories), GovMemMode::V1);

    assert!(!gm.should_block("never-seen-session-id", Some("SEC")));
}

#[test]
fn t01d_govmem_and_pipeline_share_one_arc_not_a_copy() {
    // The core Gate 3 correctness guardrail: GovMem must observe writes made
    // through the SAME Arc from elsewhere (simulating what
    // GovernancePipeline::ingest_to_memory does), not a snapshot taken at
    // construction time.
    let session_memories: Arc<RwLock<HashMap<String, SessionMemory>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let session_id = "t01d-shared-arc-test";

    let gm = GovMem::new_with_sessions(Arc::clone(&session_memories), GovMemMode::V1);

    // GovMem constructed first, session didn't exist yet — must not block.
    assert!(!gm.should_block(session_id, Some("SEC")));

    // Now write through the ORIGINAL Arc handle, as Pipeline would via
    // ingest_to_memory — not through anything GovMem exposes.
    {
        let config = MemoryConfig::default();
        let mut memories = session_memories.write();
        let mem = memories
            .entry(session_id.to_string())
            .or_insert_with(|| SessionMemory::new(session_id));
        for _ in 0..6 {
            mem.ingest_signal(&escalation_signal(session_id), RequestClassification::Escalation, &config);
        }
        assert!(mem.threshold_modifier() <= 0.40, "test setup failed to reach Escalated");
    }

    // GovMem must see it immediately — same Arc, no separate copy to sync.
    assert!(
        gm.should_block(session_id, Some("SEC")),
        "GovMem must observe writes made through the shared Arc from outside itself"
    );
}
