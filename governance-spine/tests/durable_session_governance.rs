//! A1 — Durable Session Governance: Rust-side regression tests.
//!
//! Before A1, the Python client minted a brand-new Sentinel session_id on
//! every single turn (abigail_hardened_enhanced.py:927), so these Rust
//! accumulation mechanisms — all of which already worked correctly when
//! given the SAME session_id twice — never actually got to accumulate
//! anything in production. These tests pin the mechanisms A1's durable
//! session_id now actually exercises, plus the one genuinely new piece of
//! Rust behavior: end_session() now also forgets Arbiter and OverWatch
//! state for that session_id (previously it only cleared session_memories).
//!
//! Numbered per the A1 design doc (A1_DESIGN.md) test plan.

use governance_spine::governance_signal::SignalBuilder;
use governance_spine::session_memory::RequestClassification;
use governance_spine::{
    Arbiter, ArbiterConfig, CryptoEngine, Direction, GovernancePipeline, MemoryConfig,
    MemoryState, SecurityState, Severity, SessionMemory, SignalSource,
};
use std::sync::Arc;

fn fresh_arbiter() -> Arbiter {
    let crypto = Arc::new(CryptoEngine::new("durable-session-governance-test-seed"));
    Arbiter::new(ArbiterConfig::default(), crypto)
}

// ── Test 1 + 2: drift / cumulative threat increase across turns ────────────

#[test]
fn cumulative_threat_increases_across_turns_same_session() {
    let mut mem = SessionMemory::new("conv-threat-test");
    let config = MemoryConfig::default();

    let signal = || {
        SignalBuilder::new(SignalSource::Sentinel, Direction::Inbound, "conv-threat-test")
            .severity(Severity::Medium, 0.75)
            .build()
    };

    let v1 = mem.ingest_signal(&signal(), RequestClassification::Boundary, &config);
    let v2 = mem.ingest_signal(&signal(), RequestClassification::Boundary, &config);
    let v3 = mem.ingest_signal(&signal(), RequestClassification::Boundary, &config);

    assert!(
        v2.cumulative_threat > v1.cumulative_threat,
        "turn 2 ({}) must exceed turn 1 ({}) — same session must accumulate, not reset",
        v2.cumulative_threat, v1.cumulative_threat
    );
    assert!(
        v3.cumulative_threat > v2.cumulative_threat,
        "turn 3 ({}) must exceed turn 2 ({})", v3.cumulative_threat, v2.cumulative_threat
    );
}

// ── Test 3: memory floor persists across turns ──────────────────────────────

#[test]
fn memory_floor_persists_after_escalation() {
    let mut mem = SessionMemory::new("conv-floor-test");
    let config = MemoryConfig::default();
    let arbiter = fresh_arbiter();

    let signal = || {
        SignalBuilder::new(SignalSource::Sentinel, Direction::Inbound, "conv-floor-test")
            .severity(Severity::Medium, 0.75)
            .build()
    };

    // Drive cumulative_threat up to Elevated (>= 1.5) — a few medium signals.
    let mut verdict = mem.ingest_signal(&signal(), RequestClassification::Boundary, &config);
    for _ in 0..4 {
        verdict = mem.ingest_signal(&signal(), RequestClassification::Boundary, &config);
    }
    assert_eq!(verdict.state, MemoryState::Elevated, "expected accumulation to reach Elevated");

    // Even though the Arbiter's OWN per-signal decision might be S1 (a mild
    // signal in isolation), the memory floor must force at least S2.
    let floored = arbiter.apply_memory_floor(&verdict.state, SecurityState::S1);
    assert_eq!(floored, SecurityState::S2, "Elevated memory must floor the state at S2");

    // The floor is a function of memory_state, not of "how long ago" it was
    // set — it persists as long as memory_state stays Elevated, regardless
    // of how many more (mild) turns occur in between.
    let one_more_mild_turn = mem.ingest_signal(
        &SignalBuilder::new(SignalSource::Sentinel, Direction::Inbound, "conv-floor-test")
            .severity(Severity::Low, 0.2)
            .build(),
        RequestClassification::Benign,
        &config,
    );
    let floored_again = arbiter.apply_memory_floor(&one_more_mild_turn.state, SecurityState::S1);
    assert!(
        floored_again >= SecurityState::S2,
        "floor must not silently reset after an intervening mild turn"
    );
}

// ── Test 4 + 5: escalation ratchets upward, locks survive multiple turns ──

#[test]
fn escalation_ratchets_upward_same_session() {
    let arbiter = fresh_arbiter();
    let sid = "conv-escalation-test";

    assert_eq!(arbiter.current_state(sid), SecurityState::S1);

    let medium = SignalBuilder::new(SignalSource::Sentinel, Direction::Inbound, sid)
        .severity(Severity::Medium, 0.75) // >= medium_confidence_threshold (0.70)
        .build();
    assert_eq!(arbiter.process(&medium), SecurityState::S2, "Medium signal must escalate S1->S2");

    let high = SignalBuilder::new(SignalSource::Sentinel, Direction::Inbound, sid)
        .severity(Severity::High, 0.85) // >= high_confidence_threshold (0.80)
        .build();
    assert_eq!(arbiter.process(&high), SecurityState::S3, "High signal must escalate S2->S3");

    let critical = SignalBuilder::new(SignalSource::Sentinel, Direction::Inbound, sid)
        .severity(Severity::Critical, 0.95) // >= critical_confidence_threshold (0.90)
        .build();
    assert_eq!(arbiter.process(&critical), SecurityState::S4, "Critical signal must escalate S3->S4");
}

#[test]
fn lock_state_survives_multiple_subsequent_turns() {
    let arbiter = fresh_arbiter();
    let sid = "conv-lock-survives-test";

    let critical = SignalBuilder::new(SignalSource::Sentinel, Direction::Inbound, sid)
        .severity(Severity::Critical, 0.99)
        .build();
    assert_eq!(arbiter.process(&critical), SecurityState::S4);

    // Several subsequent clean turns in the SAME conversation must not
    // silently clear the lock — only an explicit operator reset does
    // (C3, unchanged by A1).
    for _ in 0..3 {
        let clean = SignalBuilder::new(SignalSource::Sentinel, Direction::Inbound, sid).build();
        assert_eq!(
            arbiter.process(&clean), SecurityState::S4,
            "lock must survive across multiple subsequent turns of the same conversation"
        );
    }
}

#[test]
fn different_sessions_remain_independent() {
    let arbiter = fresh_arbiter();
    let locked_sid = "conv-a-locked";
    let other_sid = "conv-b-untouched";

    let critical = SignalBuilder::new(SignalSource::Sentinel, Direction::Inbound, locked_sid)
        .severity(Severity::Critical, 0.99)
        .build();
    assert_eq!(arbiter.process(&critical), SecurityState::S4);

    // A second, distinct conversation must start clean — durable session_id
    // means "reuse across turns of ONE conversation," not global escalation.
    assert_eq!(arbiter.current_state(other_sid), SecurityState::S1);
}

// ── Test 8: end_session performs cleanup ────────────────────────────────────

#[test]
fn arbiter_forget_session_clears_lock_state() {
    let arbiter = fresh_arbiter();
    let sid = "conv-forget-test";

    let critical = SignalBuilder::new(SignalSource::Sentinel, Direction::Inbound, sid)
        .severity(Severity::Critical, 0.99)
        .build();
    assert_eq!(arbiter.process(&critical), SecurityState::S4);

    arbiter.forget_session(sid);

    assert_eq!(
        arbiter.current_state(sid), SecurityState::S1,
        "forget_session must remove the entry entirely, not just leave it locked \
         (current_state defaults to S1 only when no entry exists — an S4 lock \
         never auto-clears on its own, per the previous test)"
    );
}

#[test]
fn pipeline_end_session_clears_session_memory_entry() {
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline init");
    let sid = "conv-end-session-memory-test";

    let _ = pipeline.inbound("hello, how are you today?", sid, "gtx-end-test-1");
    assert!(
        pipeline.session_memory_state(sid).is_some(),
        "one turn must create a session_memories entry"
    );

    pipeline.end_session(sid, "test-actor");

    assert!(
        pipeline.session_memory_state(sid).is_none(),
        "end_session must remove the session_memories entry (pre-existing behavior, unchanged by A1)"
    );
}

#[test]
fn pipeline_end_session_resets_arbiter_and_overwatch_to_defaults() {
    let pipeline = GovernancePipeline::default_pipeline().expect("pipeline init");
    let sid = "conv-end-session-full-cleanup-test";

    let _ = pipeline.inbound("hello, how are you today?", sid, "gtx-end-test-2");
    pipeline.end_session(sid, "test-actor");

    // After end_session, a session_id that was previously in use must read
    // back exactly like one that was never seen — arbiter and overwatch
    // state (not just session_memories) are now forgotten too.
    assert_eq!(pipeline.current_state(sid), SecurityState::S1);
    assert_eq!(pipeline.session_overwatch_drift(sid), 0.0);
}
