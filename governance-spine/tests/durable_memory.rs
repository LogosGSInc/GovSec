//! GS-BUILD-01 verification: StrategicMemory must be durable across a restart.
//!
//! Proves the two acceptance criteria from GOVSPINE-02-REORDERED:
//!   1. Write a value, "kill and restart" (drop + reconstruct from disk),
//!      confirm the value is still readable.
//!   2. SENTOW_MEMORY_PATH is the actual location written to, not just printed.

use governance_spine::{StrategicMemory, SessionMemory};

fn temp_path(tag: &str) -> std::path::PathBuf {
    // Unique per process + tag so parallel test binaries don't collide.
    std::env::temp_dir().join(format!("gs_build01_{}_{}.json", tag, std::process::id()))
}

#[test]
fn strategic_memory_survives_restart() {
    let path = temp_path("restart");
    let _ = std::fs::remove_file(&path);

    // ── process lifetime #1: write then "exit" (drop) ─────────────────────────
    {
        let mut mem = StrategicMemory::with_path(Some(path.clone()));
        assert!(mem.is_durable(), "store with a path must report durable");

        let mut fp = SessionMemory::new("actor-42").to_fingerprint();
        fp.escalated = true;
        fp.final_cumulative_threat = 8.0;

        let persisted = mem.ingest_session("actor-42", fp);
        assert!(persisted, "durable write must report persisted=true");
        assert_eq!(mem.total_sessions("actor-42"), 1);
    } // mem dropped — simulates process termination

    // Criterion 2: the configured path is the real write location.
    assert!(path.exists(), "SENTOW_MEMORY_PATH file must exist on disk after a write");

    // ── process lifetime #2: reload from disk ─────────────────────────────────
    let reloaded = StrategicMemory::with_path(Some(path.clone()));
    assert_eq!(reloaded.actor_count(), 1, "actor profile must survive the restart");
    assert_eq!(reloaded.total_sessions("actor-42"), 1, "session count must survive");
    assert_eq!(reloaded.escalated_sessions("actor-42"), 1, "escalation must survive");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn in_memory_store_reports_non_durable_and_persists_nothing() {
    let mut mem = StrategicMemory::new();
    assert!(!mem.is_durable(), "no-path store must report non-durable");

    let fp = SessionMemory::new("ephemeral").to_fingerprint();
    let persisted = mem.ingest_session("ephemeral", fp);
    assert!(!persisted, "in-memory-only store must report persisted=false, never claim durability");
    // The profile still exists in-process for the current run…
    assert_eq!(mem.total_sessions("ephemeral"), 1);
    // …but a fresh in-memory store starts empty (nothing survived).
    assert_eq!(StrategicMemory::new().actor_count(), 0);
}

#[test]
fn corrupt_snapshot_starts_empty_without_panicking() {
    let path = temp_path("corrupt");
    std::fs::write(&path, b"{ this is not valid json ]").unwrap();

    // Availability over hard-fail on a non-security-critical read: a garbled
    // snapshot must not crash the gate; it starts empty and logs a warning.
    let mem = StrategicMemory::with_path(Some(path.clone()));
    assert_eq!(mem.actor_count(), 0);
    assert!(mem.is_durable());

    let _ = std::fs::remove_file(&path);
}
