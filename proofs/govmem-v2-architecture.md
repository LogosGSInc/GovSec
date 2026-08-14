# GovMem V2 — RL-Enhanced Multi-Turn Detection

**Date:** April 24, 2026  
**Status:** Phase 1 Complete (infrastructure shipped)  
**Target:** 97–100% defense rate by closing F01/F02 multi-turn drift gaps.

## Purpose

GovMem V2 adds semantic, RL-based multi-turn detection on top of GovMem V1’s rule-based session memory to catch sequences of individually-benign turns that converge on policy violation.

## Two-Tier Design

- **GovMem V1:**
  - Rule-based session memory and per-session counters.
  - 5-state machine (Clear → Watching → Elevated → Escalated → Locked).
  - Tracks boundary probes, authority claims, and extraction attempts.

- **GovMem V2:**
  - Semantic embeddings per message (drift trajectory over time).
  - Memory Policy Agent (MPA) trained with GRPO-style RL.
  - 12-department tracking (EXE/ENG/PRD/SEC/LGL/FIN/OPS/REV/MKT/HR/DAT/GRC).
  - Cross-layer signal aggregation from Sentinel, Corridor, OverWatch, OIM, Arbiter, Constitution.

## Integration & Deployment

- Signals recorded each turn via `record_layer_signal(...)`.
- V1 mode (current default):  
  `make up`
- V2 mode (RL-enhanced, Phase 2 target):  
  `docker-compose -f docker-compose.yml -f docker-compose.govmem-v2.yml up`  
  with `GOVMEM_MODE=v2` and `MPA_MODEL_PATH=/models/mpa_v2.onnx`.

## Phase 2 Plan (2–4 weeks)

1. Integrate sentence embeddings (rust-bert or candle).
2. Collect labeled sessions (BD1A v4.1 attacks, benign, edge cases).
3. Train MPA offline to maximize true positives and minimize false positives.
4. Ship ONNX inference model and run retraining offline on new data.

---

**Validated by:** David W. Smith, Founder & CEO  
**Dev Harness Repo:** https://github.com/LogosGSInc/logos-asf  
**Patent Backbone:** US Provisional 63/953,447 (HAAP v2.0)
