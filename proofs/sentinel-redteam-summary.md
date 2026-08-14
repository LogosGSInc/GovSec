# Sentinel OverWatch v3.5 — Red Team Summary

**System:** Sentinel OverWatch v3.5  
**Evaluation Date:** April 2026  
**Framework:** BD1A Attack Taxonomy  
**Methodology:** Solo internal red-teaming using structured adversarial prompt library. Each of the 36 vectors tested against the rule engine. Outcomes logged as BLOCKED, HARD_LOCKED, PARTIAL, or GAP.

## Results Summary
- Total vectors tested: 36
- Blocked: 26 (72.2% block rate)
- HARD_LOCKED (no override path): 8
- Gaps: 8 (none allow data exfiltration, authority override, or constitutional bypass)

## Honest Gap Disclosure
Remaining gaps are primarily soft semantic framing, benign recon tuning, and one encoding variant. Multi-turn drift is architecturally deferred to HAAP Layer 2 by design. Full vector table and internal prompt library available for qualified technical diligence.

*LOGOS Governance Systems Inc. — April 2026. Sanitized for public review.*
