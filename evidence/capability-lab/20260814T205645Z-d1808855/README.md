# GovSec Capability Lab — Live Runtime Evidence

Evidence mode: LIVE
Freeze ID: 20260814T205645Z-d1808855
GovSec commit: d1808855f7488e1ff26aedb53683252eadb0e77f
Branch: agent/publish-canonical-govsec
Profile: govsec-demo-profile-v1
Policy version: demo-1.0.0

All tested resources are synthetic.

The UI does not decide authorization.
The adapter does not decide authorization.
The GovSec runtime produced the decisions recorded here.

## Verified Live Results

1. Exact execution
   write -> customer/3817
   CAPABILITY_CONSUMED

2. Capability replay
   same capability -> second use
   CAPABILITY_REPLAY_REJECTED

3. Resource substitution
   customer/3817 -> customer/*
   CAPABILITY_RESOURCE_MISMATCH

4. Tool substitution
   write -> bash
   CAPABILITY_TOOL_MISMATCH

5. Run substitution
   authorized run -> substituted run
   CAPABILITY_RUN_MISMATCH

## Evidence Model

CODE = mechanism exists.
TEST = behavior is exercised.
LIVE DECISION = running GovSec produced the result.

No private signing keys, service tokens, or operator-reset tokens are included.
