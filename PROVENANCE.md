# Source Provenance

## GovSec runtime

This public repository contains the GovSec governance runtime maintained by LOGOS Governance Systems, Inc.

The public tree was reconstituted from the verified GovSec runtime baseline used during the August 2026 capability-binding evidence work, followed by repository-boundary cleanup and removal of unrelated product and agent-framework material.

The public repository intentionally excludes:

- LOGOS ASF department-agent material;
- Abigail-specific orchestration and prompt assets;
- DEP.KEYSTONE source and training-ingress material;
- standalone GovMem promotion utilities;
- OpenClaw source and demonstration overlays;
- build products, credentials, and local runtime state.

Those exclusions define repository scope; they do not represent deletion of LOGOS development history.

## Evidence lineage

Each frozen evidence set identifies the runtime source revision against which that evidence was generated and carries SHA-256 checksums for its artifacts.

Evidence should be interpreted according to the source revision recorded in its manifest. A later repository cleanup or refactor does not retroactively change what an earlier evidence freeze proves.

## Ownership

GovSec and LOGOS-authored GovSec integration code are owned by LOGOS Governance Systems, Inc., subject to the rights and licenses of third-party dependencies.

## Development process

GovSec has been developed through human-directed software engineering with AI-assisted development tools.

Architecture decisions, implementation selection, testing, modification, release decisions, and publication remain under human direction and corporate control.
