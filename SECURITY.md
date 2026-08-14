# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately to `logosgs@proton.me`.

Include the affected component, revision, reproduction steps, expected impact, and evidence that can be shared safely.

Do not include production credentials, customer information, regulated data, or destructive proof-of-concept activity in a public issue.

## Supported baseline

The current `main` branch is the supported public evaluation baseline.

Historical revisions, experimental branches, demonstration environments, and separately maintained integrations may not receive equivalent security fixes.

## Security model

GovSec enforcement depends on:

- trusted runtime configuration;
- protected signing keys;
- verified policy material;
- correct adapter placement;
- complete coverage of consequential execution paths;
- preservation of capability-bound fields;
- fail-closed handling of verification and boundary failures.

See `LIMITATIONS.md` for current constraints.
