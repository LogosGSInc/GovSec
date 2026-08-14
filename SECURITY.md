# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately to `logosgs@proton.me`.

Include the affected component, revision, reproduction steps, expected impact, and evidence that can be shared safely. Do not include production credentials, customer information, personal data, or destructive proof-of-concept activity.

Do not open a public issue for an unremediated vulnerability.

## Supported baseline

Only the current private `main` branch is considered the supported evaluation baseline. Historic revisions, experimental branches, demonstrations, and separately maintained integrations may not receive security fixes.

## Security limits

GovSec is designed to fail closed at governed context, provider, and action boundaries. These controls depend on correct deployment, trusted key handling, complete adapter coverage, policy configuration, and durable operational monitoring. See `LIMITATIONS.md`.
