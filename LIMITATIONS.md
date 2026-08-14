# Current Limitations

This repository is a verified development baseline, not a claim of complete production readiness.

Known limitations include:

- The checked-in constitution is a signed placeholder artifact and enforces no approved production policy.
- The audit chain is cryptographically tamper-evident but is not an external immutable or independently durable audit sink.
- In-memory audit and governance state can be lost when the server stops unless deployment-specific persistence is configured and verified.
- Correct enforcement depends on every consequential model and tool path reaching the GovSec boundary.
- Product-specific adapters, including OpenClaw integration, are maintained separately.
- The action classifier recognizes a finite vocabulary and denies unknown tools.
- DEP.KEYSTONE provides a defined build-trust ingress boundary; it does not alone establish full lifecycle authorization.
- Test success does not establish SOC 2, HIPAA, FedRAMP, or another compliance certification.
- Local tests are not equivalent to independent penetration testing or third-party assurance.

Production deployment requires an approved constitution, threat modeling, key-management procedures, durable audit storage, recovery testing, and adapter-coverage verification.
