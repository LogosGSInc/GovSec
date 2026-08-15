# Current Limitations

GovSec is an active development and evaluation baseline, not a claim of complete production readiness.

Current limitations include:

- The checked-in governance-spine constitution is a verification artifact, not an approved deployment-specific production policy.
- Frozen Capability Lab evidence uses synthetic resources and a local canonical runtime environment; it is not evidence of a production customer deployment.
- Correct enforcement depends on every consequential execution path actually reaching the applicable GovSec boundary.
- The baseline action classifier recognizes a finite vocabulary and denies unknown action classes by default.
- Cross-session strategic actor memory does not currently provide a server-authenticated durable actor identity suitable for authorization-bearing decisions.
- Evidence Plane v1 provides signed, hash-linked local evidence, explicit signed checkpoints, and an external sink contract, but the independently operated WORM sink is not provisioned by this repository.
- Evidence checkpoint persistence and restoration are deployment responsibilities until the external durable evidence sink is configured and verified.
- Runtime state durability depends on deployment configuration and must be verified for the intended environment.
- Test success and demonstration evidence do not constitute independent penetration testing, formal verification, SOC 2, HIPAA, FedRAMP, or another compliance certification.
- Product-specific adapters and complete third-party agent runtimes are outside this repository.

Production deployment requires deployment-specific threat modeling, key management, approved policy configuration, adapter-coverage verification, durable evidence handling, operational monitoring, recovery testing, and security review.
