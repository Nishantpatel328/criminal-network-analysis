# Threat model

**Scope:** analyst browser, edge/API, policy enforcement, graph store, analytics worker, audit service, and operational administrators.

## Assets and trust boundaries

Sensitive assets include identity mappings, case-scoped graph records, sources and evaluations, derived groupings, access tokens, audit records, policy rules, and exports. The browser is untrusted (Z0); edge and API controls enforce access (Z1/Z2); the identity-bearing graph and pseudonymised analytics plane are separated. A compromise of analytics must not reveal direct identities.

## Primary threats and mitigations

| Threat | Mitigation | Residual risk / monitoring |
|---|---|---|
| Stolen unattended workstation | Memory-only state, five-minute idle wipe, reauthentication, no offline cache | Screen photography remains possible; watermark and audit review deter and investigate |
| Browser XSS or malicious extension | Strict CSP, no stored token, same-origin API, no dynamic HTML rendering, hardened workstation baseline | Session can be abused while active; monitor anomalous reads and endpoint telemetry |
| Excessive or curious-user access | Case/purpose checks, RBAC/ABAC policy point, disclosure audit sequences, rate limits | Authorised misuse needs supervisory audit and sanctions |
| Inference mistaken for fact | Mandatory derivation envelope, persistent caveats, hypothesis framing, recorded human review | Human overreliance; conduct training and sample case-file review |
| Re-identification abuse | Separate, justified, separately audited request; only API can resolve surrogates | Legitimate access remains sensitive; monitor high-volume requests |
| Analytics-plane compromise | Opaque surrogates and minimised edge attributes; separate identity mapping | Structural metadata can still be sensitive; encrypt, segment, and rotate keys |
| API or policy bypass | Central policy enforcement, deny-safe responses, schema validation, no client-side authorisation assumptions | New endpoints can drift; require security review and regression tests |
| Audit-log tampering | Append-only protected store, restricted write path, integrity verification and external retention | Privileged collusion; independent audit export and alerting |
| Data poisoning or unreliable sources | Source/assessment grades, exclusion rules, provenance, stability testing, analyst-visible evaluation key | Bad but plausible data; source governance and quality review |
| Denial of service | Request-size ceilings, bounded graph expansions, rate limiting, queue isolation | Capacity exhaustion; load tests, quotas, and incident runbook |

## Security requirements and validation

Security changes require review against this model. Validate least-privilege access, redaction failures, session wipe, audit completeness, pseudonymisation boundary, export/review gate, rate limits, dependency integrity, and recovery procedures. Report suspected disclosure or integrity incidents through the incident-response process; preserve audit evidence and notify the responsible controller as required by the applicable regime.
