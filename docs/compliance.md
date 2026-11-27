# Compliance control matrix

**Status:** implementation baseline. This document is a control map, not legal advice; the controller must validate jurisdiction-specific obligations before deployment.

| Obligation | Implemented control | Evidence to retain |
|---|---|---|
| CJIS access control and authentication | OIDC/mTLS at the edge, role and case checks in the policy enforcement point, short reauthentication window | IdP configuration, access reviews, authentication logs |
| CJIS audit and accountability | Per-disclosure audit sequence, correlation ID, actor/case/purpose records, rendered watermark | Immutable audit records, audit-review reports |
| CJIS media and session protection | No browser persistence or API cache; idle wipe; response headers and service worker prohibit caching | Security tests, browser configuration baseline |
| LED lawful/fair processing and purpose limitation | Case-scoped requests require a declared purpose and lawful-basis reference at ingestion | Processing register, source approvals, policy decisions |
| LED data quality and data-subject categorisation | Subject categories drive protection and analytics exclusion for victims/witnesses | Data-quality checks, redaction and classification tests |
| LED automated decision safeguards / GDPR Art. 22 | Derived outputs are hypotheses, are never per-person risk scores, and require human review | Derivation envelopes, recorded reviews, export gate tests |
| GDPR/LED security of processing | Pseudonymised analytics plane, least privilege, encryption in transit, rate limits, redaction, monitoring | Architecture review, penetration tests, incident exercises |
| Data minimisation and storage limitation | Analytics gets only surrogate graph data; retention follows case schedule and deletion workflow | Data-flow map, retention review logs |
| Supplier and transfer governance | Approved processors, data-processing terms, location/transfer assessment, access review | Contracts, transfer impact assessments, supplier audits |

## Release gates

Before production use, the controller must approve: a DPIA/LED impact assessment, threat-model review, records of processing, jurisdictional retention schedule, incident-response exercise, access-control test, audit-log integrity test, and an independent review of the analytic method and its documentation. Controls are revalidated after material changes to data sources, policy rules, model parameters, hosting, or exports.
