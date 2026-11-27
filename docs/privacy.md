# Privacy design and data-protection controls

**Status:** implementation baseline. **Owner:** Data Protection Officer and Security Engineering.

## Purpose and boundaries

This service supports case-scoped analysis of lawfully held investigative data. It produces structural hypotheses about disclosed graph data; it does not make findings of fact, predict offending, assign criminality scores, or take adverse decisions about individuals. Automated outputs are separated from evidential records and require recorded human review before onward use.

## Data minimisation and purpose limitation

- Every browser request declares a case identifier and permitted purpose. The API policy decision is the authority for disclosure; the client cannot widen it.
- The analytics tier receives opaque surrogate identifiers, coarse relationship types, and weights. Names, dates of birth, contact details, photos, and special-category data remain outside that tier.
- UI state is memory-only. It uses no localStorage, IndexedDB, cookies, response cache, or offline mode. An idle workstation clears released records after five minutes; session reauthentication is expected within 15 minutes.
- Redaction returns counts and neutral notices, not a list of withheld fields. This prevents a redaction notice itself revealing that a sensitive attribute exists.

## Transparency and human oversight

Derived groupings are visibly labelled as inferences, show their method, version, snapshot, stability, caveats, and limitations, and never use labels such as “gang” or “leader.” Reviewers can record agreement or disagreement. A result cannot be treated as a decision without an accountable human assessment and supporting evidence.

## Retention, access, and rights

Retention is defined by the relevant case schedule and lawful authority, with a review trigger on case closure, legal hold release, or source-data deletion. Access is least-privilege, case-scoped, purpose-bound, and logged. Requests for access, rectification, restriction, or erasure are assessed under the applicable law-enforcement exemption and preservation duties; the system must preserve the decision and reason without exposing protected operational details.

## Accountability

Each disclosure and review carries an audit sequence, actor, case, purpose, policy obligations, and watermark where required. The controller maintains records of processing, a DPIA/LED impact assessment, data-sharing agreements, processor terms, retention schedules, and incident-response records. New data sources, new analytic methods, and any expansion to automated decision support require privacy and legal review before release.
