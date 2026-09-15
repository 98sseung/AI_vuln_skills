---
name: burp-attacker-review
description: >-
  Actively verifies prioritized web vulnerability candidates from a Burp surface-map state using targeted raw-packet retrieval, safe differential tests, feature-by-feature summaries, and a final cross-feature review. Use for authorized deep assessment after mapping, or for a focused review by feature, vulnerability class, candidate, or newly observed traffic. Avoid rebuilding or repeatedly loading full Burp History when compatible state exists.
---

# Burp Attacker Review

## Objective

Verify meaningful attacker-view hypotheses from Burp traffic while keeping context bounded. Consume the compact state produced by `burp-surface-map`, retrieve only the raw packets required for the current candidate, run low-risk control comparisons, update candidate dispositions, and write evidence-backed findings.

Do not lead with missing headers, cookie flags, banners, or scanner-style configuration observations unless they materially increase a verified attack path.

This skill assumes an authorized assessment. Default to non-destructive verification and stop for additional authorization when a test would cause material side effects, access third-party data, notify users, spend funds or OTPs, lock accounts, or modify non-disposable records.

## State Contract

Primary state:

```text
.burp-review/<target-key>/state.json
```

If compatible current state exists, treat it as the primary analysis index. Do not rebuild the complete endpoint inventory from raw History unless state is missing, stale, schema-incompatible, or materially contradicted by current traffic.

If state is missing, perform one lightweight target-scoped indexing pass compatible with the `burp-surface-map` schema, then continue. Do not make multiple full-History passes. If traffic has materially changed, recommend or perform an incremental surface-map refresh before broad review.

Preserve earlier dispositions and negative evidence. Reopen a candidate only when new evidence materially changes its endpoint, role, parameter, sink, or response model.

## Modes

Select the smallest mode that satisfies the request:

- `all` (default): review all remaining high-priority candidates, then medium-priority candidates as budget allows.
- `feature <feature-id>`: review unresolved candidates in one feature.
- `class <vulnerability-class>`: review candidates of one applicable class.
- `candidate <candidate-id>`: verify one candidate.
- `new`: review only candidates marked `new_since_last_review`.
- `remaining`: continue unresolved candidates without reopening disposed ones.
- `cross-feature`: analyze stored feature summaries and retrieve raw packets only for a specific cross-feature hypothesis.

Do not interpret `all` as loading all raw packets at once. It means process the feature queue serially.

## Tool Setup

- Use Burp MCP Proxy History tools to retrieve captured packets by stable reference or narrow host/path/method query.
- Use the matching HTTP/1 or HTTP/2 request-sending tool for authorized verification.
- Use browser rendering only when execution context is essential, such as XSS confirmation.
- Use Burp Collaborator or another user-authorized callback service for OOB verification. Do not start external listeners, scan internal networks, or use local-file disclosure payloads without appropriate authorization.

## Context Budget

- Analyze one feature cluster at a time.
- Default to at most 15 raw packets per feature and 6 active candidates per feature in one pass.
- Start with one baseline and one meaningful control per candidate. Expand only when the result remains high-value and unsettled.
- Keep at most 30 active candidates in one `all` run; report remaining queued candidates rather than silently skipping them.
- After a feature is processed, release its raw packet detail from working context and retain only the redacted feature summary, candidate dispositions, packet references, and evidence.
- Re-query narrowly when evidence is missing. Never reload the full raw History merely to regain context.

User-specified time, request, or risk limits override these defaults.

## Workflow

### 1. Load and Validate State

1. Resolve the target and state path.
2. Check schema compatibility, scope hosts, snapshot cursor/timestamp, and unresolved candidates.
3. Select candidates using the requested mode, then order by priority, score, and likely impact.
4. Mark selected candidates `queued`; leave all other state untouched.
5. If current Burp traffic reveals new endpoints or security-relevant variants, add them through a bounded incremental map rather than restarting analysis.

### 2. Build a Feature Queue

Process a single feature at a time. For each feature:

1. Load its endpoint metadata and unresolved candidates.
2. Retrieve representative baseline packets only for the selected candidates.
3. Confirm the actual behavior, sink, authentication mode, role, and state transition before choosing a test.
4. Apply vulnerability prerequisites. A structural cue may create a hypothesis but does not justify a probe by itself.
5. Define the expected vulnerable result and a control comparison before sending a request.

Prioritize authentication, authorization, tenant boundaries, account security, admin functions, financial/approval actions, sensitive data, file operations, and proven server-side sinks.

### 3. Apply Class Gates

Activate a class only when its prerequisites are observed:

| Class | Required evidence before active testing |
| --- | --- |
| IDOR/BOLA | User-controlled object/tenant reference and an ownership boundary |
| RBAC/authorization | Protected action/resource and distinct privilege context or a defined expected role |
| CSRF | State-changing action, ambient browser credential, and plausible cross-site request delivery; consider SameSite, token binding, Origin/Referer checks, and content-type constraints |
| SSRF | Evidence that the server consumes a URL/host or performs a fetch/callback/import |
| XXE | XML-capable parser or XML-bearing upload/API flow |
| SSTI | Server-side render/template behavior, not string reflection alone |
| SQL/NoSQL/LDAP/XPath injection | Input plausibly reaches a corresponding query/expression sink and differential testing is meaningful |
| XSS | User input reaches a browser-rendered context; confirmation requires executable context, not reflection alone |
| Path traversal/download abuse | User-controlled file/path/object selection reaches file retrieval or storage behavior |
| Malicious upload | File ingestion exists and downstream storage, parsing, rendering, or execution is observable |
| Command injection/native weakness | Command/job/native or legacy component evidence exists |
| Open redirect/OAuth flow abuse | User-controlled navigation target or redirect state exists |
| Account/authenticator lifecycle | Observed login, reset, OTP, ownership, device, re-authentication, or approval transition |
| Prompt/tool-use abuse | LLM/agent input reaches a privileged tool, data source, instruction boundary, or action; model text alone is insufficient |
| Business logic | An observed state machine, trust transition, price/status/role field, approval, or cross-feature dependency exists |

If prerequisites are absent, set the candidate to `not-applicable` or leave the class `not-observed`; do not fetch more raw packets solely to prove absence.

### 4. Retrieve Progressively

Use this order:

```text
state metadata
  -> compact request/response summary
  -> one raw baseline packet
  -> one differential/control packet
  -> additional packet only when it can settle a high-value candidate
```

Preserve the captured method, host, protocol, headers, content type, and body shape. Redact secrets in notes and output, but use the authorized captured session when required for a valid test. When testing a hypothesis about a missing header/token, remove only that element and keep the rest stable.

### 5. Verify Safely

Use the least harmful test that distinguishes the hypothesis from its control:

- Authentication: compare valid, invalid, expired/tampered where safely available, and unauthenticated behavior.
- Authorization/IDOR: use owned test accounts and objects. Prefer same-object cross-role comparisons; do not read unrelated real-user data without explicit authorization.
- CSRF: first evaluate deliverability and defenses. Send a state-changing proof only against a disposable fixture or with explicit authorization.
- XSS: use harmless unique canaries through the real input path. Confirm executable browser context; reflection alone is insufficient.
- SQL/NoSQL/LDAP/XPath: prefer boolean/error differentials against a stable baseline. Avoid destructive writes and expensive delay payloads unless explicitly authorized.
- SSRF/XXE/OOB: use unique benign callbacks. Avoid internal-network scanning and local-file disclosure. Correlate the callback with a control.
- SSTI: start with arithmetic or string canaries; do not escalate to code execution merely to increase impact.
- File download/export: retrieve only enough content to prove type, ownership, and sensitivity; redact samples.
- Upload: use harmless files and disposable paths. Do not upload executable content to production or attempt execution without explicit authorization.
- Command injection: use a benign canary only in an authorized test environment; avoid destructive commands.
- Account/OTP/approval flows: avoid lockout, irreversible credential changes, third-party notifications, charges, and OTP consumption unless authorized.
- HTTP methods/admin files: begin with observed paths, `OPTIONS`, or harmless method changes; do not brute-force broad wordlists or write via `PUT`, `DELETE`, or WebDAV outside disposable scope.
- Prompt/tool-use abuse: require observable unauthorized data access, tool invocation, state change, or instruction boundary failure; do not claim impact from suggestive model output alone.

For every sent request, record candidate ID, packet reference, changed element, baseline result, control result, timestamp, and any cleanup needed.

### 6. Classify Evidence

Use these exact dispositions:

- `confirmed`: exploit condition reproduced with a meaningful control comparison.
- `needs-confirmation`: a reachable dangerous surface exists, but final proof is blocked by missing authorization, role/account/object fixture, browser execution, OOB visibility, or required business rule. Record a one-line blocker and the next safe test.
- `not-exploitable`: the input reaches the relevant sink or boundary, and an observed defense positively neutralizes the tested condition. Record the concrete defense.
- `not-reproduced`: reasonable testing produced no exploit condition, but absence is not positively demonstrated. Record the test scope and limitation; do not call it safe.
- `not-applicable`: prerequisites for the class are contradicted or absent from the observed feature. No active test is required.
- `blocked`: the test could not be performed because of tooling, access, state, or authorization constraints. Record the blocker without guessing a result.

Do not convert `not-reproduced` to `not-exploitable` based on effort alone.

### 7. Update Candidate and Feature State

After each candidate, update its status, redacted evidence, test/control summaries, packet references, next action, and timestamp. Set `new_since_last_review` to `false` once triaged.

After each feature, retain only a compact summary:

```json
{
  "feature_id": "user-management",
  "reviewed_candidate_ids": ["cand-001"],
  "confirmed": [],
  "open_candidates": ["cand-001 needs a second owned role"],
  "negative_evidence": [],
  "trust_relationships": ["userId propagates into order APIs"],
  "state_transitions": [],
  "last_reviewed_at": "<ISO-8601>"
}
```

Do not store raw secrets or full packet bodies in state.

### 8. Cross-Feature Review

Run after the requested feature queue, or directly in `cross-feature` mode. Combine feature summaries, not all raw packets.

Look for inconsistencies in:

- Identity and session propagation.
- Object ownership and tenant propagation.
- Role and privilege transitions.
- Price, quantity, discount, refund, and payment transitions.
- Status and approval state machines.
- Password reset, device binding, logout, token refresh, and re-authentication transitions.
- Object IDs reused across ordinary and administrative features.
- Inputs trusted by a downstream feature without server-side revalidation.

Create a new candidate only when summaries support a concrete cross-feature hypothesis. Retrieve the minimum packets necessary to test that hypothesis; do not reopen unrelated feature traffic.

### 9. Coverage Pass

For each broad class, determine one of:

- `covered-confirmed`
- `covered-not-reproduced`
- `observed-needs-manual`
- `not-observed`
- `not-applicable`
- `out-of-scope-low-signal`

Consider account/authenticator lifecycle, session/cookie tampering when authorization-relevant, authorization/IDOR, injection families, upload/download/traversal, malicious upload, XSS/CSRF, SSRF/XXE/SSTI, open redirect, browser-visible sensitive data, admin/unnecessary files/method exposure, error information disclosure, and business logic.

Do not force raw-packet analysis for an unobserved or non-applicable class. Exclude credential-reuse/guessability, rate-limit/load testing, and TLS/certificate checks unless the user explicitly includes them.

## Findings File

When at least one candidate is `confirmed` or materially `needs-confirmation`, create or update one file in the current project:

```text
<target-host>.md
```

Use stable candidate IDs to update existing entries instead of duplicating them across repeated runs. If no candidate qualifies, do not create an empty file; report `no findings to file`.

For each entry include only:

- Severity and concise issue name.
- Candidate ID.
- Location: host, method, normalized path, and affected role/feature.
- One-line impact.
- Status: `Confirmed` or `Needs confirmation` with blocker.
- Evidence: baseline and control result, kept brief and redacted.
- Reusable HTTP payload in a fenced block, with explicit placeholders for secrets, accounts, IDs, callbacks, or destructive values.
- Cleanup note only when applicable.

Do not include large response bodies, live tokens, full personal data, broad checklist matrices, or speculative issues. Mark unexecuted payloads clearly.

## Reporting

Report in the user's language and lead with results:

1. Confirmed findings and exact differential evidence.
2. Needs-confirmation candidates and the single next test or missing prerequisite.
3. Meaningful negative evidence; distinguish `not-exploitable` from `not-reproduced`.
4. Features/classes not observed, not applicable, blocked, or still queued.
5. State and findings file paths.

Do not report a target or class as safe based on partial Burp History.

## Stop Condition

Stop when:

1. Every candidate selected by the requested mode has a disposition or explicit queued/blocked state.
2. Each selected feature has a compact saved summary.
3. Applicable classes for those features have been considered.
4. Cross-feature review has been completed when the requested mode requires it.
5. State and the findings file, when warranted, have been updated without duplicate entries.

Unobserved or non-applicable classes do not require further History searches. Report candidates left for a later `remaining`, `new`, or focused review rather than expanding context indefinitely.
