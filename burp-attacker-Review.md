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
- `bypass <candidate-id>`: when a previously applicable high-risk candidate is blocked or transformed, run a bounded WAF/filter differential ladder against that candidate only.

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

#### High-Risk and RCE-Related Priority Set

Treat the following as explicit first-class candidate families when their prerequisites are observed. Do not rely on the generic term `injection families` to cover them implicitly:

- OS command and argument injection.
- Server-side code evaluation and framework expression injection, including EL, OGNL, SpEL, and MVEL-like sinks.
- Server-side template injection (SSTI).
- Server-Side Includes injection (SSI Injection).
- Unsafe deserialization and gadget-triggered execution paths.
- Malicious file upload, upload validation bypass, archive extraction abuse, and upload-to-webroot or upload-to-execution chains.
- Local/remote file inclusion and path traversal that can reach interpretation, inclusion, overwrite, or execution.
- XXE or SSRF chains that reach privileged internal services, management interfaces, file writes, or execution-capable endpoints.
- Exposed debug, console, job runner, script, plugin, package, deployment, or administrative functions capable of server-side execution.
- Memory-corruption/native gateway candidates only when CGI, native modules, unsafe parsers, or legacy components are supported by technology evidence.

Prioritize these candidates highly, but distinguish the primitive from its final impact. A successful upload, template error, include reflection, parser exception, or HTTP 500 does not by itself prove RCE.

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
| SSI Injection | SSI-capable file/page handling, include directives, `.shtml`/`.shtm`, CGI, or user-controlled content rendered by an SSI-enabled server |
| Expression language/code evaluation | Framework expression or dynamic evaluation behavior suggesting EL, OGNL, SpEL, MVEL, script, or code-evaluation sinks |
| Unsafe deserialization | Serialized object formats, binary/base64 object state, type metadata, object streams, dynamic class loading, or parser behavior consistent with object reconstruction |
| SQL/NoSQL/LDAP/XPath injection | Input plausibly reaches a corresponding query sink and differential testing is meaningful |
| XSS | User input reaches a browser-rendered context; confirmation requires executable context, not reflection alone |
| Path traversal/LFI/RFI/download abuse | User-controlled file/path/object/include selection reaches file retrieval, inclusion, overwrite, or storage behavior |
| Malicious upload/upload-to-execution | File ingestion exists and downstream storage, archive extraction, parsing, rendering, webroot placement, inclusion, or execution is observable |
| Command/argument injection | Command, process, job, script, converter, compiler, diagnostic, or system utility invocation is supported by observed behavior |
| Native/legacy weakness | CGI, native modules, unsafe parsers, long-input boundaries, or legacy components are supported by technology evidence |
| Open redirect/OAuth flow abuse | User-controlled navigation target or redirect state exists |
| Account/authenticator lifecycle | Observed login, reset, OTP, ownership, device, re-authentication, or approval transition |
| Prompt/tool-use abuse | LLM/agent input reaches a privileged tool, data source, instruction boundary, or action; model text alone is insufficient |
| Business logic | An observed state machine, trust transition, price/status/role field, approval, or cross-feature dependency exists |

If prerequisites are absent, set the candidate to `not-applicable` or leave the class `not-observed`; do not fetch more raw packets solely to prove absence.

### 4. Distinguish WAF, Filter, and Application Behavior

When an applicable high-risk candidate is blocked, stripped, rewritten, normalized, or inconsistently handled, determine the enforcement layer before concluding it is mitigated:

- Edge/WAF: challenge or block template, edge-specific headers/request ID, connection behavior, or a response inconsistent with the application baseline.
- Application gateway/framework: request accepted by the edge but rejected during routing, binding, deserialization, validation, or parser handling.
- Application defense: the request reaches the feature and the dangerous value is safely rejected, encoded, parameterized, normalized, or treated as inert data.
- Unknown: evidence cannot reliably distinguish the layer.

Record status, headers, body signature/hash, length class, latency class, application markers, and any unique request ID. A `403`, `406`, connection reset, different error page, or WAF fingerprint proves filtering behavior only; it does not prove the underlying vulnerability is fixed or bypassed.

#### Bounded WAF/Filter Bypass Procedure

Use this procedure only for an already-applicable candidate and only within the authorized target scope:

1. Capture a normal application baseline, a known-inert control, and the blocked/filtered candidate.
2. Identify the likely transformation boundary: URL decoder, proxy, WAF rule, router, body parser, template engine, file validator, query builder, shell wrapper, or downstream service.
3. Change one transformation dimension at a time so the decisive cause remains attributable.
4. Compare edge response and application behavior against both controls.
5. Stop when the sink is reached and the hypothesis can be classified, or when the bounded variant budget is exhausted.

Permitted transformation families for controlled differential testing include:

- Canonicalization: encoding layer, case, whitespace, Unicode normalization, delimiter, separator, comment, quoting, and path normalization variants.
- GET/query token separation: when the underlying sink grammar supports it, try one comment-based separator such as `/**/` in place of a blocked whitespace/token boundary. Apply it only to the candidate parameter, not every query parameter.
- POST body inspection-window testing: add one bounded, syntactically valid, inert padding value that the application safely ignores or accepts, while preserving the candidate's decoded meaning and body schema. Do not use oversized bodies or repeated padding growth that could create load.
- Structural representation: query versus body placement, form/JSON/XML/multipart representation, scalar versus array/object shape, nesting, alternate but application-supported methods, and filename/content-type metadata.
- Parser differentials: duplicate parameters or keys, ordering, empty/null values, mixed encodings, and proxy/framework interpretation differences.
- Equivalent grammar: context-appropriate alternate operators, functions, expression syntax, template delimiters, SSI forms, shell quoting/separators, or database dialect constructs.
- Upload handling: filename normalization, extension and case handling, declared versus detected media type, archive extraction, storage path, retrieval path, and downstream rendering/parsing behavior.

Choose variants as a minimum distinguishing set, not as a payload list. Use at most one representative from each relevant family in the initial pass:

| Observation or hypothesis | First distinct variant |
| --- | --- |
| GET parameter is blocked at a token/whitespace boundary | One `/**/`-style comment separator, if valid for the suspected sink |
| POST body appears subject to a bounded inspection window | One modest inert-padding variant with an unchanged application-level control |
| WAF and application may decode differently | One encoding/canonicalization variant |
| Edge and framework may bind parameters differently | One duplicate-key, array/nesting, or parameter-location variant selected from captured application behavior |
| Body parser or route handling appears content-type dependent | One alternate representation that the endpoint is already known to support |
| Template, SSI, expression, query, or shell grammar is filtered by signature | One semantically equivalent grammar variant appropriate to that exact sink |
| Upload filtering differs from downstream handling | One filename/media-type/storage or retrieval-path differential using a harmless file |

Do not combine multiple obfuscations in the first request. Preserve a transformation ledger so successful behavior can be reduced to the minimum necessary change. Fingerprint each attempt by transformation family, decoded semantic value, parameter location, content type, and body shape; skip an attempt when that fingerprint is equivalent to one already tested.

Default budget per candidate:

- Initial pass: up to 4 variants from different transformation families.
- Hard cap: 8 total transformation variants.
- At most 1 initial variant per family. A second variant from the same family is allowed only when the first result provides new evidence that the family targets the correct enforcement boundary.
- Up to 2 control requests in addition to the captured baseline.
- One dimension changed per variant whenever possible.

Stop early when three distinct transformation families return the same block signature and no new application evidence, or when two variants from one family are equivalent after decoding/normalization. Exceed the hard cap only when the user requests deeper bypass work and the next small set of variants is likely to settle a critical candidate. Do not use large payload dictionaries, uncontrolled fuzzing, request floods, or parser-desynchronization tests with cross-user impact. HTTP request-smuggling/desync checks require explicit authorization and isolated connection handling because they may affect other users.

Do not disable logging, suppress defensive telemetry, rotate identities to evade controls, or treat rate-limit exhaustion as a bypass technique. Retain correlation/request IDs when available so the activity remains auditable.

#### Bypass Outcome Standard

Use precise intermediate outcomes:

- `blocked-at-edge`: repeatable edge/WAF rejection; application reachability not shown.
- `rejected-by-application`: application processed the request and applied a concrete defense.
- `normalized-and-neutralized`: canonicalization occurred and the resulting value was rendered or processed inertly.
- `parser-differential-observed`: layers interpreted an equivalent request differently, but exploit impact is not yet proven.
- `sink-reached`: the transformed request reached the relevant sink; exploit condition remains to be classified.
- `bypass-confirmed`: the transformed request passed the control and reproduced the underlying exploit condition with a negative control.

Only `bypass-confirmed` may support a vulnerability finding. `blocked-at-edge`, a changed status code, or `sink-reached` without exploit impact is not enough.

### 5. Retrieve Progressively

Use this order:

```text
state metadata
  -> compact request/response summary
  -> one raw baseline packet
  -> one differential/control packet
  -> additional packet only when it can settle a high-value candidate
```

Preserve the captured method, host, protocol, headers, content type, and body shape. Redact secrets in notes and output, but use the authorized captured session when required for a valid test. When testing a hypothesis about a missing header/token, remove only that element and keep the rest stable.

### 6. Verify Safely

Use the least harmful test that distinguishes the hypothesis from its control:

- Authentication: compare valid, invalid, expired/tampered where safely available, and unauthenticated behavior.
- Authorization/IDOR: use owned test accounts and objects. Prefer same-object cross-role comparisons; do not read unrelated real-user data without explicit authorization.
- CSRF: first evaluate deliverability and defenses. Send a state-changing proof only against a disposable fixture or with explicit authorization.
- XSS: use harmless unique canaries through the real input path. Confirm executable browser context; reflection alone is insufficient.
- SQL/NoSQL/LDAP/XPath: prefer boolean/error differentials against a stable baseline. Avoid destructive writes and expensive delay payloads unless explicitly authorized.
- SSRF/XXE/OOB: use unique benign callbacks. Avoid internal-network scanning and local-file disclosure. Correlate the callback with a control.
- SSTI: start with arithmetic or string canaries; do not escalate to code execution merely to increase impact.
- SSI Injection: begin with a harmless non-command directive such as a date or controlled environment-variable echo in disposable content, paired with an inert-text control. Do not invoke command-executing SSI directives without explicit authorization.
- Expression language/code evaluation: begin with arithmetic or string canaries and a syntactically similar inert control. Treat evaluation as confirmed only when the server returns or uses the computed result consistently.
- Unsafe deserialization: first establish object reconstruction through format, type-resolution, parser, or controlled callback differentials. Do not use destructive or public gadget chains against production; require explicit authorization and an isolated/disposable target before execution-oriented confirmation.
- File download/export: retrieve only enough content to prove type, ownership, and sensitivity; redact samples.
- Upload: test extension, content type, filename/path, archive handling, retrieval, and storage location with harmless files and disposable paths. Do not upload a webshell or executable payload to production. An upload-to-execution test requires explicit authorization and a controlled non-destructive canary that can be cleaned up.
- Command injection: use a benign canary only in an authorized test environment; avoid destructive commands.
- WAF/filter handling: if the baseline exploit canary is blocked but the class prerequisites remain valid, use the bounded differential procedure above. Confirm the underlying sink and impact rather than reporting a bypass from status-code changes alone.
- Path traversal/LFI/RFI: prefer owned canary files and controlled include targets. Do not retrieve sensitive operating-system files or include remote executable content without explicit authorization.
- Account/OTP/approval flows: avoid lockout, irreversible credential changes, third-party notifications, charges, and OTP consumption unless authorized.
- HTTP methods/admin files: begin with observed paths, `OPTIONS`, or harmless method changes; do not brute-force broad wordlists or write via `PUT`, `DELETE`, or WebDAV outside disposable scope.
- Prompt/tool-use abuse: require observable unauthorized data access, tool invocation, state change, or instruction boundary failure; do not claim impact from suggestive model output alone.

For every sent request, record candidate ID, packet reference, changed element, baseline result, control result, timestamp, and any cleanup needed.

#### RCE Confirmation Standard

Classify server-side code or command execution as `confirmed` only when all of the following are present:

1. A controlled input reaches an execution-capable sink or chain.
2. A unique, non-destructive server-side effect or computed result is observed.
3. A meaningful inert/negative control does not produce that effect.
4. The effect is attributable to the target server rather than client-side rendering, reflection, caching, or an unrelated callback.

If the primitive is proven but execution requires a higher-risk step, classify the primitive appropriately and mark the RCE impact `needs-confirmation`. Do not inflate severity from upload success, error messages, timing noise, or technology fingerprints alone.

### 7. Classify Evidence

Use these exact dispositions:

- `confirmed`: exploit condition reproduced with a meaningful control comparison.
- `needs-confirmation`: a reachable dangerous surface exists, but final proof is blocked by missing authorization, role/account/object fixture, browser execution, OOB visibility, or required business rule. Record a one-line blocker and the next safe test.
- `not-exploitable`: the input reaches the relevant sink or boundary, and an observed defense positively neutralizes the tested condition. Record the concrete defense.
- `not-reproduced`: reasonable testing produced no exploit condition, but absence is not positively demonstrated. Record the test scope and limitation; do not call it safe.
- `not-applicable`: prerequisites for the class are contradicted or absent from the observed feature. No active test is required.
- `blocked`: the test could not be performed because of tooling, access, state, or authorization constraints. Record the blocker without guessing a result.

Do not convert `not-reproduced` to `not-exploitable` based on effort alone.

For filter-protected candidates, also retain the enforcement layer, transformation family, exact single change, edge result, application result, control result, and one of the bypass outcomes above. A WAF block does not automatically justify `not-exploitable`.

### 8. Update Candidate and Feature State

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

### 9. Cross-Feature Review

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

### 10. Coverage Pass

For each broad class, determine one of:

- `covered-confirmed`
- `covered-not-reproduced`
- `observed-needs-manual`
- `not-observed`
- `not-applicable`
- `out-of-scope-low-signal`

Consider account/authenticator lifecycle, session/cookie tampering when authorization-relevant, authorization/IDOR, SQL/NoSQL/LDAP/XPath injection, command/argument injection, expression-language/code evaluation, SSTI, SSI Injection, unsafe deserialization, upload/download/traversal/LFI/RFI, malicious upload and upload-to-execution, XSS/CSRF, SSRF/XXE and execution chains, open redirect, browser-visible sensitive data, debug/console/job-runner/admin exposure, native/legacy weakness where evidenced, error information disclosure, business logic, and WAF/filter/parser differentials for applicable high-risk candidates.

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
