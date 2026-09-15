---
name: burp-surface-map
description: >-
  Passively indexes and incrementally refreshes a web target's Burp Proxy HTTP History. Use before active vulnerability review, or after browsing new features, to normalize and deduplicate endpoints, group them by feature, determine applicable attack classes, rank candidates, and maintain reusable state without sending attack requests. Do not use this skill to verify or claim vulnerabilities.
---

# Burp Surface Map

## Objective

Turn changing Burp Proxy History into a compact, reusable attack-surface map for `burp-attacker-review`.

This skill is passive: it may query and inspect captured History, but it must not replay, mutate, or send HTTP requests. Its job is to organize evidence and produce candidates, not to prove vulnerabilities.

Store state at:

```text
.burp-review/<target-key>/state.json
```

Use a filesystem-safe target key derived from the primary host. Keep one state file per target. Update it atomically when possible; do not discard previously reviewed results during a refresh.

## Inputs

Derive or ask only when required:

- `target_host`: primary user-facing host.
- `scope_hosts`: start with `target_host`; add only related API, authentication, gateway, or resource hosts supported by captured evidence.
- `mode`: `init`, `refresh`, or `rebuild`. Default to `refresh` when compatible state exists, otherwise `init`.
- `history_cursor`: a stable Burp History ID when available; otherwise use timestamp plus request fingerprints.

Use `rebuild` only when the user requests it, the schema is incompatible, or state is materially inconsistent with current traffic.

## Tool Setup

- Use Burp MCP Proxy History tools when available. If needed, discover a target-scoped History query tool.
- Prefer target- or regex-scoped History queries over loading the full global History.
- Never use request-sending tools in this skill.
- Do not perform broad subdomain discovery or wordlist enumeration. Derive related hosts from `Origin`, `Referer`, browser API calls, JavaScript references, shared flow identifiers, or clearly related feature paths.

## Context and Retrieval Budget

Endpoint coverage may be broad; raw packet context must stay narrow.

Default working limits, adjustable when the user requests wider coverage:

- Index up to 5,000 relevant History items per refresh operation.
- Keep at most 3 representative packet references per security-semantic fingerprint.
- Read response metadata and compact schema before raw response bodies.
- Read at most 30 raw bodies per refresh, prioritizing authentication, authorization, sensitive data, file, parser, URL-fetch, administrative, and financial/business surfaces.
- Retain at most 40 active candidates; record overflow counts and the cutoff instead of silently dropping them.

If a tool result is large, paginate or query narrower slices. Do not repeatedly place the complete raw History in model context.

## Workflow

### 1. Load State and Select the Delta

If state exists:

1. Validate `schema_version`, `target_host`, and scope.
2. Start after `last_history_id` when the tool exposes stable IDs.
3. Otherwise query a bounded time window and discard fingerprints already listed in `seen_fingerprints` unless their security-relevant variant changed.
4. Preserve prior endpoint review status, candidate dispositions, findings links, negative evidence, and feature summaries.

If state does not exist, create an initial target-scoped snapshot. A refresh must analyze new or changed traffic, not rebuild the old map by default.

### 2. Derive Evidence-Backed Scope

Include a related host only when captured evidence connects it to the target, for example:

- XHR/fetch from the primary application.
- `Origin` or `Referer` from an in-scope host.
- Shared authentication flow or business object identifiers.
- API/auth/gateway host referenced by target JavaScript or responses.
- A clear feature path belonging to the observed application flow.

Record the evidence for every added host. Exclude unrelated analytics, advertisements, telemetry, and third-party content unless it participates in an in-scope security boundary.

### 3. Build a Compact Endpoint Index

For each useful History item, record metadata first:

- History ID or stable packet reference.
- Timestamp, scheme, host, port, method, and path.
- Normalized path.
- Request content type and sorted parameter/key names; do not store secrets.
- Authentication mode such as cookie, bearer, basic, mutual TLS indicator, or unauthenticated. Store names and roles, not credential values.
- Status, response content type, response length, redirect target class, and compact response schema/field names.
- State-changing flag.
- Observed role/account context when supported by evidence.
- Security-relevant traits: identifier, upload, download, export, redirect, URL fetch, XML/parser, render/template, search/query, admin, account lifecycle, payment, approval, LLM/tool use, or sensitive response.

Do not copy large raw request or response bodies into state. Store packet references and redacted summaries.

### 4. Normalize and Deduplicate

Normalize volatile path segments such as integers, UUIDs, high-entropy IDs, hashes, timestamps, and opaque object keys:

```text
/users/1042                 -> /users/{id}
/orders/550e8400-e29b-...   -> /orders/{uuid}
/files/a8f13c9e7d...        -> /files/{token}
```

Do not normalize meaningful static route names, version segments, actions, roles, or status values when they distinguish behavior.

Create a security-semantic fingerprint from:

```text
host | method | normalized_path | request_content_type |
sorted_parameter_names | auth_mode
```

Merge duplicate traffic under one endpoint entry, but preserve separate variants when any of the following differs materially:

- Authenticated versus unauthenticated or role/account context.
- Status or redirect behavior.
- Parameter shape, body schema, or content type.
- Response schema, sensitivity, or size class.
- State-changing behavior.
- Error behavior or server-side sink evidence.

Keep representative packet references for baseline, auth/role differential, and response/error differential when available.

### 5. Group by Feature

Group endpoints by observed business capability rather than URL alone, for example:

- Authentication and session lifecycle.
- Account/profile/security settings.
- User or tenant management.
- Orders, payments, refunds, and approvals.
- Uploads, downloads, imports, and exports.
- Administration and privileged operations.
- Messaging, templates, reports, or content management.

An endpoint may belong to more than one feature when it crosses trust boundaries. Use stable, short feature IDs. Record unresolved groupings instead of inventing application semantics.

### 6. Determine Vulnerability Applicability

Determine applicability for every broad vulnerability family, but activate a class only when the observed feature, input, sink, or trust boundary supports it. `not-observed` is a valid result and does not require more raw traffic.

| Observed primitive | Applicable classes |
| --- | --- |
| Object or tenant identifier | IDOR/BOLA, horizontal/vertical authorization |
| Privileged or state-changing action | Authorization, business logic; CSRF only with ambient credentials and plausible cross-site delivery |
| URL fetch, webhook, import, proxy | SSRF; open redirect only for client navigation behavior |
| XML/SOAP/SAML/SVG/Office parsing | XXE and parser abuse |
| Template/render/message/report sink | XSS, SSTI, content injection as behavior supports |
| Search/filter/query expression | SQL/NoSQL/LDAP/XPath or expression injection as behavior supports |
| File path, download, archive, upload | Traversal, IDOR, unsafe download, malicious upload, archive abuse |
| Command/job/script/native gateway | Command injection or native weakness only with supporting technology evidence |
| Redirect/return/next destination | Open redirect, OAuth/SSO flow abuse |
| Login/reset/OTP/device/approval flow | Authentication and authenticator lifecycle, ownership, step bypass |
| LLM prompt, agent, model, tool input | Prompt/tool-use abuse only when application impact is observable |
| Sensitive browser-visible response | Sensitive data exposure, authorization, client-side secret handling |

Candidate generation is not verification. Do not label an issue vulnerable from parameter names or structure alone.

### 7. Rank Candidates

Score attention priority from observed evidence. Use the score as a queueing aid, not a severity rating:

- `+5`: privileged/admin action or authentication/security setting.
- `+4`: authorization-sensitive object, financial action, approval, role/status/price transition.
- `+3`: user-controlled identifier, file path/upload/download, URL/parser/template/command sink.
- `+2`: sensitive response, ownership/tenant field, meaningful auth/status/schema differential.
- `+1`: unusual error, method, or redirect differential.

Suggested queue bands:

- `high`: score 7 or more.
- `medium`: score 4–6.
- `low`: score 0–3; retain in inventory unless new evidence raises it.

Deduplicate candidates by `endpoint_id + vulnerability_class + security_context`. Do not regenerate a disposed candidate unless new evidence materially changes its model.

### 8. Update State

Use this logical schema. Additional fields are allowed, but preserve compatibility:

```json
{
  "schema_version": 1,
  "target": {
    "target_host": "app.example.com",
    "scope_hosts": [
      {"host": "api.example.com", "reason": "XHR from primary UI"}
    ]
  },
  "snapshot": {
    "last_history_id": 620,
    "last_timestamp": "<ISO-8601>",
    "seen_fingerprints": [],
    "indexed_items": 620,
    "overflow": null
  },
  "endpoints": {
    "ep-001": {
      "fingerprint": "api.example.com|PUT|/users/{id}|application/json|name,role|cookie",
      "feature_ids": ["user-management"],
      "traits": ["state-changing", "object-id", "role-field"],
      "variants": [],
      "packet_refs": [],
      "review_state": "unreviewed"
    }
  },
  "features": {
    "user-management": {
      "endpoint_ids": ["ep-001"],
      "priority": "high",
      "summary": "",
      "review_state": "unreviewed"
    }
  },
  "candidates": {
    "cand-001": {
      "endpoint_id": "ep-001",
      "feature_id": "user-management",
      "class": "vertical-authorization",
      "observations": ["role field in state-changing request"],
      "score": 9,
      "priority": "high",
      "status": "unverified",
      "new_since_last_review": true,
      "packet_refs": [],
      "evidence": [],
      "next_test": "compare low-privileged and authorized control",
      "updated_at": "<ISO-8601>"
    }
  },
  "feature_summaries": {},
  "cross_feature": {
    "trust_relationships": [],
    "open_hypotheses": [],
    "last_reviewed_at": null
  }
}
```

Redact cookies, authorization values, CSRF tokens, passwords, API keys, personal identifiers, and sensitive response values. Parameter names and explicit placeholders are acceptable.

## Output

After writing state, report only:

- Target and evidence-backed scope hosts.
- Number of new/changed History items, unique endpoints, features, and candidates by priority.
- Top candidate IDs with endpoint, class, score, and reason.
- Coverage gaps caused by budget, missing roles/accounts, missing response bodies, or incomplete browsing.
- The exact suggested next invocation, such as `burp-attacker-review mode:all`, `mode:feature user-management`, or `mode:new`.

Do not create a vulnerability findings file and do not claim `Confirmed`, `Not exploitable`, or `safe`.

## Stop Condition

Stop when the relevant History delta has been indexed, duplicates have been merged, observed features have been grouped, applicable candidates have been ranked, and compatible state has been updated. Do not send probes or keep searching for attack classes unsupported by the observed surface.
