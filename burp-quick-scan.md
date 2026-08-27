---
name: burp-quick-scan
description: >-
  Fast Burp MCP triage of the same attacker-view scope as burp-attacker-review, optimized for speed over exhaustive proof. Use when Codex
  needs a quick single-pass attacker-view scan of a target's Burp Proxy HTTP History: snapshot the traffic, ignore low-value header-only
  findings, and triage the same web security classes (access control, account/authenticator lifecycle, sensitive data exposure, SSRF, SSTI,
  injection, XXE, XSS, CSRF, upload/download, admin/file/method exposure, business logic, and related exploit-oriented classes) with one
  low-risk probe per high-signal candidate, deferring slow/OOB confirmation rather than driving every item to a confirmed verdict, then write
  a findings file (md/txt) in the current folder with the core issue and reusable HTTP payloads for confirmed or needs-confirmation items.
  This is the fast counterpart of burp-attacker-review; the coverage scope is the same, only verification depth is reduced.
---

# Burp Quick Scan

## Objective

Triage a web target from Burp Proxy History as an attacker would, fast: map real behavior in a single pass, select high-signal
hypotheses across the same classes as the deep review, send at most one low-risk probe per candidate, and deliver a findings file with
payloads. This is the fast counterpart of `burp-attacker-review`. The **coverage scope is intentionally the same** — the same hosts,
the same hypothesis classes, the same checklist classes. Only the **verification depth is reduced**: fewer passes, fewer requests per
candidate, and expensive/out-of-band confirmation is deferred to `Needs confirmation` instead of being driven to a settled verdict.

This is a project-agnostic skill. Apply project-specific rules, report formats, asset classifications, or checklist overlays only when
the current workspace instructions or user request explicitly provide them. Do not assume any fixed customer, domain, product, or
internal checklist is present.

Do not lead with missing security headers, cookie flags, banner disclosure, or other configuration-only findings unless they materially
increase the exploitability of a verified attack path.

Prefer breadth and speed over exhaustive proof. It is acceptable — and expected — to leave items as `Needs confirmation` when settling
them would require multiple passes, OOB infrastructure, or destructive requests. Do not skip a whole class to save time; cover every
class at least at triage level.

When the user needs a fully proven, multi-pass assessment with negative evidence and OOB confirmation, use `burp-attacker-review`
instead. Use this skill when the user asks for a quick scan, a first look, a fast triage, or a time-boxed pass.

## Tool Setup

- Use Burp MCP tools when available. If Burp tools are not loaded, discover them with `tool_search` using a query such as `burp proxy
history send http request`.
- Prefer `get_proxy_http_history_regex` for target-scoped snapshots.
- Use `send_http1_request` or `send_http2_request` for verification.
- For confirmed findings and important manual checks, record the request as a payload in the findings file (see step 6).
- OOB infrastructure (Burp Collaborator or the bundled `<skill_dir>/scripts/oob_http_server.py`) is **optional in fast mode**. By default,
  do not stand up an OOB server; classify OOB-dependent candidates (blind SSRF/XXE/OOB injection) as `Needs confirmation` with a payload
  template. Only set up OOB if the user explicitly asks to confirm a blind finding now. Resolve `<skill_dir>` from the directory containing
  this `SKILL.md`; do not assume the current project contains the script.

## Inputs

Derive or ask only if missing:

- `target_host`: required primary user-facing target, for example `app.example.com`.
- `scope_hosts`: derived list of in-scope hosts. Start with `target_host`, then add related API/auth/resource hosts observed in Burp
History when they are called by the primary target or clearly serve the same feature flow.
- `scheme` and `port`: default to HTTPS/443 when History indicates HTTPS.
- `scope`: default to Burp History for `target_host` plus derived `scope_hosts`.
- `risk_limit`: default to non-destructive verification only.

## Fast Standard

This replaces the deep skill's multi-pass `Depth Standard`. Coverage stays wide; effort per item stays low.

- Make a **single combined pass** over Burp History. Extract endpoints, parameters/IDs, state-changing actions, and sensitive data /
  server-side sinks in one read instead of four separate passes.
- Re-query History with a narrower regex **only** when a high-severity candidate (auth/RBAC bypass, IDOR/BOLA, injection, SSRF, RCE-class)
  clearly appears and one extra query would settle it cheaply. Do not iteratively re-query low-severity surfaces.
- Send **at most one low-risk probe per high-signal candidate**, with a control comparison only when it costs one extra request. Do not
  build long payload ladders.
- Cover **every** hypothesis class and checklist class at least at triage level (see steps 3 and 5). Speed comes from fewer requests per
  class, never from dropping a class.
- Defer anything that needs OOB callbacks, timing analysis, destructive mutation, multi-step business-logic chaining, or an RBAC matrix
  not present in History to `Needs confirmation` with a ready-to-run payload. Do not spend the pass trying to settle these.
- Prefer a few clearly-supported findings plus a clean list of `Needs confirmation` items over forcing verdicts.

## Workflow

### 1. Snapshot Burp History (single pass)

Collect a feature-scoped packet snapshot, not just a single-host snapshot. The snapshot is a point-in-time analysis baseline; capture it
at the start because History may keep changing while the user browses and may be cleared during or after the scan. Base the scan on this
snapshot unless the user explicitly asks to refresh it.

1. Query History for `target_host`.
2. Derive related hosts. Include a host in `scope_hosts` when evidence shows it belongs to the same tested flow:
   - Request `Host` differs from `target_host` but has `Origin` or `Referer` from `target_host`.
   - Browser XHR/fetch/API calls from the target page go to that host.
   - Static JavaScript from the target references that host or API base URL.
   - Host shares session cookies, bearer tokens, CSRF headers, product path prefixes, or business identifiers with the target flow.
   - Path names clearly bind it to the target feature, for example `api.example.com/orders/v1/...` for `portal.example.com`.
3. Query History for each derived `scope_host` in the same pass. Add a bounded domain/path pattern query only if obvious related hosts
   (`api.`, `auth.`, `login.`, `gateway.`, login paths, API prefixes, download/admin paths, state-changing methods) are visible and not
   yet captured.
4. Avoid unconstrained subdomain enumeration or broad wordlist discovery unless the user explicitly authorizes it. A related host must be
   evidence-backed by History, page content, JavaScript, shared auth material, or a clear feature path.
5. Extract the useful map across all `scope_hosts` in this one pass:
   - Authentication flow and role/account indicators.
   - Cookies, bearer tokens, CSRF tokens, and refresh behavior, with values redacted in notes.
   - Host-to-host relationships: primary UI host, API hosts, auth hosts, static/resource hosts, and which requests connect them.
   - Endpoints, methods, query/body parameters, JSON keys, and numeric IDs.
   - Status patterns: `200`, `302`, `401`, `403`, `404`, `500`.
   - State-changing endpoints: `POST`, `PUT`, `PATCH`, `DELETE`, plus JavaScript-triggered actions.
   - Sensitive response surfaces: exports, keys, personal data, admin pages, write forms, hidden fields.
   - Sensitive data categories in responses or browser-visible state: passwords, national or identity verification numbers, account/card
     numbers, email, phone, name, birthdate/sex, member/customer IDs, GUIDs, device identifiers, MAC/IP, country, service usage records,
     partner personal data, and comparable regulated data.
   - Account/security workflows: login, logout, password change/reset, OTP/SMS/email/voice verification, device or account ownership
     binding, step-up authentication, approval flows, and identity verification steps.
   - Server-side sinks suggested by parameters, bodies, content types, or features: URL fetchers, webhooks, imports, XML parsers,
     template/render endpoints, file paths, uploads, search/filter/sort fields, report/export builders, shell-like job runners, and
     LLM/chat/prompt endpoints.

Summarize the snapshot before testing: primary target, derived `scope_hosts`, evidence for each related host, observed roles/session,
primary endpoint clusters, and candidate attack surfaces.

### 2. Filter Out Noise

Default exclude:

- Missing or weak security headers.
- Cookie flag issues by themselves.
- Version banners by themselves.
- Generic CORS observations without a cross-origin credentialed exploit path.
- Scanner-style findings not tied to a reachable exploit.

Keep these only as supporting context when they amplify a verified issue, such as XSS plus non-HttpOnly tokens.

### 3. Choose High-Signal Attack Hypotheses (same classes, triage depth)

Do not treat the list below as closed. Build hypotheses from observed inputs and likely server-side sinks. Cover every class; spend the
most probes on the high-severity ones. Prioritize:

- Authentication bypass: protected resource without valid auth, token tampering, refresh misuse.
- Authorization/RBAC bypass: low-privileged session reaches admin/export/write endpoints.
- IDOR/BOLA: changing IDs exposes another tenant/store/user/object.
- Sensitive data exposure: exports, keys, credentials, personal data, internal metadata.
- XSS: payload is actually reflected/stored and executable in context.
- CSRF: state-changing endpoint lacks anti-CSRF protection and uses ambient credentials.
- Upload/download abuse: unsafe file retrieval, path traversal, unrestricted export.
- Malicious file upload: script upload, executable upload location, content-type/extension bypass, archive traversal, or upload-to-execute
  chains.
- SSRF: URL, webhook, image fetch, import, callback, metadata, or proxy-like parameters cause server-side DNS/HTTP interaction or internal
  resource access.
- XXE: XML/SOAP/SAML/Office/SVG upload or XML API endpoints parse external entities or DTDs.
- SSTI/template injection: template, message, email, report, CMS, or render parameters evaluate expressions instead of treating them as
  text.
- Injection: SQL, NoSQL, LDAP, XPath, command, SSI, header, CRLF, format string, template, expression language, prompt/LLM, or
  deserialization only when response behavior, OOB interaction, timing, or downstream action proves a differential.
- Account and authenticator lifecycle abuse: missing re-authentication on sensitive changes, ownership mismatch for phone/account/device/
  OTP, password reset/change flow bypass, identity verification step bypass, or approval-step bypass. Do not assess reuse, fixed, or
  guessable credential properties unless the user explicitly re-adds them.
- Session and cookie abuse only when directly visible in the current traffic: signed token tampering, client-side role cookies,
  authorization-relevant cookie fields, or browser-visible session material.
- Open redirect/phishing: redirect or return URL parameters allow navigation to attacker-controlled locations.
- Exposure and surface hygiene: admin pages exposed to ordinary users, unnecessary sample/test/backup files, directory listing,
  unnecessary HTTP methods, browser-visible secrets in HTML/JavaScript/DOM/storage, and error/system information disclosure.
- Native/legacy weakness checks: buffer overflow or format-string style probes only when long inputs, native gateways, CGI, or legacy
  components are suggested by History or technology evidence.
- Business logic abuse: workflow skips, price/role/status tampering, missing approval gates, or race-sensitive actions when History
  exposes the state model.

In fast mode, define a control comparison only when it costs at most one extra request; otherwise note the control you would run and move on.

The parameter-name cues below are a reference aid for first-pass triage only. They are not the candidate list. Do not derive findings by
matching parameter names against this table, and do not assume a name maps to its listed attack or that an absent name means the attack
does not apply. Names are unreliable: dangerous behavior often hides behind generic names, and the highest-impact classes (IDOR/BOLA,
authorization/RBAC, business logic) usually have no naming signal at all.

Identify the actual candidates from observed behavior and structure in History rather than from names:

- For every identifier-carrying value seen in History, regardless of its name, encoding, or format, treat the object it references as an
  IDOR/BOLA candidate and check whether authorization is enforced per object.
- For every state-changing endpoint and multi-step flow in History, treat it as an authorization/RBAC, CSRF, and business-logic candidate.
- For every input that reaches a server-side sink (fetch, parser, template/render, file path, query, command, export, LLM/tool call),
  treat it as the matching injection/SSRF/XXE/SSTI/traversal candidate based on what the server does with it, not what the field is called.
- Behavior decides the class: whether the server fetches the value, parses it, renders it, runs it, or checks authorization on it takes
  precedence over any parameter name.

Reference cues (triage hints only, not a checklist):

- URL-like values (`url`, `uri`, `callback`, `webhook`, `image`, `avatar`, `redirect`, `host`, `endpoint`) -> SSRF/open redirect.
- XML content types, SOAP, SAML, SVG, Office uploads, `xml` fields -> XXE/XML parser attacks.
- `template`, `message`, `content`, `body`, `title`, `memo`, `description`, `email`, `report` -> XSS/SSTI/content injection.
- `search`, `filter`, `sort`, `where`, `id`, `no`, `query`, JSON arrays/objects -> SQL/NoSQL/LDAP/XPath/IDOR.
- `cmd`, `exec`, `job`, `script`, `path`, `file`, `filename`, archive/upload flows -> command injection/path traversal/deserialization.
- `prompt`, `chat`, `assistant`, `agent`, `system`, `tool`, `model` -> prompt injection or tool-use abuse.
- `redirect`, `return`, `next`, `continue`, `callback_url` -> open redirect or OAuth/SSO flow abuse.
- `otp`, `sms`, `voice`, `email_code`, `password`, `reset`, `certificate`, `account`, `identity`, `verify`, `step` -> account/
  authenticator lifecycle, ownership, re-authentication, or flow bypass checks.
- `page`, `download`, `template`, `sample`, `backup`, `admin`, `swagger`, `actuator`, `debug` paths -> exposed management or unnecessary
  files/features.

### 4. Verify Fast (one low-risk probe per candidate)

Send the single most informative low-risk request for each high-signal candidate. Do not build payload ladders; if one probe does not
settle it, mark `Needs confirmation` with the next payload and move on.

- For download/export findings, a `HEAD` or single ranged/`GET` request is enough to triage. Only fetch the full body when one request
  clearly proves sensitive content; otherwise record headers/filename/type/size and mark `Needs confirmation`.
- For XSS, send one harmless canary through the real input path/method (`GET`, `POST`, JSON, multipart, editor, upload metadata). The bar
  is reflection into an executable context plus encoding analysis; if actual script execution needs a browser render you cannot do in one
  shot, mark `Needs confirmation` with the canary payload.
- Use one invalid/no-auth control where it cheaply distinguishes authentication bypass from authorization bypass.
- When verifying a related API host, send to the actual API `Host` and preserve relevant `Origin`, `Referer`, auth, CSRF, and custom
  headers from the captured browser request unless the hypothesis specifically tests their absence.
- For SSTI, send one engine-appropriate arithmetic canary (`7*7`); do not escalate to RCE.
- For SQL/NoSQL/LDAP/XPath, send one boolean/error differential against the existing baseline; do not run time-based or destructive checks.
- For SSRF/XXE/blind injection, do not stand up OOB infrastructure by default. Mark `Needs confirmation` with an OOB payload template
  unless the user asks to confirm now.
- For command injection, prompt injection, account/authenticator lifecycle, admin/file exposure, and HTTP methods, use only the single
  safest observation (benign canary, `OPTIONS`, owned test account, paths already in History). Defer anything destructive or multi-step.
- Do not execute destructive `POST`, `PUT`, `PATCH`, or `DELETE` requests unless the user explicitly authorizes it or a safe test fixture
  is confirmed. Harmless submissions needed to prove XSS/content injection are acceptable in authorized QA scope when they can be cleaned up.

Classify each candidate into one of three fast levels (this collapses the deep skill's four levels for speed):

- `Confirmed`: the single probe (with a cheap control where applicable) reproduces the exploit condition.
- `Needs confirmation`: a reachable dangerous surface exists but one low-risk probe did not settle it — because it needs OOB/timing,
  authorization, destructive mutation, a browser render, an RBAC matrix, or a multi-step chain. Always attach a one-line reason and a
  ready-to-run payload. This is the expected home for most non-trivial items in a fast scan.
- `Not seen`: one reasonable probe showed no exploit signal, or no candidate of this class appeared in the snapshot. Note in one line
  whether it was probed-and-quiet or simply not observed. Do not call this "safe" — a fast scan does not positively demonstrate absence.

### 5. Checklist Coverage Pass (one quick pass)

Before writing the findings file, do one quick pass comparing the observed target against the same checklist classes as the deep skill,
plus any project-specific checklist supplied by the workspace or user. Exclude reuse/fixed/guessable credential checks, unlimited-request/
rate-limit checks, and TLS/certificate checks unless the user explicitly re-adds them. Classify coverage honestly and quickly:

- `covered-confirmed`: one probe showed it vulnerable.
- `covered-quiet`: one reasonable probe, no exploit signal.
- `needs-manual`: feature exists in History but proof needs destructive, OOB, browser, or multi-step testing -> defer.
- `not-observed`: no History evidence of the feature or sink.
- `out-of-scope-low-signal`: mostly configuration/header hygiene without a concrete exploit path.

At minimum, ensure the pass considers: account/authenticator lifecycle where observed, cookie tampering where authorization-relevant,
authorization/IDOR, injection families, upload/download/path traversal, malicious file upload, XSS/CSRF, SSRF/XXE/SSTI, open redirect,
browser-visible sensitive data, admin/unnecessary files/directory listing/method exposure, system/error information disclosure, and
business logic abuse. Triage every class; `needs-manual` and `not-observed` are valid fast outcomes.

### 6. Write Findings File

When there is at least one confirmed vulnerability or one item that needs manual/authorized confirmation, write a single findings file in
the current working directory. If there are no such items, do not create a file; report "no findings to file" instead.

- Format: `.md` (default) or `.txt`.
- Location: the current folder. Do not write outside it. Each project is run separately, so do not append to or assume any pre-existing
  findings file from another project.
- File name: derive from the audit target, for example `<target_host>.md` (such as `app.example.com.md`) or, when the user gave a
  feature/project name, `<project-or-feature>.md`. Keep one file per audit target.

Keep the content lean: core issue plus payload only. Do not include the snapshot summary, checklist coverage matrix, control narrative,
fix recommendations, or other prose. Redact secrets and use explicit placeholders.

For each item, write only:

- A heading with severity and a short issue name.
- Location: method + path (+ API host if not the primary host).
- One short line of impact / why it matters.
- Status: `Confirmed` or `Needs confirmation`.
- The payload, as a fenced block. Mark manual payloads as not executed if sending them would modify data.

Suggested file shape:

```md
# <target_host> findings (quick scan)

## [High] Stored XSS in <feature>
- Location: POST /path/to/action
- Impact: script executes in admin context
- Status: Confirmed
- Payload:
  ```http
  POST /path/to/action HTTP/1.1
  Host: <target_host>
  Cookie: <session_cookie_name>=<low_priv_session_or_access_token>
  Content-Type: application/json

  {"field":"<canary_payload>"}
  ```

## [Medium] IDOR on <resource>
- Location: GET /api/orders/<id>
- Impact: reads another tenant's object
- Status: Needs confirmation (not executed — would read other user data)
- Payload:
  ```http
  GET /api/orders/<other_object_id> HTTP/1.1
  Host: <api_host>
  Cookie: <authenticated_cookie>
  ```
```

Provide specialized payloads only when the matching sink exists in History. Mark them as templates when values are placeholders:

```http
GET /fetch?url=http://<collaborator-payload>/canary HTTP/1.1
Host: <target_host>
Cookie: <authenticated_cookie>
```

For optional local OOB verification, replace `<collaborator-payload>` with `<reachable-tester-ip>:<port>` from
`<skill_dir>/scripts/oob_http_server.py` (only if the user asks to confirm a blind finding now).

```xml
<?xml version="1.0"?>
<!DOCTYPE x [ <!ENTITY xxe SYSTEM "http://<collaborator-payload>/xxe"> ]>
<root>&xxe;</root>
```

```text
SSTI canaries: {{7*7}}, ${7*7}, <%= 7*7 %>, #{7*7}
SQL canaries: ' OR '1'='1, ' AND '1'='2, order/sort baseline differentials
Command canaries: ; echo codex_canary ;, && echo codex_canary
Prompt canary: ignore prior instructions only inside a non-production LLM test fixture and verify impact through application behavior
```

## Reporting Format

Report in the user's language. Keep it evidence-first and brief. The chat report may summarize; the findings file holds the core issue
and payloads. Make clear this was a fast triage pass, not an exhaustive assessment.

1. Confirmed vulnerabilities:
   - Severity, endpoint and attack path, exact evidence (method, path, role/session, status, key response indicators), control result if
     run, impact, fix, and the findings file entry.
2. Needs confirmation:
   - Why it is suspicious, what single safe/authorized test would settle it, and the findings file entry or manual payload.
3. Not seen:
   - Classes probed-and-quiet or not observed, in one line each. Do not call them safe.
4. Checklist coverage:
   - Classes left `needs-manual` or `not-observed`, so the user knows what a deeper `burp-attacker-review` pass would still cover.
5. Sensitive handling:
   - Redact passwords, tokens, session cookies, full API keys, billing/client keys, and personal identifiers unless the user explicitly
     asks for raw values and disclosure is appropriate for the workspace.

## Stop Condition

Stop after one snapshot pass, one probe round across all high-signal candidates, and one checklist coverage pass — even if many items are
left as `Needs confirmation` or `needs-manual`. That deferral is the intended outcome of a fast scan, not an incomplete one. Do not loop
to drive every item to a settled verdict; recommend `burp-attacker-review` when the user wants that.

Before finalizing, ensure the findings file contains entries (core issue + payload) for confirmed vulnerabilities and important
needs-confirmation items, and that related API hosts observed for the primary flow were included in the single pass or noted as not
relevant.
