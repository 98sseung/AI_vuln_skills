---
name: burp-attacker-review
description: >-
  Burp MCP workflow for deep attacker-view vulnerability assessment from Proxy HTTP History. Use when Codex needs to snapshot
  a target's Burp traffic, ignore low-value header-only findings, identify meaningful attack points across access control, account/
  authenticator lifecycle, sensitive data exposure, SSRF, SSTI, injection, XXE, XSS, CSRF, upload/download, admin/file/method exposure,
  business logic, or other exploit-oriented web security classes, thoroughly verify whether vulnerabilities actually exist, and write a
  findings file (md/txt) in the current folder containing the core issue and reusable HTTP payloads for confirmed findings or items needing
  manual confirmation.
---

# Burp Attacker Review

## Objective

Assess a changing web target from Burp Proxy History as an attacker would: map real behavior, select high-signal hypotheses, verify them
with low-risk requests, and deliver a findings file with payloads that reproduce the evidence.

This is a project-agnostic skill. Apply project-specific rules, report formats, asset classifications, or checklist overlays only when
the current workspace instructions or user request explicitly provide them. Do not assume any fixed customer, domain, product, or
internal checklist is present.

Do not lead with missing security headers, cookie flags, banner disclosure, or other configuration-only findings unless they materially
increase the exploitability of a verified attack path.

Prefer depth over speed. Do not stop after the first valid finding; continue until the target's observed endpoints, parameters, state-
changing actions, sensitive surfaces, and server-side sinks have been reviewed and classified.

## Tool Setup

- Use Burp MCP tools when available. If Burp tools are not loaded, discover them with `tool_search` using a query such as `burp proxy
history send http request`.
- Prefer `get_proxy_http_history_regex` for target-scoped snapshots.
- Use `send_http1_request` or `send_http2_request` for verification.
- For confirmed findings, control comparisons, and important manual checks, record the request as a payload in the findings file (see
  step 6).
- For SSRF/XXE/OOB checks, use Burp Collaborator or this skill's bundled callback server at `<skill_dir>/scripts/oob_http_server.py`
when the target can reach the tester host. Resolve `<skill_dir>` from the directory containing this `SKILL.md`; do not assume the
current project contains the script.

## Inputs

Derive or ask only if missing:

- `target_host`: required primary user-facing target, for example `app.example.com`.
- `scope_hosts`: derived list of in-scope hosts. Start with `target_host`, then add related API/auth/resource hosts observed in Burp
History when they are called by the primary target or clearly serve the same feature flow.
- `scheme` and `port`: default to HTTPS/443 when History indicates HTTPS.
- `scope`: default to Burp History for `target_host` plus derived `scope_hosts`.
- `risk_limit`: default to non-destructive verification only.

## Depth Standard

- Spend the time and tokens needed for a careful review.
- Make multiple passes over Burp History: first for endpoint inventory, second for parameters and IDs, third for state-changing actions,
fourth for sensitive data and server-side sinks.
- Re-query History with narrower regexes when a promising path appears.
- For every confirmed issue, still continue looking for unrelated issue classes.
- Preserve negative evidence: record meaningful hypotheses that were tested and not reproduced.
- Prefer a smaller number of well-proven findings over a long list of speculative scanner-style issues.

## Workflow

### 1. Snapshot Burp History

Collect a feature-scoped packet snapshot, not just a single-host snapshot:

The snapshot is a point-in-time analysis baseline. Capture and summarize the relevant History items at the start of the review because
Burp History may continue changing while the user browses/tests, and the user may clear History during or after the review. Base the
current review on this initial snapshot unless the user explicitly asks to refresh or extend it.

1. Query History for `target_host`.
2. Derive related hosts before concluding coverage is complete. Include a host in `scope_hosts` when evidence shows it belongs to the
same tested flow:
   - Request `Host` differs from `target_host` but has `Origin` or `Referer` from `target_host`.
   - Browser XHR/fetch/API calls from the target page go to that host.
   - Static JavaScript from the target references that host or API base URL.
   - Host shares session cookies, bearer tokens, CSRF headers, product path prefixes, or business identifiers with the target flow.
   - Path names clearly bind it to the target feature, for example `api.example.com/orders/v1/...` for `portal.example.com`.
3. Query History for each derived `scope_host`. Also query bounded domain/path patterns when needed, such as:
   - Same organization domain plus feature keyword: `example.com.*orders`, `orders.*example.com`.
   - API host patterns visible in History: `api.`, `s-api.`, `m-api.`, `gateway.`, `auth.`, `login.`, `static.`, `cdn.`.
   - Login paths, API prefixes, file/download endpoints, admin paths, or state-changing methods.
4. Avoid unconstrained subdomain enumeration or broad wordlist discovery unless the user explicitly authorizes it. A related host must
be evidence-backed by History, page content, JavaScript, shared auth material, or a clear feature path.
5. Extract the useful map across all `scope_hosts`:
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
   - Server-side sinks suggested by parameters, bodies, content types, or features:
     URL fetchers, webhooks, imports, XML parsers, template/render endpoints, file paths, uploads, search/filter/sort fields, report/
     export builders, shell-like job runners, and LLM/chat/prompt endpoints.

Summarize the snapshot before testing: primary target, derived `scope_hosts`, evidence for including each related host, observed roles/
session, primary endpoint clusters, and candidate attack surfaces.

### 2. Filter Out Noise

Default exclude:

- Missing or weak security headers.
- Cookie flag issues by themselves.
- Version banners by themselves.
- Generic CORS observations without a cross-origin credentialed exploit path.
- Scanner-style findings not tied to a reachable exploit.

Keep these only as supporting context when they amplify a verified issue, such as XSS plus non-HttpOnly tokens.

### 3. Choose High-Signal Attack Hypotheses

Do not treat the list below as closed. Build hypotheses from observed inputs and likely server-side sinks. Prioritize:

- Authentication bypass: protected resource without valid auth, token tampering, refresh misuse.
- Authorization/RBAC bypass: low-privileged session reaches admin/export/write endpoints.
- IDOR/BOLA: changing IDs exposes another tenant/store/user/object.
- Sensitive data exposure: exports, keys, credentials, personal data, internal metadata.
- XSS: payload is actually reflected/stored and executable in context.
- CSRF: state-changing endpoint lacks anti-CSRF protection and uses ambient credentials.
- Upload/download abuse: unsafe file retrieval, path traversal, unrestricted export.
- Malicious file upload: script upload, executable upload location, content-type/extension bypass, archive traversal, or upload-to-
execute chains.
- SSRF: URL, webhook, image fetch, import, callback, metadata, or proxy-like parameters cause server-side DNS/HTTP interaction or
internal resource access.
- XXE: XML/SOAP/SAML/Office/SVG upload or XML API endpoints parse external entities or DTDs.
- SSTI/template injection: template, message, email, report, CMS, or render parameters evaluate expressions instead of treating them as
text.
- Injection: SQL, NoSQL, LDAP, XPath, command, SSI, header, CRLF, format string, template, expression language, prompt/LLM, or
deserialization only when response behavior, OOB interaction, timing, or downstream action proves a differential.
- Account and authenticator lifecycle abuse: missing re-authentication on sensitive changes, ownership mismatch for phone/account/
device/OTP, password reset/change flow bypass, identity verification step bypass, or approval-step bypass. Do not assess reuse, fixed,
or guessable credential properties unless the user explicitly re-adds them.
- Session and cookie abuse only when directly visible in the current traffic: signed token tampering, client-side role cookies,
authorization-relevant cookie fields, or browser-visible session material.
- Open redirect/phishing: redirect or return URL parameters allow navigation to attacker-controlled locations.
- Exposure and surface hygiene: admin pages exposed to ordinary users, unnecessary sample/test/backup files, directory listing,
unnecessary HTTP methods, browser-visible secrets in HTML/JavaScript/DOM/storage, and error/system information disclosure.
- Native/legacy weakness checks: buffer overflow or format-string style probes only when long inputs, native gateways, CGI, or legacy
components are suggested by History or technology evidence.
- Business logic abuse: workflow skips, price/role/status tampering, missing approval gates, or race-sensitive actions when History
exposes the state model.

For each hypothesis, define a control comparison before sending requests.

The parameter-name cues below are a reference aid for first-pass triage only. They are not the candidate list. Do not derive findings by
matching parameter names against this table, and do not assume a name maps to its listed attack or that an absent name means the attack
does not apply. Names are unreliable: dangerous behavior often hides behind generic names, and the highest-impact classes (IDOR/BOLA,
authorization/RBAC, business logic) usually have no naming signal at all.

Identify the actual candidates separately, from observed behavior and structure in History rather than from names:

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

### 4. Verify Safely

Use the method that proves the claim without unnecessary side effects:

- For download/export findings, execute the download when it is needed to prove impact. `HEAD` is optional for quick triage, but do not
stop at `HEAD` if the body, file type, or sensitive content matters. Avoid storing large files unless necessary; record headers,
filename, type, size, and a redacted content sample when useful.
- For XSS, use the application's real input path and method: `GET`, `POST`, JSON, multipart, editor forms, upload metadata, or admin/CMS
fields. The standard is actual script execution or a browser-rendered executable sink, not mere string reflection. Use harmless canaries
and test/QA records where possible.
- Use invalid/no-auth controls to distinguish authentication bypass from authorization bypass.
- Use same endpoint with low-privileged versus unauthenticated requests where possible.
- When verifying a related API host, send the request to the actual API `Host` and preserve relevant `Origin`, `Referer`, auth, CSRF,
and custom headers from the captured browser request unless the hypothesis specifically tests their absence.
- Use harmless canary payloads for reflection or parser behavior.
- Use Burp Collaborator for SSRF/XXE/OOB injection when an internet-reachable callback is needed. If the target can reach the tester
host, run the bundled local callback server from this skill directory instead:

  ```bash
  python3 <skill_dir>/scripts/oob_http_server.py --host 0.0.0.0 --port 8000
  ```

  Then use `http://<reachable-tester-ip>:8000/<canary>` as the callback URL. Prefer benign HTTP/DNS callbacks and avoid internal network
  scanning.
- For SSTI, start with arithmetic/string canaries such as engine-appropriate `7*7` expressions; do not jump to RCE payloads.
- For SQL/NoSQL/LDAP/XPath, prefer boolean/error/differential checks against a baseline; avoid destructive writes or expensive time
delays unless explicitly authorized.
- For command injection, avoid destructive commands; use a benign canary only when the environment is authorized for that check.
- For prompt injection, verify only observable application behavior such as instruction leakage, unauthorized tool/action invocation, or
policy bypass; do not claim it from model text alone without impact.
- For XXE, prefer parser error or OOB DNS/HTTP proof; do not request local file disclosure such as `/etc/passwd` unless explicitly
authorized.
- For account/authenticator lifecycle checks, use only owned test accounts and avoid account lockout, irreversible password changes, OTP
spending, or third-party notifications unless explicitly authorized.
- For admin/file exposure, start from paths observed in History or page links. Do not brute-force large wordlists unless explicitly
authorized.
- For HTTP methods, prefer `OPTIONS` or harmless method changes. Do not write with `PUT`, `DELETE`, or WebDAV methods outside a
confirmed disposable path.
- Do not execute destructive `POST`, `PUT`, `PATCH`, or `DELETE` requests unless the user explicitly authorizes it or a safe test
fixture is confirmed. Harmless form/API submissions needed to prove XSS or content injection are acceptable in authorized QA scope when
they can be identified and cleaned up.

Classify evidence into one of four levels. Keep the boundaries sharp: the distinction between `Not exploitable` and `Not reproduced` is
about the strength of the negative evidence, not about effort.

- `Confirmed`: exploit condition is reproduced and has a control comparison.
- `Needs confirmation`: a reachable dangerous surface exists but the result is not settled, because the final mutation/impact needs
  authorization, or because access depends on an RBAC matrix or business rule not present in History. Always attach a one-line reason
  (for example: "needs authorization to send the state-changing request" or "depends on RBAC matrix not in History").
- `Not exploitable`: the input reaches the relevant sink, but a defense was actively observed to neutralize it, so absence is positively
  demonstrated. Use only with concrete evidence of the defense, such as consistent output encoding across contexts for XSS, no error/
  boolean/timing differential plus parameterization evidence for SQLi, or normalized/blocked traversal sequences. Record the observed
  defense in one line.
- `Not reproduced`: tested with reasonable payloads and no exploit condition appeared, but absence is not positively demonstrated —
  the sample was partial or the class resists proof of absence (IDOR/BOLA, authorization, business logic, OOB-dependent SSRF/XXE). Note
  the limitation in one line. Do not call this "safe".

### 5. Checklist Coverage Pass

Before writing the findings file, compare the observed target against the generic exploit-oriented web checklist classes below plus any
project-specific checklist supplied by the current workspace or user. Exclude reuse/fixed/guessable credential checks, unlimited-
request/rate-limit checks, and TLS/certificate checks unless the user explicitly re-adds them. Do not force every checklist item into
active testing; classify coverage honestly:

- `covered-confirmed`: tested and vulnerable.
- `covered-not-reproduced`: tested with reasonable safe checks and not reproduced.
- `observed-needs-manual`: History shows the feature exists, but proof would require destructive or environment-specific testing.
- `not-observed`: no History evidence of the feature or sink.
- `out-of-scope-low-signal`: mostly configuration/header hygiene without a concrete exploit path for this task.

At minimum, ensure the pass considers: account/authenticator lifecycle where observed, cookie tampering where authorization-relevant,
authorization/IDOR, injection families, upload/download/path traversal, malicious file upload, XSS/CSRF, SSRF/XXE/SSTI, open redirect,
browser-visible sensitive data, admin/unnecessary files/directory listing/method exposure, system/error information disclosure, and
business logic abuse.

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
# <target_host> findings

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

For local OOB verification, replace `<collaborator-payload>` with `<reachable-tester-ip>:<port>` from `<skill_dir>/scripts/
oob_http_server.py`.

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

Report in the user's language. Keep it evidence-first. The chat report may summarize; the findings file holds the core issue and
payloads.

1. Confirmed vulnerabilities:
   - Severity.
   - Endpoint and attack path.
   - Exact evidence: method, path, role/session context, status, important response headers/body indicators.
   - Control result.
   - Impact.
   - Fix.
   - Findings file name and the relevant entry.
2. Needs confirmation:
   - Why it is suspicious.
   - What safe or authorized test would prove it.
   - Findings file entry or manual payload if written.
3. Not reproduced:
   - Hypothesis and payload class tested.
   - Observed result.
4. Checklist coverage:
   - Important checklist classes that were not observed, out of scope, or need manual/authorized testing.
   - Do not list every low-signal item unless the user asks for a full checklist matrix.
5. Sensitive handling:
   - Redact passwords, tokens, session cookies, full API keys, billing/client keys, and personal identifiers unless the user explicitly
   asks for raw values and disclosure is appropriate for the workspace.

## Stop Condition

Stop when all high-signal hypotheses from the snapshot and all relevant exploit-oriented checklist coverage classes have one of:
confirmed, needs confirmation, not exploitable, not reproduced, not observed, or out of scope. Do not stop solely because one confirmed
vulnerability has been found. Before finalizing, ensure the findings file contains entries (core issue + payload) for confirmed
vulnerabilities and important manual checks.

Do not claim completion until related API hosts observed for the primary target flow have been included or explicitly classified as not
relevant with evidence.
