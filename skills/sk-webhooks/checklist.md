# Webhook security checklist

Source of truth for `sk-webhooks` check IDs. Checks describe **concepts** that apply to any language,
framework or provider: receiving webhooks (someone else calls you) and sending webhooks (you call a
URL your users configure). `references/guide.md` explains how to verify and fix each one.

Columns: **Mode** S = static, D = dynamic, S+D = both. OWASP = OWASP API Security Top 10 (2023).

## Inventory (INV)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| WH-INV-001 | Every inbound webhook receiver is identified: path, provider/sender, handler, verification method | S | Medium | API9 | CWE-1059 |
| WH-INV-002 | Every outbound webhook sender is identified: who configures the URL, which events and data are sent | S | Medium | API9 | CWE-1059 |

## Inbound: authenticity (SIG)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| WH-SIG-001 | Every inbound request is authenticated (HMAC or asymmetric signature, or provider SDK verification) **before** any processing | S+D | Critical | API10 | CWE-345 |
| WH-SIG-002 | The signature is computed over the exact raw request bytes, not a re-serialized parsed body | S | High | API10 | CWE-347 |
| WH-SIG-003 | Signatures are compared in constant time | S | Medium | API10 | CWE-208 |
| WH-SIG-004 | Verification fails closed: a bad or missing signature returns 4xx and stops; a missing secret is an error, not a skip | S+D | Critical | API10 | CWE-636 |
| WH-SIG-005 | Webhook secrets are not hardcoded, are distinct per sender/endpoint, and can be rotated (two secrets valid during rotation) | S | High | API8 | CWE-798 |
| WH-SIG-006 | The signature scheme/version is fixed by the receiver; weaker or "none" variants from headers are not accepted | S | High | API10 | CWE-327 |
| WH-SIG-007 | Secret tokens in the URL, or source-IP allow-lists, are not the only control | S | Medium | API10 | CWE-290 |

## Inbound: replay and duplicates (REPLAY / IDEM)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| WH-REPLAY-001 | A timestamp is covered by the signature and checked against a tolerance window (e.g. 5 minutes) | S+D | High | API10 | CWE-294 |
| WH-REPLAY-002 | Delivery / event IDs are remembered for at least the tolerance window, so captured requests cannot be replayed | S | High | API10 | CWE-294 |
| WH-IDEM-001 | Handlers are idempotent: a redelivered event does not apply its side effect twice (unique constraint / processed-events store) | S | High | API6 | CWE-841 |
| WH-IDEM-002 | Out-of-order delivery is handled: state changes check the current object state or version, not arrival order | S | Medium | API6 | CWE-362 |

## Inbound: processing (PROC)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| WH-PROC-001 | For high-value actions (payments, plan changes, account linking), the event is re-fetched or confirmed via the sender's API rather than trusting payload values | S | High | API10 | CWE-20 |
| WH-PROC-002 | The payload is schema-validated and bounded (body size limit, types, lengths) | S+D | Medium | API10 | CWE-20 |
| WH-PROC-003 | The receiver acknowledges quickly and processes asynchronously; slow processing cannot cause retry storms | S | Low | API4 | CWE-400 |
| WH-PROC-004 | Error responses to the sender are generic (no stack traces or internal details) | S+D | Low | API8 | CWE-209 |
| WH-PROC-005 | Exemptions (CSRF, session auth, body parsing) are scoped to the webhook route only | S | Medium | API8 | CWE-352 |

## Outbound (OUT)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| WH-OUT-001 | User-supplied destination URLs are protected against SSRF: https only, DNS resolved and private / loopback / link-local / metadata addresses blocked, the connection pinned to the checked IP (no DNS rebinding) | S | Critical | API7 | CWE-918 |
| WH-OUT-002 | Redirects are not followed, or every hop is re-validated | S | High | API7 | CWE-918 |
| WH-OUT-003 | Outbound deliveries are signed (per-subscriber secret, timestamp, event ID) so receivers can verify them | S | Medium | API10 | CWE-345 |
| WH-OUT-004 | Subscriber secrets are random, shown once, rotatable, and stored encrypted | S | Medium | API8 | CWE-522 |
| WH-OUT-005 | Deliveries have timeouts, response-size limits, bounded retries with backoff, and auto-disable for failing endpoints | S | Medium | API4 | CWE-400 |
| WH-OUT-006 | Responses from subscriber endpoints are not shown back to users (turns blind SSRF into full SSRF) | S | High | API7 | CWE-918 |
| WH-OUT-007 | Payloads contain only data that subscriber is authorized to see (tenant isolation, no secrets) | S | High | API3 | CWE-200 |
| WH-OUT-008 | Destination URL ownership is verified before events are sent (challenge / confirmation) | S | Low | API10 | CWE-346 |
| WH-OUT-009 | TLS certificate verification is enabled for deliveries | S | High | API8 | CWE-295 |

## Tests (TEST)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| WH-TEST-001 | Tests cover: missing/bad signature rejected, stale timestamp rejected, duplicate delivery applied once, private-IP destination URL rejected | S | Low | API10 | CWE-1125 |
