# Secure product design checklist

Source of truth for `sk-design` check IDs. Covers the design of a product or feature rather than individual
lines of code: context, attack surface, security principles, components, connections, data, identity, abuse
cases, threats and operations. Based on the OWASP Secure Product Design, Threat Modeling, Attack Surface
Analysis and Abuse Case cheat sheets (and NIST SP 800-218 SSDF). `references/guide.md` explains the method.

Columns: **Mode** S = static (code, configuration, docs and interview). OWASP = OWASP Top 10 2021 (A04 Insecure Design).

## Context and threat model (CTX / THREAT)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DESIGN-CTX-001 | The product's context is documented: purpose, users and roles, data handled and its classification, business impact and required security level | S | Medium | A04 | CWE-657 |
| DESIGN-THREAT-001 | A current threat model exists: system model (data flows, trust boundaries), STRIDE threats per component/flow, ranked, each with a response (mitigate, eliminate, transfer, accept) and an owner | S | High | A04 | CWE-657 |
| DESIGN-THREAT-002 | Agreed mitigations are turned into testable security requirements and tests (unit/integration/abuse-case tests) | S | Medium | A04 | CWE-1053 |

## Attack surface (SURF)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DESIGN-SURF-001 | The attack surface is inventoried: entry points (HTTP, GraphQL, WebSocket, gRPC, queues, jobs, uploads, webhooks), external integrations, data stores, admin interfaces and trust boundaries | S | Medium | A04 | CWE-1059 |
| DESIGN-SURF-002 | The attack surface is minimized: unused endpoints, features, ports, integrations and permissions are removed; admin and internal interfaces are separated from public ones | S | Medium | A05 | CWE-1188 |

## Principles (PRIV / DEPTH / ZT / FAIL)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DESIGN-PRIV-001 | Least privilege and separation of duties apply to users, services, components, CI/CD and data access; sensitive actions need more than one person or factor | S | High | A01 | CWE-250 |
| DESIGN-DEPTH-001 | Defence in depth: no critical asset depends on a single control; failure of one layer is detected and contained | S | Medium | A04 | CWE-693 |
| DESIGN-ZT-001 | Zero trust: every request (including internal service-to-service calls) is authenticated and authorized; network location grants nothing | S | High | A01 | CWE-306 |
| DESIGN-FAIL-001 | Secure defaults and fail-secure behaviour: features ship locked down; errors, timeouts and dependency failures deny rather than allow | S | High | A04 | CWE-636 |

## Components and connections (COMP / CONN)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DESIGN-COMP-001 | Third-party libraries and services are chosen deliberately (security record, maintenance, licensing, usage limits), preferring paved-road/golden-path components | S | Medium | A06 | CWE-1104 |
| DESIGN-CONN-001 | All connections are documented (who talks to whom, over what, with which identity); tiers, environments and tenants are segregated; intentional absence of connections is explicit | S | High | A04 | CWE-653 |

## Data and identity (DATA / IAM)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DESIGN-DATA-001 | Sensitive data is identified and minimized, encrypted in transit and at rest, with defined retention, deletion and backup handling | S | High | A02 | CWE-311 |
| DESIGN-IAM-001 | Authentication and authorization follow one central model (identity provider, deny-by-default policy, a single enforcement layer reused everywhere) | S | High | A01 | CWE-285 |

## Abuse cases (ABUSE)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DESIGN-ABUSE-001 | Abuse and misuse cases are defined for key workflows (fraud, automation/scraping, enumeration, race conditions, resource exhaustion, workflow skipping) with controls | S | Medium | A04 | CWE-840 |

## Configuration and operations (CONF / OPS / SDLC)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DESIGN-CONF-001 | A secure configuration baseline exists: hardened images, minimal permissions, secure protocols only, patching/update process, environment separation | S | Medium | A05 | CWE-1188 |
| DESIGN-OPS-001 | Security events are logged and monitored, and the product has a practiced incident-response plan (including a kill switch for risky features) | S | Medium | A09 | CWE-778 |
| DESIGN-OPS-002 | Secrets management and key rotation are designed in (secret store, per-environment credentials, rotation procedure) | S | Medium | A07 | CWE-798 |
| DESIGN-SDLC-001 | Security is part of delivery: code review, SAST/dependency/secret scanning and security tests in CI, dependency update process | S | Medium | A06 | CWE-1104 |

## AI features (AI), only if the product uses LLMs/agents

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DESIGN-AI-001 | AI/LLM features are designed assuming untrusted input can steer the model: least-privilege tools, human approval for high-impact actions, output treated as untrusted, per-user data isolation | S | High | A04 | CWE-1427 |
