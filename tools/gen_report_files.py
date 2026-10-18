#!/usr/bin/env python3
"""
Generate templates/report.md and schema/report.schema.json for the concept skills.

The report shape is shared; only the title, ID prefix and inventory table differ per skill.
Run after adding a skill here:  python tools/gen_report_files.py
"""
import json
import os
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SKILLS = {
    "sk-graphql": {
        "prefix": "GQL", "title": "GraphQL Security Report", "report": "security-report-graphql.md",
        "inventory_title": "GraphQL surface",
        "inventory_intro": "{{endpoint_count}} endpoint(s), {{query_count}} queries, {{mutation_count}} mutations, {{subscription_count}} subscriptions. Introspection: {{introspection_status}}.",
        "inventory_cols": ["Kind", "Name", "Defined at", "Auth / guards", "Findings"],
        "inventory_row": ["{{kind}}", "`{{name}}`", "`{{file}}:{{line}}`", "{{guards}}", "{{finding_ids}}"],
    },
    "sk-webhooks": {
        "prefix": "WH", "title": "Webhook Security Report", "report": "security-report-webhooks.md",
        "inventory_title": "Webhook inventory",
        "inventory_intro": "{{receiver_count}} inbound receiver(s), {{sender_count}} outbound sender(s).",
        "inventory_cols": ["Direction", "Endpoint / sender", "Defined at", "Verification", "Findings"],
        "inventory_row": ["{{direction}}", "`{{name}}`", "`{{file}}:{{line}}`", "{{verification}}", "{{finding_ids}}"],
    },
    "sk-openapi": {
        "prefix": "OAS", "title": "OpenAPI Contract Report", "report": "security-report-openapi.md",
        "inventory_title": "Spec vs code",
        "inventory_intro": "Spec: `{{spec_file}}` ({{spec_version}}), {{spec_ops}} operations. Code: {{code_routes}} routes. Undocumented: {{undocumented}} · Stale: {{stale}} · Auth mismatches: {{auth_mismatch}}.",
        "inventory_cols": ["Method", "Path", "In spec", "In code", "Spec security", "Code auth", "Findings"],
        "inventory_row": ["{{method}}", "`{{path}}`", "{{in_spec}}", "{{in_code}}", "{{spec_security}}", "{{code_auth}}", "{{finding_ids}}"],
    },
    "sk-auth": {
        "prefix": "AUTH", "title": "Authentication Security Report", "report": "security-report-auth.md",
        "inventory_title": "Authentication flows",
        "inventory_intro": "Mechanisms: {{mechanisms}}. Password hashing: {{hashing}}. MFA: {{mfa}}. Session: {{session_type}}.",
        "inventory_cols": ["Flow", "Entry point", "Defined at", "Controls found", "Findings"],
        "inventory_row": ["{{flow}}", "`{{entry}}`", "`{{file}}:{{line}}`", "{{controls}}", "{{finding_ids}}"],
    },
    "sk-tokens": {
        "prefix": "TOK", "title": "Token Security Report", "report": "security-report-tokens.md",
        "inventory_title": "Token inventory",
        "inventory_intro": "{{token_kinds}} kind(s) of token found.",
        "inventory_cols": ["Token", "Issued at", "Verified at", "Lifetime", "Stored in", "Findings"],
        "inventory_row": ["{{token}}", "`{{issue_site}}`", "`{{verify_site}}`", "{{lifetime}}", "{{storage}}", "{{finding_ids}}"],
    },
    "sk-secrets": {
        "prefix": "SEC", "title": "Secrets Exposure Report", "report": "security-report-secrets.md",
        "inventory_title": "Secrets found",
        "inventory_intro": "{{secret_count}} secret(s) in the working tree, {{history_count}} only in git history. Rotation required: {{rotate_count}}.",
        "inventory_cols": ["Type", "Location", "Committed", "In history only", "Rotate", "Findings"],
        "inventory_row": ["{{type}}", "`{{file}}:{{line}}`", "{{tracked}}", "{{history_only}}", "{{rotate}}", "{{finding_ids}}"],
    },
    "sk-cicd": {
        "prefix": "CICD", "title": "CI/CD Pipeline Security Report", "report": "security-report-cicd.md",
        "inventory_title": "Pipelines",
        "inventory_intro": "Platforms: {{platforms}}. {{workflow_count}} workflow(s), {{deploy_count}} deploying to production.",
        "inventory_cols": ["Workflow", "Triggers", "Permissions", "Secrets used", "Deploys", "Findings"],
        "inventory_row": ["`{{file}}`", "{{triggers}}", "{{permissions}}", "{{secrets}}", "{{deploys}}", "{{finding_ids}}"],
    },
    "sk-docker": {
        "prefix": "DOCKER", "title": "Container Security Report", "report": "security-report-docker.md",
        "inventory_title": "Images and workloads",
        "inventory_intro": "{{dockerfile_count}} Dockerfile(s), {{compose_count}} compose file(s), {{k8s_count}} Kubernetes manifest(s).",
        "inventory_cols": ["Artifact", "Base image", "Runs as", "Privileges", "Exposed ports", "Findings"],
        "inventory_row": ["`{{file}}`", "{{base}}", "{{user}}", "{{privileges}}", "{{ports}}", "{{finding_ids}}"],
    },
    "sk-prompt-injection": {
        "prefix": "PI", "title": "Prompt Injection Security Report", "report": "security-report-prompt-injection.md",
        "inventory_title": "LLM integration points",
        "inventory_intro": "{{llm_call_count}} model call site(s), {{tool_count}} tool(s), {{untrusted_channels}} untrusted input channel(s).",
        "inventory_cols": ["Call site", "Untrusted inputs", "Tools / sinks", "Approval", "Findings"],
        "inventory_row": ["`{{file}}:{{line}}`", "{{inputs}}", "{{sinks}}", "{{approval}}", "{{finding_ids}}"],
    },
    "sk-oauth2": {
        "prefix": "OAUTH", "title": "OAuth 2.0 Security Report", "report": "security-report-oauth2.md",
        "inventory_title": "OAuth roles and flows",
        "inventory_intro": "Roles in this project: {{roles}}. Providers: {{providers}}.",
        "inventory_cols": ["Flow / role", "Client type", "Grant", "PKCE", "State / nonce", "Findings"],
        "inventory_row": ["{{flow}}", "{{client_type}}", "{{grant}}", "{{pkce}}", "{{state}}", "{{finding_ids}}"],
    },
    "sk-password": {
        "prefix": "PWD", "title": "Password Security Report", "report": "security-report-password.md",
        "inventory_title": "Password lifecycle",
        "inventory_intro": "Hashing: {{algorithm}} ({{parameters}}). Pepper: {{pepper}}. Legacy hashes: {{legacy}}.",
        "inventory_cols": ["Stage", "Entry point", "Defined at", "Controls found", "Findings"],
        "inventory_row": ["{{stage}}", "`{{entry}}`", "`{{file}}:{{line}}`", "{{controls}}", "{{finding_ids}}"],
    },
    "sk-rag": {
        "prefix": "RAG", "title": "RAG Pipeline Security Report", "report": "security-report-rag.md",
        "inventory_title": "RAG pipeline",
        "inventory_intro": "Sources: {{sources}}. Vector store: {{vector_store}}. Embedding model: {{embedding_model}}. Tenancy: {{tenancy}}.",
        "inventory_cols": ["Stage", "Component", "Defined at", "Access control", "Findings"],
        "inventory_row": ["{{stage}}", "{{component}}", "`{{file}}:{{line}}`", "{{acl}}", "{{finding_ids}}"],
    },
    "sk-rest": {
        "prefix": "REST", "title": "REST Security Report", "report": "security-report-rest.md",
        "inventory_title": "Endpoints",
        "inventory_intro": "{{route_count}} endpoints. Content types: {{content_types}}. Auth: {{auth_scheme}}.",
        "inventory_cols": ["Method", "Path", "Auth", "Content type checked", "Size limit", "Findings"],
        "inventory_row": ["{{method}}", "`{{path}}`", "{{auth}}", "{{ctype}}", "{{limit}}", "{{finding_ids}}"],
    },
    "sk-design": {
        "prefix": "DESIGN", "title": "Secure Design Review", "report": "security-report-design.md",
        "inventory_title": "Threat model summary",
        "inventory_intro": "Assets: {{asset_count}}. Trust boundaries: {{boundary_count}}. Threats: {{threat_count}} ({{mitigated}} mitigated, {{accepted}} accepted, {{open}} open). Full model: `threat-model.md`.",
        "inventory_cols": ["Threat", "STRIDE", "Component / flow", "Likelihood × impact", "Response", "Owner"],
        "inventory_row": ["{{threat}}", "{{stride}}", "{{component}}", "{{risk}}", "{{response}}", "{{owner}}"],
    },
    "sk-ratelimit": {
        "prefix": "RL", "title": "Rate Limiting Report", "report": "security-report-ratelimit.md",
        "inventory_title": "Sensitive operations and their limits",
        "inventory_intro": "{{op_count}} sensitive operation(s); {{limited}} limited, {{unlimited}} unlimited. Limiter: {{limiter}} (store: {{store}}).",
        "inventory_cols": ["Operation", "Endpoint", "Limit", "Key (user/IP/account)", "Findings"],
        "inventory_row": ["{{operation}}", "`{{endpoint}}`", "{{limit}}", "{{key}}", "{{finding_ids}}"],
    },
    "sk-business": {
        "prefix": "BIZ", "title": "Business Logic Security Report", "report": "security-report-business.md",
        "inventory_title": "Business workflows",
        "inventory_intro": "{{workflow_count}} workflow(s) reviewed; {{abuse_count}} abuse cases considered.",
        "inventory_cols": ["Workflow", "Steps", "Server-side invariants", "Abuse cases", "Findings"],
        "inventory_row": ["{{workflow}}", "{{steps}}", "{{invariants}}", "{{abuse}}", "{{finding_ids}}"],
    },
    "sk-race": {
        "prefix": "RACE", "title": "Race Condition Report", "report": "security-report-race.md",
        "inventory_title": "Concurrency-sensitive operations",
        "inventory_intro": "{{op_count}} operation(s) reviewed. Concurrency control in use: {{mechanisms}}.",
        "inventory_cols": ["Operation", "Location", "Invariant", "Protection", "Findings"],
        "inventory_row": ["{{operation}}", "`{{file}}:{{line}}`", "{{invariant}}", "{{protection}}", "{{finding_ids}}"],
    },
    "sk-payments": {
        "prefix": "PAY", "title": "Payment Flow Security Report", "report": "security-report-payments.md",
        "inventory_title": "Payment flows",
        "inventory_intro": "Providers: {{providers}}. Flows: checkout {{checkout}}, subscriptions {{subscriptions}}, refunds {{refunds}}, payouts {{payouts}}.",
        "inventory_cols": ["Flow", "Amount source", "Confirmation", "Idempotency", "Findings"],
        "inventory_row": ["{{flow}}", "{{amount_source}}", "{{confirmation}}", "{{idempotency}}", "{{finding_ids}}"],
    },
    "sk-email": {
        "prefix": "MAIL", "title": "Email & Notification Security Report", "report": "security-report-email.md",
        "inventory_title": "Outgoing messages",
        "inventory_intro": "{{message_count}} message type(s) via {{providers}}.",
        "inventory_cols": ["Message", "Trigger", "User-controlled fields", "Links built from", "Findings"],
        "inventory_row": ["{{message}}", "{{trigger}}", "{{user_fields}}", "{{link_base}}", "{{finding_ids}}"],
    },
    "sk-inject": {
        "prefix": "INJ", "title": "Injection Security Report", "report": "security-report-inject.md",
        "inventory_title": "Sinks reviewed",
        "inventory_intro": "{{sink_count}} sink(s) reviewed across {{classes}} injection class(es).",
        "inventory_cols": ["Class", "Sink", "Location", "Input source", "Verdict", "Findings"],
        "inventory_row": ["{{class}}", "`{{sink}}`", "`{{file}}:{{line}}`", "{{source}}", "{{verdict}}", "{{finding_ids}}"],
    },
    "sk-xss": {
        "prefix": "XSS", "title": "Cross-Site Scripting Report", "report": "security-report-xss.md",
        "inventory_title": "Rendering sinks",
        "inventory_intro": "Templating: {{templating}}. Frameworks: {{frameworks}}. CSP: {{csp}}.",
        "inventory_cols": ["Sink", "Location", "Context", "Data source", "Encoding/sanitizing", "Findings"],
        "inventory_row": ["`{{sink}}`", "`{{file}}:{{line}}`", "{{context}}", "{{source}}", "{{protection}}", "{{finding_ids}}"],
    },
    "sk-upload": {
        "prefix": "UPL", "title": "File Upload Security Report", "report": "security-report-upload.md",
        "inventory_title": "Upload points",
        "inventory_intro": "{{upload_count}} upload point(s). Storage: {{storage}}.",
        "inventory_cols": ["Endpoint", "Allowed types", "Size limit", "Stored as / where", "Served how", "Findings"],
        "inventory_row": ["`{{endpoint}}`", "{{types}}", "{{limit}}", "{{storage}}", "{{served}}", "{{finding_ids}}"],
    },
    "sk-deserialize": {
        "prefix": "DESER", "title": "Deserialization Security Report", "report": "security-report-deserialize.md",
        "inventory_title": "Deserialization points",
        "inventory_intro": "{{point_count}} deserialization point(s); {{untrusted}} receive untrusted data.",
        "inventory_cols": ["Format / API", "Location", "Data source", "Safe mode", "Findings"],
        "inventory_row": ["{{api}}", "`{{file}}:{{line}}`", "{{source}}", "{{safe}}", "{{finding_ids}}"],
    },
    "sk-ssrf": {
        "prefix": "SSRF", "title": "SSRF Report", "report": "security-report-ssrf.md",
        "inventory_title": "Server-side fetches",
        "inventory_intro": "{{fetch_count}} outbound fetch site(s); {{user_url}} take a user-influenced URL.",
        "inventory_cols": ["Fetch site", "Client", "URL source", "Validation", "Findings"],
        "inventory_row": ["`{{file}}:{{line}}`", "{{client}}", "{{source}}", "{{validation}}", "{{finding_ids}}"],
    },
    "sk-redirect": {
        "prefix": "REDIR", "title": "Open Redirect Report", "report": "security-report-redirect.md",
        "inventory_title": "Redirects and forwards",
        "inventory_intro": "{{redirect_count}} redirect/forward site(s); {{dynamic}} use a request-supplied target.",
        "inventory_cols": ["Site", "Target source", "Validation", "Findings"],
        "inventory_row": ["`{{file}}:{{line}}`", "{{source}}", "{{validation}}", "{{finding_ids}}"],
    },
    "sk-ai": {
        "prefix": "AI", "title": "AI / LLM Application Security Report", "report": "security-report-ai.md",
        "inventory_title": "AI features",
        "inventory_intro": "Providers/models: {{models}}. Features: {{features}}. Agents/tools: {{agents}}. RAG: {{rag}}.",
        "inventory_cols": ["Feature", "Model call", "Data sent", "Output goes to", "Limits", "Findings"],
        "inventory_row": ["{{feature}}", "`{{file}}:{{line}}`", "{{data}}", "{{sinks}}", "{{limits}}", "{{finding_ids}}"],
    },
    "sk-agents": {
        "prefix": "AGENT", "title": "Agent & Tool Security Report", "report": "security-report-agents.md",
        "inventory_title": "Agents, tools and MCP servers",
        "inventory_intro": "{{agent_count}} agent(s), {{tool_count}} tool(s), {{mcp_count}} MCP server(s) ({{remote}} remote).",
        "inventory_cols": ["Tool / server", "Capability", "Credentials", "Approval", "Sandbox", "Findings"],
        "inventory_row": ["{{tool}}", "{{capability}}", "{{credentials}}", "{{approval}}", "{{sandbox}}", "{{finding_ids}}"],
    },
    "sk-tests": {
        "prefix": "TEST", "title": "Security Test Coverage Report", "report": "security-report-tests.md",
        "inventory_title": "Security-relevant paths and their tests",
        "inventory_intro": "Test framework(s): {{frameworks}}. {{route_count}} endpoint(s): {{unauth_tested}} with an unauthenticated test, {{authz_tested}} with a cross-user test, {{validation_tested}} with an invalid-input test.",
        "inventory_cols": ["Endpoint / path", "Defined at", "Auth", "Unauth test", "Cross-user test", "Invalid-input test", "Findings"],
        "inventory_row": ["`{{method}} {{path}}`", "`{{file}}:{{line}}`", "{{auth}}", "{{unauth}}", "{{authz}}", "{{validation}}", "{{finding_ids}}"],
    },
    "sk-fuzz": {
        "prefix": "FUZZ", "title": "Fuzzing & Property Testing Report", "report": "security-report-fuzz.md",
        "inventory_title": "Fuzz targets",
        "inventory_intro": "Languages: {{languages}}. Existing tooling: {{tooling}}. {{target_count}} target(s), {{covered_count}} with a harness or property test.",
        "inventory_cols": ["Target", "Defined at", "Input", "Harness / property test", "Runs in CI", "Findings"],
        "inventory_row": ["`{{name}}`", "`{{file}}:{{line}}`", "{{input}}", "{{harness}}", "{{ci}}", "{{finding_ids}}"],
    },
    "sk-review": {
        "prefix": "REVIEW", "any_check": True, "title": "Security Review of Changes", "report": "security-report-review.md",
        "inventory_title": "Changed files",
        "inventory_intro": "Diff: {{diff_range}}. {{file_count}} file(s), +{{added}} / -{{removed}} lines. Security-sensitive: {{sensitive_count}}.",
        "inventory_cols": ["File", "Change", "Category", "Findings"],
        "inventory_row": ["`{{file}}`", "{{change}}", "{{category}}", "{{finding_ids}}"],
    },
    "sk-crypto": {
        "prefix": "CRYPTO", "title": "Cryptography Report", "report": "security-report-crypto.md",
        "inventory_title": "Cryptography uses",
        "inventory_intro": "{{use_count}} crypto use(s). Libraries: {{libraries}}. Key storage: {{key_storage}}.",
        "inventory_cols": ["Purpose", "Primitive / mode", "Defined at", "Key source", "Findings"],
        "inventory_row": ["{{purpose}}", "{{primitive}}", "`{{file}}:{{line}}`", "{{key_source}}", "{{finding_ids}}"],
    },
    "sk-authz": {
        "prefix": "AUTHZ", "title": "Access Control Report", "report": "security-report-authz.md",
        "inventory_title": "Access matrix",
        "inventory_intro": "Model: {{model}}. Enforcement: {{enforcement}}. Default: {{default}}. Tenancy: {{tenancy}}.",
        "inventory_cols": ["Role", "Action", "Resource", "Enforced at", "Findings"],
        "inventory_row": ["{{role}}", "{{action}}", "{{resource}}", "`{{file}}:{{line}}`", "{{finding_ids}}"],
    },
    "sk-logging": {
        "prefix": "LOG", "title": "Security Logging Report", "report": "security-report-logging.md",
        "inventory_title": "Security events",
        "inventory_intro": "Logger: {{logger}}. Error tracker: {{tracker}}. Shipping/retention/alerts: {{platform}}.",
        "inventory_cols": ["Event", "Logged", "Where", "Fields", "Findings"],
        "inventory_row": ["`{{event}}`", "{{logged}}", "`{{file}}:{{line}}`", "{{fields}}", "{{finding_ids}}"],
    },
    "sk-cloud": {
        "prefix": "CLOUD", "title": "Cloud & IaC Security Report", "report": "security-report-cloud.md",
        "inventory_title": "Cloud resources",
        "inventory_intro": "IaC: {{iac}}. Providers: {{providers}}. {{resource_count}} resource(s) reviewed. State backend: {{state_backend}}.",
        "inventory_cols": ["Resource", "Type", "Defined at", "Exposure", "Findings"],
        "inventory_row": ["`{{name}}`", "{{type}}", "`{{file}}:{{line}}`", "{{exposure}}", "{{finding_ids}}"],
    },
    "sk-deps": {
        "prefix": "DEPS", "title": "Dependency & Supply-Chain Report", "report": "security-report-deps.md",
        "inventory_title": "Manifests",
        "inventory_intro": "{{manifest_count}} manifest(s), {{dependency_count}} dependencies. Vulnerability scanner: {{scanner}}.",
        "inventory_cols": ["Manifest", "Ecosystem", "Dependencies", "Lockfile", "Findings"],
        "inventory_row": ["`{{file}}`", "{{ecosystem}}", "{{count}}", "{{lockfile}}", "{{finding_ids}}"],
    },
    "sk-privacy": {
        "prefix": "PRIV", "title": "Privacy & Personal Data Report", "report": "security-report-privacy.md",
        "inventory_title": "Personal-data map",
        "inventory_intro": "{{field_count}} personal-data field(s), {{sensitive_count}} highly sensitive. Processors: {{processors}}.",
        "inventory_cols": ["Field", "Sensitivity", "Stored in", "Shared with", "Retention", "Findings"],
        "inventory_row": ["`{{field}}`", "{{sensitivity}}", "{{stored}}", "{{shared}}", "{{retention}}", "{{finding_ids}}"],
    },
    "sk-config": {
        "prefix": "CONF", "title": "Security Configuration Report", "report": "security-report-config.md",
        "inventory_title": "Configuration sources",
        "inventory_intro": "Frameworks: {{frameworks}}. Environments: {{environments}}. Startup validation: {{validation}}.",
        "inventory_cols": ["Environment", "Source", "Defined at", "Notes", "Findings"],
        "inventory_row": ["{{environment}}", "{{source}}", "`{{file}}:{{line}}`", "{{notes}}", "{{finding_ids}}"],
    },
    "sk-csrf": {
        "prefix": "CSRF", "title": "CSRF Report", "report": "security-report-csrf.md",
        "inventory_title": "State-changing routes",
        "inventory_intro": "Auth: {{auth}}. CSRF mechanism: {{mechanism}}. SameSite: {{samesite}}.",
        "inventory_cols": ["Route", "Defined at", "Cookie auth", "Protection", "Findings"],
        "inventory_row": ["`{{method}} {{path}}`", "`{{file}}:{{line}}`", "{{cookie_auth}}", "{{protection}}", "{{finding_ids}}"],
    },
    "sk-browser": {
        "prefix": "BROWSER", "title": "Browser Security Report", "report": "security-report-browser.md",
        "inventory_title": "Headers and cookies",
        "inventory_intro": "Headers set by: {{header_source}}. {{cookie_count}} auth cookie(s). {{third_party_count}} third-party script(s).",
        "inventory_cols": ["Item", "Value / attributes", "Set at", "Findings"],
        "inventory_row": ["`{{name}}`", "{{value}}", "`{{file}}:{{line}}`", "{{finding_ids}}"],
    },
    "sk-dos": {
        "prefix": "DOS", "title": "Resource Exhaustion Report", "report": "security-report-dos.md",
        "inventory_title": "Limits",
        "inventory_intro": "Body limit: {{body_limit}}. Max page size: {{page_limit}}. Timeouts: {{timeouts}}.",
        "inventory_cols": ["Area", "Limit", "Set at", "Findings"],
        "inventory_row": ["{{area}}", "{{limit}}", "`{{file}}:{{line}}`", "{{finding_ids}}"],
    },
    "sk-validation": {
        "prefix": "VAL", "title": "Input Validation Report", "report": "security-report-validation.md",
        "inventory_title": "Entry points",
        "inventory_intro": "Validator: {{validator}}. {{entry_count}} entry point(s): {{validated}} validated, {{strict}} strict.",
        "inventory_cols": ["Entry point", "Defined at", "Validation", "Strict", "Findings"],
        "inventory_row": ["`{{name}}`", "`{{file}}:{{line}}`", "{{validation}}", "{{strict}}", "{{finding_ids}}"],
    },
    "sk-mobile": {
        "prefix": "MOB", "title": "Mobile App Security Report", "report": "security-report-mobile.md",
        "inventory_title": "App surface",
        "inventory_intro": "Platforms: {{platforms}}. Framework: {{framework}}. Pinning: {{pinning}}. Secure storage: {{storage}}.",
        "inventory_cols": ["Platform", "Item", "Defined at", "Notes", "Findings"],
        "inventory_row": ["{{platform}}", "`{{item}}`", "`{{file}}:{{line}}`", "{{notes}}", "{{finding_ids}}"],
    },
    "sk-electron": {
        "prefix": "DESK", "title": "Desktop App Security Report", "report": "security-report-electron.md",
        "inventory_title": "Windows, APIs and IPC",
        "inventory_intro": "Framework: {{framework}}. {{window_count}} window(s), {{api_count}} exposed API(s), {{ipc_count}} IPC channel(s).",
        "inventory_cols": ["Kind", "Name", "Defined at", "Validation", "Findings"],
        "inventory_row": ["{{kind}}", "`{{name}}`", "`{{file}}:{{line}}`", "{{validation}}", "{{finding_ids}}"],
    },
    "sk-websocket": {
        "prefix": "WS", "title": "Real-time Channel Security Report", "report": "security-report-websocket.md",
        "inventory_title": "Endpoints and message types",
        "inventory_intro": "Library: {{library}}. {{endpoint_count}} endpoint(s), {{message_count}} message type(s).",
        "inventory_cols": ["Endpoint / message", "Defined at", "Auth", "Authorization", "Findings"],
        "inventory_row": ["`{{name}}`", "`{{file}}:{{line}}`", "{{auth}}", "{{authz}}", "{{finding_ids}}"],
    },
    "sk-queue": {
        "prefix": "QUEUE", "title": "Queues & Background Jobs Report", "report": "security-report-queue.md",
        "inventory_title": "Queues and jobs",
        "inventory_intro": "Brokers: {{brokers}}. Job system: {{jobs}}. {{queue_count}} queue(s)/job type(s).",
        "inventory_cols": ["Queue / job", "Producer", "Consumer", "Validation", "Findings"],
        "inventory_row": ["`{{name}}`", "`{{producer}}`", "`{{consumer}}`", "{{validation}}", "{{finding_ids}}"],
    },
    "sk-cache": {
        "prefix": "CACHE", "title": "Caching Security Report", "report": "security-report-cache.md",
        "inventory_title": "Cache layers",
        "inventory_intro": "Layers: {{layers}}. {{route_count}} user-specific route(s).",
        "inventory_cols": ["Layer", "What is cached", "Key", "Configured at", "Findings"],
        "inventory_row": ["{{layer}}", "{{what}}", "{{key}}", "`{{file}}:{{line}}`", "{{finding_ids}}"],
    },
    "sk-saml": {
        "prefix": "SAML", "title": "SAML SSO Security Report", "report": "security-report-saml.md",
        "inventory_title": "SAML connections",
        "inventory_intro": "Library: {{library}}. {{idp_count}} IdP connection(s).",
        "inventory_cols": ["IdP / tenant", "Signed assertions", "Audience / destination", "Replay", "Findings"],
        "inventory_row": ["{{idp}}", "{{signed}}", "{{conditions}}", "{{replay}}", "{{finding_ids}}"],
    },
    "sk-grpc": {
        "prefix": "GRPC", "title": "gRPC Security Report", "report": "security-report-grpc.md",
        "inventory_title": "Methods",
        "inventory_intro": "{{service_count}} service(s), {{method_count}} method(s). Transport: {{transport}}. Reflection: {{reflection}}.",
        "inventory_cols": ["Method", "Defined at", "Auth", "Authorization", "Findings"],
        "inventory_row": ["`{{method}}`", "`{{file}}:{{line}}`", "{{auth}}", "{{authz}}", "{{finding_ids}}"],
    },
    "sk-domain": {
        "prefix": "DOMAIN", "title": "Domain & DNS Security Report", "report": "security-report-domain.md",
        "inventory_title": "Domains and records",
        "inventory_intro": "Domains: {{domains}}. DNS in code: {{dns_in_code}}. SPF/DMARC/CAA: {{mail_auth}}.",
        "inventory_cols": ["Record", "Type", "Target / value", "Source", "Findings"],
        "inventory_row": ["`{{name}}`", "{{type}}", "`{{value}}`", "{{source}}", "{{finding_ids}}"],
    },
    "sk-extension": {
        "prefix": "EXT", "title": "Browser Extension Security Report", "report": "security-report-extension.md",
        "inventory_title": "Permissions and message listeners",
        "inventory_intro": "Manifest: {{manifest_version}}. Host access: {{host_access}}. {{listener_count}} message listener(s).",
        "inventory_cols": ["Kind", "Name", "Defined at", "Needed for / validation", "Findings"],
        "inventory_row": ["{{kind}}", "`{{name}}`", "`{{file}}:{{line}}`", "{{notes}}", "{{finding_ids}}"],
    },
    "sk-dast": {
        "prefix": "DAST", "title": "Dynamic Scan Report", "report": "security-report-dast.md",
        "inventory_title": "Scanned surface",
        "inventory_intro": "Target: {{target}}. Scanner: {{scanner}}. Alerts: {{alert_count}} ({{confirmed}} confirmed).",
        "inventory_cols": ["URL / endpoint", "Method", "Alerts", "Findings"],
        "inventory_row": ["`{{url}}`", "{{method}}", "{{alerts}}", "{{finding_ids}}"],
    },
    "sk-repo": {
        "prefix": "REPO", "title": "Repository Hygiene Report", "report": "security-report-repo.md",
        "inventory_title": "Checks",
        "inventory_intro": "Platform: {{platform}}. Branch protection: {{protection}}. Signed commits: {{signed}}. Scanners: {{scanners}}.",
        "inventory_cols": ["Area", "Evidence", "Source", "Findings"],
        "inventory_row": ["{{area}}", "{{evidence}}", "{{source}}", "{{finding_ids}}"],
    },
    "sk-incident": {
        "prefix": "IR", "title": "Incident Readiness Report", "report": "security-report-incident.md",
        "inventory_title": "Readiness areas",
        "inventory_intro": "Plan: {{plan}}. On call: {{oncall}}. Restore tested: {{restore}}.",
        "inventory_cols": ["Area", "Evidence", "Source", "Findings"],
        "inventory_row": ["{{area}}", "{{evidence}}", "{{source}}", "{{finding_ids}}"],
    },
    "sk-database": {
        "prefix": "DB", "title": "Database Security Report", "report": "security-report-database.md",
        "inventory_title": "Data stores",
        "inventory_intro": "Stores: {{stores}}. Access layer: {{orm}}. Raw query sites: {{raw_count}}.",
        "inventory_cols": ["Store", "Connection defined at", "TLS", "DB user", "Exposure", "Findings"],
        "inventory_row": ["{{store}}", "`{{file}}:{{line}}`", "{{tls}}", "{{db_user}}", "{{exposure}}", "{{finding_ids}}"],
    },
}

TEMPLATE = """<!--
SecurityKit report template. Fill every {{{{placeholder}}}}; keep headings and their order.
Repeat the FINDING block once per confirmed finding, sorted by severity then check ID.
If a severity group has no findings, write "None." under its heading.
Never include secrets: redact to the first 4 characters + "…".
-->
# {title}

**Project:** {{{{project_name}}}}
**Generated:** {{{{generated_at}}}} by SecurityKit {skill} {{{{skill_version}}}}
**Scope:** {{{{scope}}}}  <!-- "full checklist" or "section: <name>" -->
**Modes:** static {{{{static_mode}}}} · dynamic {{{{dynamic_status}}}}

## Score: {{{{score}}}}/100

| Critical | High | Medium | Low | Passed | Skipped | Needs review |
|---:|---:|---:|---:|---:|---:|---:|
| {{{{critical}}}} | {{{{high}}}} | {{{{medium}}}} | {{{{low}}}} | {{{{passed_count}}}} | {{{{skipped_count}}}} | {{{{review_count}}}} |

Score = 100 − 25×Critical − 10×High − 4×Medium − 1×Low (minimum 0).
{{{{candidates_reviewed}}}} candidates reviewed, {{{{candidates_rejected}}}} rejected as false positives.

### Top fixes

1. {{{{top_fix_1}}}}
2. {{{{top_fix_2}}}}
3. {{{{top_fix_3}}}}

---

## Findings

### Critical

<!-- FINDING -->
#### [{{{{check_id}}}}] {{{{title}}}}

| | |
|---|---|
| **Severity** | {{{{severity}}}} |
| **Location** | `{{{{file}}}}:{{{{line}}}}`  <!-- or: `{{{{method}}}} {{{{url}}}}` → {{{{status}}}} --> |
| **References** | OWASP {{{{owasp}}}} · {{{{cwe}}}} |

**Evidence**

```{{{{lang}}}}
{{{{evidence_snippet}}}}
```

**Impact.** {{{{impact}}}}

**Fix.** {{{{fix}}}}

**Regression test.** {{{{regression_test}}}}
<!-- /FINDING -->

### High

### Medium

### Low

---

## Needs manual review

<!-- Plausible issues that could not be proven with evidence. Not counted in the score. -->

| Check | Where | Why it could not be confirmed |
|---|---|---|
| {{{{check_id}}}} | {{{{location}}}} | {{{{reason}}}} |

## Checks passed

| Check | Title | Note |
|---|---|---|
| {{{{check_id}}}} | {{{{title}}}} | {{{{note}}}} |

## Checks skipped

| Check | Title | Reason |
|---|---|---|
| {{{{check_id}}}} | {{{{title}}}} | {{{{reason}}}} <!-- e.g. "dynamic, no endpoint URL", "not applicable: <why>" --> |

## {inventory_title}

{inventory_intro}

| {cols} |
|{seps}|
| {row} |

---

*A clean report is not a guarantee of security. SecurityKit finds common, checkable issues;
it does not replace a professional penetration test or threat model. All analysis ran locally;
no code left this machine.*
"""


def schema(skill, prefix, any_check=False):
    # any_check: the skill reports other skills' check IDs (e.g. sk-review), so accept any SecurityKit ID.
    id_prefix = "[A-Z][A-Z0-9]*" if any_check else prefix
    check = {"type": "string", "pattern": f"^{id_prefix}-[A-Z][A-Z0-9]*-[0-9]{{3}}$"}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://github.com/getsecuritykit/kit/skills/{skill}/schema/report.schema.json",
        "title": f"SecurityKit {skill} report",
        "type": "object",
        "required": ["schemaVersion", "tool", "generatedAt", "scope", "modes", "score", "summary",
                     "findings", "passed", "skipped", "inventory"],
        "additionalProperties": False,
        "properties": {
            "schemaVersion": {"const": "1.0"},
            "tool": {
                "type": "object", "required": ["name", "skill", "version"], "additionalProperties": False,
                "properties": {"name": {"const": "SecurityKit"}, "skill": {"const": skill}, "version": {"type": "string"}},
            },
            "generatedAt": {"type": "string", "format": "date-time"},
            "project": {"type": "object", "additionalProperties": False, "properties": {"name": {"type": "string"}}},
            "scope": {
                "type": "object", "required": ["type"], "additionalProperties": False,
                "properties": {"type": {"enum": ["full", "section"]}, "section": {"type": "string"}},
            },
            "modes": {
                "type": "object", "required": ["static", "dynamic"], "additionalProperties": False,
                "properties": {
                    "static": {"type": "boolean"},
                    "dynamic": {"type": "boolean"},
                    "target": {"type": ["string", "null"], "description": "URL probed in dynamic mode"},
                    "ownershipConfirmed": {"type": "boolean"},
                    "fix": {"type": "boolean"},
                    "tests": {"type": "boolean"},
                },
            },
            "score": {"type": "integer", "minimum": 0, "maximum": 100},
            "summary": {
                "type": "object", "required": ["critical", "high", "medium", "low", "passed", "skipped"],
                "additionalProperties": False,
                "properties": {k: {"type": "integer", "minimum": 0} for k in [
                    "critical", "high", "medium", "low", "passed", "skipped", "needsReview",
                    "candidatesReviewed", "candidatesRejected"]},
            },
            "findings": {"type": "array", "items": {"$ref": "#/$defs/finding"}},
            "needsReview": {
                "type": "array",
                "items": {"type": "object", "required": ["checkId", "location", "reason"], "additionalProperties": False,
                          "properties": {"checkId": {"$ref": "#/$defs/checkId"}, "location": {"type": "string"},
                                         "reason": {"type": "string"}}},
            },
            "passed": {
                "type": "array",
                "items": {"type": "object", "required": ["checkId"], "additionalProperties": False,
                          "properties": {"checkId": {"$ref": "#/$defs/checkId"}, "title": {"type": "string"},
                                         "note": {"type": "string"}}},
            },
            "skipped": {
                "type": "array",
                "items": {"type": "object", "required": ["checkId", "reason"], "additionalProperties": False,
                          "properties": {"checkId": {"$ref": "#/$defs/checkId"}, "title": {"type": "string"},
                                         "reason": {"type": "string", "minLength": 1}}},
            },
            "inventory": {
                "type": "array",
                "description": "What was audited (operations, receivers/senders, spec-vs-code rows). Shape varies by skill.",
                "items": {"type": "object", "required": ["kind", "name"],
                          "properties": {"kind": {"type": "string"}, "name": {"type": "string"},
                                         "file": {"type": "string"}, "line": {"type": "integer", "minimum": 1},
                                         "findingIds": {"type": "array", "items": {"type": "string"}}}},
            },
        },
        "$defs": {
            "checkId": check,
            "severity": {"enum": ["Critical", "High", "Medium", "Low"]},
            "location": {
                "type": "object", "required": ["file", "line"], "additionalProperties": False,
                "properties": {"file": {"type": "string", "description": "Path relative to the project root, forward slashes"},
                               "line": {"type": "integer", "minimum": 1}, "endLine": {"type": "integer", "minimum": 1}},
            },
            "request": {
                "type": "object", "required": ["method", "url", "status", "responseExcerpt"], "additionalProperties": False,
                "properties": {"method": {"type": "string"}, "url": {"type": "string"}, "as": {"type": "string"},
                               "requestExcerpt": {"type": "string"}, "status": {"type": "integer"},
                               "responseExcerpt": {"type": "string"}},
            },
            "finding": {
                "type": "object",
                "required": ["id", "checkId", "title", "severity", "evidence", "impact", "fix", "regressionTest",
                             "references", "source"],
                "additionalProperties": False,
                "anyOf": [{"required": ["location"]}, {"required": ["request"]}],
                "properties": {
                    "id": {"type": "string", "pattern": f"^SK-{prefix}-[0-9]{{4}}$"},
                    "checkId": {"$ref": "#/$defs/checkId"},
                    "title": {"type": "string", "minLength": 1},
                    "severity": {"$ref": "#/$defs/severity"},
                    "location": {"$ref": "#/$defs/location"},
                    "request": {"$ref": "#/$defs/request"},
                    "evidence": {"type": "string", "minLength": 1},
                    "impact": {"type": "string", "minLength": 1},
                    "fix": {"type": "string", "minLength": 1},
                    "regressionTest": {"type": "string", "minLength": 1},
                    "references": {
                        "type": "object", "required": ["owasp", "cwe"], "additionalProperties": False,
                        "properties": {
                            "owasp": {"type": "array", "description": "OWASP API Top 10 2023 (API1-API10) or OWASP Top 10 2021 (A01-A10)",
                                      "items": {"type": "string", "pattern": "^(API([1-9]|10)(:2023)?|A(0[1-9]|10)(:2021)?)$"}},
                            "cwe": {"type": "array", "items": {"type": "string", "pattern": "^CWE-[0-9]+$"}},
                        },
                    },
                    "source": {"enum": ["script", "review", "dynamic"]},
                    "severityAdjusted": {"type": "string"},
                    "fixed": {"type": "boolean"},
                },
            },
        },
    }


for skill, cfg in SKILLS.items():
    base = os.path.join(ROOT, "skills", skill)
    os.makedirs(os.path.join(base, "templates"), exist_ok=True)
    os.makedirs(os.path.join(base, "schema"), exist_ok=True)
    md = TEMPLATE.format(
        title=cfg["title"], skill=skill, inventory_title=cfg["inventory_title"],
        inventory_intro=cfg["inventory_intro"],
        cols=" | ".join(cfg["inventory_cols"]), seps="|".join("---" for _ in cfg["inventory_cols"]),
        row=" | ".join(cfg["inventory_row"]),
    )
    with open(os.path.join(base, "templates", "report.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(md)
    with open(os.path.join(base, "schema", "report.schema.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(schema(skill, cfg["prefix"], cfg.get("any_check", False)), fh, indent=2)
        fh.write("\n")
    print("wrote", skill)
