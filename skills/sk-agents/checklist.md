# Agent and tool security checklist

Source of truth for `sk-agents` check IDs. Covers anything that lets a model take actions: function/tool calling,
agent frameworks (any language), multi-agent systems, MCP servers the project **builds**, and MCP servers / agent
tools the project **uses** (`.mcp.json`, editor and coding-agent configs). Based on the OWASP AI Agent Security and
MCP Security cheat sheets and OWASP LLM06 (Excessive Agency). `references/guide.md` explains each check. Prompt
injection itself is covered by `sk-prompt-injection`; this skill limits what an injected agent can do.

Core principle: **assume the agent will be manipulated.** Its tools, credentials and approvals decide the damage.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021.

## Tools and permissions (TOOL / AUTHZ / INPUT)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AGENT-TOOL-001 | Least privilege: each agent gets only the tools its task needs; no general-purpose shell, code, SQL, filesystem or HTTP tools when narrow tools would do; read-only variants by default | S | High | A01 | CWE-250 |
| AGENT-AUTHZ-001 | Tools act with the end user's identity and permissions (checked in the tool, not the prompt); no shared admin/service credentials that let a user reach data they could not access directly (confused deputy) | S | Critical | A01 | CWE-441 |
| AGENT-INPUT-001 | Tool arguments are validated in code: strict schemas (`additionalProperties: false`, types, lengths, enums), allow-listed paths/hosts/tables/recipients, parameterized queries, no shell strings; tool arguments never reach `eval`/shell/SQL/fetch unchecked | S | Critical | A03 | CWE-20 |
| AGENT-EXEC-001 | Code-execution and shell tools run in an isolated sandbox (container/VM/WASM) with no secrets, restricted network and filesystem, CPU/memory/time limits | S | Critical | A04 | CWE-653 |

## Approvals and limits (HITL / LIMIT)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AGENT-HITL-001 | Destructive, financial, external-communication and privilege-changing actions require human approval that shows the exact action and arguments, is bound to them (and to the user and an expiry), single-use, and cannot be granted by the model; no blanket auto-approve / skip-permissions modes in shared or production configs | S | High | A04 | CWE-862 |
| AGENT-LIMIT-001 | Agent loops have limits: max iterations/steps, recursion depth, tool-call count, timeouts, token and cost budgets per task and per user | S | Medium | A04 | CWE-770 |

## Data flow (OUTPUT / MEM / MULTI)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AGENT-OUTPUT-001 | Tool results (web pages, files, emails, API responses) are treated as untrusted data: delimited, size-limited, never allowed to grant new permissions or trigger high-impact tools without approval | S | High | A03 | CWE-1427 |
| AGENT-MEM-001 | Agent memory and conversation state are isolated per user/session, validated before being stored, size/TTL-limited, and exclude secrets | S | High | A01 | CWE-488 |
| AGENT-MULTI-001 | Multi-agent systems authenticate agent-to-agent messages, do not escalate privileges through delegation (a sub-agent never has more rights than its caller), and validate hand-offs | S | Medium | A01 | CWE-269 |

## MCP (MCP / CRED)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AGENT-MCP-001 | MCP servers used come from trusted sources, pinned to exact versions/digests (no `npx -y pkg`/`uvx pkg`/`:latest` without a version), reviewed, and their tool definitions are reviewed and pinned (detect changes / "rug pulls") | S | High | A08 | CWE-829 |
| AGENT-MCP-002 | Local MCP servers run with least privilege (sandboxed, scoped filesystem roots, no broad host access); each server has its own narrowly scoped credentials; servers never pass the client's token through to downstream APIs (token passthrough) | S | High | A01 | CWE-250 |
| AGENT-MCP-003 | MCP servers the project builds: remote (HTTP) transports require authentication (OAuth 2.1 / tokens with audience validation), use TLS, validate `Origin`/`Host`, bind local servers to 127.0.0.1, and use unguessable, non-auth session IDs | S+D | Critical | A07 | CWE-306 |
| AGENT-MCP-004 | Tool descriptions/names cannot poison the agent: descriptions are static and reviewed, contain no instructions to the model, and tools from different servers cannot shadow each other; tool output is not trusted as instructions | S | High | A03 | CWE-1427 |
| AGENT-CRED-001 | Agent/MCP configs contain no plaintext secrets; credentials come from the environment or a secret manager and are never exposed to the model's context | S | High | A07 | CWE-798 |

## Logging and testing (LOG / TEST)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AGENT-LOG-001 | Every tool call is logged with user, agent, tool, arguments (redacted) and result status; approvals and denials are audited; anomalies (loops, unusual tools) alert | S | Medium | A09 | CWE-778 |
| AGENT-TEST-001 | Tests cover tool authorization (another user's resource is refused), argument validation, approval enforcement and loop limits, including indirect-injection scenarios | S | Low | A04 | CWE-1059 |
