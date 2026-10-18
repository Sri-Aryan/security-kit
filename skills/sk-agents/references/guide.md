# Agent and tool security guide

Sources: OWASP AI Agent Security Cheat Sheet, OWASP MCP Security Cheat Sheet, OWASP LLM06 Excessive Agency.
Framework-neutral: the same ideas apply to raw function calling, agent frameworks, multi-agent systems and MCP.

**Assume the agent will be manipulated.** Any text it reads (a web page, an email, a file, a tool result, a tool
*description*) can carry instructions. Prompts don't contain the damage. These four controls in code do:

1. **What it can do**: least-privilege tools (AGENT-TOOL-001), sandboxed execution (AGENT-EXEC-001).
2. **On whose behalf**: the end user's identity and permissions inside every tool (AGENT-AUTHZ-001).
3. **With which arguments**: strict schemas and allow-lists (AGENT-INPUT-001).
4. **With whose consent**: human approval for high-impact actions (AGENT-HITL-001), plus limits (AGENT-LIMIT-001).

## Tools

- One tool, one narrow operation: `get_order_status(order_id)` instead of `run_sql(query)`; `read_project_file(path)`
  confined to a root instead of `shell(cmd)`. Read-only by default; write variants separate and gated.
- Inside each tool: resolve the **calling user** from the session (never from model-supplied arguments), check they may
  access the resource, then act with *their* scoped credentials. A service-role key behind a tool lets any user read
  anything by asking (confused deputy).
- Validate arguments as untrusted input: JSON schema with types, `enum`s, length limits and
  `additionalProperties: false` (provider "strict" mode helps but validate again in code); path containment (resolve,
  then check the prefix); URL allow-lists (`/sk-ssrf`); parameterized SQL (`/sk-inject`); argument arrays, never shell strings.
- Code/shell tools: ephemeral container/VM/WASM sandbox, no secrets in env, no network (or an egress allow-list),
  read-only mounts, CPU/memory/time limits.

## Approvals

High-impact = irreversible, financial, external communication, permission changes, data export, code execution
outside a sandbox. For these, the approval must: show the exact tool + arguments to a human; be bound to them (hash),
to the user and to an expiry; be single-use; and be granted by the UI, never by a model message. Auto-approve lists,
`bypassPermissions`, `--dangerously-skip-permissions`, `approval_policy = "never"` and `human_input_mode="NEVER"` are
acceptable only for read-only tools or inside disposable sandboxes, never in committed/shared configs.

## Loops, memory and multi-agent

- Cap steps/iterations, recursion depth, tool calls, wall time and tokens/cost per task and per user.
- Memory and checkpoints keyed by authenticated user + session; never a module-level list in a server. Don't store
  secrets in memory; validate what gets written (memory poisoning persists across sessions).
- Tool output goes back as a tool/user message, delimited and size-limited, never as a system message; it never grants
  permissions.
- Sub-agents get a subset of the caller's permissions; messages between agents are authenticated and validated.

## MCP

**Servers you use** (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`,
`.codex/config.toml`, `.gemini/settings.json`, ...):
- Trusted publishers only; pin exact versions (`pkg@1.2.3`, `pkg==1.2.3`, image digests); review tool definitions and
  re-review on change (tools such as `mcp-scan` can hash-pin definitions to detect "rug pulls").
- Least privilege: filesystem servers scoped to the project folder; containers without `--privileged`, host network or
  the Docker socket; each server gets its own narrowly scoped token from env/secret manager, never plaintext in config.
- Watch for tool poisoning (instructions hidden in descriptions) and shadowing (a tool redefining another server's tool).

**Servers you build**:
- stdio for local use; HTTP transports require authentication (OAuth 2.1 resource server, validate token **audience**
  is this server), TLS, `Origin`/`Host` validation (DNS rebinding), localhost binding for local servers,
  random session IDs that are not used as authentication.
- **No token passthrough**: never forward the client's token to downstream APIs; obtain the server's own credentials
  (or token exchange) per user.
- Static, reviewed tool descriptions; validate every argument; return minimal results; log every call.
