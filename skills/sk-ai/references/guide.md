# AI / LLM application security guide

Sources: OWASP Top 10 for LLM Applications 2025, OWASP LLM Prompt Injection Prevention, AI Agent Security and Secure
AI Model Ops cheat sheets. Provider- and framework-neutral.

**The model is an untrusted component.** Treat it like a very capable intern who will follow instructions hidden in
any text it reads: whatever it sees may be repeated, whatever it produces may be attacker-chosen, and whatever it can
do, an attacker can make it do. Put every security decision in code around the model.

## Map each feature (AI-INV-001)

For every model call: **who** can trigger it (anonymous, user, admin, background job) · **what goes in** (system prompt,
user text, retrieved documents, records, tool results) · **what comes out and where it goes** (UI, HTML, SQL, shell,
email, another model, a tool call) · **what limits apply** (tokens, rate, cost). Most findings fall out of this table.

## OWASP LLM Top 10 2025 → checks

| Risk | Check | What to look for |
|---|---|---|
| LLM01 Prompt injection | AI-PI-001 | untrusted text reaching the context; deep dive `/sk-prompt-injection` |
| LLM02 Sensitive information disclosure | AI-DISC-001, AI-PRIV-001 | secrets, other users' data, unneeded PII in prompts; provider retention |
| LLM03 Supply chain | AI-SUPPLY-001 | `trust_remote_code=True`, pickle weights, unpinned hub models, unvetted plugins |
| LLM04 Data and model poisoning | AI-POISON-001 | user content flowing into fine-tuning/embeddings without review |
| LLM05 Improper output handling | AI-OUT-001/002 | output into `innerHTML`, SQL, `eval`/shell, URLs, file paths; unvalidated JSON |
| LLM06 Excessive agency | AI-AGENCY-001 | broad tools, no approval; deep dive `/sk-agents` |
| LLM07 System prompt leakage | AI-SYSPROMPT-001 | keys/rules in the system prompt; prompt returned to clients |
| LLM08 Vector and embedding weaknesses | AI-VECTOR-001 | cross-tenant retrieval; deep dive `/sk-rag` |
| LLM09 Misinformation | AI-MISINFO-001 | unreviewed high-stakes output; hallucinated packages/URLs used automatically |
| LLM10 Unbounded consumption | AI-COST-001 | no `max_tokens`, no rate limits/quotas, model chosen by the caller |

Also: **AI-KEY-001** (provider keys in client bundles), **AI-AUTHZ-001** (authorization in prompts), **AI-LOG-001**
(prompts in logs/traces), **AI-TEST-001** (security evals).

## Safe patterns

- **Output**: render as text; if Markdown is needed, sanitize HTML and restrict images/links. Text-to-SQL: read-only DB
  role, statement/table allow-list, `LIMIT`, parse before executing; better, let the model choose parameters for fixed
  queries. Never `eval`/shell model output outside a disposable sandbox.
- **Structured output**: provider JSON-schema mode or tool calls, then validate again in code (zod, pydantic) and fail closed.
- **Authorization**: filter data to the caller's permissions *before* it enters the context; check permissions on every
  action the model requests using the end user's identity.
- **Data minimization**: send the fields the task needs; mask identifiers; zero-retention / no-training settings and a DPA
  for each provider; keep regulated data on approved providers/regions.
- **Cost**: `max_tokens` on every call; input length caps; per-user rate limits and daily token/cost budgets; timeouts;
  provider-side spending limits; server-side model allow-list.
- **Keys**: model calls only from the server; separate keys per environment with spend caps; rotate on exposure (`/sk-secrets`).
- **Supply chain**: pin hub revisions (commit hash), `safetensors`, `weights_only=True`, no `trust_remote_code` unless
  the code was reviewed at that revision.
- **Logs**: redact prompts/completions before logging or tracing; restrict and expire trace data.
