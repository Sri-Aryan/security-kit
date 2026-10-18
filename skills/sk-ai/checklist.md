# AI / LLM application security checklist

Source of truth for `sk-ai` check IDs. Covers any application feature that calls a large language model (chat,
assistants, summarizers, classifiers, text-to-SQL, code generation, embeddings, agents) with any provider (hosted APIs,
self-hosted or local models) and any framework. Based on the OWASP Top 10 for LLM Applications 2025 (LLM01–LLM10),
the OWASP LLM Prompt Injection Prevention, AI Agent Security and Secure AI Model Ops cheat sheets.
`references/guide.md` explains each check.

This skill is the **umbrella audit** for LLM features. Three areas have their own deep-dive skill; `sk-ai` records the
top-level result and points to them: prompt injection → `sk-prompt-injection`, tools/agents/MCP → `sk-agents`,
retrieval and vector stores → `sk-rag`.

Core principle: **the model is an untrusted component.** Its input may be attacker-controlled, its output may be
attacker-steered, and anything in its context may be repeated back. Enforce security in code around the model.

Columns: **Mode** S = static, D = dynamic (harmless-marker tests). OWASP = OWASP Top 10 2021.

## Inventory and injection (INV / PI)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AI-INV-001 | Every LLM feature is inventoried: model/provider, what data goes into the prompt, where the output goes, who can call it | S | Medium | A04 | CWE-1059 |
| AI-PI-001 | Prompt injection paths (user input, documents, web pages, emails, tool results) cannot change what the feature is allowed to do; deep dive: `sk-prompt-injection` (LLM01) | S+D | High | A03 | CWE-1427 |

## Data sent to the model (DISC / PRIV)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AI-DISC-001 | Prompts contain only the data the feature needs: no secrets/credentials, no other users' or tenants' data, PII minimized or masked before sending (LLM02) | S | High | A04 | CWE-359 |
| AI-PRIV-001 | Third-party model providers are covered by the privacy policy/DPA; data retention and training opt-out are configured (e.g. zero-retention, `store: false`); sensitive data stays on approved providers/regions | S | Medium | A04 | CWE-359 |

## System prompt (SYSPROMPT)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AI-SYSPROMPT-001 | The system prompt is treated as public: it holds no secrets, keys, internal URLs or access rules, and is never returned to clients or logged to them; leaked-prompt detection where it matters (LLM07) | S+D | Medium | A04 | CWE-200 |

## Output handling (OUT / AGENCY)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AI-OUT-001 | Model output is untrusted at every sink: escaped/sanitized before HTML/Markdown rendering, parameterized (never raw) before SQL, never run as shell/code, validated before URLs, file paths, redirects and emails (LLM05) | S+D | Critical | A03 | CWE-94 |
| AI-OUT-002 | Output consumed by code is structured (JSON schema / tool calls) and validated before use; parse failures fail closed | S | Medium | A04 | CWE-20 |
| AI-AGENCY-001 | Tools and actions given to the model follow least privilege with approval for high-impact actions; deep dive: `sk-agents` (LLM06) | S | High | A01 | CWE-250 |
| AI-AUTHZ-001 | Authorization decisions are made in code, never by the model and never stated only in the prompt ("only answer admins"); data the model can read is filtered to the caller's permissions before it enters the context | S | High | A01 | CWE-863 |

## Supply chain and model integrity (SUPPLY / POISON)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AI-SUPPLY-001 | Models, adapters and datasets come from trusted sources, pinned to a revision/hash; no `trust_remote_code=True` on untrusted repos; weights loaded with safe formats (`safetensors`, `weights_only=True`), not pickle (LLM03) | S | High | A08 | CWE-494 |
| AI-POISON-001 | Fine-tuning, feedback and embedding data is validated, provenance-tracked and access-controlled; user feedback cannot flow into training without review (LLM04) | S | Medium | A08 | CWE-1039 |

## Retrieval (VECTOR)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AI-VECTOR-001 | Vector stores and retrieval enforce per-user/tenant access and treat retrieved text as untrusted; deep dive: `sk-rag` (LLM08) | S | High | A01 | CWE-639 |

## Reliability (MISINFO)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AI-MISINFO-001 | High-stakes outputs (medical, legal, financial, security, code merged automatically) are grounded, cite sources, are labelled as AI-generated and have human review; generated package names/URLs are verified before use (LLM09) | S | Medium | A04 | CWE-1426 |

## Cost and abuse (COST)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AI-COST-001 | Unbounded consumption is prevented: output token limits, input size limits, per-user rate limits and quotas, timeouts, loop/retry caps; `model`, `max_tokens` and similar parameters are not taken from the request (LLM10) | S+D | High | A04 | CWE-770 |

## Keys and access (KEY)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AI-KEY-001 | Provider API keys stay server-side: no keys in browser/mobile bundles (`NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` prefixes, `dangerouslyAllowBrowser: true`), per-environment keys with spending limits; LLM endpoints require authentication | S | Critical | A05 | CWE-522 |

## Logging and testing (LOG / TEST)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AI-LOG-001 | Prompts and completions that are logged or traced (LangSmith, Langfuse, Helicone, provider dashboards) have PII/secrets redacted, retention limits and restricted access; abuse and injection attempts are monitored | S | Medium | A09 | CWE-532 |
| AI-TEST-001 | Security tests/evals exist for the LLM features: injection and leakage prompts, output-encoding tests, rate-limit tests, run on model or prompt changes | S | Low | A04 | CWE-1059 |
