# Prompt injection checklist

Source of truth for `sk-prompt-injection` check IDs. Covers any application that sends text to a large
language model: chatbots, assistants, agents with tools, summarizers, classifiers, text-to-SQL, coding
agents, whatever the provider or framework. Based on the OWASP LLM Prompt Injection Prevention and AI Agent
Security cheat sheets and OWASP Top 10 for LLM Applications (LLM01, LLM02, LLM05, LLM06, LLM07, LLM10).
`references/guide.md` explains each check.

Core principle: **the model cannot reliably tell instructions from data.** Anything an attacker can get into
the context can steer the model, so security must be enforced in code around the model, not by the prompt.

Columns: **Mode** S = static, D = dynamic (harmless-marker tests). OWASP = OWASP Top 10 2021.

## Untrusted channels and separation (CHAN / SEP)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PI-CHAN-001 | Every untrusted channel into the context is identified: user input, retrieved documents, web pages, emails, files, images, tool results, conversation memory | S | High | A03 | CWE-1427 |
| PI-SEP-001 | Trusted instructions are separated from untrusted data: the system prompt is constant; untrusted content goes in user/tool messages, clearly delimited, never concatenated into the system prompt | S | High | A03 | CWE-1427 |
| PI-SEP-002 | The system prompt contains no secrets, credentials or internal-only data (assume it will be extracted) | S | High | A04 | CWE-200 |

## Tools and actions (TOOL)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PI-TOOL-001 | Tool calls are authorized and validated in code, outside the model: the *calling user's* permissions, argument schemas, allow-lists (URLs, paths, tables, recipients) | S | Critical | A01 | CWE-863 |
| PI-TOOL-002 | Least privilege: each context gets the minimum tool set; no general shell/code/SQL tools; read-only credentials and narrow API scopes | S | High | A01 | CWE-250 |
| PI-TOOL-003 | High-impact actions (payments, deletions, sending messages/emails, code execution, external writes) require human approval bound to the exact action and arguments | S | High | A04 | CWE-862 |
| PI-TOOL-004 | Model output is never executed directly as code, shell commands or SQL | S | Critical | A03 | CWE-94 |

## Output handling (OUT)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PI-OUT-001 | Model output is treated as untrusted at every sink: escaped/sanitized before HTML, parameterized before SQL, validated before URLs, files or commands | S | High | A03 | CWE-79 |
| PI-OUT-002 | Rendering of model output cannot exfiltrate data: external images and links are restricted (CSP `img-src`, link/image allow-lists, no auto-fetch) | S+D | High | A04 | CWE-200 |
| PI-OUT-003 | Outputs used by code are structured and schema-validated; responses are checked for leaked system prompt, secrets and PII | S | Medium | A04 | CWE-20 |

## Input handling (IN)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PI-IN-001 | Inputs are bounded and normalized (length limits, Unicode normalization, invisible-character removal, decoded-content inspection) as defence in depth | S | Medium | A03 | CWE-20 |
| PI-IN-002 | Remote content (web pages, emails, documents, images, metadata) is sanitized before entering the context: hidden text, comments, markup and invisible Unicode removed | S | Medium | A03 | CWE-1427 |

## Data, memory, abuse, monitoring (DATA / MEM / ABUSE / MON / GUARD)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PI-DATA-001 | Context is isolated per user/tenant: conversation memory, caches and retrieved data never cross users | S | High | A01 | CWE-200 |
| PI-DATA-002 | Prompts contain only the data the current user may see; secrets never enter the context | S | High | A01 | CWE-200 |
| PI-MEM-001 | Writes to persistent memory from untrusted content are controlled (memory/session poisoning) | S | Medium | A08 | CWE-1427 |
| PI-ABUSE-001 | Per-user rate limits, token limits (`max_tokens`) and cost budgets bound brute-force (best-of-N) jailbreaking and denial of wallet | S | Medium | A04 | CWE-770 |
| PI-MON-001 | Injection attempts and tool use are logged and alerted on without logging sensitive prompt content; there is a kill switch | S | Medium | A09 | CWE-778 |
| PI-GUARD-001 | Where risk warrants, independent guardrails screen inputs, outputs and proposed actions, and their failure modes (injectable, approval fatigue) are understood | S | Low | A04 | CWE-693 |

## Tests (TEST)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PI-TEST-001 | Direct and indirect injection are tested with harmless markers and instrumented tools; results recorded per objective (disclosure, unauthorized tool use, exfiltration) | S+D | Low | A04 | CWE-1125 |
