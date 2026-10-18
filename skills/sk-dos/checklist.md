# Denial-of-service and resource-exhaustion checklist

Source of truth for `sk-dos` check IDs. Covers how a single client (or a few) can exhaust an application's CPU,
memory, connections, disk or money, in any stack: body and payload limits, unbounded pagination and loops sized by
input, catastrophic regexes, decompression and parser bombs, missing timeouts, unbounded in-memory structures,
expensive synchronous work, and retry storms. Request-rate limiting: `sk-ratelimit`. GraphQL depth/cost: `sk-graphql`.
Upload limits: `sk-upload`. Based on the OWASP Denial of Service cheat sheet and API4:2023 (Unrestricted Resource
Consumption). `references/guide.md` gives limits to start from.

Columns: **Mode** S = static, D = dynamic. OWASP = API Top 10 2023 / OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DOS-BODY-001 | Request bodies, JSON depth/size, form fields, headers and multipart parts have explicit, small limits at the app and proxy | S+D | Medium | API4 | CWE-770 |
| DOS-PAGE-001 | Page sizes, `limit`/`per_page`/`count` parameters and result sets are capped server-side; there is no "return everything" mode | S+D | Medium | API4 | CWE-770 |
| DOS-COMPLEX-001 | Loops, allocations, recursion, string repetition and sorting are not sized directly by user input without a cap | S | High | API4 | CWE-400 |
| DOS-REGEX-001 | Regexes applied to input have no catastrophic backtracking (nested or overlapping quantifiers) or run on a linear-time engine with input length caps | S | Medium | API4 | CWE-1333 |
| DOS-DECOMPRESS-001 | Decompression and parsing of input are bounded: max decompressed size, entity expansion disabled, image pixel limits, archive entry limits | S | High | API4 | CWE-409 |
| DOS-TIMEOUT-001 | Outbound HTTP, database and cache calls have timeouts; servers have header/body/idle timeouts | S | Medium | API4 | CWE-400 |
| DOS-RESOURCE-001 | No unbounded in-memory structures keyed or grown by input (global maps, caches, queues, listeners); caches have size limits and TTLs | S | Medium | API4 | CWE-401 |
| DOS-COST-001 | Expensive operations (exports, reports, media processing, AI calls, bulk email) run asynchronously with per-user quotas and concurrency limits | S | Medium | API4 | CWE-770 |
| DOS-RETRY-001 | Retries use capped attempts with exponential backoff and jitter; no infinite retry loops or retry storms against dependencies | S | Low | API4 | CWE-400 |
