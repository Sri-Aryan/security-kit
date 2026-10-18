# Race condition checklist

Source of truth for `sk-race` check IDs. Covers concurrency bugs that attackers trigger on purpose by sending
many parallel requests (single-packet attacks make the window tiny but reliable): double spending, coupon
reuse, overselling, duplicate accounts, bypassed limits. Applies to any language, database and deployment
(multiple instances, workers, serverless). `references/guide.md` shows the safe patterns.

Columns: **Mode** S = static, D = dynamic (parallel requests against a test environment). OWASP = OWASP Top 10 2021 / API 2023.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| RACE-RMW-001 | Read-modify-write of balances, counters, stock and quotas uses an atomic update, row lock or optimistic version check | S+D | Critical | A04 | CWE-362 |
| RACE-CHECK-001 | Check-then-act sequences (does it exist? is it eligible? then insert/redeem) are protected by a unique constraint, lock or atomic conditional write (TOCTOU) | S+D | High | A04 | CWE-367 |
| RACE-SINGLE-001 | Single-use items (tokens, codes, coupons, invites, one-time rewards) are consumed atomically (`UPDATE … WHERE used = false` / delete-returning) | S+D | High | A04 | CWE-367 |
| RACE-TXN-001 | Multi-step state changes run in one transaction with an isolation level that prevents the anomaly in question | S | High | A04 | CWE-362 |
| RACE-LIMIT-001 | Limits and quotas are enforced atomically (not count-then-insert) | S+D | Medium | API4 | CWE-362 |
| RACE-LOCK-001 | Locks work across instances: no process-local mutexes for shared state; distributed locks have expiry, owner tokens and safe release | S | Medium | A04 | CWE-667 |
| RACE-IDEM-001 | Retried or duplicated requests (double-clicks, client retries, webhook redelivery) are idempotent via idempotency keys or unique request IDs | S+D | High | A04 | CWE-841 |
| RACE-FILE-001 | File operations avoid TOCTOU (exists-then-open, predictable temp files); use atomic create and secure temp APIs | S | Medium | A04 | CWE-377 |
| RACE-SHARED-001 | Request handlers do not share mutable module-level/global state across concurrent requests | S | Medium | A04 | CWE-362 |
| RACE-TEST-001 | Concurrency tests fire parallel requests at critical operations and assert the invariant holds | S | Low | A04 | CWE-1125 |
