# Race condition guide

Applies to any language and data store. Attackers do not need luck: sending 20–50 requests in one burst (or a
single TCP packet carrying many HTTP/2 requests) lands them inside a millisecond window. Any **read → decide →
write** sequence that is not atomic is exploitable.

## Patterns and their safe forms

| Pattern | Vulnerable | Safe |
|---|---|---|
| Counter / balance (RACE-RMW) | `acct = load(); acct.balance -= x; save(acct)` | `UPDATE accounts SET balance = balance - $x WHERE id = $id AND balance >= $x` (check rows affected), `SELECT … FOR UPDATE` in a transaction, or a version column (optimistic locking) |
| Check then insert (RACE-CHECK) | `if not exists(claim): insert(claim)` | unique constraint on (user, promo) and handle the duplicate error; `INSERT … ON CONFLICT DO NOTHING RETURNING` |
| Single use (RACE-SINGLE) | `if token.used: fail; token.used = true; save` | `UPDATE tokens SET used = true WHERE id = $id AND used = false` and require 1 row; `DELETE … RETURNING`; `findOneAndUpdate({used:false}, {$set:{used:true}})` |
| Quota (RACE-LIMIT) | `if count() >= max: fail; insert()` | serializable transaction, a counter row updated atomically, or a constraint |
| Multi-step (RACE-TXN) | several writes without a transaction | one transaction; choose isolation that blocks the anomaly (often `SERIALIZABLE` or explicit row locks) |
| Locks (RACE-LOCK) | in-process mutex; Redis `SETNX` without TTL | DB row locks, or `SET key token NX PX ttl` with a token-checked release (Lua script) |
| Duplicates (RACE-IDEM) | double-click creates two orders | client-generated `Idempotency-Key`, stored with the result and a unique constraint |
| Files (RACE-FILE) | `if !exists(p) write(p)`; `/tmp/fixed-name` | open with exclusive create (`O_CREAT|O_EXCL`, `'wx'`), `mkstemp`, `mkdtemp` |
| Shared state (RACE-SHARED) | module-level variables mutated per request | request-scoped state; per-user data in the DB/cache |

## Verifying

For each money/stock/quota/one-time operation: find the read, the decision and the write. If they are not one atomic
statement, inside one locking transaction, or guarded by a constraint, it is a candidate. Then confirm there is no
lock elsewhere (decorators, middleware, queue serialization).

## Testing

Fire N concurrent requests (e.g. `Promise.all`, `asyncio.gather`, a thread pool) at the operation in a test
environment and assert the invariant: one redemption, balance never negative, stock never below zero.
