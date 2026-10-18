# Business logic security checklist

Source of truth for `sk-business` check IDs. Business logic flaws are valid requests used in ways the design
did not intend: no malformed input, no injection, so scanners and frameworks rarely catch them. Concepts apply
to any domain (e-commerce, fintech, SaaS plans, marketplaces, bookings, rewards). Based on the OWASP Abuse
Case, Transaction Authorization and REST Security (out-of-order execution) cheat sheets and OWASP API6:2023
(Unrestricted Access to Sensitive Business Flows). `references/guide.md` explains each check.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP API Top 10 2023 / Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| BIZ-PRICE-001 | Prices, totals, discounts, fees, taxes and currency are computed server-side from trusted data; client-supplied values are ignored | S+D | Critical | A04 | CWE-602 |
| BIZ-QTY-001 | Quantities, amounts and counts are validated: positive, integer where required, bounded, overflow-safe | S+D | High | API6 | CWE-1284 |
| BIZ-COUPON-001 | Coupons, vouchers, gift cards, referral rewards and trials are single-use (or per-user limited) atomically, not stackable unless intended, and expire | S+D | High | API6 | CWE-841 |
| BIZ-FLOW-001 | Multi-step workflows are enforced server-side as a state machine; steps (verification, payment, approval) cannot be skipped, repeated or reordered | S+D | High | API6 | CWE-841 |
| BIZ-TRUST-001 | No security or business decision relies on client-side state: hidden fields, cookies, local storage, front-end checks, client-sent flags | S | High | A04 | CWE-602 |
| BIZ-LIMIT-001 | Business limits are enforced server-side: per-user quotas, free-tier caps, trial/multi-account abuse, purchase limits per customer | S | Medium | API6 | CWE-799 |
| BIZ-AUTHZ-001 | Each business action checks the actor's right to perform it on this object, including separation of duties (no approving your own request) | S+D | High | API5 | CWE-285 |
| BIZ-MONEY-001 | Money uses decimal/integer minor units (no floating point); rounding and currency conversion happen server-side with defined rules | S | Medium | A04 | CWE-1339 |
| BIZ-REVERSAL-001 | Refunds, cancellations, returns and chargebacks cannot exceed the original amount, cannot be repeated, and restore state consistently | S+D | High | A04 | CWE-840 |
| BIZ-RACE-001 | Scarce resources (stock, balance, seats, one-time rewards) are protected against concurrent requests (see `sk-race`) | S+D | High | A04 | CWE-362 |
| BIZ-ENUM-001 | Business identifiers that grant value or access (coupon/gift/invite codes, invoice and order numbers in links) are unguessable | S | Medium | API6 | CWE-330 |
| BIZ-ABUSE-001 | Abuse cases for key workflows are documented and covered by tests (automation, scraping, reselling, referral farming) | S | Low | API6 | CWE-840 |
