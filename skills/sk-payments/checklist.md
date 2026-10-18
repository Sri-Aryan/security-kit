# Payment flow security checklist

Source of truth for `sk-payments` check IDs. Covers integrations with payment providers (Stripe, PayPal,
Adyen, Braintree, Square, Razorpay, Mollie, Paddle, LemonSqueezy, app stores…) in any language: checkout,
confirmation, webhooks, refunds, subscriptions/entitlements, payouts, keys and card data. Based on the OWASP
Third-Party Payment Gateway Integration and Transaction Authorization cheat sheets and PCI DSS scope basics.
Webhook mechanics are covered in depth by `sk-webhooks`; concurrency by `sk-race`. `references/guide.md`
explains each check.

Columns: **Mode** S = static, D = dynamic (provider test mode only). OWASP = OWASP Top 10 2021 / API 2023.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| PAY-AMOUNT-001 | Amount, currency, products, discounts and quantities sent to the provider are computed server-side from trusted data | S+D | Critical | A04 | CWE-602 |
| PAY-CONFIRM-001 | Orders are fulfilled only after server-side confirmation (verified webhook or provider API lookup), never from redirect/return URL parameters or client callbacks | S+D | Critical | A08 | CWE-345 |
| PAY-WEBHOOK-001 | Payment webhooks verify the provider signature over the raw body (and timestamp) before acting | S | Critical | A08 | CWE-345 |
| PAY-MATCH-001 | Confirmations are matched to the expected order: amount, currency, order/session ID, merchant account and status | S | High | A08 | CWE-345 |
| PAY-IDEM-001 | Creates/charges/refunds send idempotency keys, events are processed once (persistent dedupe), and fulfillment is idempotent | S | High | A04 | CWE-841 |
| PAY-STATE-001 | Orders follow an explicit state machine (pending → paid → fulfilled / failed / refunded / disputed); late, failed and out-of-order events are handled and reconciled | S | Medium | A04 | CWE-841 |
| PAY-REFUND-001 | Refunds are authorized by role, bounded by the captured amount, not repeatable, and audited | S | High | API5 | CWE-285 |
| PAY-SUB-001 | Plans, entitlements and premium flags derive from provider state (webhooks/API), never from client input | S | High | A04 | CWE-602 |
| PAY-KEY-001 | Secret/restricted keys stay server-side, are least-privilege (restricted keys), separated by environment, and never in bundles or the repo | S | Critical | A07 | CWE-798 |
| PAY-PCI-001 | Raw card data (PAN, CVV, PIN) never touches application servers, logs or databases; hosted fields/Checkout/Elements are used; CVV is never stored | S | Critical | A02 | CWE-311 |
| PAY-FRAUD-001 | Card-testing and fraud defenses: rate limits on payment attempts, CAPTCHA/step-up, provider fraud tools (e.g. Radar), velocity rules | S | Medium | API6 | CWE-799 |
| PAY-PAYOUT-001 | Payouts, withdrawals and transfers require strong authentication (step-up), protect payout-destination changes (cooldown, notification) and enforce limits | S | High | A07 | CWE-306 |
| PAY-LOG-001 | Payment events are logged (IDs, outcomes, correlation) without card data or secrets; alerts fire on paid-without-confirmation and callback floods | S | Medium | A09 | CWE-532 |
