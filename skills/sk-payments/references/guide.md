# Payment flow guide

Sources: OWASP Third-Party Payment Gateway Integration and Transaction Authorization cheat sheets; PCI DSS scope
basics. Provider-neutral (Stripe, PayPal, Adyen, Braintree, Square, Razorpay, Mollie, Paddle…).

**Rule of thumb: the browser is never the source of truth for money.** Amounts come from your database; payment
status comes from the provider (verified webhook or API call); card data goes straight from the browser to the provider.

## Correct flow

```
checkout(cart_ids, quantities):            # client sends IDs only
    total = Σ catalog_price(id) × qty − validated_discounts + tax + shipping      # server-side
    order = create(status="pending", total, currency, idempotency_key)
    session = provider.create(amount=order.total, currency, metadata={order_id}, idempotency_key=order.id)
    redirect user to provider (hosted page / Elements — card data never hits your server)

return_url (success page):                 # informational only
    show "processing"; optionally retrieve session server-side; NEVER fulfil from query params

webhook:                                    # the source of truth
    event = provider.verify(raw_body, signature, secret)               # reject if invalid
    if seen(event.id): return 200                                      # dedupe
    order = find(event.metadata.order_id)
    require event.amount == order.total and event.currency == order.currency and event.account == ours
    transition order pending → paid (atomically, only from pending) ; then fulfil once
```

## Other flows

- **Refunds** (PAY-REFUND): role-checked; amount ≤ captured − already refunded; idempotency key; audit log;
  restore stock/entitlements consistently.
- **Subscriptions** (PAY-SUB): entitlements updated from subscription webhooks (created/updated/deleted, payment
  failed), never from client requests; handle downgrades, cancellations and failed renewals.
- **Payouts/withdrawals** (PAY-PAYOUT): step-up authentication; payout destination changes require re-auth, a cooldown
  and notification; daily limits; manual review above thresholds.
- **Reconciliation** (PAY-STATE): periodic job comparing orders with provider records; alert on "paid without
  confirmation", late webhooks after expiry, disputes.

## Keys and card data (PAY-KEY, PAY-PCI)

Secret/restricted keys only on the server, from a secret manager, separate test/live, least-privilege restricted keys
where the provider supports them. Publishable keys are fine in the client. Never collect PAN/CVV in your own form
fields or APIs; never log or store them (CVV must never be stored at all).

## Fraud and monitoring (PAY-FRAUD, PAY-LOG)

Rate-limit payment attempts per user/IP/card fingerprint, add CAPTCHA/step-up on anomalies, enable provider fraud
tools. Log IDs and outcomes (event ID, order ID, status), not payloads, card data or secrets. Alert on
callback floods, repeated failures, and orders paid without a matching provider record.
