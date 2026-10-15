# Webhook security guide: how to verify and fix each concept

Language- and provider-neutral. A webhook is just an HTTP request that is **not** from your own users, so
none of your normal authentication applies. Every receiver needs its own proof of origin, and every sender
is an outbound HTTP client pointed at a URL someone else chose.

---

## Inbound: proving the request is genuine (WH-SIG-*)

**The correct shape, in any language:**

```
raw = read the request body as raw bytes            # before any JSON parsing
sig = header "<provider>-signature"                  # also parse timestamp / version from it
if secret is missing: fail (500), never skip
expected = HMAC_SHA256(secret, timestamp + "." + raw)  # exact construction is provider-specific
if not constant_time_equal(expected, sig): return 401   # stop here, do nothing else
if abs(now - timestamp) > 300s: return 401
if already_processed(event_id): return 200            # acknowledge, do not re-apply
enqueue(event); return 200
```

If the provider ships an SDK verification function, using it is the best option: it already handles raw
bytes, constant-time comparison and timestamp tolerance. Check that its tolerance has not been disabled.

**Verify.**
- Find each receiver route (paths like `/webhook`, `/hooks/...`, `/callback`, `/ipn`, `/events`).
- Follow the handler: is there an HMAC/signature or SDK verify call **before** any database write,
  email, or state change? Middleware applied to the route counts. A comment saying "TODO verify" does not.
- Raw bytes: is the body read raw for this route (raw body parser, `get_data()`, reading the stream)? If the
  code parses JSON then re-serializes it to compute the HMAC, key order and whitespace differ, so either
  verification always fails (and someone disables it) or it is bypassable.
- Comparison: `==`, `===`, `.equals()` on signatures are timing-unsafe. Look for the language's
  constant-time compare (`timingSafeEqual`, `hmac.compare_digest`, `MessageDigest.isEqual`,
  `subtle.ConstantTimeCompare`, `hash_equals`, `FixedTimeEquals`, `secure_compare`).
- Fail closed: look for `if (secret) { verify }`, `try { verify } catch { log }` followed by processing,
  or a feature flag that turns verification off.
- Scheme: if the header carries a version (`v1=`, `sha256=`), the receiver must require the strong one.
- Secrets: env/secret manager, one per sender; support two during rotation.

**Fix.** Implement the shape above. Scope the raw-body parser and any CSRF exemption to the webhook route.

## Replay and duplicates (WH-REPLAY-*, WH-IDEM-*)

Providers retry, so duplicates are normal. Attackers who capture one request can replay it.

**Verify.** Is a timestamp part of the signed string, and checked? Is the event/delivery ID stored (unique
index, cache with TTL ≥ tolerance) and checked before applying side effects? Do state changes look at the
current object state (e.g. "only move to `paid` from `pending`") instead of trusting arrival order?

**Fix.** Signed timestamp with a ~5 minute window; processed-events table with a unique constraint on the
event ID, inserted in the same transaction as the side effect; state-machine guards.

## Processing (WH-PROC-*)

- High-value events (payment succeeded, subscription upgraded): fetch the object from the provider API by
  ID and act on that, not on payload amounts/status.
- Validate the payload against a schema; set a body-size limit on the route.
- Return 2xx fast and do the work in a queue; slow handlers cause retries and duplicate processing.
- Return generic errors.

## Outbound: SSRF in webhook delivery (WH-OUT-001/002/006)

Letting users register a URL that your server calls is SSRF by design. A single string check is not enough.

**The correct shape:**

```
url = parse(user_url); require scheme == "https"; reject credentials in URL
ips = resolve(url.host)                       # all A/AAAA records
reject if any ip is loopback, private (10/8, 172.16/12, 192.168/16, fc00::/7), link-local
       (169.254/16 incl. 169.254.169.254, fe80::/10), unspecified, multicast, or carrier-grade NAT
connect to the checked ip (pin it), send Host / SNI = url.host       # prevents DNS rebinding
do not follow redirects (or re-run all checks for every hop)
timeouts (connect + total), max response size, never show the response body to the user
```

Validate at registration **and** at delivery time (DNS can change). Bypass inputs to test against your
validator: `http://127.0.0.1`, `http://localhost`, `http://[::1]`, `http://0.0.0.0`, `http://2130706433`,
`http://0x7f000001`, `http://127.1`, `http://169.254.169.254/latest/meta-data/`, `http://[::ffff:127.0.0.1]`,
a public hostname that resolves to 127.0.0.1, and a public URL that redirects to an internal one.

## Outbound: signing and secrets (WH-OUT-003/004/009)

Sign each delivery with a per-subscriber secret over `timestamp + "." + body`, and include an event ID so
receivers can dedupe. Generate secrets with a CSPRNG, show them once, allow rotation, and store them
encrypted. Keep TLS verification on.

## Outbound: reliability and data (WH-OUT-005/007/008)

Timeouts, bounded retries with exponential backoff, auto-disable after repeated failures. Build payloads
from the subscriber's own tenant data only. Never include secrets or other tenants' data. Optionally verify
URL ownership with a challenge request before activation.

## Test ideas (WH-TEST-*)

- No signature → 401; wrong signature → 401; correct signature, body changed by one byte → 401.
- Correct signature, timestamp 10 minutes old → 401.
- Same valid delivery twice → side effect happens once.
- Register `http://169.254.169.254/` / `http://127.0.0.1:6379` / a redirect to an internal URL → rejected.
