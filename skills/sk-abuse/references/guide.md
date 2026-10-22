# Abuse and fraud guide

Sources: OWASP Automated Threats to Web Applications (OAT-019 Account Creation, OAT-011 Scraping, OAT-017 Spamming,
OAT-020 Account Aggregation, OAT-021 Denial of Inventory), Cloudflare Turnstile / Google reCAPTCHA / hCaptcha server
verification docs, Stripe trial and fraud guidance; OWASP cheat sheets.

Abuse is not a single bug: it is what happens when something valuable (free credits, AI calls, a trial, a referral
bonus, a public profile page) can be obtained more times, or more cheaply, than intended. Start by listing **what a new
account gets** and **what an anonymous visitor can trigger**, then check each item's controls.

## Inventory first

For each valuable action (sign-up, trial start, free credits, AI/LLM call, email/SMS send, export, file processing,
public page/link creation, referral reward), record: who can do it (anonymous / new / verified / paying), what it costs
you, and the server-side controls (verification, quota, rate limit, CAPTCHA, fingerprint).

## Checks

| Check | Confirm | Good practice |
|---|---|---|
| ABUSE-SIGNUP-001 | What stops a script creating 10,000 accounts? | Turnstile/hCaptcha/reCAPTCHA on sign-up (or the auth provider's bot protection), rate limit per IP/ASN, email verification before value is granted. |
| ABUSE-CAPTCHA-001 | Is the token sent to the server and checked with `siteverify`? | Verify server-side every time; check `success`, `hostname` and `action`; reject reused tokens; reCAPTCHA v3 threshold ~0.5, tuned with data. |
| ABUSE-EMAIL-001 | Can one inbox claim many trials (`a.b+1@gmail.com`)? | Normalise (lower-case; strip `+tag`; Gmail dots) for eligibility; block or limit disposable domains when sign-up grants value. |
| ABUSE-TRIAL-001 | Delete account → sign up again → new trial? | Track trial use by normalised email, payment fingerprint (Stripe `card.fingerprint`), verified phone or device; require a payment method for high-value trials. |
| ABUSE-FREE-001 | What is the worst-case bill from one free account? From anonymous traffic? | Server-side quotas per user and per IP/device for AI, email/SMS, exports; hard caps on anonymous use; provider spend limits. |
| ABUSE-PAYWALL-001 | Does a free account's API response or page payload contain the premium content? | Filter on the server by plan; never send then hide. |
| ABUSE-MULTI-001 | Can I refer myself? Is the reward paid at sign-up? | Reward after the referee pays or is active for N days; once per payment method/device; block same-IP/same-card pairs. |
| ABUSE-SCRAPE-001 | Can an unauthenticated client list everything (`?limit=10000`, sequential IDs)? | Auth for bulk endpoints, max page sizes (see `/sk-dos`), random IDs, per-account rate limits. |
| ABUSE-UGC-001 | Do new accounts get public, indexed pages with followed links? | `rel="nofollow ugc noopener"`, `noindex` for new/unverified profiles, delay links, report button, moderation queue. |
| ABUSE-BOT-001 | Is "bot detection" a User-Agent check? | Treat UA as a hint only; use rate limits, Turnstile, WAF/bot management. |
| ABUSE-MONITOR-001 | Would you notice 5,000 sign-ups in an hour, or AI spend tripling? | Metrics and alerts on sign-ups, trials, credits consumed, messages sent, provider spend. |

## Severity guidance

Raise severity with the money at stake: unlimited anonymous AI calls or SMS sends are **High** (direct cost, possible
account suspension by the provider); free-tier farming of a cheap feature is **Low–Medium**.

## Related skills

`/sk-ratelimit` (limits and keys), `/sk-business` (logic flaws, coupons), `/sk-email` (SMS pumping, open relays),
`/sk-payments` (payment flows), `/sk-baas` (anonymous users in RLS).
