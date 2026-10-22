# Abuse and fraud checklist

Source of truth for `sk-abuse` check IDs. Covers the abuse that hits products with open sign-up and free value: bot
sign-ups, CAPTCHA that is never verified, disposable emails, trial and credit farming, free-tier cost abuse (AI, email,
compute), referral self-dealing, paywalls enforced only in the UI, scraping of premium content, user-generated spam and
naive bot detection. Pairs with `/sk-ratelimit` (request limits), `/sk-business` (logic flaws) and `/sk-email`
(messaging abuse). Based on the OWASP Automated Threats to Web Applications (OAT) handbook and the OWASP cheat sheets.
`references/guide.md` explains each check.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| ABUSE-SIGNUP-001 | Sign-up is protected against automation (CAPTCHA/Turnstile, provider bot detection, attestation) when accounts get anything of value | S+D | Medium | A04 | CWE-799 |
| ABUSE-CAPTCHA-001 | CAPTCHA tokens are verified on the server (siteverify) with expected hostname/action and a sane score threshold | S+D | High | A04 | CWE-602 |
| ABUSE-EMAIL-001 | Eligibility is keyed on a normalised email; disposable domains are blocked or limited where sign-up grants value | S | Medium | A04 | CWE-840 |
| ABUSE-TRIAL-001 | Trials and free credits are granted once per person (after verification, keyed on something hard to rotate), not once per account | S | Medium | A04 | CWE-840 |
| ABUSE-FREE-001 | Costly free-tier and anonymous features (AI, email/SMS, exports, compute, storage) have server-side quotas per account and per IP/device | S+D | High | A04 | CWE-770 |
| ABUSE-PAYWALL-001 | Paid features and premium data are enforced on the server; free users never receive premium data that the UI merely hides | S+D | High | A01 | CWE-602 |
| ABUSE-MULTI-001 | Referral and invite rewards require a qualifying event (verified, paying or active referee), block self-referral, and pay once per device/payment method | S | Medium | A04 | CWE-840 |
| ABUSE-SCRAPE-001 | Bulk data and premium content are not trivially scrapable: no unauthenticated list endpoints with large pages, no sequential public IDs for private content | S+D | Medium | A01 | CWE-200 |
| ABUSE-UGC-001 | User-generated public content is protected against spam and phishing: `rel="nofollow ugc"` links, limits for new accounts, reporting and moderation | S | Low | A04 | CWE-799 |
| ABUSE-BOT-001 | Bot handling on high-value endpoints doesn't rely on the User-Agent or other client-controlled hints | S | Low | A04 | CWE-807 |
| ABUSE-MONITOR-001 | Abuse signals (sign-ups per hour, trial starts, AI spend, messages sent) are logged and alert on spikes | S | Low | A09 | CWE-778 |
