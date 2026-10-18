# Domain, DNS and email-authentication guide

Sources: OWASP WSTG (subdomain takeover), OWASP Vulnerability Disclosure cheat sheet, RFC 7208 (SPF), RFC 6376
(DKIM), RFC 7489 (DMARC), RFC 8659 (CAA), RFC 9116 (security.txt).

Your domain is the root of trust for your users: links, cookies, emails and certificates all depend on it. Most of
it lives in DNS and registrar dashboards, so this skill combines what IaC shows with questions to the user.

## Subdomain takeover (DOMAIN-TAKEOVER-001)

A `CNAME docs → acme-docs.herokuapp.com` (or an S3 website, Azure app, GitHub Pages site, CloudFront distribution,
Netlify/Vercel project, helpdesk/docs host) keeps resolving after the service is deleted. Whoever claims that name on
the provider then serves content on your subdomain: phishing, cookie theft (see DOMAIN-COOKIE-001), OAuth redirect
abuse. Fixes: remove DNS records in the same change that deletes the resource (manage both in IaC), inventory
third-party records regularly, avoid wildcard records, prefer provider verification (TXT ownership records) where offered.

## Email authentication (DOMAIN-SPF-001, DOMAIN-DMARC-001, DOMAIN-DKIM-001)

```
example.com.         TXT  "v=spf1 include:_spf.google.com include:mailgun.org -all"
_dmarc.example.com.  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s"
sel1._domainkey      TXT  "v=DKIM1; k=rsa; p=<2048-bit key>"
parked.example.      TXT  "v=spf1 -all"   + DMARC p=reject   (domains that never send mail)
```
Start DMARC at `p=none` with reports, fix legitimate senders, then move to `quarantine` and `reject`. Keep SPF under
10 DNS lookups. Rotate DKIM keys; use 2048-bit RSA.

## Certificates (DOMAIN-CAA-001, DOMAIN-TLS-001)

CAA: `0 issue "letsencrypt.org"` (plus your other CAs), `0 iodef "mailto:security@example.com"`. Automate issuance and
renewal (ACME, managed certificates) and monitor expiry and Certificate Transparency logs for unexpected certificates.
Limit wildcard certificates: one stolen key covers every subdomain.

## Disclosure (DOMAIN-SECTXT-001)

`/.well-known/security.txt`:
```
Contact: mailto:security@example.com
Expires: 2027-06-30T00:00:00.000Z
Policy: https://example.com/security-policy
Preferred-Languages: en
```

## Cookies and registrar (DOMAIN-COOKIE-001, DOMAIN-REG-001)

Host-only cookies (no `Domain` attribute, or the `__Host-` prefix) so subdomains can't read or overwrite sessions.
Registrar: transfer lock, auto-renew, MFA, a role account rather than one person's email, DNS-provider MFA and
audit logs; DNSSEC where the provider supports it.
