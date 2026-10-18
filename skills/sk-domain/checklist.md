# Domain, DNS and email-authentication checklist

Source of truth for `sk-domain` check IDs. Covers the security of an organization's domains as far as the repository
defines or touches them (DNS records in Terraform/OpenTofu, Pulumi, CloudFormation, zone files, Cloudflare/Route 53/
Azure/Google DNS configs) plus what the user can tell: subdomain takeover through dangling records, wildcard records,
SPF, DKIM and DMARC, CAA, certificate automation, `security.txt`, cookies scoped to the parent domain, DNSSEC and
registrar protection. Based on the OWASP Vulnerability Disclosure and Email Validation cheat sheets, OWASP WSTG
(subdomain takeover) and RFC 7208/6376/7489/8659/9116. `references/guide.md` explains each check.

Columns: **Mode** S = static (repo), M = manual (ask the user / check records they share). OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DOMAIN-TAKEOVER-001 | DNS records pointing at third-party services (cloud storage websites, PaaS apps, CDNs, docs/helpdesk hosts) are removed when the service is deprovisioned; wildcard records are avoided | S+M | High | A05 | CWE-350 |
| DOMAIN-SPF-001 | Sending domains publish SPF ending in `-all` or `~all` (never `+all`/`?all`), within the 10-lookup limit; non-sending domains publish `v=spf1 -all` | S+M | Medium | A05 | CWE-290 |
| DOMAIN-DMARC-001 | DMARC is published with `p=quarantine` or `p=reject` (after monitoring) and a reporting address | S+M | Medium | A05 | CWE-290 |
| DOMAIN-DKIM-001 | Outbound mail is DKIM-signed with 2048-bit keys that are rotated | S+M | Low | A02 | CWE-326 |
| DOMAIN-CAA-001 | CAA records restrict which certificate authorities may issue for the domain | S+M | Low | A05 | CWE-295 |
| DOMAIN-TLS-001 | Certificates are issued and renewed automatically and expiry is monitored; wildcard certificates and their keys aren't spread across many systems | M | Medium | A02 | CWE-298 |
| DOMAIN-SECTXT-001 | `/.well-known/security.txt` is published with `Contact` and an unexpired `Expires` (and a vulnerability disclosure policy) | S+M | Low | A09 | CWE-1059 |
| DOMAIN-COOKIE-001 | Session cookies aren't scoped to the parent domain (`Domain=.example.com`) unless every subdomain is equally trusted | S | Medium | A05 | CWE-1275 |
| DOMAIN-REG-001 | Domains have registrar lock, auto-renew, MFA on the registrar/DNS accounts, and optionally DNSSEC | M | Medium | A05 | CWE-284 |
