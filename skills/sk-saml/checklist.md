# SAML SSO checklist

Source of truth for `sk-saml` check IDs. Covers SAML 2.0 single sign-on where the application is the Service
Provider (SP), with any library (passport-saml/@node-saml, samlify, python3-saml/OneLogin, pysaml2, ruby-saml,
Spring Security SAML, ITfoxtec/Sustainsys, Shibboleth, SimpleSAMLphp) or a hand-rolled parser: signature
validation, signature wrapping, conditions (audience, recipient, time, InResponseTo), replay, XML parser hardening,
trusted certificates and algorithms, RelayState, account linking, logout and library versions. OAuth/OIDC:
`sk-oauth2`. Based on the OWASP SAML Security cheat sheet. `references/guide.md` explains each check.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| SAML-SIG-001 | Every response/assertion signature is validated by a maintained library; signature checks are never disabled; unsigned assertions are rejected | S | Critical | A07 | CWE-347 |
| SAML-WRAP-001 | The application reads identity only from the element the library verified (no own XPath/DOM lookups on the raw XML); responses with multiple assertions are rejected | S | Critical | A07 | CWE-347 |
| SAML-COND-001 | Conditions are enforced: Audience = this SP, Destination/Recipient = this ACS URL, NotBefore/NotOnOrAfter with small clock skew, InResponseTo matches an outstanding request (or IdP-initiated SSO is consciously allowed) | S | High | A07 | CWE-287 |
| SAML-REPLAY-001 | Assertion IDs are remembered until expiry so a captured response can't be replayed | S | Medium | A07 | CWE-294 |
| SAML-XML-001 | XML parsing of SAML messages forbids DTDs/external entities and the library is patched against canonicalization/comment tricks | S | High | A05 | CWE-611 |
| SAML-CERT-001 | The IdP signing certificate comes from trusted metadata configured in advance, never from the response's KeyInfo; SHA-1 signatures are rejected | S | Critical | A02 | CWE-295 |
| SAML-RELAY-001 | RelayState used for post-login redirects is validated (relative paths or allow-listed hosts) | S | Medium | A01 | CWE-601 |
| SAML-LINK-001 | Users are matched on a stable, IdP-scoped identifier; email-based linking only for verified, IdP-owned domains; one tenant's IdP can't log in users of another tenant | S | High | A07 | CWE-287 |
| SAML-LOGOUT-001 | Single logout requests/responses are signed and validated, and local sessions end on logout | S | Low | A07 | CWE-613 |
| SAML-LIB-001 | The SAML/XML-signature libraries are current (several had signature-bypass vulnerabilities) | S | High | A06 | CWE-1104 |
