# SAML SSO guide

Sources: OWASP SAML Security cheat sheet; OASIS SAML 2.0 profiles; published signature-wrapping and canonicalization
research.

SAML login is a signed XML document that says "this is user X". Every serious SAML bug is a way to make the SP accept
a document the IdP didn't sign for this SP, now, for this request. So: **verify the signature with a trusted key, use
only what was verified, and check it was meant for you, now, once.**

## Signature (SAML-SIG-001, SAML-WRAP-001, SAML-CERT-001)

- Use a maintained library; never verify signatures or extract identity by hand.
- Require signed assertions (and ideally signed responses): `wantAssertionsSigned`, `strict: true` (python3-saml),
  `want_assertions_signed`, Spring `assertingparty` verification credentials.
- The IdP certificate comes from configured metadata (fetched over HTTPS and pinned, or pasted per tenant), never from
  `KeyInfo` in the message.
- Read the NameID/attributes from the library's validated result. Hand XPath (`//NameID`) can pick an unsigned element
  injected next to the signed one (XML signature wrapping). Reject responses with more than one assertion.
- Reject SHA-1 (`rsa-sha1`, `sha1` digests).

## Conditions and replay (SAML-COND-001, SAML-REPLAY-001)

Audience = your SP entity ID; Destination/Recipient = your ACS URL; NotBefore/NotOnOrAfter with ≤ a few minutes of
skew; InResponseTo matches a request you sent (store request IDs; node-saml `validateInResponseTo: 'always'` with a
`cacheProvider`); remember assertion IDs until they expire and reject repeats. If IdP-initiated SSO is enabled, that's
a conscious decision with replay caching.

## Parser and libraries (SAML-XML-001, SAML-LIB-001)

DTDs/external entities off (defusedxml, `disallow-doctype-decl`, `DtdProcessing.Prohibit`). Keep SAML and xml-crypto/
xmlsec libraries current: ruby-saml, xml-crypto, passport-saml/node-saml, python3-saml, samlify and others have shipped
fixes for signature bypasses and comment-truncation canonicalization bugs.

## After login (SAML-RELAY-001, SAML-LINK-001, SAML-LOGOUT-001)

Validate RelayState like any redirect (relative paths or allow-listed hosts). Key users by (IdP entity ID, NameID) or a
stable immutable attribute; in multi-tenant apps, scope lookups to the tenant whose IdP signed the assertion; link to
existing accounts by email only for domains verified for that tenant. Validate signed SLO messages and end local sessions.
