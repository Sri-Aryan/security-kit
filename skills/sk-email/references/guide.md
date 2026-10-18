# Email and notification guide

Sources: OWASP Injection Prevention, Forgot Password, Authentication and Unvalidated Redirects cheat sheets.
Provider-neutral. Every message the application sends is output: treat recipients, headers, subject, body,
links and attachments like any other sink that user data can reach.

## Headers and sender (MAIL-HDR-001, MAIL-SPOOF-001)

- Use the library's structured fields (`to`, `subject`) and validate addresses; strip `\r` and `\n` from any
  user-influenced header value (CRLF injection adds `Bcc:` recipients or rewrites the body).
- `From` is always your domain. Put a user's address in `Reply-To` only after validation.
- Configure SPF, DKIM and DMARC (`p=quarantine` or `reject`) for every sending domain (DNS, outside the code; ask).

## Content (MAIL-HTML-001, MAIL-TPL-001, MAIL-TOKEN-001)

- Render email HTML with an auto-escaping template engine; never interpolate user text into raw HTML strings or use
  triple-stash / `|safe` / `<%-` / `{!! !!}` on user data. Injected links and forms in a trusted sender's email are
  phishing.
- Templates are files you ship; user input is data passed to them, never the template source.
- Never email passwords. Links carry single-use, short-lived tokens.

## Links (MAIL-LINK-001)

Build every link from a configured `APP_URL`. Using the request `Host`/`X-Forwarded-Host` lets an attacker trigger a
reset/invite email whose link points to their server and leaks the token.

## Enumeration and abuse (MAIL-ENUM-001, MAIL-RELAY-001, MAIL-RATE-001)

- Same response for registered and unregistered addresses ("If the address exists, we sent an email").
- Contact forms, invites and "share by email" are relay features: fixed templates, recipients validated, user text
  clearly quoted, per-user/per-recipient/per-IP limits, CAPTCHA for anonymous forms, logging.

## Attachments (MAIL-ATTACH-001)

Pass generated content as buffers. Many libraries read a `path` from disk or fetch an `href` URL, so a
user-controlled value means arbitrary file read or SSRF.

## Transport and SMS (MAIL-SMTP-001, MAIL-SMS-001)

TLS with certificate verification to SMTP/provider APIs; credentials from configuration. For SMS/voice: validate
numbers, allow-list destination countries (SMS pumping/toll fraud targets premium-rate ranges), rate-limit per
number, account and IP, and keep message templates fixed.
