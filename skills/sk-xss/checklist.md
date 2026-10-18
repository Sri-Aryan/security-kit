# Cross-site scripting checklist

Source of truth for `sk-xss` check IDs. Covers reflected, stored and DOM-based XSS in server-rendered pages,
SPAs (React, Vue, Angular, Svelte), templates (Jinja, Django, ERB, Blade, Thymeleaf, Razor, EJS, Handlebars…),
and browser-side JavaScript, plus Content Security Policy. Based on the OWASP Cross Site Scripting Prevention,
DOM based XSS Prevention, Content Security Policy and HTML5 Security cheat sheets. `references/guide.md` maps each
output context to its encoder.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021 (A03).

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| XSS-SINK-001 | Untrusted data never reaches raw DOM HTML sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html()`/`$(html)`) unsanitized | S+D | High | A03 | CWE-79 |
| XSS-SINK-002 | Framework auto-escaping is not bypassed for untrusted data (`dangerouslySetInnerHTML`, `v-html`, `{@html}`, `[innerHTML]`, `bypassSecurityTrust*`, `|safe`, `mark_safe`, `Markup`, `html_safe`/`raw`, `<%- %>`, `{{{ }}}`, `{!! !!}`, `@Html.Raw`, `th:utext`) | S+D | High | A03 | CWE-79 |
| XSS-TPL-001 | Template engines have auto-escaping enabled (not globally disabled) | S | High | A03 | CWE-79 |
| XSS-DOM-001 | DOM sources (`location.*`, `document.referrer`, `window.name`, `postMessage` data, storage) do not flow into sinks unsanitized | S+D | High | A03 | CWE-79 |
| XSS-URL-001 | User-supplied URLs in `href`/`src`/`action`/`formaction` are validated (http/https only; no `javascript:`/`data:`) | S+D | High | A03 | CWE-83 |
| XSS-JS-001 | Data embedded in `<script>` blocks, inline event handlers or JS strings is safely serialized/encoded (no raw interpolation; `</script>` safe) | S+D | High | A03 | CWE-79 |
| XSS-EVAL-001 | Strings from data are never executed (`eval`, `new Function`, `setTimeout`/`setInterval` with strings) | S | High | A03 | CWE-95 |
| XSS-SANITIZE-001 | HTML that must be allowed is sanitized with a maintained library (DOMPurify, sanitize-html, nh3, OWASP Java HTML Sanitizer, HtmlSanitizer) with a safe configuration; no regex sanitizers | S | High | A03 | CWE-79 |
| XSS-MD-001 | Markdown/rich-text rendering sanitizes output and disables raw HTML/unsafe links | S | Medium | A03 | CWE-79 |
| XSS-POSTMSG-001 | `message` listeners check `event.origin`; `postMessage` does not target `*` with sensitive data | S | Medium | A03 | CWE-345 |
| XSS-RESP-001 | Endpoints that echo input respond with a non-HTML content type and `nosniff` (JSON APIs, JSONP callbacks validated) | S+D | Medium | A03 | CWE-79 |
| XSS-UPLOAD-001 | User-uploaded HTML/SVG/XML is not served inline from the application origin | S | Medium | A03 | CWE-79 |
| XSS-CSP-001 | A Content Security Policy is set and strong: nonce/hash-based `script-src` without `'unsafe-inline'`/`'unsafe-eval'`, `object-src 'none'`, `base-uri 'none'` (or `'self'`), `frame-ancestors` | S+D | Medium | A05 | CWE-693 |
| XSS-COOKIE-001 | Session cookies are `HttpOnly` (limits XSS impact) | S | Low | A05 | CWE-1004 |
| XSS-TEST-001 | Tests render payloads in each confirmed context and assert they are inert | S | Low | A03 | CWE-1125 |
