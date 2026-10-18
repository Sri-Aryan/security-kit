# XSS guide: contexts, encoders and CSP

Sources: OWASP Cross Site Scripting Prevention, DOM based XSS Prevention, Content Security Policy and HTML5 Security
cheat sheets.

**XSS = untrusted data interpreted as HTML/JS by the browser.** The defence is context-aware output encoding, which
modern frameworks do automatically, so most XSS today comes from **bypassing** the framework, from **DOM sinks** in
client code, and from **URL/JS contexts** that HTML escaping does not cover.

## Output contexts

| Context | Example | Safe approach |
|---|---|---|
| HTML body | `<p>{{ name }}</p>` | framework auto-escaping (default in React, Vue, Angular, Svelte, Jinja (Flask), Django, Razor, ERB, Blade, Thymeleaf `th:text`) |
| HTML attribute (quoted) | `<input value="{{ v }}">` | auto-escaping; always quote attributes |
| URL (`href`, `src`) | `<a href={url}>` | parse; allow only `http:`/`https:` (and relative); then attribute-encode |
| JavaScript | `<script>var x = …</script>` | don't interpolate; pass data via `json_script`/`tojson`/`serialize-javascript` or `data-*` attributes |
| CSS | `style="color: {{ c }}"` | allow-list values |
| Raw HTML that must render | user rich text, Markdown | sanitize with DOMPurify / sanitize-html / nh3 / OWASP Java HTML Sanitizer / HtmlSanitizer |

## Dangerous APIs (XSS-SINK, XSS-DOM, XSS-EVAL)

DOM: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html()` / `$(html)`, `eval`,
`new Function`, string `setTimeout`/`setInterval`, `location = …` (for `javascript:`). Use `textContent`,
`setAttribute` with validated values, and DOM APIs.

Framework bypasses: `dangerouslySetInnerHTML`, `v-html`, `{@html}`, `[innerHTML]`/`bypassSecurityTrust*`, `|safe`,
`mark_safe`, `Markup`, `html_safe`/`raw`/`<%==`, `<%-`, `{{{ }}}`, `{!! !!}`, `@Html.Raw`, `th:utext`. Each use needs
either developer-authored content or a sanitizer.

DOM sources: `location.*`, `document.referrer`, `window.name`, `postMessage` data (check `event.origin`), storage,
router query parameters.

## Content Security Policy (XSS-CSP-001)

A strong CSP limits damage when encoding fails:
```
Content-Security-Policy: script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none';
                         frame-ancestors 'none'; form-action 'self'
```
Avoid `'unsafe-inline'`, `'unsafe-eval'`, `*`, `https:` and `data:` in `script-src`. Roll out with
`Content-Security-Policy-Report-Only` first. Consider Trusted Types for large SPAs.

## Related

Session cookies `HttpOnly`; uploads served from a separate origin or as attachments; JSON APIs with
`application/json` + `nosniff`; validated JSONP callback names (or no JSONP).
