# Browser extension checklist

Source of truth for `sk-extension` check IDs. Covers browser extensions (Chrome/Edge/Brave Manifest V3 and V2,
Firefox WebExtensions, Safari web extensions; plain or built with WXT, Plasmo, CRXJS): permissions and host access,
extension CSP and remotely hosted code, message passing between pages, content scripts and the background, content
script DOM handling, web-accessible resources, storage of tokens, network endpoints, update URLs and OAuth. Based on
the Chrome extension security guidance, Mozilla's add-on policies and the OWASP HTML5 Security cheat sheet.
`references/guide.md` explains each check.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| EXT-PERM-001 | Permissions and host permissions are the minimum needed: no `<all_urls>`/`*://*/*` when specific hosts suffice, sensitive permissions (`cookies`, `webRequest`, `debugger`, `nativeMessaging`, `management`, `history`, `tabs`, `scripting`) only with a clear need; optional permissions requested at use time | S | High | A01 | CWE-250 |
| EXT-REMOTE-001 | No remotely hosted or dynamically evaluated code: no `eval`/`new Function`/string timers, no remote `<script>` in extension pages, no executing fetched code | S | Critical | A08 | CWE-829 |
| EXT-CSP-001 | The extension CSP is not weakened (`unsafe-eval`, remote script sources, `unsafe-inline` in MV2) | S | High | A05 | CWE-693 |
| EXT-MSG-001 | Message handlers validate the sender: `onMessageExternal` and `externally_connectable` limited to specific origins/IDs; content scripts check `event.origin`/`source` for `window.postMessage`; messages never trigger privileged actions without validation | S | High | A01 | CWE-346 |
| EXT-CONTENT-001 | Content scripts treat page data as untrusted (no `innerHTML` with page content) and never expose extension APIs or secrets to the page | S | High | A03 | CWE-79 |
| EXT-WAR-001 | `web_accessible_resources` lists only what pages must load, with narrow `matches` (and `use_dynamic_url` where possible) | S | Low | A05 | CWE-200 |
| EXT-STORAGE-001 | Tokens and secrets aren't kept in `storage.sync` or page-visible storage; client secrets aren't shipped in the extension | S | Medium | A07 | CWE-922 |
| EXT-NET-001 | The extension talks to its backend over HTTPS only and doesn't send browsing data or page content beyond what its purpose needs | S | Medium | A02 | CWE-319 |
| EXT-UPDATE-001 | Updates come from the store or an HTTPS `update_url` the developer controls | S | Medium | A08 | CWE-494 |
