# Browser extension guide

Sources: Chrome extension docs (security, Manifest V3, permissions, messaging), Mozilla add-on policies, OWASP HTML5
Security cheat sheet.

An extension runs with powers no website has: read every page, every cookie, every request. Users trust its
permissions; attackers want to borrow them. Keep permissions **narrow**, code **local**, and treat **pages and other
extensions as untrusted** callers.

## Permissions (EXT-PERM-001)

Prefer `activeTab` (temporary access to the tab the user clicked on) over host permissions; specific hosts over
`<all_urls>`; `optional_permissions` / `optional_host_permissions` requested via `permissions.request()` when a feature
is used. Justify each sensitive permission (`cookies`, `webRequest`, `debugger`, `nativeMessaging`, `management`,
`history`, `tabs`, `scripting`, `downloads`).

## Code (EXT-REMOTE-001, EXT-CSP-001)

All code ships in the package. No `eval`, `new Function`, string timers, remote `<script>` tags, `importScripts` from
URLs, or "fetch config then execute". Don't loosen `content_security_policy` (`unsafe-eval`, remote origins). Remote
*data* is fine; validate it.

## Messaging (EXT-MSG-001, EXT-CONTENT-001)

- `externally_connectable.matches` lists exact origins; `ids` lists exact extension IDs.
- `onMessageExternal`/`onConnectExternal`: check `sender.origin`/`sender.id` first; validate message shape; map
  message types to allowed actions.
- Content scripts receiving `window.postMessage`: check `event.source === window` and `event.origin`, and never relay
  arbitrary commands to the background.
- Content scripts and extension pages render page data with `textContent`/DOM APIs, never `innerHTML`; never put
  tokens or extension-only data where page scripts can read them (DOM, `window` properties, page localStorage).

## Resources, storage, network, updates (EXT-WAR-001, EXT-STORAGE-001, EXT-NET-001, EXT-UPDATE-001)

- `web_accessible_resources`: only files pages must load, narrow `matches`, `use_dynamic_url: true` where possible.
- Tokens in `storage.session` (memory, MV3) or `storage.local`, never `storage.sync`; no OAuth client secrets in the
  package (use `chrome.identity` with PKCE and a backend for confidential exchanges).
- HTTPS for every backend call; send the minimum page data needed and disclose it.
- Store-hosted updates, or an HTTPS `update_url` you control.
