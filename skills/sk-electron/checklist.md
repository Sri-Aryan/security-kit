# Desktop app (Electron / Tauri) security checklist

Source of truth for `sk-electron` check IDs. Covers desktop apps built on web technology: Electron (and frameworks
on top of it) and Tauri. In these apps an XSS can become code execution on the user's machine, so the checks focus
on the bridge between web content and the operating system: Node integration, context isolation and sandboxing,
preload APIs, IPC handlers, remote content and navigation, `shell.openExternal`, custom protocols, CSP, auto-update
and code signing, Electron fuses, and Tauri capabilities. Based on the Electron security checklist, the Tauri
security docs and the OWASP Node.js/HTML5 cheat sheets. `references/guide.md` explains each check.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DESK-NODE-001 | `nodeIntegration` (and `nodeIntegrationInSubFrames`/`InWorker`) is off for every window and webview | S | Critical | A04 | CWE-749 |
| DESK-ISO-001 | `contextIsolation` and `sandbox` are on for every window; `webSecurity` is never disabled; `allowRunningInsecureContent` is off | S | Critical | A04 | CWE-693 |
| DESK-PRELOAD-001 | Preload scripts expose a minimal, specific API via `contextBridge` (no raw `ipcRenderer`, `require`, `shell`, `fs` or generic invoke) | S | High | A04 | CWE-749 |
| DESK-IPC-001 | IPC handlers validate the sender (`event.senderFrame`) and their arguments; no generic exec/read/write-file channels | S | High | A01 | CWE-20 |
| DESK-NAV-001 | Windows load only local or trusted content; navigation (`will-navigate`) and new windows (`setWindowOpenHandler`) are restricted; `<webview>` is off or locked down | S | High | A04 | CWE-601 |
| DESK-SHELL-001 | `shell.openExternal`/`open`/`openPath` receive only validated URLs (http/https/mailto allow-list) | S | High | A03 | CWE-78 |
| DESK-PROTOCOL-001 | Custom protocols and file handlers validate paths and inputs (no traversal, no arbitrary file reads) | S | Medium | A01 | CWE-22 |
| DESK-CSP-001 | Renderer pages have a strict Content Security Policy (no `unsafe-eval`, no remote scripts) | S | Medium | A05 | CWE-693 |
| DESK-UPDATE-001 | Auto-updates use HTTPS and signature verification; release builds are code-signed (and notarized on macOS) | S | High | A08 | CWE-494 |
| DESK-FUSES-001 | Electron fuses harden the binary: `RunAsNode` and Node CLI inspect off, ASAR integrity validation and `OnlyLoadAppFromAsar` on | S | Low | A05 | CWE-16 |
| DESK-TAURI-001 | Tauri capabilities/allowlist grant the minimum: scoped fs/shell/http permissions, no `**` scopes, no `shell.open` for all URLs, CSP set | S | High | A01 | CWE-250 |
