# Desktop app (Electron / Tauri) guide

Sources: Electron security checklist (electronjs.org/docs/latest/tutorial/security), Tauri security and capabilities
docs, OWASP Node.js and HTML5 Security cheat sheets.

In a browser, XSS steals a session. In a desktop app it can run programs on the user's machine. Treat the renderer as
a browser tab that may be compromised, and keep the bridge to the operating system **narrow and validated**.

## Electron baseline

```js
new BrowserWindow({
  webPreferences: {
    preload: path.join(__dirname, 'preload.js'),
    contextIsolation: true,      // DESK-ISO-001 (default since 12)
    sandbox: true,               // DESK-ISO-001 (default since 20)
    nodeIntegration: false,      // DESK-NODE-001 (default)
    webSecurity: true,
  },
});
win.webContents.on('will-navigate', (e, url) => { if (!isAppUrl(url)) e.preventDefault(); });      // DESK-NAV-001
win.webContents.setWindowOpenHandler(({ url }) => { openIfSafe(url); return { action: 'deny' }; });
```

- **Preload (DESK-PRELOAD-001)**: one function per action with a fixed channel:
  `contextBridge.exposeInMainWorld('api', { saveNote: (t) => ipcRenderer.invoke('note:save', String(t)) })`.
  Never expose `ipcRenderer`, `require`, `shell`, or `invoke(channel, ...args)`.
- **IPC (DESK-IPC-001)**: in every handler, check `event.senderFrame.url` is your app's origin, validate arguments
  (types, allow-lists, paths contained in an app directory), and never offer "run command" / "read any file" channels.
- **Content (DESK-NAV-001)**: load local files (`loadFile`) or a custom `app://` protocol; if remote content is needed,
  put it in a window without a preload; disable `<webview>` or validate in `will-attach-webview`.
- **openExternal (DESK-SHELL-001)**: `const u = new URL(url); if (['https:', 'mailto:'].includes(u.protocol)) shell.openExternal(u.href)`.
- **Protocols (DESK-PROTOCOL-001)**: resolve against a root and reject paths that escape it.
- **CSP (DESK-CSP-001)**: `default-src 'self'; script-src 'self'; object-src 'none'` via meta tag or `session.webRequest.onHeadersReceived`.
- **Updates (DESK-UPDATE-001)**: electron-updater/Squirrel over HTTPS, publisher signature verification on, signed and
  notarized builds.
- **Fuses (DESK-FUSES-001)**: `@electron/fuses`: `RunAsNode: false`, `EnableNodeCliInspectArguments: false`,
  `EnableNodeOptionsEnvironmentVariable: false`, `EnableEmbeddedAsarIntegrityValidation: true`, `OnlyLoadAppFromAsar: true`.
- Keep Electron on a supported major version (security fixes ship only for the latest three).

## Tauri (DESK-TAURI-001)

Tauri v2 grants nothing by default; each capability file lists permissions per window. Keep them specific
(`fs:allow-read-text-file` with a scope like `$APPDATA/notes/*`, not `fs:default` with `**`), avoid
`shell:allow-execute`/`allow-spawn` unless commands are fixed with validated args, scope `http` to known URLs, keep the
`csp` set in `tauri.conf.json`, and don't enable `dangerousRemoteDomainIpcAccess`. In Tauri v1, the `allowlist` should
not use `"all": true`. Rust commands (`#[tauri::command]`) validate their inputs like IPC handlers.
