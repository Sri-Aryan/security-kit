"""sk-electron rules: Electron window options, preload/IPC, navigation, shell, protocols, updates, fuses; Tauri config."""

SKILL = "sk-electron"

ELECTRON = r"\belectron\b|BrowserWindow|ipcMain|ipcRenderer|contextBridge"

RULES = [
    # ------------------------------------------------------------------ NODE / ISO
    {
        "id": "desk-node-integration-on", "check_id": "DESK-NODE-001", "title": "Node integration enabled in a renderer", "files": ["js", "web"],
        "pattern": r"nodeIntegration(InSubFrames|InWorker)?\s*:\s*true|nodeintegration(=\"true\"|\s*/?>|\s+\w)", "confidence": "HIGH",
        "note": "Any XSS or loaded page gets require('child_process'): remote code execution on the user's machine.",
        "examples": {"match": ["new BrowserWindow({ webPreferences: { nodeIntegration: true } });", "<webview src=\"https://x\" nodeintegration></webview>"],
                     "no_match": ["new BrowserWindow({ webPreferences: { nodeIntegration: false, contextIsolation: true } });"]},
    },
    {
        "id": "desk-isolation-off", "check_id": "DESK-ISO-001", "title": "Context isolation, sandbox or web security disabled", "files": ["js"],
        "pattern": r"contextIsolation\s*:\s*false|sandbox\s*:\s*false|webSecurity\s*:\s*false|allowRunningInsecureContent\s*:\s*true|experimentalFeatures\s*:\s*true|enableBlinkFeatures\s*:|app\.commandLine\.appendSwitch\(\s*['\"](disable-web-security|ignore-certificate-errors|no-sandbox)['\"]",
        "file_requires": ELECTRON, "confidence": "HIGH",
        "examples": {"match": ["new BrowserWindow({ webPreferences: { contextIsolation: false, preload } });","app.commandLine.appendSwitch('ignore-certificate-errors'); // electron"],
                     "no_match": ["webPreferences: { contextIsolation: true, sandbox: true, preload } // BrowserWindow"]},
    },
    # ------------------------------------------------------------------ PRELOAD
    {
        "id": "desk-preload-exposes-raw", "check_id": "DESK-PRELOAD-001", "title": "Preload exposes raw Electron/Node APIs to the page", "files": ["js"],
        "pattern": r"exposeInMainWorld\([^\n]*\b(ipcRenderer|require|shell|child_process|fs|process|remote)\b\s*[,)}]|exposeInMainWorld\([^\n]*\{\s*(ipcRenderer|invoke|send|on)\s*:\s*(ipcRenderer\.\w+|\(\s*channel|\(\s*\.\.\.args\))|window\.(ipcRenderer|require|electron)\s*=",
        "confidence": "HIGH", "note": "Expose one function per action, with fixed channel names, never ipcRenderer itself or a channel parameter.",
        "examples": {"match": ["contextBridge.exposeInMainWorld('electron', { ipcRenderer });", "contextBridge.exposeInMainWorld('api', { invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args) });"],
                     "no_match": ["contextBridge.exposeInMainWorld('api', { saveNote: (text) => ipcRenderer.invoke('note:save', String(text)) });"]},
    },
    # ------------------------------------------------------------------ IPC
    {
        "id": "desk-ipc-dangerous-handler", "check_id": "DESK-IPC-001", "title": "IPC handler passes renderer input to the OS (exec, files, shell)", "files": ["js"],
        "pattern": r"ipcMain\.(handle|on)\(\s*['\"`][^'\"`]+['\"`]\s*,\s*(async\s*)?\(?[^)]*\)?\s*=>\s*[^\n]*(exec|execSync|spawn|execFile|readFile|readFileSync|writeFile|writeFileSync|unlink|rm|openPath|openExternal|require)\(",
        "not_near": {"pattern": r"senderFrame|validateSender|allow_?list|allowlist|ALLOWED_|path\.relative|startsWith\(\s*(base|root|ALLOWED)", "lines": 4},
        "confidence": "MEDIUM",
        "examples": {"match": ["ipcMain.handle('run', async (e, cmd) => exec(cmd));", "ipcMain.handle('read', (e, p) => fs.readFileSync(p, 'utf8'));"],
                     "no_match": ["ipcMain.handle('read', (e, name) => { validateSender(e.senderFrame); return fs.readFileSync(path.join(NOTES, path.basename(name)), 'utf8'); });"]},
    },
    {
        "id": "desk-ipc-no-sender-check", "check_id": "DESK-IPC-001", "type": "absence", "scope": "file",
        "title": "IPC handlers without any sender validation", "files": ["js"],
        "when": r"ipcMain\.(handle|on)\(", "missing": r"senderFrame|sender\.getURL\(\)|validateSender|isTrustedSender|event\.sender\.id",
        "confidence": "LOW",
        "examples": {"match": ["ipcMain.handle('note:save', (e, text) => save(text));"], "no_match": ["ipcMain.handle('note:save', (e, text) => { validateSender(e.senderFrame); return save(text); });"]},
    },
    # ------------------------------------------------------------------ NAV
    {
        "id": "desk-remote-content", "check_id": "DESK-NAV-001", "title": "Window loads remote content", "files": ["js"],
        "pattern": r"\.loadURL\(\s*(['\"`]https?://(?!localhost|127\.0\.0\.1)|[a-zA-Z_$][\w.$]*\s*\))|<webview\b",
        "file_requires": ELECTRON, "not_near": {"pattern": r"isDev|is\.dev|NODE_ENV\s*===?\s*['\"]development|VITE_DEV_SERVER_URL|ELECTRON_RENDERER_URL|MAIN_WINDOW_WEBPACK_ENTRY", "lines": 3},
        "confidence": "MEDIUM", "note": "Remote pages in a privileged window can reach the preload API. Prefer local files; restrict navigation.",
        "examples": {"match": ["win.loadURL('https://app.acme.com'); // BrowserWindow"], "no_match": ["win.loadFile(path.join(__dirname, 'index.html')); // BrowserWindow"]},
    },
    {
        "id": "desk-no-navigation-guard", "check_id": "DESK-NAV-001", "type": "absence", "scope": "project",
        "title": "No navigation or new-window restrictions anywhere", "files": ["js"],
        "when": r"new\s+BrowserWindow\(", "missing": r"will-navigate|setWindowOpenHandler|new-window|will-attach-webview",
        "confidence": "MEDIUM",
        "examples": {"match": ["const win = new BrowserWindow({ webPreferences: { preload } });"],
                     "no_match": ["const win = new BrowserWindow({ webPreferences: { preload } });\nwin.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));"]},
    },
    # ------------------------------------------------------------------ SHELL
    {
        "id": "desk-open-external-unvalidated", "check_id": "DESK-SHELL-001", "title": "shell.openExternal/openPath with an unvalidated value", "files": ["js", "rs"],
        "pattern": r"shell\.(openExternal|openPath|openItem)\(\s*(?!['\"`]https://)[a-zA-Z_$][\w.$\[\]]*\s*[,)]|open::that\(\s*[a-z_]\w*\s*\)|tauri::api::shell::open\(",
        "not_near": {"pattern": r"(?i)(new URL\(|\.protocol\s*===?\s*['\"]https?:|ALLOWED_\w*(PROTOCOL|HOST|ORIGIN)|isSafeUrl|allow_?list|allowlist|startsWith\(\s*['\"]https://)", "lines": 4},
        "confidence": "HIGH", "note": "file:, smb:, custom schemes and local paths can launch programs. Allow only https:/mailto: after parsing.",
        "examples": {"match": ["win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: 'deny' }; });"],
                     "no_match": ["const u = new URL(url);\nif (u.protocol === 'https:') shell.openExternal(u.toString());"]},
    },
    # ------------------------------------------------------------------ PROTOCOL
    {
        "id": "desk-protocol-path", "check_id": "DESK-PROTOCOL-001", "title": "Custom protocol maps request URLs to files without containment", "files": ["js"],
        "pattern": r"protocol\.(handle|registerFileProtocol|registerBufferProtocol|interceptFileProtocol)\(",
        "not_near": {"pattern": r"path\.relative|startsWith\(\s*(base|root|ROOT|APP_DIR)|normalize[^\n]*startsWith|isInside|\.\.(['\"])", "lines": 8},
        "confidence": "LOW",
        "examples": {"match": ["protocol.registerFileProtocol('app', (req, cb) => cb({ path: decodeURI(req.url.slice(6)) }));"],
                     "no_match": ["protocol.handle('app', (req) => {\n  const p = path.resolve(ROOT, new URL(req.url).pathname.slice(1));\n  if (path.relative(ROOT, p).startsWith('..')) return new Response('', { status: 403 });\n  return net.fetch(pathToFileURL(p).toString());\n});"]},
    },
    # ------------------------------------------------------------------ CSP
    {
        "id": "desk-no-csp", "check_id": "DESK-CSP-001", "type": "absence", "scope": "project",
        "title": "Desktop renderer without a Content Security Policy", "files": ["js", "web", "config"],
        "when": r"new\s+BrowserWindow\(|\"tauri\"\s*:|tauri\.conf|\"app\"\s*:\s*\{[^}]*\"windows\"",
        "missing": r"Content-Security-Policy|\"csp\"\s*:\s*\"|onHeadersReceived",
        "confidence": "MEDIUM",
        "examples": {"match": ["const win = new BrowserWindow({ webPreferences: { preload } });"],
                     "no_match": ["const win = new BrowserWindow({ webPreferences: { preload } });\n// index.html: <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\">"]},
    },
    # ------------------------------------------------------------------ UPDATE / FUSES
    {
        "id": "desk-insecure-update", "check_id": "DESK-UPDATE-001", "title": "Auto-update over HTTP or with signature checks disabled", "files": ["js", "config", ".yml", ".json"],
        "pattern": r"(?i)(setFeedURL\(\s*\{?\s*(url\s*:\s*)?['\"`]http://|\"url\"\s*:\s*\"http://[^\"]*(update|release|download)|publish\s*:[^\n]*url\s*:\s*['\"]?http://|verifyUpdateCodeSignature['\"]?\s*:\s*false|\"pubkey\"\s*:\s*\"\"|dangerousInsecureTransportProtocol\s*:\s*true|\"dangerousUseHttpScheme\"\s*:\s*true)",
        "confidence": "HIGH",
        "examples": {"match": ["autoUpdater.setFeedURL({ url: 'http://updates.acme.com/latest' });", "\"win\": { \"verifyUpdateCodeSignature\": false }"],
                     "no_match": ["autoUpdater.setFeedURL({ url: 'https://updates.acme.com/latest' });"]},
    },
    {
        "id": "desk-runasnode-fuse", "check_id": "DESK-FUSES-001", "title": "Electron RunAsNode/inspect fuses left enabled", "files": ["js", "config"],
        "pattern": r"FuseV1Options\.(RunAsNode|EnableNodeCliInspectArguments|EnableNodeOptionsEnvironmentVariable)\]\s*:\s*true|\b(runAsNode|enableNodeCliInspectArguments|enableNodeOptionsEnvironmentVariable)\s*:\s*true|FuseV1Options\.(EnableEmbeddedAsarIntegrityValidation|OnlyLoadAppFromAsar)\]\s*:\s*false",
        "confidence": "MEDIUM",
        "examples": {"match": ["[FuseV1Options.RunAsNode]: true,"], "no_match": ["[FuseV1Options.RunAsNode]: false,"]},
    },
    # ------------------------------------------------------------------ TAURI
    {
        "id": "desk-tauri-broad-capability", "check_id": "DESK-TAURI-001", "title": "Tauri permission or scope too broad", "files": ["config", ".json", ".json5", ".toml"],
        "pattern": r"\"(all|open)\"\s*:\s*true|\"scope\"\s*:\s*\[\s*\"(\$\w+/)?\*\*|\"path\"\s*:\s*\"(\$HOME|\$\w+)?/?\*\*\"|\"(shell|fs|http):(allow-execute|allow-spawn|default|scope)\"|\"url\"\s*:\s*\"https?://\*\*?\"|\"dangerousRemoteDomainIpcAccess\"|\"dangerousDisableAssetCspModification\"\s*:\s*true",
        "file_requires": r"(?i)tauri|capabilit|\"permissions\"\s*:|\"allowlist\"\s*:", "confidence": "MEDIUM",
        "examples": {"match": ["{ \"tauri\": { \"allowlist\": { \"shell\": { \"all\": true } } } }", "{ \"identifier\": \"main\", \"permissions\": [ { \"identifier\": \"fs:scope\", \"allow\": [{ \"path\": \"$HOME/**\" }] } ] }"],
                     "no_match": ["{ \"identifier\": \"main\", \"permissions\": [ { \"identifier\": \"fs:allow-read-text-file\", \"allow\": [{ \"path\": \"$APPDATA/notes/*\" }] } ] }"]},
    },
]
