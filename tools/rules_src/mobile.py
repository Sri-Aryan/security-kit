"""sk-mobile rules: Android manifest/network config, iOS plist, Kotlin/Java/Swift, React Native, Flutter, Capacitor."""

SKILL = "sk-mobile"

MOBILE_CODE = ["java", "kt", "swift", ".m", "dart", "js"]
MANIFEST = r"(?i)AndroidManifest\.xml$"

MACROS = {
    "SENSITIVE_KEY": r"(?i:token|jwt|session|password|passwd|secret|api_?key|pin|credential|auth|refresh|card|ssn)",
}

RULES = [
    # ------------------------------------------------------------------ STORAGE
    {
        "id": "mob-insecure-kv-storage", "check_id": "MOB-STORAGE-001", "title": "Sensitive value written to insecure key-value storage", "files": MOBILE_CODE,
        "pattern": r"(getSharedPreferences\([^)]*\)\.edit\(\)|\.edit\(\)|SharedPreferences\.Editor|UserDefaults\.standard|NSUserDefaults|AsyncStorage|SharedPreferences\.getInstance\(\)|prefs|Preferences\.set|MMKV)[^\n]*\.(putString|setString|set|setItem|setValue|setObject|putInt|encode)\(\s*[^\n]*['\"`][^'\"`]*{{SENSITIVE_KEY}}",
        "not_near": {"pattern": r"EncryptedSharedPreferences|SecureStore|Keychain|KeyStore|flutter_secure_storage|FlutterSecureStorage|react-native-keychain|encrypt", "lines": 4},
        "confidence": "MEDIUM", "note": "Plain preferences/defaults are readable on rooted/jailbroken devices and in backups.",
        "examples": {"match": ["prefs.edit().putString(\"auth_token\", token).apply()", "await AsyncStorage.setItem('refreshToken', t);", "UserDefaults.standard.set(token, forKey: \"sessionToken\")"],
                     "no_match": ["await SecureStore.setItemAsync('refreshToken', t);", "prefs.edit().putString(\"theme\", \"dark\").apply()"]},
    },
    # ------------------------------------------------------------------ SECRET
    {
        "id": "mob-secret-in-resources", "check_id": "MOB-SECRET-001", "title": "Secret-looking value in app resources or config", "files": [".xml", ".plist", ".json", ".dart", ".swift", ".kt", "js"],
        "pattern": r"(?i)(<string\s+name=\"[^\"]*(secret|private_key|client_secret|api_secret|admin)[^\"]*\">[^<]{8,}</string>|<key>[^<]*(Secret|PrivateKey|ClientSecret|ApiSecret)[^<]*</key>\s*<string>[^<]{8,}</string>|\b(client_?secret|api_?secret|private_?key|secret_?key|admin_?token)\s*[:=]\s*['\"](?!{{PLACEHOLDER}})[A-Za-z0-9_\-+/=]{12,}['\"])",
        "path_includes": r"(?i)(android|ios|app|mobile|lib/|src/|res/values|Info\.plist|\.xcconfig|GoogleService|app\.json|app\.config)", "redact": True, "confidence": "MEDIUM",
        "note": "Anything in the app can be extracted with standard tools. Keep secrets on a backend and give the app short-lived, scoped tokens.",
        "examples": {"match": ["<string name=\"stripe_secret_key\">q8Zr3LmN0vXw2KpTq8Zr</string>"], "no_match": ["<string name=\"app_name\">Acme</string>"]},
    },
    # ------------------------------------------------------------------ NET
    {
        "id": "mob-cleartext-allowed", "check_id": "MOB-NET-001", "title": "Cleartext HTTP allowed", "files": [".xml", ".plist", "config", "dart", "js"], "multiline": True,
        "pattern": r"usesCleartextTraffic=\"true\"|cleartextTrafficPermitted=\"true\"|<key>NSAllowsArbitraryLoads</key>\s*<true\s*/>|NSAllowsArbitraryLoads\s*[:=]\s*(true|YES)|<key>NSAllowsArbitraryLoadsInWebContent</key>\s*<true\s*/>|androidScheme\s*:\s*['\"]http['\"]|cleartext\s*:\s*true",
        "confidence": "HIGH",
        "examples": {"match": ["<application android:usesCleartextTraffic=\"true\" android:label=\"Acme\">", "<key>NSAllowsArbitraryLoads</key>\n<true/>"],
                     "no_match": ["<application android:usesCleartextTraffic=\"false\">"]},
    },
    # ------------------------------------------------------------------ TLS
    {
        "id": "mob-trust-all", "check_id": "MOB-TLS-001", "title": "TLS validation disabled in the app", "files": MOBILE_CODE,
        "pattern": r"onReceivedSslError\([^)]*\)\s*\{[^}]*\.proceed\(\)|handler\.proceed\(\)|checkServerTrusted\([^)]*\)\s*(throws\s+[\w.]+\s*)?\{\s*\}|getAcceptedIssuers\(\)\s*\{\s*return\s+(null|new\s+X509Certificate\[0\])|hostnameVerifier\s*\{\s*_?,\s*_?\s*->\s*true\s*\}|HostnameVerifier\s*\{[^}]*return\s+true|ALLOW_ALL_HOSTNAME_VERIFIER|badCertificateCallback\s*=\s*\([^)]*\)\s*=>\s*true|completionHandler\(\s*\.useCredential\s*,\s*URLCredential\(trust:|disableTLSCertificateValidation|trustAllCerts",
        "confidence": "HIGH",
        "examples": {"match": ["override fun onReceivedSslError(v: WebView, handler: SslErrorHandler, e: SslError) { handler.proceed() }", "client.badCertificateCallback = (cert, host, port) => true;"],
                     "no_match": ["override fun onReceivedSslError(v: WebView, handler: SslErrorHandler, e: SslError) { handler.cancel() }"]},
    },
    # ------------------------------------------------------------------ COMP
    {
        "id": "mob-exported-component", "check_id": "MOB-COMP-001", "title": "Exported Android component without a permission", "files": [".xml"], "path_includes": MANIFEST,
        "pattern": r"<(activity|activity-alias|service|receiver|provider)\b(?![^>]*android:permission=)(?=[^>]*android:exported=\"true\")[^>]*>",
        "not_near": {"pattern": r"android\.intent\.category\.LAUNCHER", "lines": 4},
        "confidence": "MEDIUM", "note": "Any app on the device can start/bind/query it. Remove exported or require a signature-level permission.",
        "examples": {"match": ["<service android:name=\".SyncService\" android:exported=\"true\" />"],
                     "no_match": ["<service android:name=\".SyncService\" android:exported=\"true\" android:permission=\"com.acme.SYNC\" />"]},
    },
    {
        "id": "mob-provider-grant-all", "check_id": "MOB-COMP-001", "title": "Content provider grants broad URI permissions", "files": [".xml"], "path_includes": MANIFEST,
        "pattern": r"android:grantUriPermissions=\"true\"|<path-permission\b[^>]*android:pathPrefix=\"/\"|<root-path\b",
        "confidence": "LOW",
        "examples": {"match": ["<provider android:name=\".Files\" android:authorities=\"com.acme.files\" android:grantUriPermissions=\"true\" />"], "no_match": ["<provider android:name=\".Files\" android:exported=\"false\" />"]},
    },
    # ------------------------------------------------------------------ DEEPLINK
    {
        "id": "mob-applink-not-verified", "check_id": "MOB-DEEPLINK-001", "title": "HTTP(S) deep link without App Links verification", "files": [".xml"], "path_includes": MANIFEST,
        "pattern": r"<intent-filter(?![^>]*android:autoVerify=\"true\")[^>]*>",
        "near": {"pattern": r"android:scheme=\"https?\"", "lines": 6}, "confidence": "LOW",
        "note": "Without autoVerify any app can claim the link and receive tokens or codes in it.",
        "examples": {"match": ["<intent-filter>\n  <action android:name=\"android.intent.action.VIEW\" />\n  <data android:scheme=\"https\" android:host=\"acme.com\" />\n</intent-filter>"],
                     "no_match": ["<intent-filter android:autoVerify=\"true\">\n  <data android:scheme=\"https\" android:host=\"acme.com\" />\n</intent-filter>"]},
    },
    {
        "id": "mob-deeplink-to-webview", "check_id": "MOB-DEEPLINK-001", "title": "Deep-link parameter loaded into a WebView or used for navigation", "files": MOBILE_CODE,
        "pattern": r"(loadUrl|load\(URLRequest|loadRequest|WebView\([^)]*source\s*=\s*\{\s*\{\s*uri\s*:|launchUrl|openURL|Linking\.openURL|navigate)\([^\n]*(getQueryParameter|intent\.data|intent\.getStringExtra|url\.queryItems|queryParameters|route\.params|Linking\.getInitialURL|uri\.queryParameters|deepLink)",
        "confidence": "MEDIUM",
        "examples": {"match": ["webView.loadUrl(intent.data?.getQueryParameter(\"url\"))"], "no_match": ["webView.loadUrl(\"https://acme.com/help\")"]},
    },
    # ------------------------------------------------------------------ WEBVIEW
    {
        "id": "mob-webview-risky-settings", "check_id": "MOB-WEBVIEW-001", "title": "WebView with risky settings (JS bridge, file access, universal access)", "files": MOBILE_CODE,
        "pattern": r"addJavascriptInterface\(|setAllowUniversalAccessFromFileURLs\(\s*true|setAllowFileAccessFromFileURLs\(\s*true|setAllowFileAccess\(\s*true|allowUniversalAccessFromFileURLs\s*=\s*true|allowFileAccessFromFileURLs\s*=\s*true|allowingReadAccessTo\s*:|originWhitelist=\{\s*\[\s*['\"]\*['\"]\s*\]\s*\}|allowFileAccess(FromFileURLs)?=\{\s*true\s*\}|allowUniversalAccessFromFileURLs=\{\s*true\s*\}|mixedContentMode=['\"]always['\"]|javascriptMode\s*:\s*JavascriptMode\.unrestricted",
        "confidence": "MEDIUM", "note": "Combined with any untrusted content, these let web pages call native code or read local files.",
        "examples": {"match": ["webView.addJavascriptInterface(Bridge(this), \"Android\")", "<WebView originWhitelist={['*']} source={{ uri }} />"],
                     "no_match": ["webView.settings.javaScriptEnabled = false"]},
    },
    # ------------------------------------------------------------------ DEBUG
    {
        "id": "mob-debuggable-backup", "check_id": "MOB-DEBUG-001", "title": "App debuggable or full backup allowed", "files": [".xml", "kt", ".gradle", ".kts"],
        "pattern": r"android:debuggable=\"true\"|android:allowBackup=\"true\"|debuggable\s*(=\s*)?true|isDebuggable\s*=\s*true",
        "path_excludes": r"(?i)(debug/|/debug|src/debug)", "confidence": "MEDIUM",
        "note": "allowBackup copies app data (tokens, databases) via adb/cloud backup; use dataExtractionRules/fullBackupContent to exclude secrets.",
        "examples": {"match": ["<application android:allowBackup=\"true\" android:label=\"Acme\">", "release { debuggable true }"], "no_match": ["<application android:allowBackup=\"false\">"]},
    },
    {
        "id": "mob-sensitive-log", "check_id": "MOB-DEBUG-001", "title": "Sensitive value written to the device log", "files": MOBILE_CODE,
        "pattern": r"(Log\.[dviwe]|println|print|NSLog|os_log|debugPrint|console\.log|Logger\.\w+)\s*\([^\n]*{{SENSITIVE_KEY}}\w*\s*[,)}+]",
        "confidence": "LOW",
        "examples": {"match": ["Log.d(\"Auth\", \"token=\" + token)", "print(\"session: \\(sessionToken)\")"], "no_match": ["Log.d(\"Auth\", \"login ok\")"]},
    },
    # ------------------------------------------------------------------ AUTH
    {
        "id": "mob-biometric-no-crypto", "check_id": "MOB-AUTH-001", "title": "Biometric prompt not bound to a cryptographic key", "files": MOBILE_CODE,
        "pattern": r"\.authenticate\(\s*promptInfo\s*\)|evaluatePolicy\(\s*\.deviceOwnerAuthentication(WithBiometrics)?|LocalAuthentication\.authenticateAsync\(|localAuth\.authenticate\(|authenticateWithBiometrics\(",
        "not_near": {"pattern": r"CryptoObject|SecAccessControl|kSecAccessControl|biometryCurrentSet|setUserAuthenticationRequired|requireAuthentication\s*:\s*true|SecureStore", "lines": 8},
        "confidence": "LOW", "note": "A success callback can be hooked on a rooted device; unlock a Keystore/Keychain key that releases the token instead.",
        "examples": {"match": ["biometricPrompt.authenticate(promptInfo)"], "no_match": ["biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))"]},
    },
    # ------------------------------------------------------------------ PRIV
    {
        "id": "mob-no-flag-secure", "check_id": "MOB-PRIV-001", "type": "absence", "scope": "project",
        "title": "No screenshot protection anywhere (FLAG_SECURE / snapshot masking)", "files": ["java", "kt", "swift", "dart", "js"],
        "when": r"(?i)(password|card_?number|cvv|pin_?code|otp)\w*\s*(=|:)?\s*(EditText|TextField|SecureField|TextInput|<TextInput)",
        "missing": r"FLAG_SECURE|isSecureTextEntry|secureTextEntry|preventScreenCapture|ScreenCapture|flutter_windowmanager|applicationWillResignActive|sceneWillResignActive|isCaptured",
        "confidence": "LOW",
        "examples": {"match": ["val cardNumber = EditText(this)"], "no_match": ["window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)\nval cardNumber = EditText(this)"]},
    },
]
