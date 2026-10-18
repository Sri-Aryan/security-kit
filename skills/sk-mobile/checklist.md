# Mobile app security checklist

Source of truth for `sk-mobile` check IDs. Covers Android and iOS apps, native (Kotlin/Java, Swift/Objective-C) and
cross-platform (React Native, Flutter, Expo, Capacitor/Ionic, .NET MAUI): local storage, secrets in the app, network
security and TLS, exported components and deep links, WebViews, debug and backup flags, biometrics, screenshots and
clipboard, and app integrity. The app's backend APIs: `sk-api` and friends. Based on the OWASP Mobile Application
Security Verification Standard (MASVS v2) and Testing Guide (MASTG). `references/guide.md` maps each check to MASVS.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021 (closest category; MASVS group in the guide).

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| MOB-STORAGE-001 | Tokens, credentials and sensitive personal data are stored only in the Keystore/Keychain or encrypted storage (EncryptedSharedPreferences, SecureStore, flutter_secure_storage), not SharedPreferences, UserDefaults, AsyncStorage, plain files or unencrypted databases | S | High | A04 | CWE-922 |
| MOB-SECRET-001 | The app binary contains no secrets: API secret keys, private keys, admin tokens, signing keys (anything shipped in an app can be extracted) | S | Critical | A07 | CWE-798 |
| MOB-NET-001 | Cleartext HTTP is disabled (no `usesCleartextTraffic`, `cleartextTrafficPermitted`, `NSAllowsArbitraryLoads`) | S | High | A02 | CWE-319 |
| MOB-TLS-001 | TLS certificate validation is never weakened (custom trust-all TrustManagers, hostname verifiers, WebView `onReceivedSslError` proceed, `badCertificateCallback` true); pinning is used for high-risk apps | S | Critical | A02 | CWE-295 |
| MOB-COMP-001 | Android components (activities, services, receivers, providers) are exported only when needed and protected by permissions; content providers don't expose files or SQL | S | High | A01 | CWE-926 |
| MOB-DEEPLINK-001 | Deep links / universal links are verified (`autoVerify`, associated domains) and their parameters are validated before navigation, auth or WebView loading | S | Medium | A01 | CWE-939 |
| MOB-WEBVIEW-001 | WebViews load only trusted content; JavaScript bridges, file access and universal file-URL access are off unless required; React Native `originWhitelist` is restricted | S | High | A03 | CWE-749 |
| MOB-DEBUG-001 | Release builds are not debuggable, disable or restrict backups of sensitive data, and don't log sensitive data | S | Medium | A05 | CWE-489 |
| MOB-AUTH-001 | Biometric unlock is bound to a Keystore/Keychain key (CryptoObject / access control), not a boolean callback | S | Medium | A07 | CWE-287 |
| MOB-PRIV-001 | Sensitive screens block screenshots/recents previews (`FLAG_SECURE`, iOS snapshot masking) and sensitive fields disable keyboard caching/clipboard where appropriate | S | Low | A04 | CWE-200 |
| MOB-INTEGRITY-001 | High-risk apps verify integrity server-side (Play Integrity, App Attest/DeviceCheck) and don't rely on client-side checks alone | S | Low | A08 | CWE-693 |
