# Mobile app security guide

Sources: OWASP MASVS v2 and MASTG. Platform- and framework-neutral; examples cover Android, iOS, React Native,
Flutter, Expo and Capacitor.

**Assume the attacker has the app and a rooted/jailbroken device.** They can unpack the binary, read its storage, hook
its functions and replay its requests. So: no secrets in the app, sensitive data only in hardware-backed storage, all
real security decisions on the server.

## Checks and MASVS groups

| Check | MASVS | Safe approach |
|---|---|---|
| MOB-STORAGE-001 | STORAGE | Android Keystore + EncryptedSharedPreferences/EncryptedFile (or DataStore + Tink); iOS Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; RN `react-native-keychain`/Expo `SecureStore`; Flutter `flutter_secure_storage`; SQLCipher for databases |
| MOB-SECRET-001 | CRYPTO / RESILIENCE | no secret API keys in code, resources, `Info.plist`, `.env` bundled by the build; use a backend and short-lived tokens; restrict publishable keys (API key restrictions by app signature/bundle ID) |
| MOB-NET-001 | NETWORK | Android `network_security_config.xml` with `cleartextTrafficPermitted="false"`; iOS ATS on (no `NSAllowsArbitraryLoads`); exceptions only for specific domains with reasons |
| MOB-TLS-001 | NETWORK | default trust; certificate/public-key pinning for high-risk apps (network security config `<pin-set>`, `TrustKit`, OkHttp `CertificatePinner`) with backup pins and an update plan |
| MOB-COMP-001 | PLATFORM | `android:exported="false"` unless needed; signature permissions for IPC; providers without `grantUriPermissions` on broad paths |
| MOB-DEEPLINK-001 | PLATFORM | App Links (`autoVerify="true"` + `assetlinks.json`), Universal Links (associated domains); treat parameters as untrusted; never put tokens in custom-scheme links |
| MOB-WEBVIEW-001 | PLATFORM | load only your own HTTPS content; no `addJavascriptInterface` with untrusted pages; file access off; RN `originWhitelist` limited to your domains |
| MOB-DEBUG-001 | RESILIENCE / STORAGE | release builds non-debuggable; `allowBackup="false"` or backup rules excluding secrets; no sensitive logs (strip with R8/ProGuard rules) |
| MOB-AUTH-001 | AUTH | BiometricPrompt with `CryptoObject`; Keychain items with `SecAccessControl` (`.biometryCurrentSet`); the server still authorizes |
| MOB-PRIV-001 | PRIVACY | `FLAG_SECURE` on sensitive screens; hide content in iOS app-switcher snapshots; `secureTextEntry` and no autocorrect on secrets |
| MOB-INTEGRITY-001 | RESILIENCE | Play Integrity API / App Attest verified **server-side**; client-only root/jailbreak checks are speed bumps |

## Reviewing

Check the release configuration (Gradle build types, Xcode release scheme, Expo `app.config`), not just debug.
Platform files: `AndroidManifest.xml`, `res/xml/network_security_config.xml`, `Info.plist`, entitlements,
`app.json`/`app.config.(js|ts)`, `capacitor.config.*`, `pubspec.yaml`. If an APK/IPA build is available locally,
MobSF can be run offline by the user for a binary-level view.
