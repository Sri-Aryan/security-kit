# Cryptography checklist

Source of truth for `sk-crypto` check IDs. Covers how the application uses cryptography in any language: algorithms,
modes, IVs and nonces, keys and their management, key derivation, randomness, signatures, TLS settings in clients and
servers, and comparisons of secrets. Password hashing is covered by `sk-password`, JWTs and tokens by `sk-tokens`.
Based on the OWASP Cryptographic Storage, Key Management, Transport Layer Security and Pinning cheat sheets.
`references/guide.md` lists the safe choice for each primitive.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| CRYPTO-ALG-001 | No broken or weak algorithms for security purposes: MD5/SHA-1 for integrity or signatures, DES/3DES/RC4/Blowfish, RSA < 2048 bits, small DH groups | S | High | A02 | CWE-327 |
| CRYPTO-MODE-001 | Symmetric encryption uses an authenticated mode (AES-GCM, ChaCha20-Poly1305) or encrypt-then-MAC; never ECB; no unauthenticated CBC/CTR for data an attacker can modify | S | High | A02 | CWE-327 |
| CRYPTO-IV-001 | IVs and nonces are random (or unique counters for GCM) per encryption, never constant, zero, or derived from the key | S | High | A02 | CWE-329 |
| CRYPTO-KEY-001 | Keys are not hardcoded, not derived from short strings, and are loaded from a KMS, HSM or secret manager | S | Critical | A02 | CWE-321 |
| CRYPTO-KDF-001 | Keys derived from passwords or passphrases use a real KDF (Argon2id, scrypt, PBKDF2 with ≥ 600k iterations, HKDF for key material), never a plain hash or the raw password | S | High | A02 | CWE-916 |
| CRYPTO-RAND-001 | Security values (keys, IVs, salts, tokens, IDs that must be unguessable) come from a CSPRNG | S | High | A02 | CWE-338 |
| CRYPTO-ASYM-001 | Asymmetric crypto uses safe padding and parameters: RSA-OAEP for encryption, RSA-PSS or Ed25519/ECDSA P-256+ for signatures; no PKCS#1 v1.5 encryption; no textbook RSA | S | High | A02 | CWE-780 |
| CRYPTO-MAC-001 | Integrity uses HMAC or signatures (not a plain hash of secret + data), and MACs, signatures and tokens are compared in constant time | S | Medium | A02 | CWE-208 |
| CRYPTO-TLS-001 | TLS certificate and hostname verification is never disabled; only TLS 1.2+ with modern cipher suites is allowed | S | High | A02 | CWE-295 |
| CRYPTO-CUSTOM-001 | No home-made cryptography (custom ciphers, XOR "encryption", hand-rolled protocols, Base64 treated as encryption); deprecated libraries replaced | S | High | A02 | CWE-327 |
| CRYPTO-KMS-001 | Key management: keys have owners, rotation schedules and separate purposes (encryption vs signing vs per-environment); data keys are wrapped (envelope encryption); old keys can decrypt during rotation | S | Medium | A02 | CWE-320 |
| CRYPTO-REST-001 | Sensitive data at rest (personal data, credentials for third parties, documents) is encrypted with managed keys at the storage or field level | S | Medium | A02 | CWE-311 |
