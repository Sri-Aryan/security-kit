# Cryptography guide

Sources: OWASP Cryptographic Storage, Key Management, Transport Layer Security and Pinning cheat sheets.

**Rule one: use a high-level, well-reviewed library and its defaults.** Most crypto bugs come from choosing
primitives by hand. Prefer: libsodium / NaCl (`secretbox`, `box`, `sign`), Google Tink, pyca/cryptography
`Fernet`/`AESGCM`, Go `crypto/cipher` AEADs, WebCrypto `AES-GCM`, .NET `AesGcm`, Java `AES/GCM/NoPadding`.

## Safe choices

| Need | Use | Avoid |
|---|---|---|
| Encrypt data | AES-256-GCM or ChaCha20-Poly1305 with a random 96-bit nonce per message (or XChaCha20 with random 192-bit nonce) | ECB, unauthenticated CBC/CTR, DES/3DES/RC4/Blowfish, static IVs |
| Integrity / authenticity | HMAC-SHA-256, compared with `timingSafeEqual` / `compare_digest` / `hmac.Equal` / `MessageDigest.isEqual` | `sha256(secret + data)`, `==` on MACs |
| Signatures | Ed25519, ECDSA P-256 (deterministic or good RNG), RSA-PSS ≥ 3072 bits | RSA < 2048, PKCS#1 v1.5 for new designs, DSA |
| Asymmetric encryption | Hybrid: X25519/ECDH + AEAD (HPKE, libsodium `box`), or RSA-OAEP-SHA-256 | RSA PKCS#1 v1.5 encryption, textbook RSA |
| Key from a password | Argon2id, scrypt, PBKDF2-HMAC-SHA-256 (≥ 600,000 iterations) with a random salt | `sha256(password)` as a key, raw password bytes |
| Key from key material | HKDF with a context label per purpose | reusing one key for several purposes |
| Random values | `crypto.randomBytes`, `secrets`, `SecureRandom`, `crypto/rand`, `RandomNumberGenerator`, `getRandomValues` | `Math.random`, `random`, `rand`, `java.util.Random` |
| Hash (non-secret) | SHA-256 / SHA-3 / BLAKE2 | MD5, SHA-1 for anything security-related |
| Transport | TLS 1.2+ (1.3 preferred), verification on, system or pinned CA bundle | `rejectUnauthorized: false`, `verify=False`, `InsecureSkipVerify`, SSLv3/TLS 1.0/1.1 |

## Keys (CRYPTO-KEY-001, CRYPTO-KMS-001)

- Keys live in a KMS/HSM or secret manager (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault), never in code,
  images or plain config. Locally, environment variables injected at runtime are the minimum.
- **Envelope encryption**: a KMS key encrypts per-record or per-tenant data keys; only wrapped data keys are stored.
- One key, one purpose, one environment. Store a key ID with each ciphertext so keys can rotate; keep old keys for
  decryption only until data is re-encrypted.
- A hardcoded key found by this skill must be **rotated**, not just moved: assume it is compromised.

## Data at rest (CRYPTO-REST-001)

Turn on storage encryption (database, disks, buckets) with managed keys as a baseline. Add field-level encryption for
high-value fields (government IDs, health data, third-party credentials, tokens) so a database dump or a read-only SQL
injection doesn't expose them.

## Reviewing a hit

Ask what the value protects. MD5 for an ETag is fine; MD5 for a signature is not. A constant IV in a test fixture is
fine; in production code it is a finding. Confirm the code path is reachable in production before reporting.
