"""sk-crypto rules: algorithms, modes, IVs, keys, KDFs, randomness, padding, MACs, TLS verification."""

SKILL = "sk-crypto"

MACROS = {
    "SECURITY_CTX": r"(?i:sign|signature|verify|integrity|checksum|hmac|token|password|secret|key|auth|nonce|otp|session|reset|cert)",
}

RULES = [
    # ------------------------------------------------------------------ ALG
    {
        "id": "crypto-weak-hash-security", "check_id": "CRYPTO-ALG-001", "title": "MD5/SHA-1 used where security depends on it", "files": ["code"],
        "pattern": r"(?i)(createHash|hashlib\.new|MessageDigest\.getInstance)\(\s*['\"](md5|sha1|sha-1)['\"]|hashlib\.(md5|sha1)\(|DigestUtils\.(md5|sha1)\w*\(|\b(md5|sha1)\.(New|Sum)\w*\(|Digest::(MD5|SHA1)|\bmd5\(|\bsha1\(|\b(MD5|SHA1)\.Create\(|MD5CryptoServiceProvider|SHA1Managed",
        "near": {"pattern": "{{SECURITY_CTX}}", "lines": 3},
        "not_near": {"pattern": r"(?i)(usedforsecurity\s*=\s*False|etag|cache[_-]?key|checksum of (file|asset)|gravatar|non[-_ ]?security)", "lines": 2},
        "confidence": "MEDIUM",
        "note": "Fine for non-security uses (cache keys, ETags); not for signatures, integrity, tokens or passwords.",
        "examples": {"match": ["const sig = crypto.createHash('md5').update(secret + body).digest('hex');", "token = hashlib.sha1(user.email + SECRET).hexdigest()"],
                     "no_match": ["const etag = crypto.createHash('md5').update(file).digest('hex'); // etag", "const sig = crypto.createHmac('sha256', key).update(body).digest('hex');"]},
    },
    {
        "id": "crypto-weak-cipher", "check_id": "CRYPTO-ALG-001", "title": "Broken or weak cipher (DES, 3DES, RC4, Blowfish, RC2)", "files": ["code", "config"],
        "pattern": r"(?i)['\"](des|des-ede3?|des-ede3-cbc|des-cbc|3des|tripledes|desede(/\w+/\w+)?|rc4|arcfour|rc2|bf-cbc|blowfish)['\"]|\b(DES|TripleDES|RC2|RC4|ARC4|Blowfish)\.(new|Create)\(|DESCryptoServiceProvider|TripleDESCryptoServiceProvider|RC2CryptoServiceProvider|des\.NewCipher|des\.NewTripleDESCipher|rc4\.NewCipher|algorithms\.(TripleDES|Blowfish|ARC4|CAST5|IDEA)\(",
        "confidence": "HIGH",
        "examples": {"match": ["const c = crypto.createCipheriv('des-ede3-cbc', key, iv);", "Cipher c = Cipher.getInstance(\"DESede/CBC/PKCS5Padding\");", "cipher = ARC4.new(key)"],
                     "no_match": ["const c = crypto.createCipheriv('aes-256-gcm', key, iv);"]},
    },
    {
        "id": "crypto-small-rsa", "check_id": "CRYPTO-ALG-001", "title": "RSA/DSA/DH key smaller than 2048 bits", "files": ["code"],
        "pattern": r"(?i)(modulusLength|key_size|keysize|bits|keySize)\s*[:=,]?\s*(512|768|1024)\b|generate_private_key\([^)]*\b(512|768|1024)\b|KeyPairGenerator[^\n]*initialize\(\s*(512|768|1024)\b|rsa\.GenerateKey\([^,]+,\s*(512|768|1024)\)|RSA\.generate\(\s*(512|768|1024)\b|new\s+RSACryptoServiceProvider\(\s*(512|768|1024)\)",
        "near": {"pattern": r"(?i)rsa|dsa|\bdh\b|diffie|keypair|generateKeyPair", "lines": 3}, "confidence": "HIGH",
        "examples": {"match": ["crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });", "key = RSA.generate(1024)"],
                     "no_match": ["crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });"]},
    },
    # ------------------------------------------------------------------ MODE
    {
        "id": "crypto-ecb", "check_id": "CRYPTO-MODE-001", "title": "ECB mode (or a default that means ECB)", "files": ["code"],
        "pattern": r"(?i)['\"]aes-\d+-ecb['\"]|['\"]AES/ECB/|Cipher\.getInstance\(\s*\"(AES|DES|DESede)\"\s*\)|MODE_ECB|modes\.ECB\(|CipherMode\.ECB|NewECB|\bECB\b\s*\(",
        "confidence": "HIGH", "note": "Java's Cipher.getInstance(\"AES\") defaults to AES/ECB/PKCS5Padding.",
        "examples": {"match": ["Cipher c = Cipher.getInstance(\"AES\");", "cipher = AES.new(key, AES.MODE_ECB)"],
                     "no_match": ["Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");"]},
    },
    {
        "id": "crypto-unauthenticated-mode", "check_id": "CRYPTO-MODE-001", "title": "CBC/CTR/CFB/OFB encryption without a MAC", "type": "absence", "scope": "file", "files": ["code"],
        "when": r"(?i)['\"]aes-\d+-(cbc|ctr|cfb|ofb)['\"]|['\"]AES/(CBC|CTR|CFB|OFB)/|MODE_(CBC|CTR|CFB|OFB)|modes\.(CBC|CTR|CFB|OFB)\(|NewCBCEncrypter|NewCTR\(|CipherMode\.CBC",
        "missing": r"(?i)hmac|createHmac|\bmac\b|Mac\.getInstance|authTag|tag|encrypt_then_mac|verify",
        "confidence": "MEDIUM", "note": "Without a MAC, ciphertext can be modified (bit flipping, padding oracles). Use AES-GCM or ChaCha20-Poly1305.",
        "examples": {"match": ["const c = crypto.createCipheriv('aes-256-cbc', key, iv);\nreturn Buffer.concat([iv, c.update(data), c.final()]);"],
                     "no_match": ["const c = crypto.createCipheriv('aes-256-cbc', key, iv);\nconst mac = crypto.createHmac('sha256', macKey).update(ct).digest();"]},
    },
    # ------------------------------------------------------------------ IV
    {
        "id": "crypto-static-iv", "check_id": "CRYPTO-IV-001", "title": "Constant, zero or reused IV/nonce", "files": ["code"],
        "pattern": r"(?i)\b(iv|nonce|initVector|initialization_?vector)\w*\s*[:=]\s*(Buffer\.(alloc|from)\(\s*(\d+|['\"][^'\"]*['\"])|b['\"][^'\"]*['\"]|bytes\(\d+\)|new\s+byte\[\s*\d+\s*\]|['\"][0-9A-Za-z+/=]{8,}['\"]|\[\s*0\s*(,\s*0\s*)+\]|make\(\[\]byte,\s*\d+\)|new\s+IvParameterSpec\(\s*new\s+byte)",
        "not_near": {"pattern": r"(?i)randomBytes|urandom|get_random_bytes|SecureRandom|rand\.Read|RandomNumberGenerator|getRandomValues|secrets\.token_bytes|nextBytes", "lines": 2},
        "confidence": "HIGH",
        "examples": {"match": ["const iv = Buffer.alloc(16, 0);", "iv = b'0000000000000000'", "byte[] iv = new byte[16];\nCipher c = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");"],
                     "no_match": ["const iv = crypto.randomBytes(12);", "byte[] iv = new byte[12];\nnew SecureRandom().nextBytes(iv);"]},
    },
    # ------------------------------------------------------------------ KEY
    {
        "id": "crypto-hardcoded-key", "check_id": "CRYPTO-KEY-001", "title": "Encryption/signing key hardcoded in source", "files": ["code"],
        "pattern": r"(?i)\b\w*(enc(ryption)?|aes|cipher|crypt|sign(ing)?|hmac|secret|master|data)_?key\w*\s*[:=]\s*(Buffer\.from\(\s*)?(b)?['\"](?!{{PLACEHOLDER}})[A-Za-z0-9+/=_\-!@#$%^&*]{12,}['\"]",
        "redact": True, "path_excludes": r"(?i)(test|spec|fixture|example|sample)", "confidence": "HIGH",
        "note": "Anyone with the code (or the built artifact) can decrypt or forge. Load keys from a KMS or secret manager; rotate this one.",
        "examples": {"match": ["const ENCRYPTION_KEY = 'q8Zr3LmN0vXw2KpTq8Zr3LmN';", "AES_KEY = b'k3yk3yk3yk3yk3yk3yk3yk3'"],
                     "no_match": ["const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;", "const ENCRYPTION_KEY = await kms.decrypt(wrappedKey);"]},
    },
    # ------------------------------------------------------------------ KDF
    {
        "id": "crypto-key-from-hash", "check_id": "CRYPTO-KDF-001", "title": "Key derived with a plain hash or the raw passphrase", "files": ["code"],
        "pattern": r"(?i)\b\w*key\w*\s*[:=]\s*[^\n]*(createHash\(\s*['\"](sha256|sha1|md5|sha512)['\"]\s*\)\.update\(\s*\w*(pass|secret|phrase|pwd)|hashlib\.(sha256|sha1|md5|sha512)\(\s*\w*(pass|secret|phrase|pwd)|Buffer\.from\(\s*\w*(pass|phrase|pwd)\w*\s*[,)]|\.getBytes\(\)\s*;?\s*$)",
        "near": {"pattern": r"(?i)cipher|encrypt|decrypt|aes|createCipheriv|SecretKeySpec", "lines": 5}, "confidence": "MEDIUM",
        "examples": {"match": ["const key = crypto.createHash('sha256').update(passphrase).digest();\nconst c = crypto.createCipheriv('aes-256-gcm', key, iv);"],
                     "no_match": ["const key = crypto.scryptSync(passphrase, salt, 32);\nconst c = crypto.createCipheriv('aes-256-gcm', key, iv);"]},
    },
    {
        "id": "crypto-pbkdf2-low-iterations", "check_id": "CRYPTO-KDF-001", "title": "PBKDF2 with a low iteration count", "files": ["code"],
        "pattern": r"(?i)pbkdf2(Sync)?\(\s*[^,]+,\s*[^,]+,\s*([1-9]\d{0,4})\s*,|pbkdf2_hmac\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*([1-9]\d{0,4})\s*[,)]|\biterations\s*[:=]\s*([1-9]\d{0,4})\b(?![\d_])|PBEKeySpec\([^,]+,[^,]+,\s*([1-9]\d{0,4})\s*,|Rfc2898DeriveBytes\([^,]+,[^,]+,\s*([1-9]\d{0,4})\s*[,)]",
        "near": {"pattern": r"(?i)pbkdf2|PBEKeySpec|Rfc2898DeriveBytes", "lines": 3}, "confidence": "MEDIUM",
        "note": "OWASP recommends at least 600,000 iterations for PBKDF2-HMAC-SHA256, or Argon2id/scrypt.",
        "examples": {"match": ["const key = crypto.pbkdf2Sync(pw, salt, 1000, 32, 'sha256');"], "no_match": ["const key = crypto.pbkdf2Sync(pw, salt, 600000, 32, 'sha256');"]},
    },
    # ------------------------------------------------------------------ RAND
    {
        "id": "crypto-weak-random", "check_id": "CRYPTO-RAND-001", "title": "Non-cryptographic randomness used for a security value", "files": ["code"],
        "pattern": "{{WEAK_RANDOM}}", "near": {"pattern": r"(?i)\b(key|iv|nonce|salt|token|secret|otp|password|session|csrf|reset|invite|code)\w*\s*[:=]", "lines": 2},
        "confidence": "MEDIUM",
        "examples": {"match": ["const iv = Buffer.from(String(Math.random()));", "salt = str(random.random())"],
                     "no_match": ["const iv = crypto.randomBytes(12);"]},
    },
    # ------------------------------------------------------------------ ASYM
    {
        "id": "crypto-rsa-pkcs1-encryption", "check_id": "CRYPTO-ASYM-001", "title": "RSA encryption with PKCS#1 v1.5 or no padding", "files": ["code"],
        "pattern": r"RSA/ECB/PKCS1Padding|RSA/NONE/NoPadding|RSA/ECB/NoPadding|RSA_PKCS1_PADDING|RSA_NO_PADDING|padding\.PKCS1v15\(\)|PKCS1_v1_5\.new|RSAEncryptionPadding\.Pkcs1|EncryptPKCS1v15|\"RSA\"\s*\)",
        "near": {"pattern": r"(?i)encrypt|decrypt|Cipher|publicEncrypt|privateDecrypt", "lines": 3}, "confidence": "HIGH",
        "note": "PKCS#1 v1.5 encryption is vulnerable to padding-oracle attacks (Bleichenbacher). Use OAEP with SHA-256.",
        "examples": {"match": ["Cipher c = Cipher.getInstance(\"RSA/ECB/PKCS1Padding\");\nc.init(Cipher.ENCRYPT_MODE, pub);", "ct = pub.encrypt(data, padding.PKCS1v15())"],
                     "no_match": ["ct = pub.encrypt(data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))"]},
    },
    # ------------------------------------------------------------------ MAC
    {
        "id": "crypto-hash-as-mac", "check_id": "CRYPTO-MAC-001", "title": "Plain hash of secret + data used as a MAC", "files": ["code"],
        "pattern": r"(?i)(createHash\(\s*['\"]sha\d+['\"]\s*\)\.update\(\s*[^)]*(secret|key)\w*\s*\+|hashlib\.sha\d+\(\s*[^)]*(secret|key)\w*\s*\+|sha256\(\s*[^)]*(secret|key)\w*\s*\.\s*\$|DigestUtils\.sha\d+Hex\(\s*[^)]*(secret|key)\w*\s*\+)",
        "confidence": "MEDIUM", "note": "hash(secret + message) is vulnerable to length extension. Use HMAC.",
        "examples": {"match": ["const sig = crypto.createHash('sha256').update(secret + payload).digest('hex');"],
                     "no_match": ["const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex');"]},
    },
    {
        "id": "crypto-non-constant-compare", "check_id": "CRYPTO-MAC-001", "title": "MAC/signature/token compared with == (timing leak)", "files": ["code"],
        "pattern": r"(?i)\b\w*(signature|sig|hmac|mac|digest|expected_?\w*|computed_?\w*)\w*\s*(===?|!==?)\s*\w*(signature|sig|hmac|mac|digest|header|provided|received|given)\w*|\.equals\(\s*\w*(signature|hmac|mac|digest)\w*\s*\)",
        "near": {"pattern": r"(?i)hmac|signature|digest|createHmac|Mac\.getInstance", "lines": 6},
        "not_near": {"pattern": r"timingSafeEqual|compare_digest|hmac\.Equal|ConstantTimeCompare|MessageDigest\.isEqual|FixedTimeEquals|secure_compare|hash_equals", "lines": 3},
        "confidence": "MEDIUM",
        "examples": {"match": ["const expected = crypto.createHmac('sha256', key).update(body).digest('hex');\nif (expected === signature) next();"],
                     "no_match": ["const expected = crypto.createHmac('sha256', key).update(body).digest();\nif (crypto.timingSafeEqual(expected, Buffer.from(signature, 'hex'))) next();"]},
    },
    # ------------------------------------------------------------------ TLS
    {
        "id": "crypto-tls-verify-off", "check_id": "CRYPTO-TLS-001", "title": "TLS certificate or hostname verification disabled", "files": ["code", "config", "env", "shell", "docker"],
        "pattern": r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['\"]?0|verify\s*=\s*False|ssl\._create_unverified_context|CERT_NONE|check_hostname\s*=\s*False|InsecureSkipVerify\s*:\s*true|TrustAllCerts|X509TrustManager[^\n]*\{\s*$|ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|setHostnameVerifier\(\s*\([^)]*\)\s*->\s*true|ServerCertificateValidationCallback\s*=[^\n]*true|ServerCertificateCustomValidationCallback\s*=[^\n]*true|DangerousAcceptAnyServerCertificateValidator|verify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)|curl\s+(-k|--insecure)\b|wget\s+--no-check-certificate|sslmode=disable",
        "confidence": "HIGH",
        "examples": {"match": ["const agent = new https.Agent({ rejectUnauthorized: false });", "requests.get(url, verify=False)", "tls.Config{InsecureSkipVerify: true}"],
                     "no_match": ["const agent = new https.Agent({ ca: fs.readFileSync('ca.pem') });"]},
    },
    {
        "id": "crypto-old-tls", "check_id": "CRYPTO-TLS-001", "title": "Old TLS/SSL protocol versions allowed", "files": ["code", "config"],
        "pattern": r"(?i)(minVersion\s*:\s*['\"]TLSv1(\.1)?['\"]|secureProtocol\s*:\s*['\"](SSLv\d|TLSv1(_1)?)_method['\"]|PROTOCOL_(SSLv2|SSLv3|TLSv1|TLSv1_1)\b|TLSVersion\.(TLSv1|TLSv1_1)\b|MinVersion\s*:\s*tls\.Version(SSL30|TLS10|TLS11)|SslProtocols\.(Ssl2|Ssl3|Tls|Tls11)\b|ssl_protocols\s+[^;]*(SSLv[23]|TLSv1(\.1)?\s)|TLSv1(\.1)?\s*;)",
        "confidence": "HIGH",
        "examples": {"match": ["tls.createServer({ minVersion: 'TLSv1', key, cert });", "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;"],
                     "no_match": ["tls.createServer({ minVersion: 'TLSv1.2', key, cert });", "ssl_protocols TLSv1.2 TLSv1.3;"]},
    },
    # ------------------------------------------------------------------ CUSTOM
    {
        "id": "crypto-xor-or-base64", "check_id": "CRYPTO-CUSTOM-001", "title": "XOR or Base64 used as 'encryption'", "files": ["code"],
        "pattern": r"(?i)(def|function|func|fun|static\s+\w+|public\s+\w+|private\s+\w+)\s+(encrypt|decrypt|obfuscate|cipher|scramble)\w*\s*\(",
        "near": {"pattern": r"\^\s*\w|\^=|btoa\(|atob\(|base64|b64encode|b64decode|Base64\.(getEncoder|getDecoder|encode|decode)|Convert\.(To|From)Base64|\.charCodeAt\([^)]*\)\s*\^", "lines": 6},
        "not_near": {"pattern": r"(?i)createCipheriv|Cipher\.getInstance|AESGCM|Fernet|nacl|sodium|secretbox|aes\.NewCipher|Aes\.Create|crypto\.subtle", "lines": 10},
        "confidence": "MEDIUM",
        "examples": {"match": ["function encrypt(text) {\n  return btoa(text.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ 42)).join(''));\n}"],
                     "no_match": ["function encrypt(text) {\n  const c = crypto.createCipheriv('aes-256-gcm', key, iv);\n  return Buffer.concat([c.update(text), c.final()]).toString('base64');\n}"]},
    },
    {
        "id": "crypto-deprecated-library", "check_id": "CRYPTO-CUSTOM-001", "title": "Deprecated or unmaintained crypto library", "files": ["code", "config"],
        "pattern": r"(?i)(^\s*(from|import)\s+Crypto\.Cipher\b(?![^\n]*Cryptodome)|['\"]pycrypto['\"]|^\s*pycrypto\b|['\"]crypto-js['\"]|require\(\s*['\"]crypto-js|['\"]node-rsa['\"]|['\"]sjcl['\"]|['\"]bcrypt-nodejs['\"]|['\"]mcrypt['\"]|\bmcrypt_(encrypt|decrypt)\()",
        "confidence": "LOW", "note": "pycrypto is unmaintained (use pyca/cryptography or PyCryptodome); crypto-js is discontinued (use WebCrypto or node:crypto); mcrypt was removed from PHP.",
        "examples": {"match": ["import CryptoJS from 'crypto-js';", "$c = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $k, $d, MCRYPT_MODE_CBC, $iv);"],
                     "no_match": ["import { webcrypto } from 'node:crypto';"]},
    },
]
