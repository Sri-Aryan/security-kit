"""sk-privacy rules: personal data exposure, third-party sharing, consent, deletion, sensitive fields, prod dumps."""

SKILL = "sk-privacy"

MACROS = {
    "PII": r"(?i:email|e_?mail|phone|mobile|full_?name|first_?name|last_?name|address|street|zip|postcode|ssn|national_?id|passport|dob|birth\w*|gender|ip_?address|location|lat|lng)",
    "SENSITIVE_PII": r"(?i:ssn|social_?security\w*|national_?id\w*|passport\w*|tax_?id|driver_?licen[cs]e\w*|medical\w*|diagnosis|health\w*|condition|prescription|biometric\w*|dob|date_?of_?birth|birth_?date|iban|bank_?account\w*|account_?number|religion|ethnicity|sexual\w*)",
}

RULES = [
    # ------------------------------------------------------------------ SHARE
    {
        "id": "priv-pii-to-analytics", "check_id": "PRIV-SHARE-001", "title": "Personal data sent to an analytics/marketing SDK", "files": ["code", "web"],
        "pattern": r"(?i)\b(analytics|mixpanel|amplitude|segment|posthog|gtag|dataLayer|heap|fullstory|FS|hotjar|hj|intercom|braze|klaviyo|_learnq|customerio|cio|Sentry|LogRocket|clarity|rudderanalytics|fbq|ttq|snaptr|pendo|hubspot|_hsq)\.?(identify|track|people\.set|capture|setUserProperties|setUser|alias|register|push|set|page|event)\s*\([^\n]*\b{{PII}}\b",
        "confidence": "MEDIUM", "note": "Send an internal user ID instead of email/name, or hash and minimize; list each processor.",
        "examples": {"match": ["analytics.identify(user.id, { email: user.email, name: user.name });", "posthog.capture('signup', { email })"],
                     "no_match": ["analytics.identify(user.id, { plan: user.plan });"]},
    },
    {
        "id": "priv-tracking-without-consent", "check_id": "PRIV-CONSENT-001", "type": "absence", "scope": "project",
        "title": "Tracking scripts loaded with no consent mechanism in the project", "files": ["js", "web", "py", "rb", "php"],
        "when": r"(?i)googletagmanager\.com|gtag\(|\bfbq\(|connect\.facebook\.net|static\.hotjar\.com|hotjar|mixpanel\.init|amplitude\.(init|getInstance)|posthog\.init|clarity\.ms|snap\.licdn\.com|analytics\.tiktok\.com|js\.hs-scripts\.com|segment\.com/analytics",
        "missing": r"(?i)consent|cookie.?banner|cookiebot|onetrust|usercentrics|klaro|didomi|termly|iubenda|osano|optIn|opt_in|ad_storage|analytics_storage",
        "confidence": "MEDIUM",
        "examples": {"match": ["<script async src=\"https://www.googletagmanager.com/gtag/js?id=G-X\"></script>"],
                     "no_match": ["<script>gtag('consent', 'default', { analytics_storage: 'denied' });</script>\n<script async src=\"https://www.googletagmanager.com/gtag/js?id=G-X\"></script>"]},
    },
    # ------------------------------------------------------------------ EXPOSE
    {
        "id": "priv-pii-in-url", "check_id": "PRIV-EXPOSE-001", "title": "Personal or secret data placed in a URL query string", "files": ["code", "web"],
        "pattern": r"(?i)['\"`][^'\"`\s]*[?&](email|e-mail|phone|mobile|ssn|dob|birth\w*|address|password|passwd|token|card|iban|national_?id)=",
        "confidence": "MEDIUM", "note": "URLs end up in browser history, server and proxy logs, analytics and Referer headers.",
        "examples": {"match": ["fetch(`/api/users/lookup?email=${email}`);", "redirect('/verify?phone=' + phone)"],
                     "no_match": ["fetch('/api/users/lookup', { method: 'POST', body: JSON.stringify({ email }) });"]},
    },
    {
        "id": "priv-full-record-response", "check_id": "PRIV-EXPOSE-001", "title": "Whole user/customer record returned to the client", "files": ["code"],
        "pattern": r"(res\.(json|send)|jsonify|JsonResponse|Response|Ok|ResponseEntity\.ok|c\.JSON\([^,]+,|render\s+json:)\s*\(?\s*(user|users|customer|customers|patient|patients|member|members|profile|profiles|account|accounts|employee|employees)\s*\)?\s*[;)]?\s*$",
        "confidence": "LOW", "note": "Raw records carry every column (hashes, tokens, internal notes, other people's data). Serialize an explicit field list.",
        "examples": {"match": ["res.json(user);", "return jsonify(customer)"], "no_match": ["res.json({ id: user.id, name: user.name });"]},
    },
    {
        "id": "priv-pii-browser-storage", "check_id": "PRIV-EXPOSE-001", "title": "Personal data stored in browser storage", "files": ["js", "web"],
        "pattern": r"(?i)(localStorage|sessionStorage)\.setItem\(\s*['\"`][^'\"`]*\b(email|phone|address|ssn|dob|birth|profile|user|customer|patient|card)\w*['\"`]",
        "confidence": "LOW", "note": "Readable by any script on the origin (XSS, third-party scripts) and persists on shared devices.",
        "examples": {"match": ["localStorage.setItem('userProfile', JSON.stringify(profile));"], "no_match": ["localStorage.setItem('theme', 'dark');"]},
    },
    # ------------------------------------------------------------------ ENC
    {
        "id": "priv-sensitive-field-plaintext", "check_id": "PRIV-ENC-001", "title": "Highly sensitive personal field stored as plain text", "files": ["code", "sql", "config"],
        "pattern": r"\b{{SENSITIVE_PII}}\b['\"]?\s*[:=]?\s*(String|VARCHAR|varchar|TEXT|text|CHAR|char|Column\(\s*(String|Text|db\.String|db\.Text)|models\.(Char|Text)Field|@Column|DataTypes\.(STRING|TEXT)|t\.(string|text)|\{\s*type\s*:\s*String)",
        "not_near": {"pattern": r"(?i)encrypt|cipher|EncryptedType|encrypted_|attr_encrypted|Lockbox|pgcrypto|fernet|kms|vault|tokeni[sz]", "lines": 2},
        "confidence": "LOW",
        "examples": {"match": ["  ssn: { type: String, required: true },", "    date_of_birth VARCHAR(10),", "    diagnosis = models.TextField()"],
                     "no_match": ["  ssn: { type: String, set: encrypt, get: decrypt },", "  theme: { type: String },"]},
    },
    # ------------------------------------------------------------------ MIN
    {
        "id": "priv-fingerprint-location", "check_id": "PRIV-MIN-001", "title": "Device fingerprinting or precise location collected", "files": ["js", "web", "code"],
        "pattern": r"@fingerprintjs|fingerprintjs|FingerprintJS|navigator\.geolocation\.(getCurrentPosition|watchPosition)|CLLocationManager|requestLocationUpdates|ACCESS_FINE_LOCATION|canvas\.toDataURL\([^)]*\)[^\n]*(hash|fingerprint)",
        "confidence": "LOW", "note": "Confirm the purpose, consent and retention; prefer coarse location.",
        "examples": {"match": ["navigator.geolocation.watchPosition(save);", "import FingerprintJS from '@fingerprintjs/fingerprintjs';"],
                     "no_match": ["const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;"]},
    },
    # ------------------------------------------------------------------ DSR / RET
    {
        "id": "priv-no-account-deletion", "check_id": "PRIV-DSR-001", "type": "absence", "scope": "project",
        "title": "User accounts exist but no account deletion/erasure code was found", "files": ["code", "sql"],
        "when": r"(?i)(class|model|table|create\s+table|interface|type)\s+[`'\"]?(users?|accounts?|customers?|members?|profiles?)\b",
        "missing": r"(?i)(delete_?account|deleteAccount|account_?deletion|close_?account|closeAccount|erase\w*user|anonymi[sz]e|gdpr|right_?to_?be_?forgotten|purge_?user|purgeUser|destroy_?user|deleteUser|delete_user|deleteMe|delete_me|\bon_delete\b.*CASCADE)",
        "confidence": "LOW",
        "examples": {"match": ["class User(Base):\n    __tablename__ = 'users'"], "no_match": ["class User(Base):\n    __tablename__ = 'users'\n\ndef delete_account(user): anonymize(user)"]},
    },
    {
        "id": "priv-no-retention", "check_id": "PRIV-RET-001", "type": "absence", "scope": "project",
        "title": "Personal data stored but no retention/purge mechanism found", "files": ["code", "sql", "config"],
        "when": r"(?i)\b(email|phone|ip_?address|address)\b\s*[:=]?\s*(String|VARCHAR|varchar|TEXT|text|Column\(|models\.\w+Field|@Column|DataTypes\.|t\.string|\{\s*type\s*:)",
        "missing": r"(?i)(retention|purge|expire_?after|expireAfterSeconds|ttl\b|TTL\s*=|delete_?old|cleanup_?old|prune|data_?lifecycle|lifecycle_rule|older_?than)",
        "confidence": "LOW",
        "examples": {"match": ["  email: { type: String, required: true },"], "no_match": ["  email: { type: String, required: true },\n// nightly job: purge inactive accounts after 24 months (retention policy)"]},
    },
    # ------------------------------------------------------------------ ANON
    {
        "id": "priv-prod-dump-to-dev", "check_id": "PRIV-ANON-001", "title": "Production database dump used outside production", "files": ["shell", "code", "config", "docker", "Makefile"],
        "pattern": r"(?i)(pg_dump|mysqldump|mongodump|mongoexport|pg_restore|mongorestore|heroku\s+pg:pull|pgcopydb|db:pull|snapshot)[^\n]*\b(prod|production|live)(?![a-z])",
        "not_near": {"pattern": r"(?i)anonymi[sz]|mask|scrub|obfuscat|fake|synthetic|redact|pseudonymi", "lines": 4}, "confidence": "MEDIUM",
        "examples": {"match": ["pg_dump $PROD_DATABASE_URL | psql $LOCAL_DATABASE_URL", "heroku pg:pull DATABASE_URL localdb --app acme-production"],
                     "no_match": ["pg_dump $PROD_DATABASE_URL | anonymize | psql $LOCAL_DATABASE_URL"]},
    },
]
