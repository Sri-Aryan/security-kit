"""sk-passkeys rules: WebAuthn/passkey ceremonies, magic links and emailed/SMS one-time codes."""

SKILL = "sk-passkeys"

MACROS = {
    "VERIFY_AUTHN": r"verifyAuthenticationResponse\(|verify_authentication_response\(|\.FinishLogin\(|\.ValidateLogin\(|finishAssertion\(|MakeAssertionAsync\(|finish_passkey_authentication\(|verifyAuthentication\(|server\.verifyAuthentication\(",
    "GEN_REG": r"generateRegistrationOptions\(|generate_registration_options\(|\.BeginRegistration\(|startRegistration\(\s*StartRegistrationOptions|RequestNewCredential\(|start_passkey_registration\(|register_begin\(|server\.register_begin\(",
    "SESSION_SET": r"(?i:createSession|setSession|lucia\.createSession|signIn\(|login\(|req\.login\(|req\.session\.\w+\s*=|session\[['\"]\w+['\"]\]\s*=|cookies\(\)\.set\(|res\.cookie\(|set_cookie\(|setCookie\(|issueSession|create_session)",
}

RULES = [
    # ------------------------------------------------------------------ CHALLENGES
    {
        "id": "passkey-weak-challenge", "check_id": "PASSKEY-CHAL-001", "title": "WebAuthn challenge that is fixed or not cryptographically random", "files": ["code"],
        "pattern": r"(?i)\bchallenge\s*[:=]\s*(['\"`][^'\"`$]{2,}['\"`]\s*[,;}\n)]|[^\n;]*({{WEAK_RANDOM}}|Date\.now\(\)|new\s+Date\(\)|\btime\.time\(\)))",
        "near": {"pattern": r"(?i)webauthn|passkey|publicKey|credential|attestation|assertion|rpId|rp_id", "lines": 15}, "confidence": "HIGH",
        "examples": {"match": ["const options = { publicKey: { challenge: 'abc123', rp: { name: 'Acme' } } };", "const challenge = Math.random().toString(36); // webauthn"],
                     "no_match": ["const options = await generateAuthenticationOptions({ rpID }); // webauthn challenge from the library"]},
    },
    {
        "id": "passkey-challenge-from-client", "check_id": "PASSKEY-CHAL-001", "title": "Expected challenge taken from the client response", "files": ["code"],
        "pattern": r"(?i)(expectedChallenge|expected_challenge)\s*[:=]\s*(req\.body|body\b|request\.(json|data|body)|response\.|credential\.|input\.|\w*clientData\w*\.challenge|data\[)",
        "confidence": "HIGH", "note": "The expected challenge must come from server-side storage tied to this session, so replayed or forged responses fail.",
        "examples": {"match": ["await verifyAuthenticationResponse({ response: body, expectedChallenge: body.challenge, expectedOrigin, expectedRPID });"],
                     "no_match": ["await verifyAuthenticationResponse({ response: body, expectedChallenge: session.currentChallenge, expectedOrigin, expectedRPID });"]},
    },
    {
        "id": "passkey-challenge-not-cleared", "check_id": "PASSKEY-CHAL-001", "type": "absence", "scope": "file",
        "title": "Stored challenge never cleared after verification (replayable)", "files": ["code"],
        "when": "{{VERIFY_AUTHN}}",
        "missing": r"(?i)(delete|del|remove|clear|unset|destroy|expire|getdel|GETDEL|pop)\w*\s*\(?[^\n]*challenge|challenge\w*\s*=\s*(null|None|undefined|''|\"\")",
        "confidence": "LOW",
        "examples": {"match": ["const v = await verifyAuthenticationResponse({ response, expectedChallenge: user.challenge, expectedOrigin, expectedRPID });"],
                     "no_match": ["const v = await verifyAuthenticationResponse({ response, expectedChallenge: c, expectedOrigin, expectedRPID });\nawait redis.del(`challenge:${sid}`);"]},
    },
    # ------------------------------------------------------------------ ORIGIN / RP ID
    {
        "id": "passkey-origin-from-request", "check_id": "PASSKEY-ORIGIN-001", "title": "Expected origin / RP ID derived from the request", "files": ["code"],
        "pattern": r"(?i)(expectedOrigin|expected_origin|expectedRPID|expected_rp_id|rpID|rp_id|rpId|RPID|RPOrigins?)\s*[:=]\s*[^\n]*({{HOST_HEADER}}|req\.headers\.origin|req\.get\(\s*['\"]origin|request\.headers\[?\.?(get\()?\s*['\"]origin|headers\(\)\.get\(\s*['\"](origin|host)|\breq\.url\b|\brequest\.url\b|r\.Header\.Get\(\s*\"Origin)",
        "confidence": "HIGH", "note": "An attacker-controlled Origin/Host makes the server accept assertions made for another site. Configure origins and RP ID as constants.",
        "examples": {"match": ["await verifyRegistrationResponse({ response, expectedChallenge, expectedOrigin: req.headers.origin, expectedRPID: req.hostname });"],
                     "no_match": ["await verifyRegistrationResponse({ response, expectedChallenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID });"]},
    },
    # ------------------------------------------------------------------ VERIFICATION
    {
        "id": "passkey-hand-rolled-parsing", "check_id": "PASSKEY-VERIFY-001", "title": "Hand-rolled WebAuthn parsing/verification", "files": ["code"],
        "pattern": r"JSON\.parse\([^)\n]*clientDataJSON|base64url\.decode\([^)\n]*clientDataJSON|json\.loads\([^)\n]*client_?data_?json|cbor\.decode(First)?\(|cbor2\.loads\(|authenticatorData\.slice\(|parseAuthenticatorData\(|attestationObject\s*\)\s*\.\s*authData",
        "file_excludes": r"(?i)@simplewebauthn|from\s+webauthn\b|import\s+webauthn\b|from\s+fido2|go-webauthn|webauthn4j|Fido2NetLib|com\.yubico|webauthn_rs|webauthn-rs|@passwordless-id|@teamhanko|passage|@github/webauthn-json",
        "confidence": "MEDIUM", "note": "Custom WebAuthn verification routinely misses checks (type, origin, RP ID hash, flags, signature over authData+clientDataHash, counter). Use a maintained library.",
        "examples": {"match": ["const clientData = JSON.parse(Buffer.from(cred.response.clientDataJSON, 'base64url').toString());"],
                     "no_match": ["import { verifyAuthenticationResponse } from '@simplewebauthn/server';\nconst clientData = JSON.parse(Buffer.from(cred.response.clientDataJSON, 'base64url').toString());"]},
    },
    {
        "id": "passkey-client-verified-flag", "check_id": "PASSKEY-VERIFY-001", "title": "Server trusts a client-reported verification result", "files": ["code"],
        "pattern": r"(?i)(if\s*\(?\s*|=\s*)(req\.body|body|request\.(json|data)|data|input)\s*(\.|\[['\"])(verified|isVerified|passkeyVerified|webauthnOk|success)\b",
        "near": {"pattern": r"(?i)passkey|webauthn|credential|assertion", "lines": 10}, "confidence": "HIGH",
        "examples": {"match": ["// passkey login\nif (req.body.verified) { req.session.userId = req.body.userId; }"],
                     "no_match": ["// passkey login\nconst { verified } = await verifyAuthenticationResponse(opts);\nif (verified) {}"]},
    },
    # ------------------------------------------------------------------ USER VERIFICATION
    {
        "id": "passkey-uv-not-required", "check_id": "PASSKEY-UV-001", "title": "User verification not required for a sole-factor passkey", "files": ["code"],
        "pattern": r"userVerification\s*:\s*['\"]discouraged['\"]|requireUserVerification\s*:\s*false|require_user_verification\s*=\s*False|UserVerificationRequirement\.DISCOURAGED|user_verification\s*=\s*UserVerificationRequirement\.DISCOURAGED",
        "confidence": "MEDIUM", "note": "Without UV, a passkey only proves possession of the device, not that its owner unlocked it. Fine as a second factor; not as the only factor.",
        "examples": {"match": ["await verifyAuthenticationResponse({ ...opts, requireUserVerification: false });"], "no_match": ["await verifyAuthenticationResponse({ ...opts, requireUserVerification: true });"]},
    },
    # ------------------------------------------------------------------ CREDENTIAL BINDING / COUNTER
    {
        "id": "passkey-counter-ignored", "check_id": "PASSKEY-COUNTER-001", "type": "absence", "scope": "file",
        "title": "Signature counter never stored after authentication", "files": ["code"],
        "when": "{{VERIFY_AUTHN}}", "missing": r"(?i)counter|sign_?count|signCount|newCounter|new_sign_count|SignCount|update_credential|updateCredential",
        "confidence": "LOW", "note": "Synced passkeys report 0, but hardware keys increment; storing it lets you spot cloned authenticators.",
        "examples": {"match": ["const { verified } = await verifyAuthenticationResponse({ response, expectedChallenge, expectedOrigin, expectedRPID, credential });"],
                     "no_match": ["const { verified, authenticationInfo } = await verifyAuthenticationResponse(opts);\nawait db.passkey.update({ where: { id }, data: { counter: authenticationInfo.newCounter } });"]},
    },
    {
        "id": "passkey-credential-lookup-unscoped", "check_id": "PASSKEY-CRED-001", "title": "Credential loaded by ID alone during a user-scoped login", "files": ["code"],
        "pattern": r"(?i)(passkey|credential|authenticator|webauthn\w*)\w*\.(findUnique|findFirst|findOne|get|find_by|filter|query)\(\s*[^\n]*\b(id|credential_?id|credentialId)\s*[:=]+\s*(body|req\.body|response|cred|credential|data)\.(id|rawId|credentialId)",
        "not_near": {"pattern": r"(?i)userHandle|user_handle|userId\s*[:=]|user_id\s*[:=]|\.userId\s*!==?|\.user_id\s*!=|owner", "lines": 8},
        "confidence": "LOW", "note": "When a username was entered first, the credential must belong to that user. For discoverable (usernameless) logins, take the user from the credential and compare userHandle.",
        "examples": {"match": ["const cred = await db.passkey.findUnique({ where: { id: body.id } });"],
                     "no_match": ["const cred = await db.passkey.findUnique({ where: { id: body.id } });\nif (cred.userId !== pendingUserId) throw new Error('mismatch');"]},
    },
    # ------------------------------------------------------------------ REGISTRATION
    {
        "id": "passkey-registration-unauthenticated", "check_id": "PASSKEY-REG-001", "type": "absence", "scope": "file",
        "title": "Passkey registration options generated with no signed-in user in sight", "files": ["code"],
        "when": "{{GEN_REG}}",
        "missing": r"(?i)session|currentUser|current_user|req\.user|request\.user|auth\(\)|getServerSession|getUser\(|requireUser|isAuthenticated|login_required|@Authorize|\[Authorize\]|signup|sign_up|register(User|_user)|createUser",
        "confidence": "MEDIUM", "note": "Adding a passkey to an existing account must require that account's session (ideally a recent re-authentication); otherwise anyone can attach their device to any username.",
        "examples": {"match": ["app.post('/passkeys/register/options', async (req, res) => {\n  const user = await db.user.findUnique({ where: { email: req.body.email } });\n  res.json(await generateRegistrationOptions({ rpName, rpID, userName: user.email }));\n});"],
                     "no_match": ["app.post('/passkeys/register/options', requireUser, async (req, res) => {\n  res.json(await generateRegistrationOptions({ rpName, rpID, userName: req.user.email }));\n});"]},
    },
    {
        "id": "passkey-no-exclude-credentials", "check_id": "PASSKEY-REG-001", "type": "absence", "scope": "file",
        "title": "Registration without excludeCredentials", "files": ["code"],
        "when": "{{GEN_REG}}", "missing": r"(?i)excludeCredentials|exclude_credentials|ExcludeCredentials|exclusions|WithExclusions",
        "confidence": "LOW",
        "examples": {"match": ["const opts = await generateRegistrationOptions({ rpName, rpID, userName });"],
                     "no_match": ["const opts = await generateRegistrationOptions({ rpName, rpID, userName, excludeCredentials: existing });"]},
    },
    # ------------------------------------------------------------------ MAGIC LINKS
    {
        "id": "magic-weak-token", "check_id": "PASSKEY-MAGIC-001", "title": "Magic-link/login token that is short or not cryptographically random", "files": ["code"],
        "pattern": r"(?i)(magic|login|signin|sign_in|email|auth|verification|verify)_?(link|token|code)\w*\s*[:=]\s*[^\n;]*({{WEAK_RANDOM}}|Date\.now\(\)|\btime\(\)|nanoid\(\s*[1-9]\s*\)|randomBytes\(\s*([1-9]|1[0-5])\s*\)|token_hex\(\s*([1-9]|1[0-5])\s*\)|token_urlsafe\(\s*([1-9]|1[0-5])\s*\)|SecureRandom\.hex\(\s*([1-9]|1[0-5])\s*\))",
        "confidence": "HIGH", "note": "Use at least 16 random bytes (128 bits) from crypto.randomBytes / secrets.token_urlsafe.",
        "examples": {"match": ["const magicToken = Math.random().toString(36).slice(2);", "login_token = secrets.token_urlsafe(8)"],
                     "no_match": ["const magicToken = crypto.randomBytes(32).toString('base64url');"]},
    },
    {
        "id": "magic-token-stored-plain", "check_id": "PASSKEY-MAGIC-001", "title": "Login token stored in plain text", "files": ["code"],
        "pattern": r"(?i)\b(magic|login|signin|email|verification|verify)_?(token|link_token|code)\w*\s*:\s*(token|magicToken|loginToken|rawToken|code|plainToken)\s*[,}]",
        "not_near": {"pattern": r"(?i)hash|sha256|digest|createHash|bcrypt|hmac", "lines": 5}, "confidence": "LOW",
        "note": "A database leak or read-only SQL injection then becomes account takeover. Store a SHA-256 of the token and compare hashes.",
        "examples": {"match": ["await db.loginToken.create({ data: { userId, magicToken: token, expiresAt } });"],
                     "no_match": ["const hash = createHash('sha256').update(token).digest('hex');\nawait db.loginToken.create({ data: { userId, magicToken: hash, expiresAt } });"]},
    },
    {
        "id": "magic-link-get-signs-in", "check_id": "PASSKEY-MAGIC-002", "title": "GET request on a magic link signs the user in directly", "files": ["code"],
        "pattern": r"(?i)(router|app|r|server|fastify)\.get\(\s*['\"`][^'\"`]*(magic|verify|login|signin|sign-in|callback|auth/email|passwordless)[^'\"`]*['\"`]",
        "near": {"pattern": "{{SESSION_SET}}", "lines": 25}, "confidence": "LOW",
        "note": "Email security scanners open links before the user does (consuming or even using the token), and a forwarded link signs in whoever clicks it. Show a page with a 'Sign in' button that POSTs, and bind the link to the requesting browser.",
        "examples": {"match": ["app.get('/auth/magic', async (req, res) => {\n  const user = await consumeToken(req.query.token);\n  req.session.userId = user.id;\n  res.redirect('/');\n});"],
                     "no_match": ["app.get('/auth/magic', (req, res) => res.render('confirm-sign-in', { token: req.query.token }));"]},
    },
    {
        "id": "magic-link-host-header", "check_id": "PASSKEY-MAGIC-003", "title": "Magic/verification link built from the request Host", "files": ["code"],
        "pattern": r"(?i)(magic|login|signin|sign_in|verify|verification|confirm|callback|invite)\w*(link|url)\w*\s*[:=]\s*[^\n]*({{HOST_HEADER}}|req\.protocol\s*\+|request\.url_root|headers\(\)\.get\(\s*['\"](host|origin|x-forwarded-host))|`https?://\$\{\s*({{HOST_HEADER}}|req\.headers\.origin)[^`]*(token|magic|login|verify|code)",
        "confidence": "HIGH", "note": "A forged Host header makes your own email deliver a link to the attacker's domain, carrying the victim's token. Use a configured base URL.",
        "examples": {"match": ["const magicLink = `${req.protocol}://${req.headers.host}/auth/magic?token=${token}`;"],
                     "no_match": ["const magicLink = `${process.env.APP_URL}/auth/magic?token=${token}`;"]},
    },
    # ------------------------------------------------------------------ OTP CODES
    {
        "id": "otp-weak-generation", "check_id": "PASSKEY-OTP-001", "title": "One-time code generated with a non-cryptographic RNG", "files": ["code"],
        "pattern": r"(?i)(otp|code|pin|verification_?code|verificationCode|login_?code|loginCode)\w*\s*[:=]\s*[^\n;]*(Math\.floor\(\s*\d+\s*\+\s*Math\.random|Math\.random\(\)\s*\*|\brandom\.randint\(|\brandint\(|\brand\(|\bmt_rand\(|new\s+Random\(\)|rand\.Intn\()",
        "confidence": "HIGH", "note": "Use crypto.randomInt / secrets.randbelow / SecureRandom, at least 6 digits, with a short expiry.",
        "examples": {"match": ["const code = Math.floor(100000 + Math.random() * 900000);", "otp = random.randint(1000, 9999)"],
                     "no_match": ["const code = crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');"]},
    },
    {
        "id": "otp-no-attempt-limit", "check_id": "PASSKEY-OTP-001", "type": "absence", "scope": "file",
        "title": "Code verification with no attempt limit in the file", "files": ["code"],
        "when": r"(?i)(verify|check|validate)_?(otp|code|magic_?code|login_?code|email_?code)\w*\s*\(|\b(otp|code)\s*(===?|!==?)\s*[\w.]*(otp|code)\b",
        "missing": "{{RATE_LIMIT}}|(?i:attempts|tries|retries|maxAttempts)",
        "confidence": "LOW", "note": "A 6-digit code falls to about a million guesses; cap attempts per code and per account, then invalidate the code.",
        "examples": {"match": ["export async function verifyOtp(email, code) {\n  const rec = await db.otp.findFirst({ where: { email } });\n  return rec.code === code;\n}"],
                     "no_match": ["export async function verifyOtp(email, code) {\n  if (rec.attempts >= 5) throw new Error('locked');\n  return rec.code === code;\n}"]},
    },
    # ------------------------------------------------------------------ ENUMERATION
    {
        "id": "passwordless-enumeration", "check_id": "PASSKEY-ENUM-001", "title": "Passwordless request reveals whether the account exists", "files": ["code", "web"],
        "pattern": r"(?i)['\"`](no account|user not found|account (does not|doesn't) exist|not registered|email not found|no user with)[^'\"`]*['\"`]",
        "near": {"pattern": r"(?i)magic|otp|passkey|login.?link|sign.?in.?link|send.?code|one.?time", "lines": 15}, "confidence": "MEDIUM",
        "examples": {"match": ["// send magic link\nif (!user) return res.status(404).json({ error: 'No account with that email' });"],
                     "no_match": ["// send magic link\nreturn res.json({ message: 'If an account exists, we sent a link.' });"]},
    },
]
