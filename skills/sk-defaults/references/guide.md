# Insecure defaults and fail-open guide

Sources: OWASP Secure Design Principles (fail securely, secure by default), OWASP Error Handling and Authorization
cheat sheets, CWE-1188 / CWE-636 / CWE-276 / CWE-1392, Trail of Bits insecure-defaults guidance.

**Question to ask of every security control: what happens when its input is missing, empty, wrong or throws?** The
secure answer is always "the request is refused" (or "the app refuses to start"). These bugs survive testing because
tests run with a complete configuration; they appear in production when a variable is missing, a key rotates, a
dependency times out or a new environment is created.

## Checks

| Check | Fail-open pattern | Fail-closed version |
|---|---|---|
| DEFAULT-ENV-001 | `if (!process.env.WEBHOOK_SECRET) return next();` | Validate config at start-up (zod/pydantic settings, `required_env()`), throw if missing. |
| DEFAULT-FALLBACK-001 | `JWT_SECRET \|\| 'dev'`, `getenv('ALLOWED_HOSTS', '*')` | No default for secrets and allow-lists; separate `.env.development` for local values. |
| DEFAULT-CATCH-001 | `try { verify() } catch { return next() }`, `except Exception: pass`, Go `if err != nil { next.ServeHTTP(...) }` | Deny in the error path; log the error; alert on spikes. |
| DEFAULT-FLAG-001 | `VERIFY_SIGNATURES === 'true'` (unset = off), `def load(token, verify=False)` | `!== 'false'` (unset = on), refuse `false` when `NODE_ENV=production`; parameters default to verifying. |
| DEFAULT-ENVCHECK-001 | `NODE_ENV \|\| 'development'`, `DEBUG = env.bool('DEBUG', default=True)`, `if (NODE_ENV !== 'production') skipAuth()` | Default to production; debug opt-in; inject test doubles explicitly rather than sniffing the environment. |
| DEFAULT-ALLOW-001 | `switch (role) { … default: return true }`, `PERMISSIONS.get(action, True)`, `if (!allowlist.length) return true` | `default: return false`; `.get(action, False)`; empty list = deny all. |
| DEFAULT-NULL-001 | `req.headers['x-api-key'] === process.env.API_KEY` (both undefined → true), `!expected \|\| sig === expected` | Require the secret to be set; compare with `crypto.timingSafeEqual` / `hmac.compare_digest` only when both values are present. |
| DEFAULT-LIB-001 | `app.use(cors())`, `app.set('trust proxy', true)`, `cookie: { secure: false }` | Explicit origin list; trust the exact hop count; `Secure; HttpOnly; SameSite`. |
| DEFAULT-PERM-001 | `chmod 777`, `os.chmod(p, 0o777)`, `umask(0)` | `0o600` for secrets, `0o644`/`0o755` otherwise; run as a non-root user. |
| DEFAULT-ADMIN-001 | seeded `admin / admin123`, `/setup` that works forever | Random initial password printed once or set on first login; setup locks once an admin exists. |

## Confirming

For each candidate, write down the input that makes it fail open (variable unset, header absent, exception thrown, role
unknown) and whether that input can happen in production. Missing configuration *can* happen; treat "we always set
it" as defence in depth, not as a reason to dismiss. Severity follows what is unlocked (auth bypass → Critical/High).

## Tests

Add a test per confirmed finding that runs the control with the failing input (unset secret, throwing verifier,
unknown role, missing header) and asserts a denial.
