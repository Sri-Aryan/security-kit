# OpenAPI contract guide: how to verify and fix each concept

Language-neutral. A spec is a **claim** about the API. Security problems live in the gaps between the
claim and the code (drift) and in what the claim fails to forbid (open schemas, missing limits, optional
auth). The spec format is the same whatever generated it.

---

## Finding the spec (OAS-INV-001)

1. **Files**: `openapi.{yaml,yml,json}`, `swagger.{yaml,json}`, `api-docs.json`, `docs/api/*.yaml`, or any
   YAML/JSON whose top level has `openapi:` or `swagger:`.
2. **Generated at runtime**: many frameworks serve it (common paths: `/openapi.json`, `/v3/api-docs`,
   `/swagger.json`, `/api-docs`, `/docs/openapi.json`). If no file exists and the app runs locally, fetch it
   with `--spec-url` (localhost only).
3. **Generated at build time**: check scripts and CI for spec generation, and use that output.

If several specs exist (public vs internal, v1 vs v2), audit each and say which is the contract.

## Drift (OAS-DRIFT-*)

Undocumented endpoints are the classic "shadow API": nobody tests, reviews or rate-limits them. Stale spec
entries mislead clients and testers, and may still be served by an old deployment.

**Verify.** Compare the spec's operations with the code's routes (the script does this when `sk-api`'s route
discovery is installed or a routes file is given). Matching rules: same method; same path once parameter
names are ignored (`/orders/{id}` = `/orders/:orderId`); the spec's server base path (`/api/v1`) may or may
not appear in code. Treat health/metrics endpoints as "documented elsewhere" only if they truly are.

**Fix.** Document or remove each undocumented route; remove stale entries; retire deprecated operations on a
schedule; protect or remove old versions. Generate the spec from code or test the contract in CI, so drift
fails the build.

## Security declarations (OAS-AUTH-*)

- Define `components.securitySchemes` (Swagger 2.0: `securityDefinitions`) and a **top-level `security`**
  requirement, so every operation is secured unless it opts out.
- `security: []` on an operation means "no auth". A requirement list containing `{}` means "auth
  optional". Both must be deliberate, especially on POST/PUT/PATCH/DELETE.
- Compare with code: an operation the spec marks as secured but whose route has no auth middleware is a real
  gap (or the spec is wrong). Either way, one must change.
- Weak schemes: `http`/`basic` (password on every request), `apiKey` with `in: query` (keys end up in
  logs, browser history and proxies), OAuth2 `implicit` and `password` flows (deprecated in OAuth 2.1).
- Privileged operations should list the scopes/roles they need; secured operations should document 401/403.

## Data contracts (OAS-DATA-*)

- **Mass assignment**: an object schema without `additionalProperties: false` lets clients send extra
  fields. If the server binds bodies to models, extras like `role` or `isAdmin` may stick. Close write schemas.
- Fields the server controls (`id`, `role`, `ownerId`, `tenantId`, `createdAt`, `balance`, `verified`)
  should be `readOnly: true` or absent from request schemas, and the server must ignore them.
- **Excessive data exposure**: response schemas listing `password`, `passwordHash`, `secret`, `apiKey`,
  `ssn`, `cardNumber`, `cvv`, internal notes. If the schema says it is returned, it probably is.
- Constrain inputs: `maxLength`, `pattern`, `format`, `enum`, `minimum`/`maximum`. Unbounded strings are
  where injection payloads and memory abuse begin.
- Error schemas must not have `stack`, `trace`, `exception` or `sql` properties.

Note: the spec only describes. Confirm the server **enforces** the schema (request validation middleware or
explicit validation). An unenforced `additionalProperties: false` protects nothing.

## Limits (OAS-LIMIT-*)

Arrays need `maxItems`; pagination parameters need a `maximum` (and the server must clamp to it). Uploads
need size limits and an allowed content-type list. Document 429 where rate limits apply.

## Exposure (OAS-EXPO-*)

`servers` should be HTTPS and public. Internal hostnames, staging URLs and private IPs in a public spec help
attackers map infrastructure. Examples must use obviously fake data. Decide deliberately whether the spec and
Swagger UI are public. Internal and admin specs should not be.

## Test ideas

- Contract test in CI: every route in code is in the spec, and every request/response validates against it.
- Send an unknown field (e.g. `"role": "admin"`) to each write endpoint → 400, or ignored and not persisted.
- Request a page size above the documented maximum → clamped or 400.
- Call each operation the spec marks as secured without credentials → 401.
