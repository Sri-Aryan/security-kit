# GraphQL security guide: how to verify and fix each concept

Language-neutral. Every GraphQL server has the same moving parts, whatever the library:

1. **Transport**: an HTTP (and maybe WebSocket) endpoint that accepts `{query, variables, operationName}`.
2. **Context**: built once per request. This is where the caller is authenticated.
3. **Validation**: parses the document and runs rules (depth, cost, introspection) *before* execution.
4. **Execution**: resolvers run per field. This is where authorization must happen (or in the data layer they call).
5. **Error formatting**: turns exceptions into `errors[]`.

Find each part in the project first. Most findings come from asking "is this concept enforced in that part?"

---

## Introspection, suggestions, IDEs (GQL-INTRO-*)

**Verify.** Find the server construction. Look for an explicit introspection setting, a validation rule that
blocks `__schema`/`__type`, or an environment switch. Missing setting = check the library default (many enable
introspection unless told otherwise). Dynamic: send `{__schema{types{name}}}` as an anonymous caller.
Suggestions: send a misspelled field and look for "Did you mean".

**Fix.** Disable introspection outside development (driven by an environment variable, failing closed),
or allow it only for authenticated internal roles. Disable suggestions / mask "Did you mean" in production
error formatting. Serve IDEs only in development.

Disabling introspection is defence in depth, not access control: the schema is often public anyway
(client bundles, docs). Never rely on it to hide sensitive fields.

## Depth, cost, pagination, size (GQL-DOS-*)

**Verify.** Look for a validation rule or plugin that rejects documents by depth and by cost *before*
execution. Check that list fields take a size argument and that the resolver clamps it (`min(first, MAX)`),
and that a missing argument gets a default, not "everything". Check body-size limits on the HTTP layer and
execution timeouts. Check nobody disabled the standard validation rules.

Dynamic: build a query that follows a cycle in the schema (e.g. `user → posts → author → posts …`) to a
depth of 10–15 and see if it executes.

**Fix.** Add depth (typically 7–12) and cost limits (list fields multiply child cost by the page size). Clamp
page sizes in resolvers. Set request size and timeout limits at the HTTP layer. For first-party clients,
persisted queries / an allow-list remove most of this risk.

## Batching (GQL-BATCH-*)

**Verify.** Can one HTTP request carry a JSON array of operations? Can one operation use hundreds of aliases
of the same field (`a1: login(...) a2: login(...)`)? Does the rate limiter count HTTP requests only?

Dynamic: send an array of 10 `{__typename}` operations; send one operation with 100 aliased `__typename`.

**Fix.** Disable array batching or cap it (e.g. ≤ 5). Limit aliases / root fields per operation. Make
sensitive mutations (login, OTP, password reset, coupon redeem) count each invocation against the rate
limit, not each HTTP request.

## Authentication (GQL-AUTHN-*)

**Verify.** Find where the context is built. Is the token verified there (signature, expiry), and what
happens when it is missing or invalid: reject the request, or continue as anonymous? If anonymous is allowed,
every resolver must then handle "no user". For subscriptions, find the connection handler: is the token
checked on connect, and is authorization re-evaluated per published event (a user removed from a
project must stop receiving its events)?

**Fix.** Verify credentials in context creation. Either reject unauthenticated requests at the transport
or mark the few public operations explicitly and default everything else to "authenticated required".
Authenticate WebSocket connections on connect and filter events per subscriber.

## Authorization (GQL-AUTHZ-*)

The key GraphQL-specific risk: **the same type is reachable through many paths.** `User.email` may be
guarded under `me`, but reachable unguarded via `order.customer.email` or `post.author.email`.

**Verify.**
1. List sensitive types and fields (the scanner flags names like password, token, email, role, ssn, internal).
2. For each, list *every* field in the schema that returns that type (all parents).
3. Confirm the guard lives on the field/type itself (field resolver, type-level directive or policy) or in
   the data layer, so it applies on every path. A check only in a root resolver does not protect nested paths.
4. For each resolver that takes an ID: confirm it scopes the lookup to the caller (owner / tenant), and that
   generic `node(id:)` / `_entities` resolvers do the same.
5. For each privileged mutation: confirm a role check.
6. For each input type: confirm protected fields (role, ownerId, tenantId, balance, verified) are not accepted,
   or are ignored unless the caller is privileged.

**Fix.** Put authorization in one layer that every path goes through: the data/service layer, or
type/field-level policies. Scope ID lookups by owner/tenant. Remove protected fields from input types (or
reject them by role). Prefer deny-by-default policies.

## Injection and SSRF (GQL-INJ-*)

Arguments are user input like any request parameter. Follow each argument from resolver to sink (database,
shell, template, file path, outbound HTTP). Same fixes as REST: parameterised queries, argument arrays for
processes, path confinement, URL allow-lists. Custom scalars should parse and bound input (length, format).

## Error masking (GQL-ERR-*)

**Verify.** Find the error formatter. In production, are unexpected exceptions replaced with a generic
message while expected (user-facing) errors pass through? Is "debug" / "include stacktrace" tied to the
environment? Dynamic: send a syntax error and a type error and inspect `errors[].extensions`.

**Fix.** Mask unexpected errors, log them server-side with a correlation ID, and return the ID.

## CSRF (GQL-CSRF-*)

Only relevant when the browser sends credentials automatically (cookies). **Verify.** Does the endpoint
execute operations from GET requests, and mutations over GET? Does it accept `text/plain` or form-encoded
bodies (no CORS preflight)? **Fix.** Reject mutations over GET, require `application/json` (or a custom
header such as `apollo-require-preflight` / `x-csrf-token`), and use `SameSite` cookies.

## Architecture (GQL-ARCH-*)

Federated subgraphs often trust the gateway and skip auth. **Verify** that subgraphs are not reachable from
the internet and that `_service` / `_entities` are only served to the gateway. **Fix**: network isolation plus
a shared secret or mTLS between gateway and subgraphs. Persisted queries let you reject any document you did
not ship.

## Test ideas (GQL-TEST-*)

- User B queries user A's object by ID → error / null.
- A normal user selects a sensitive field through each parent path → null or error.
- A normal user calls each privileged mutation → forbidden.
- Query deeper than the limit, more expensive than the limit, an array of N+1 operations, and N+1 aliases → rejected.
- Anonymous introspection in a production-like config → rejected.
