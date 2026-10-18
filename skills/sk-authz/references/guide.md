# Authorization guide

Sources: OWASP Authorization, Multi-Tenant Security, IDOR Prevention cheat sheets; OWASP Top 10 A01; API Top 10 API1,
API3, API5. Framework-neutral.

Broken access control is the #1 web risk because authorization is usually **sprinkled**, not **designed**. Look at the
system, not just endpoints: what is the model, where is it enforced, and what happens when someone forgets?

## Map the model (AUTHZ-MODEL-001)

Write down, from the code: subjects (user, service, API key, agent), roles/permissions/attributes, resources and
their owner/tenant fields, and the rule for each action. Common shapes: **RBAC** (role → permissions), **ABAC**
(attributes of user, resource, context), **ReBAC** (relationships: member of, owner of, shared with). Policy
engines (OPA/Rego, Cedar, Casbin, Oso, OpenFGA/SpiceDB) or framework policies (Pundit, CanCanCan, Django
permissions, Laravel policies, ASP.NET policies, Spring `@PreAuthorize`, NestJS guards) make the model explicit.

## Enforce centrally and deny by default (AUTHZ-CENTRAL-001, AUTHZ-DENY-001)

- One global "authenticated" requirement, with an explicit, short list of public routes.
- One way to ask "may this subject do this action on this resource?" (`authorize(user, 'update', invoice)`), called
  in the server: in the handler or service, or as data-layer scoping. UI checks are UX, not security.
- Prefer **scoping queries** to checking afterwards: `Invoice.where(org_id: current_user.org_id).find(id)` cannot
  return another tenant's row even if a check is forgotten.

## Never trust the client for authorization (AUTHZ-CLIENT-001, AUTHZ-ESC-001)

Role, tenant, permissions and owner come from the **server-side session or user record**, never from body, query,
headers (`X-User-Role`, `X-Tenant-Id`), cookies, hidden fields or unsigned/unverified tokens. Update endpoints copy an
**allow-list** of fields; role and membership changes are separate, admin-only operations that also prevent
self-escalation and removing the last admin.

## Tenants (AUTHZ-TENANT-001)

Tenant ID from the session (or verify membership if the user picks a tenant). Every query, cache key, file path,
search index and queue message carries the tenant. Consider database row-level security (PostgreSQL RLS, Supabase
policies) as a second layer. Background jobs must re-establish the tenant from the job record, not from global state.

## Objects, fields, files (AUTHZ-OBJECT-001, AUTHZ-FIELD-001, AUTHZ-STATIC-001)

- Load by ID **and** owner/tenant, or check after loading; return 404 rather than 403 if existence itself is sensitive.
- Serialize per role (separate output schemas); never return the raw ORM object.
- Files and exports go through an authorized route or short-lived signed URLs, not public static folders.

## Freshness and tests (AUTHZ-FRESH-001, AUTHZ-TEST-001)

Short access-token lifetimes (or server-side permission lookups) so revocation takes effect. Keep a table-driven
test of role × action × resource with expected status codes, including another tenant's resource (see `/sk-tests`).
