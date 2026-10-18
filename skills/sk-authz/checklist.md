# Authorization and access-control checklist

Source of truth for `sk-authz` check IDs. Reviews the **access-control design as a whole**, in any language and
framework: the permission model, where it is enforced, default-deny, object- and tenant-level isolation, role
escalation, client-controlled authorization data, field-level access, files and exports, and how fast permission
changes take effect. `sk-api` checks each endpoint; this skill checks the system those checks belong to. Based on the
OWASP Authorization, Multi-Tenant Security and Insecure Direct Object Reference Prevention cheat sheets and OWASP
Top 10 A01. `references/guide.md` explains each check.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021 (A01) / API Top 10 2023.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| AUTHZ-MODEL-001 | There is one explicit permission model (roles, permissions, attributes or relationships) written down in code or config, not implied by scattered `if` statements | S | Medium | A01 | CWE-285 |
| AUTHZ-CENTRAL-001 | Authorization is enforced in a reusable layer (middleware, guards, policies, a policy engine) on the server, close to the data, not only in UI code | S | High | A01 | CWE-285 |
| AUTHZ-DENY-001 | Default deny: routes, resolvers, jobs and files require authentication and a permission unless explicitly marked public, and public exceptions are few and reviewed | S | High | A01 | CWE-276 |
| AUTHZ-OBJECT-001 | Every read or change of an object by ID checks the caller may access that object (or the query is scoped to them) | S+D | High | API1 | CWE-639 |
| AUTHZ-TENANT-001 | Multi-tenant data is isolated: tenant ID comes from the session, every query is tenant-scoped (or database row-level security enforces it), caches and files are tenant-keyed | S+D | Critical | A01 | CWE-668 |
| AUTHZ-ROLE-001 | Admin and privileged functions check the role/permission on the server (vertical access control) | S+D | High | API5 | CWE-269 |
| AUTHZ-CLIENT-001 | Authorization never relies on client-controlled data: roles, tenant IDs or permissions from the body, query, headers, cookies, hidden fields or unsigned tokens | S | Critical | A01 | CWE-807 |
| AUTHZ-ESC-001 | Users cannot change their own (or others') role, permissions, tenant or ownership through profile/update endpoints or invitations | S+D | Critical | A01 | CWE-269 |
| AUTHZ-FIELD-001 | Sensitive fields are filtered per role in responses and writes (API3: broken object property level authorization) | S | Medium | API3 | CWE-213 |
| AUTHZ-STATIC-001 | Files, exports, reports and signed URLs are authorized like any other resource; private files are not served from public static paths | S | High | A01 | CWE-552 |
| AUTHZ-FRESH-001 | Permission changes (role removal, user disabled, member removed) take effect promptly: no long-lived cached permissions or token claims without re-checks | S | Medium | A01 | CWE-613 |
| AUTHZ-TEST-001 | An authorization matrix (role × action × resource) is tested automatically, including cross-tenant and cross-user cases | S | Medium | A01 | CWE-1059 |
