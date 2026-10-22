# Backend-as-a-service checklist

Source of truth for `sk-baas` check IDs. Covers apps whose clients talk to the database directly through a
backend-as-a-service: Supabase (Postgres row level security, Storage, Realtime, Edge Functions), Firebase (Firestore,
Realtime Database, Cloud Storage rules, Cloud Functions, App Check), and the same ideas in Appwrite, PocketBase, Convex
and AWS Amplify. In these apps the **policies are the backend**: the anon/public key is meant to be public, so every
table, bucket and function must protect itself. Based on the Supabase and Firebase security documentation and the
OWASP Authorization cheat sheet. `references/guide.md` explains each check.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| BAAS-RLS-001 | Row level security is enabled on every table in an exposed schema (Supabase `public` and any schema in the API's exposed list), and never disabled to make a query work | S+D | Critical | A01 | CWE-284 |
| BAAS-RLS-002 | Policies do not allow every row (`using (true)` / `with check (true)`) except on data that is meant to be public and read-only | S | High | A01 | CWE-285 |
| BAAS-RLS-003 | Policies scope rows to the caller (`auth.uid()`, membership tables, `app_metadata`), not merely "signed in", and never trust user-editable `user_metadata` | S | High | A01 | CWE-639 |
| BAAS-RLS-004 | UPDATE policies have `WITH CHECK`, and users cannot change ownership, role, plan or balance columns (column privileges or triggers) | S | Medium | A01 | CWE-915 |
| BAAS-KEY-001 | Service-role / secret / admin SDK credentials never reach client code, public env variables or mobile apps | S | Critical | A07 | CWE-522 |
| BAAS-KEY-002 | Every server path that uses an RLS-bypassing admin client (service_role, firebase-admin) authenticates the caller and scopes queries to them | S | High | A01 | CWE-862 |
| BAAS-FUNC-001 | `SECURITY DEFINER` functions pin `search_path` and check the caller; functions exposed to `anon`/`public` are intended; views use `security_invoker` | S | High | A01 | CWE-269 |
| BAAS-FUNC-002 | Client-callable functions (Firebase callable/HTTP functions, Supabase Edge Functions) verify the caller (JWT verification on, `request.auth` checked) | S | High | A01 | CWE-306 |
| BAAS-FS-001 | Firestore, Realtime Database and Cloud Storage rules never allow everyone (`if true`, no condition, expired test-mode rules, `".read": true`) | S+D | Critical | A01 | CWE-284 |
| BAAS-FS-002 | Rules compare `request.auth.uid` with the document's owner/membership, not just `request.auth != null`, and avoid broad recursive wildcards | S | High | A01 | CWE-639 |
| BAAS-FS-003 | Write rules validate incoming data (`request.resource.data`): allowed keys, types, and no client-set role, plan, credits or owner | S | Medium | A04 | CWE-915 |
| BAAS-STORAGE-001 | Storage buckets are private by default; public buckets hold only public assets; object policies are scoped to the user's folder or record | S+D | High | A01 | CWE-284 |
| BAAS-AUTH-001 | Auth settings match the app: email confirmation on, sensible password minimums, anonymous sign-ins and open sign-up only when intended | S | Medium | A07 | CWE-287 |
| BAAS-APPCHECK-001 | Firebase App Check (or equivalent attestation) is enforced and browser API keys are restricted to the app's domains/bundles | S | Low | A04 | CWE-799 |
| BAAS-REALTIME-001 | Realtime subscriptions respect authorization: published tables have scoped RLS; broadcast/presence channels are private | S | Medium | A01 | CWE-200 |
| BAAS-OTHER-001 | Other BaaS permissions are least-privilege: Appwrite `Role.any()`/guests, PocketBase empty rules, public Convex functions, Amplify `allow.publicApiKey()`/`public` | S | High | A01 | CWE-284 |
| BAAS-TEST-001 | Policies and rules have automated tests (pgTAP / `supabase test db`, `@firebase/rules-unit-testing` with the emulator) that prove another user is refused | S | Low | A04 | CWE-1125 |
