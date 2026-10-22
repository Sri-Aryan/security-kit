# BaaS guide: policies are the backend

Sources: Supabase docs (Row Level Security, API keys, Securing your data, Database functions, Storage access control,
Realtime authorization, Production checklist), Firebase docs (Security Rules, Fix insecure rules, App Check, Callable
functions), Appwrite permissions, PocketBase API rules, Convex auth, Amplify Gen 2 authorization; OWASP Authorization
cheat sheet.

**The public key is public.** The Supabase anon/publishable key and the Firebase web config are in every client by
design. Anyone can call your database directly with them, skipping your UI. Whatever the policies allow, an attacker
can do, so audit the policies themselves, not the app screens.

## Supabase

| Check | What to confirm | Fix |
|---|---|---|
| BAAS-RLS-001 | `select relname, relrowsecurity from pg_class join pg_namespace n on n.oid = relnamespace where nspname = 'public' and relkind = 'r'` (or the dashboard's Security Advisor) shows RLS on for every table. Migrations: each `create table` in an exposed schema has a matching `enable row level security`. | Enable RLS everywhere; RLS with no policy = deny all. Put internal tables in an unexposed schema. |
| BAAS-RLS-002/003 | Each policy names a role (`to authenticated`) and a row filter on the caller. `using (true)`, `auth.role() = 'authenticated'` and `auth.uid() is not null` all mean "every user". | `using ((select auth.uid()) = user_id)`; for teams, `exists (select 1 from members m where m.org_id = org_id and m.user_id = (select auth.uid()))`. |
| BAAS-RLS-003 | Policies reading `auth.jwt() -> 'user_metadata'` or triggers copying `raw_user_meta_data ->> 'role'` | The user sets `user_metadata` via `auth.updateUser()`. Use `app_metadata` (server-set) or a roles table. |
| BAAS-RLS-004 | `for update` policies have `with check`; sensitive columns protected | Add `with check`, `revoke update (role, plan, credits) on profiles from authenticated`, or a `before update` trigger. |
| BAAS-KEY-001 | `service_role` / `sb_secret_…` only in server env; never `NEXT_PUBLIC_`/`VITE_`/`EXPO_PUBLIC_`, never in a `'use client'` file or mobile bundle | Move to server code; **rotate** if it ever shipped. |
| BAAS-KEY-002 | Every importer of the admin client checks `auth.getUser()` (or `getClaims()`) and filters by that user | Prefer a per-request client with the user's JWT so RLS still applies. |
| BAAS-FUNC-001 | `security definer` functions: `set search_path = ''`, check `auth.uid()`, live in an unexposed schema or have `revoke execute … from anon, public`. Views: `with (security_invoker = true)`. | |
| BAAS-FUNC-002 | Edge Functions keep `verify_jwt` on unless they verify a webhook signature themselves | |
| BAAS-STORAGE-001 | Buckets `public = false` for user files; `storage.objects` policies use `(storage.foldername(name))[1] = auth.uid()::text` or a join to the owning row | Signed URLs with short expiry for private files. |
| BAAS-REALTIME-001 | Tables in `supabase_realtime` publication have RLS; broadcast/presence channels use `private: true` with `realtime.messages` policies | |
| BAAS-AUTH-001 | Hosted Auth settings (not only `config.toml`): confirm email on, minimum password length ≥ 8 (12+ better), leaked-password protection, anonymous sign-ins only if used, CAPTCHA on sign-up | |

## Firebase

| Check | What to confirm |
|---|---|
| BAAS-FS-001 | No `allow read, write: if true;`, no `allow read;`, no test-mode `request.time < timestamp.date(...)`, no `".read": true` / `".write": true` in Realtime Database rules. Storage rules too. |
| BAAS-FS-002 | `match /users/{userId} { allow read, write: if request.auth.uid == userId; }`; shared docs check membership (`request.auth.uid in resource.data.members`). Avoid `match /{document=**}` except to deny. |
| BAAS-FS-003 | Writes validate: `request.resource.data.keys().hasOnly([...])`, types, and `!request.resource.data.diff(resource.data).affectedKeys().hasAny(['role','plan','credits'])`. |
| BAAS-FUNC-002 | `onCall` handlers check `request.auth` (and `enforceAppCheck`); `onRequest` handlers verify an ID token (`admin.auth().verifyIdToken`) or a webhook signature. |
| BAAS-KEY-001/002 | `firebase-admin` and service-account JSON only on the server; Admin SDK bypasses rules, so the function must check the caller. |
| BAAS-APPCHECK-001 | App Check initialised in clients and **enforced** per product in the console; browser API key restricted by HTTP referrer / app ID. |

## Other backends (BAAS-OTHER-001)

- **Appwrite**: avoid `Permission.write(Role.any())` / `Role.guests()`; prefer `Role.user(id)` / `Role.team(id)`, and document-level security.
- **PocketBase**: rule `""` = anyone; `null` = superusers only; write rules like `@request.auth.id != "" && user = @request.auth.id`.
- **Convex**: every public `query`/`mutation`/`action` calls `ctx.auth.getUserIdentity()` (or a helper); server-only logic uses `internalQuery`/`internalMutation`.
- **Amplify Gen 2**: `allow.owner()` / `allow.authenticated().to(['read'])`; `allow.publicApiKey()` only for read-only public data.

## Dynamic check (only with `--base-url` and user approval)

Using the **public** key from the client bundle and two test accounts the user owns: list each table/collection as
anonymous, as user A, and read/update user B's row. Record request and response excerpts. Never touch real users' data.

## Tests (BAAS-TEST-001)

Supabase: pgTAP tests (`supabase test db`) that `set local role authenticated; set local request.jwt.claims = …` and
assert another user's rows are invisible. Firebase: `@firebase/rules-unit-testing` against the emulator with
`assertFails` for cross-user reads and role writes.
