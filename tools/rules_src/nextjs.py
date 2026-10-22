"""sk-nextjs rules: Server Actions, route handlers, middleware, data leaks to the client, env exposure, framework versions.

Covers Next.js first, and the same concepts in SvelteKit, Nuxt, Remix / React Router and Astro.
"""

SKILL = "sk-nextjs"

MACROS = {
    # Server-side "who is calling?" checks across auth libraries and frameworks.
    "WHO": r"(?i:\bauth\(\)|getServerSession|getSession\(|currentUser\(|getUser\(|getClaims\(|requireUser|requireAuth|verifySession|validateRequest|getKindeServerSession|withAuth|getToken\(|getAuth\(|getIronSession|locals\.(user|session|auth)|event\.locals|requireUserId|getUserId|authenticator\.|requireUserSession|getUserSession|serverSupabaseUser|session\.user|ctx\.user|unauthorized|forbidden|401|403)",
}

# Path regex (path_includes is not macro-expanded).
ROUTE_FILE = r"(?i)(^|/)app/.*route\.[cm]?[jt]sx?$|(^|/)pages/api/|(^|/)src/routes/.*\+server\.[jt]s$|(^|/)server/(api|routes)/|(^|/)app/routes/"

RULES = [
    # ------------------------------------------------------------------ SERVER ACTIONS / FORM ACTIONS
    {
        "id": "next-action-file-no-auth", "check_id": "NEXT-ACTION-001", "type": "absence", "scope": "file",
        "title": "Server Actions / form actions with no caller check in the file", "files": ["js"],
        "when": r"(?:^|\n)[ \t]*['\"]use server['\"]|export\s+const\s+actions\s*(:\s*\w+\s*)?=|export\s+(async\s+)?function\s+action\s*\(",
        "missing": "{{WHO}}",
        "confidence": "MEDIUM",
        "note": "Every exported Server Action is a public POST endpoint that anyone can call with any arguments, whether or not a page renders the form. Check the session inside each action.",
        "examples": {"match": ["'use server';\nexport async function deletePost(id: string) {\n  await db.post.delete({ where: { id } });\n}"],
                     "no_match": ["'use server';\nexport async function deletePost(id: string) {\n  const session = await auth();\n  if (!session) throw new Error('401');\n}"]},
    },
    {
        "id": "next-action-trusts-hidden-id", "check_id": "NEXT-ACTION-002", "title": "Action reads an owner/user ID from the form", "files": ["js", "web"],
        "pattern": r"formData\.get\(\s*['\"](userId|user_id|ownerId|owner_id|authorId|accountId|tenantId|orgId|role|price|amount)['\"]\s*\)",
        "confidence": "MEDIUM", "note": "Hidden inputs are attacker-controlled. Take the user from the session and re-check ownership of any object ID.",
        "examples": {"match": ["const userId = formData.get('userId') as string;"], "no_match": ["const title = formData.get('title') as string;"]},
    },
    {
        "id": "next-action-unvalidated-args", "check_id": "NEXT-ACTION-002", "title": "Server Action body uses arguments without schema validation", "files": ["js"],
        "pattern": r"export\s+async\s+function\s+\w+\s*\(\s*\w+\s*:\s*(any|unknown|FormData|\{)",
        "file_requires": r"(?:^|\n)[ \t]*['\"]use server['\"]",
        "file_excludes": r"(?i)\b(z\.|zod|valibot|yup|superstruct|safeParse|parseAsync|createSafeActionClient|next-safe-action|zsa|arktype|typebox)\b",
        "confidence": "LOW", "note": "TypeScript types are not enforced at runtime; action arguments arrive as arbitrary serialized data.",
        "examples": {"match": ["'use server';\nexport async function update(input: { id: string; role: string }) {}"],
                     "no_match": ["'use server';\nimport { z } from 'zod';\nexport async function update(input: unknown) { const d = schema.parse(input); }"]},
    },
    # ------------------------------------------------------------------ ROUTE HANDLERS
    {
        "id": "next-route-handler-no-auth", "check_id": "NEXT-ROUTE-001", "type": "absence", "scope": "file",
        "title": "Mutating route handler with no caller check", "files": ["js"],
        "path_includes": ROUTE_FILE,
        "when": r"export\s+(async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|export\s+const\s+(POST|PUT|PATCH|DELETE)\s*=|export\s+default\s+(async\s+)?function\s+handler|defineEventHandler\(|export\s+(async\s+)?function\s+action\s*\(",
        "missing": r"{{WHO}}|(?i:webhook|signature|svix|stripe\.webhooks|verifySignature|CRON_SECRET|api[_-]?key)",
        "confidence": "LOW", "note": "Route handlers and API routes are public URLs; middleware may not cover them (matcher, CVE-2025-29927). Public endpoints are fine when that is intended.",
        "examples": {"match": ["export async function DELETE(req: Request, { params }) {\n  await db.user.delete({ where: { id: params.id } });\n}"],
                     "no_match": ["export async function DELETE(req: Request) {\n  const session = await auth();\n  if (!session) return new Response(null, { status: 401 });\n}"]},
    },
    {
        "id": "next-dynamic-api-get-sensitive", "check_id": "NEXT-ROUTE-001", "title": "GET route handler returning user data without a caller check", "files": ["js"],
        "path_includes": ROUTE_FILE,
        "pattern": r"export\s+(async\s+)?function\s+GET\b",
        "near": {"pattern": r"(?i)(prisma|db|drizzle|supabase|knex|mongoose|sql`)[\w.]*\.(user|users|account|order|invoice|profile|customer)", "lines": 15},
        "not_near": {"pattern": "{{WHO}}", "lines": 15}, "confidence": "LOW",
        "examples": {"match": ["export async function GET() {\n  const users = await prisma.user.findMany();\n  return Response.json(users);\n}"],
                     "no_match": ["export async function GET() {\n  const session = await auth();\n  const users = await prisma.user.findMany();\n}"]},
    },
    # ------------------------------------------------------------------ MIDDLEWARE
    {
        "id": "next-vuln-middleware-bypass", "check_id": "NEXT-VERSION-001", "title": "Next.js version affected by the middleware bypass (CVE-2025-29927)", "files": [".json"],
        "path_includes": r"(^|/)package\.json$",
        "pattern": r"\"next\"\s*:\s*\"[\^~]?(11\.\d+\.\d+|12\.([0-2]\.\d+|3\.[0-4])|13\.([0-4]\.\d+|5\.[0-8])|14\.([01]\.\d+|2\.([0-9]|1\d|2[0-4]))|15\.([01]\.\d+|2\.[0-2]))\"",
        "confidence": "HIGH", "note": "A crafted x-middleware-subrequest header skips middleware entirely. Fixed in 12.3.5, 13.5.9, 14.2.25 and 15.2.3. Check the lockfile for the version actually installed.",
        "examples": {"match": ["\"next\": \"14.2.3\",", "\"next\": \"^15.1.0\","], "no_match": ["\"next\": \"14.2.25\",", "\"next\": \"15.2.3\","]},
    },
    {
        "id": "next-vuln-rsc-rce", "check_id": "NEXT-VERSION-001", "title": "React Server Components version affected by CVE-2025-55182 (RCE)", "files": [".json"],
        "path_includes": r"(^|/)package\.json$",
        "pattern": r"\"next\"\s*:\s*\"[\^~]?(15\.0\.[0-4]|15\.1\.[0-8]|15\.2\.[0-5]|15\.3\.[0-5]|15\.4\.[0-7]|15\.5\.[0-6]|16\.0\.[0-6])\"|\"react-server-dom-(webpack|parcel|turbopack)\"\s*:\s*\"[\^~]?19\.(0\.0|1\.[01]|2\.0)\"",
        "confidence": "HIGH", "note": "Unauthenticated remote code execution through the RSC Flight protocol (December 2025). Follow-up advisories required further patches: upgrade to the latest patch of your release line, then rotate secrets if the app was exposed.",
        "examples": {"match": ["\"next\": \"15.3.2\",", "\"react-server-dom-webpack\": \"19.1.0\""], "no_match": ["\"next\": \"15.3.6\",", "\"next\": \"14.2.30\","]},
    },
    {
        "id": "next-middleware-auth", "check_id": "NEXT-MW-001", "title": "Auth enforced in middleware; confirm pages, actions and routes re-check", "files": ["js"],
        "path_includes": r"(?i)(^|/)(src/)?(middleware|proxy)\.[cm]?[jt]s$",
        "pattern": r"export\s+(default\s+)?(async\s+)?function\s+(middleware|proxy)\b|export\s+default\s+(clerkMiddleware|withAuth|auth|authMiddleware|NextAuth)\b|export\s*\{\s*auth\s+as\s+(middleware|proxy)",
        "file_requires": r"(?i)(auth|session|token|redirect\(|login|sign-?in)",
        "confidence": "LOW", "note": "Middleware is an optimistic first gate: it can be skipped (matcher gaps, CVE-2025-29927) and doesn't run for Server Actions' authorization needs. Keep the real check next to the data.",
        "examples": {"match": ["export async function middleware(req) {\n  const token = req.cookies.get('session');\n  if (!token) return NextResponse.redirect('/login');\n}"],
                     "no_match": ["export function middleware(req) {\n  return NextResponse.next({ headers: securityHeaders });\n}"]},
    },
    {
        "id": "next-matcher-skips-api", "check_id": "NEXT-MW-002", "title": "Middleware matcher excludes API routes", "files": ["js"],
        "path_includes": r"(?i)(^|/)(src/)?(middleware|proxy)\.[cm]?[jt]s$",
        "pattern": r"matcher[^\n]*\(\?!\s*(api|_next/static\|api|[^)]*\|api\b)", "confidence": "LOW",
        "note": "Fine if every API route checks auth itself; a finding if any relies on the middleware.",
        "examples": {"match": ["export const config = { matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'] };"],
                     "no_match": ["export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };"]},
    },
    {
        "id": "next-matcher-allowlist", "check_id": "NEXT-MW-002", "title": "Middleware protects a hand-picked list of paths", "files": ["js"],
        "path_includes": r"(?i)(^|/)(src/)?(middleware|proxy)\.[cm]?[jt]s$",
        "pattern": r"matcher\s*:\s*\[\s*['\"]/(dashboard|admin|app|account|settings|billing)\b", "confidence": "LOW",
        "note": "New protected pages outside these prefixes are silently unprotected. Prefer matching everything and allow-listing public paths.",
        "examples": {"match": ["export const config = { matcher: ['/dashboard/:path*', '/settings/:path*'] };"], "no_match": ["export const config = { matcher: ['/((?!_next/static|favicon.ico).*)'] };"]},
    },
    # ------------------------------------------------------------------ DATA LEAKS TO THE CLIENT
    {
        "id": "next-gssp-full-record", "check_id": "NEXT-LEAK-001", "title": "Full database record returned as page props", "files": ["js"],
        "pattern": r"props\s*:\s*\{[^}\n]*\b(user|users|account|profile|customer|session)\b\s*[,}]",
        "near": {"pattern": r"(?i)(prisma|db\.|knex|supabase|mongoose|findUnique|findFirst|findMany|findOne|\.query\()", "lines": 10},
        "not_near": {"pattern": r"(?i)select\s*:|omit\s*:|pick\(|\.select\(\s*['\"][^*]|toPublic|toDTO|serialize", "lines": 10}, "confidence": "LOW",
        "note": "Everything in props is serialized into the HTML (__NEXT_DATA__) for anyone who loads the page: password hashes, tokens, emails of other users.",
        "examples": {"match": ["const user = await prisma.user.findUnique({ where: { id } });\nreturn { props: { user } };"],
                     "no_match": ["const user = await prisma.user.findUnique({ where: { id }, select: { name: true } });\nreturn { props: { user } };"]},
    },
    {
        "id": "next-rsc-full-record-to-client", "check_id": "NEXT-LEAK-001", "title": "Server Component passes a full database record to a component", "files": ["js"],
        "path_includes": r"(?i)(^|/)app/",
        "pattern": r"<[A-Z]\w*\s[^>\n]*\b\w+=\{\s*(user|users|account|profile|customer|member|session|data)\s*\}",
        "near": {"pattern": r"(?i)(prisma|db\.|drizzle|knex|supabase|mongoose)[\w.]*\.(findUnique|findFirst|findMany|findOne|select\(\s*\)|select\(\s*['\"]\*)", "lines": 15},
        "file_excludes": r"(?:^|\n)[ \t]*['\"]use client['\"]",
        "confidence": "LOW", "note": "Props passed from a Server Component into a Client Component are serialized into the RSC payload. Map to a DTO with only the fields the UI needs (or use React taint APIs).",
        "examples": {"match": ["const user = await prisma.user.findUnique({ where: { id } });\nreturn <ProfileCard user={user} />;"],
                     "no_match": ["const user = await getUserDTO(id);\nreturn <ProfileCard user={user} />;"]},
    },
    {
        "id": "next-public-secret-env", "check_id": "NEXT-ENV-001", "title": "Secret in a public, client-bundled env variable", "files": ["code", "web", "env", "config"],
        "pattern": r"(?i)\b(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|PUBLIC_|GATSBY_)\w*(SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|PASSWD|DATABASE_URL|DB_URL|POSTGRES|MONGO|REDIS_URL|STRIPE_SK|SK_LIVE|OPENAI|ANTHROPIC|GEMINI|GROQ|RESEND|SENDGRID|TWILIO_AUTH|ADMIN_KEY|WEBHOOK_SECRET)\w*",
        "confidence": "HIGH", "note": "Public-prefixed variables are inlined into the JavaScript every visitor downloads. Move the call server-side and rotate the value.",
        "examples": {"match": ["NEXT_PUBLIC_OPENAI_API_KEY=placeholder", "const key = import.meta.env.VITE_STRIPE_SECRET_KEY;"],
                     "no_match": ["NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=placeholder", "const key = process.env.OPENAI_API_KEY;"]},
    },
    {
        "id": "next-config-env-inlines-secret", "check_id": "NEXT-ENV-001", "title": "Secret inlined through next.config env / Nuxt public runtimeConfig", "files": ["js"],
        "path_includes": r"(?i)(next|nuxt|vite|astro|svelte)\.config\.[cm]?[jt]s$",
        "multiline": True,
        "pattern": r"(?is)(\benv\s*:\s*\{|\bpublic\s*:\s*\{|\bdefine\s*:\s*\{)[^}]*(SECRET|PRIVATE|PASSWORD|DATABASE_URL|API_KEY|apiKey|secretKey|TOKEN)",
        "confidence": "MEDIUM", "note": "next.config `env`, Vite `define` and Nuxt `runtimeConfig.public` values end up in the client bundle.",
        "examples": {"match": ["module.exports = {\n  env: {\n    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,\n  },\n};"],
                     "no_match": ["module.exports = {\n  env: {\n    NEXT_PUBLIC_APP_NAME: 'Acme',\n  },\n};"]},
    },
    {
        "id": "next-server-module-not-guarded", "check_id": "NEXT-ONLY-001", "type": "absence", "scope": "file",
        "title": "Server-only module (DB/secrets) without `import 'server-only'`", "files": ["js"],
        "path_includes": r"(?i)(^|/)(src/)?(lib|server|db|services?|data|dal)/",
        "path_excludes": r"(?i)(\.server\.|/server/|\$lib/server|/api/|\.test\.|\.spec\.)",
        "when": r"process\.env\.\w*(SECRET|PRIVATE|SERVICE_ROLE|DATABASE_URL|_KEY\b)|from\s+['\"](@prisma/client|drizzle-orm[^'\"]*|pg|postgres|mysql2[^'\"]*|mongoose|stripe|firebase-admin|@supabase/supabase-js)['\"]",
        "missing": r"server-only|['\"]use server['\"]",
        "confidence": "LOW", "note": "Without the server-only marker a Client Component can import this module by mistake; secrets without NEXT_PUBLIC_ become undefined but the code (queries, endpoints) still ships.",
        "examples": {"match": ["import { PrismaClient } from '@prisma/client';\nexport const db = new PrismaClient();"],
                     "no_match": ["import 'server-only';\nimport { PrismaClient } from '@prisma/client';"]},
    },
    # ------------------------------------------------------------------ CONFIG
    {
        "id": "next-image-any-host", "check_id": "NEXT-IMAGE-001", "title": "Image optimizer allows any remote host", "files": ["js", "config"],
        "pattern": r"(?i)hostname\s*:\s*['\"]\*\*?['\"]|domains\s*:\s*\[\s*['\"]\*", "confidence": "MEDIUM",
        "note": "Any site can use your /_next/image endpoint as a free image proxy (cost, bandwidth, SSRF-style fetches). List the hosts you use.",
        "examples": {"match": ["images: { remotePatterns: [{ protocol: 'https', hostname: '**' }] }"], "no_match": ["images: { remotePatterns: [{ protocol: 'https', hostname: 'cdn.acme.com' }] }"]},
    },
    {
        "id": "next-image-svg", "check_id": "NEXT-IMAGE-001", "title": "SVG allowed through the image optimizer", "files": ["js"],
        "pattern": r"dangerouslyAllowSVG\s*:\s*true", "not_near": {"pattern": r"contentSecurityPolicy|contentDispositionType", "lines": 4}, "confidence": "MEDIUM",
        "examples": {"match": ["images: { dangerouslyAllowSVG: true }"], "no_match": ["images: { dangerouslyAllowSVG: true, contentDispositionType: 'attachment', contentSecurityPolicy: \"default-src 'self'; script-src 'none'; sandbox;\" }"]},
    },
    {
        "id": "next-prod-sourcemaps", "check_id": "NEXT-SOURCEMAP-001", "title": "Production browser source maps published", "files": ["js", "config"],
        "pattern": r"productionBrowserSourceMaps\s*:\s*true|\bsourcemap\s*:\s*true|\bsourceMap\s*:\s*true",
        "path_includes": r"(?i)(next|vite|nuxt|astro|svelte)\.config|angular\.json|webpack", "confidence": "LOW",
        "note": "Public source maps hand your original source (and any comments or internal URLs) to everyone. Use 'hidden' maps uploaded to your error tracker.",
        "examples": {"match": ["module.exports = { productionBrowserSourceMaps: true };", "build: { sourcemap: true }"], "no_match": ["build: { sourcemap: 'hidden' }"]},
    },
    {
        "id": "next-actions-any-origin", "check_id": "NEXT-CSRF-001", "title": "Server Actions accept any origin", "files": ["js"],
        "pattern": r"allowedOrigins\s*:\s*\[[^\]]*['\"](\*|\*\.\*|https?://\*)['\"]", "confidence": "HIGH",
        "examples": {"match": ["experimental: { serverActions: { allowedOrigins: ['*'] } }"], "no_match": ["experimental: { serverActions: { allowedOrigins: ['app.acme.com'] } }"]},
    },
    {
        "id": "next-draft-mode-no-secret", "check_id": "NEXT-DRAFT-001", "title": "Draft/preview mode enabled without checking a secret", "files": ["js"],
        "pattern": r"draftMode\(\)\)?\.enable\(\)|\.setPreviewData\(|setDraftMode\(\s*\{\s*enable\s*:\s*true",
        "not_near": {"pattern": r"(?i)secret|token|validatePreviewUrl|verify|signature", "lines": 10}, "confidence": "MEDIUM",
        "examples": {"match": ["export async function GET() {\n  (await draftMode()).enable();\n  redirect('/');\n}"],
                     "no_match": ["if (searchParams.get('secret') !== process.env.DRAFT_SECRET) return new Response('no', { status: 401 });\n(await draftMode()).enable();"]},
    },
    {
        "id": "next-revalidate-route-no-secret", "check_id": "NEXT-REVALIDATE-001", "title": "On-demand revalidation endpoint without a secret", "files": ["js"],
        "path_includes": ROUTE_FILE,
        "pattern": r"\brevalidate(Path|Tag)\(|res\.revalidate\(",
        "not_near": {"pattern": r"(?i)secret|token|signature|verify|{{WHO}}", "lines": 12}, "confidence": "LOW",
        "note": "Anyone can force cache purges and expensive regeneration.",
        "examples": {"match": ["export async function POST(req) {\n  const { path } = await req.json();\n  revalidatePath(path);\n}"],
                     "no_match": ["export async function POST(req) {\n  if (req.headers.get('x-secret') !== process.env.REVALIDATE_SECRET) return new Response(null, { status: 401 });\n  revalidatePath(path);\n}"]},
    },
]
