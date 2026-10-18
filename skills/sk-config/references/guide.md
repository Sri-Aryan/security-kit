# Security configuration guide

Sources: OWASP Top 10 A05 (Security Misconfiguration), OWASP Error Handling cheat sheet, framework security cheat
sheets (Django, Laravel, Ruby on Rails, Node.js, .NET, Java/Spring).

Misconfiguration is the gap between how a framework is set up for development and how it must run in production.
The fix is a **production profile that is safe by default** and an app that **refuses to start** when that profile
is incomplete.

## Production settings by framework

| Framework | Debug off (CONF-DEBUG-001) | Errors (CONF-ERROR-001) | Hosts (CONF-HOSTS-001) |
|---|---|---|---|
| Django | `DEBUG = False` | custom 404/500 templates | `ALLOWED_HOSTS = ['app.example.com']` |
| Flask/FastAPI | no `debug=True`, no Werkzeug debugger, `uvicorn` without `--reload` | error handlers returning generic JSON | TrustedHostMiddleware |
| Express/Node | `NODE_ENV=production` | final error handler that logs and returns `{error: "Internal error"}` | validate `Host` when building URLs |
| Spring Boot | no devtools in prod | `server.error.include-stacktrace=never`, `include-message=never` | `server.forward-headers-strategy` set deliberately |
| ASP.NET Core | `ASPNETCORE_ENVIRONMENT=Production` | `UseExceptionHandler` + `UseHsts`; developer page only under `IsDevelopment()` | `AllowedHosts` set to real hosts |
| Rails | `consider_all_requests_local = false` | `public/500.html` | `config.hosts` |
| Laravel | `APP_DEBUG=false`, `APP_ENV=production` | default error views | `TrustHosts` middleware |
| PHP | `display_errors=Off`, `log_errors=On`, `expose_php=Off` | | |

## Admin and diagnostic endpoints (CONF-ADMIN-001)

Spring actuators (`exposure.include=health,info` only, others behind auth on a separate port), Go `net/http/pprof`
(separate internal listener), H2 console, Django debug toolbar, `express-status-monitor`, GraphiQL/Playground,
Swagger UI with "try it out" against production, phpinfo, Werkzeug console: disable in production or put behind
authentication and network restrictions.

## Secrets and defaults (CONF-DEFAULT-001, CONF-ENV-001)

No `|| 'dev-secret'`, `getenv('X', 'default')`, `${X:-default}` for secrets; no `django-insecure-` keys, `keyboard cat`
session secrets, `admin/admin` seed users. Validate configuration at startup with a schema (envalid, zod with `@t3-oss/env`,
pydantic `BaseSettings`, `@ConfigurationProperties` + `@Validated`, `ValidateOnStart`) and crash on missing values.

## Surface (CONF-FEATURE-001, CONF-FILE-001)

Directory listing off (`autoindex off`, no `serveIndex`, no `Options Indexes`). Hide versions (`server_tokens off`,
`app.disable('x-powered-by')` or helmet, `ServerTokens Prod`). Static roots point at a dedicated `public/` folder,
never the project root. Block dotfiles and backups at the proxy (`location ~ /\. { deny all; }`). Don't serve source
maps publicly (upload them to the error tracker instead).
