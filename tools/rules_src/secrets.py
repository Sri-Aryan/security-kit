"""sk-secrets rules. Rules with "history": True are also applied to git history by scan_history.py."""

import base64

SKILL = "sk-secrets"

MACROS = {
    "PUBLIC_DIR": r"(?i)(^|/)(public|static|www|wwwroot|client|frontend|web|app|src/(components|pages|app|views|client)|pages|components)/",
}


def fake(*parts):
    """A fake credential for a self-test example, kept out of the files on disk.

    In this source file it is split across string literals; in the generated JSON it is base64-encoded.
    Either way, secret scanners (and GitHub push protection) do not see a credential-shaped string.
    """
    return {"b64": base64.b64encode("".join(parts).encode()).decode()}


def provider(rule_id, title, pattern, confidence="HIGH", check="SEC-CODE-001", match=(), no_match=(), files=("any",)):
    return {
        "id": rule_id, "check_id": check, "title": title, "files": list(files), "pattern": pattern,
        "confidence": confidence, "redact": True, "history": True,
        "path_excludes": r"(?i)(\.lock$|lock\.json$|\.min\.js$|\.svg$)",
        "examples": {"match": list(match), "no_match": list(no_match)},
    }


RULES = [
    # ------------------------------------------------------------------ provider formats (high confidence)
    provider("sec-aws-access-key", "AWS access key ID", r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
             match=[fake("aws_access_key_id = AKIA", "Z7Q3LXMV2K4PRT6W")], no_match=["AKIA"]),
    provider("sec-aws-secret-key", "AWS secret access key", r"(?i)aws.{0,25}(secret|sk)[\w\s'\":=]{0,20}['\"]([0-9a-zA-Z/+]{40})['\"]",
             match=[fake("AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MD", "ENG/bPxRfiCYzEXAMPLEKY'")]),
    provider("sec-github-token", "GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}",
             match=[fake("token = 'gh", "p_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5'")]),
    provider("sec-gitlab-token", "GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}", match=[fake("glp", "at-xY3zA5bC7dE9fG1hI3jK")]),
    provider("sec-slack", "Slack token or webhook", r"\bxox[abposr]-[A-Za-z0-9-]{10,}|hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
             match=[fake("https://hooks.slack.com/serv", "ices/T0123ABCD/B0456EFGH/abcDEF123ghiJKL456mno")]),
    provider("sec-stripe-live", "Stripe live secret key", r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}",
             match=[fake("stripe.api_key = 'sk_", "live_51HxYzAbCdEfGhIjKlMnOpQr'")], no_match=[fake("pk_", "live_51HxYzAbCdEfGhIjKlMnOpQr")]),
    provider("sec-stripe-test", "Stripe test secret key", r"\b(sk|rk)_test_[0-9a-zA-Z]{20,}", confidence="LOW",
             match=[fake("sk_", "test_51HxYzAbCdEfGhIjKlMnOpQr")]),
    provider("sec-google-api-key", "Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b", confidence="MEDIUM",
             match=[fake("const key = 'AI", "zaSyD3x4mpl3K3yV4lu3F0rT3st1ngPurp0s3'")]),
    provider("sec-gcp-service-account", "Google service account key file", r"\"type\"\s*:\s*\"service_account\"",
             check="SEC-KEY-001", files=("config",), match=[fake('{"type": "service', '_account", "project_id": "x"}')]),
    provider("sec-openai-key", "OpenAI API key", r"\bsk-(proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{48}\b",
             match=[fake("OPENAI_API_KEY=sk-", "proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345")]),
    provider("sec-anthropic-key", "Anthropic API key", r"\bsk-ant-(api|admin)\d{2}-[A-Za-z0-9_-]{20,}",
             match=[fake("sk-ant-", "api03-AbCdEfGhIjKlMnOpQrStUvWxYz")]),
    provider("sec-sendgrid", "SendGrid API key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
             match=[fake("SG.", "AbCdEfGhIjKlMnOpQrStUv.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfG")]),
    provider("sec-twilio", "Twilio API key", r"\bSK[0-9a-fA-F]{32}\b", confidence="MEDIUM",
             match=[fake("S", "K0123456789abcdef0123456789abcdef")]),
    provider("sec-mailgun", "Mailgun API key", r"\bkey-[0-9a-zA-Z]{32}\b", confidence="MEDIUM",
             match=[fake("key", "-0123456789abcdefghijklmnopqrstuv")]),
    provider("sec-npm-token", "npm access token", r"\bnpm_[A-Za-z0-9]{36}\b|_authToken\s*=\s*(?!\$\{)[A-Za-z0-9_-]{20,}",
             match=[fake("//registry.npmjs.org/:_authToken=npm", "_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")]),
    provider("sec-pypi-token", "PyPI token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}",
             match=[fake("password = pypi-", "AgEIcHlwaS5vcmcCJDAxMjM0NTY3LTg5YWItY2RlZi0wMTIzLTQ1Njc4OWFiY2RlZg")]),
    provider("sec-azure-storage", "Azure storage account key / connection string", r"AccountKey=[A-Za-z0-9+/=]{80,}",
             match=[fake("DefaultEndpointsProtocol=https;AccountName=x;Account", "Key=" + "A" * 86 + "==;")]),
    provider("sec-shopify", "Shopify access token", r"\bshp(at|ss|ca|pa)_[a-fA-F0-9]{32}\b",
             match=[fake("shp", "at_0123456789abcdef0123456789abcdef")]),
    provider("sec-telegram", "Telegram bot token", r"\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b", confidence="MEDIUM",
             match=[fake("123456789:", "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw1")]),
    provider("sec-webhook-secret", "Webhook signing secret", r"\bwhsec_[A-Za-z0-9+/=]{20,}",
             match=[fake("wh", "sec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")]),
    provider("sec-private-key", "Private key", r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----",
             check="SEC-KEY-001", match=[fake("-----BEGIN RSA PRIV", "ATE KEY-----")], no_match=["-----BEGIN PUBLIC KEY-----"]),
    provider("sec-jwt-literal", "Hardcoded JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", confidence="MEDIUM",
             match=[fake("Authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.", "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'")]),
    {
        "id": "sec-connection-string", "check_id": "SEC-CODE-001", "title": "Connection string with embedded password",
        "files": ["any"], "redact": 2, "history": True,
        "pattern": r"\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver|ftp|sftp|smtp|ldaps?)://[^\s:'\"/@]+:(?!\$\{|\{\{|<|%|password@|pass@|changeme|secret@|example)([^\s'\"@/]{3,})@",
        "confidence": "HIGH", "path_excludes": r"(?i)(\.lock$|lock\.json$)",
        "examples": {"match": ["DATABASE_URL=postgres://app:S3cr3tPw@db.internal:5432/app"],
                     "no_match": ["DATABASE_URL=postgres://app:${DB_PASSWORD}@db:5432/app", "postgres://user:password@localhost/db"]},
    },
    # ------------------------------------------------------------------ generic assignments
    {
        "id": "sec-generic-code", "check_id": "SEC-CODE-001", "title": "Secret-looking value assigned in code",
        "files": ["code"], "redact": 2, "history": True,
        "pattern": r"\b({{SECRET_NAME}})['\"]?\s*(?::=|=>|=|:)\s*['\"`](?!{{PLACEHOLDER}})([^'\"`\s]{12,})['\"`]",
        "entropy": {"group": 2, "min": 3.4}, "confidence": "MEDIUM",
        "not_near": {"pattern": r"(?i)(example|placeholder|dummy|fake|mock)", "lines": 0},
        "examples": {"match": ["const STRIPE_SECRET = 'q8Zr2LmXv9Tn4KwPd7Ys1HbE';", "api_key = \"4f9a2c7e1b8d6f3a0e5c9b2d7a4f1e8c\""],
                     "no_match": ["const password = 'changeme-please';", "const tokenType = 'Bearer';", "const SECRET = process.env.SECRET;"]},
    },
    {
        "id": "sec-generic-config", "check_id": "SEC-CFG-001", "title": "Secret-looking value in a configuration file",
        "files": ["config", "docker", "tf"], "redact": 2, "history": True,
        "pattern": r"\b({{SECRET_NAME}})['\"]?\s*[:=]\s*['\"]?(?!{{PLACEHOLDER}}|[A-Za-z_]\w*\.[A-Za-z_])([^'\"\s,}#()\[\]]{12,})(?![(\[.\w])",
        "entropy": {"group": 2, "min": 3.4}, "confidence": "MEDIUM",
        "path_excludes": r"(?i)(^|/)\.env(\.|$)|\.(example|sample|template|dist)$|package(-lock)?\.json$|\.lock$|lock\.json$",
        "examples": {"match": ["  password: Xq9vLm2Rt7Kp4Wz8", "spring.datasource.password=Xq9vLm2Rt7Kp4Wz8Hn"],
                     "no_match": ["  password: ${DB_PASSWORD}", "  token_url: https://auth.example.com/token"]},
    },
    {
        "id": "sec-env-file-value", "check_id": "SEC-ENV-001", "title": "Real-looking secret in a .env file",
        "files": ["env"], "redact": 3,
        "pattern": r"^\s*(export\s+)?({{SECRET_NAME}}|DATABASE_URL|DB_URL|REDIS_URL)\s*=\s*['\"]?(?!{{PLACEHOLDER}})([^'\"\s#]{8,})",
        "entropy": {"group": 3, "min": 3.0}, "confidence": "MEDIUM",
        "note": "Check git_tracked: committed .env files are the problem; local untracked ones are expected.",
        "examples": {"match": ["STRIPE_SECRET_KEY=q8Zr2LmXv9Tn4KwPd7Ys1Hb"], "no_match": ["STRIPE_SECRET_KEY=your-key-here", "DEBUG=true"]},
    },
    {
        "id": "sec-env-fallback", "check_id": "SEC-CODE-002", "title": "Secret falls back to a hardcoded value when the env var is missing",
        "files": ["code"], "redact": 6,
        "pattern": r"(process\.env\.(\w+)|os\.environ\.get\(\s*['\"](\w+)['\"]|os\.getenv\(\s*['\"](\w+)['\"]|System\.getenv\(\s*\"(\w+)\"\s*\)|ENV\.fetch\(\s*['\"]\w+['\"])\s*(?:\|\||\?\?|,|\bor\b)\s*['\"`](?!{{PLACEHOLDER}})([^'\"`\s]{8,})['\"`]",
        "near": {"pattern": r"(?i)(secret|token|passw|pwd|api_?key|private|credential|signing|salt)", "lines": 0},
        "confidence": "HIGH",
        "examples": {"match": ["const secret = process.env.JWT_SECRET || 'local-dev-secret-123';", "KEY = os.environ.get('API_KEY', 'a8f3k2m9x7q1')"],
                     "no_match": ["const port = process.env.PORT || '3000';", "const secret = process.env.JWT_SECRET;"]},
    },
    # ------------------------------------------------------------------ files that should not exist
    {
        "id": "sec-key-file-content", "check_id": "SEC-KEY-001", "title": "Key or credential file committed",
        "files": ["any"], "pattern": r".",
        "path_includes": r"(?i)(\.(pem|key|p12|pfx|jks|keystore|ppk|asc)$|(^|/)id_(rsa|dsa|ecdsa|ed25519)$|(^|/)\.?(credentials|htpasswd|netrc|pgpass)$|(^|/)\.aws/credentials$|serviceAccount\w*\.json$|(^|/)\.npmrc$|(^|/)\.pypirc$)",
        "path_excludes": r"(?i)(public|\.pub$|cert\.pem$|ca\.pem$|chain\.pem$|fullchain)",
        "file_requires": r"(?i)(PRIVATE KEY|_authToken|password|secret|aws_secret_access_key|token)",
        "confidence": "HIGH", "multiline": True,
        "examples": {"match": ["-----BEGIN PRIVATE KEY-----\nMIIE..."]},
    },
    # ------------------------------------------------------------------ client side
    {
        "id": "sec-public-env-secret", "check_id": "SEC-FRONT-001", "title": "Secret exposed through a public (client-side) env variable",
        "files": ["any"],
        "pattern": r"\b(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC|GATSBY|VUE_APP)_\w*(SECRET|PRIVATE|PASSWORD|SERVICE_ROLE|SERVICE_KEY|ADMIN|_SK\b|SK_|TOKEN|STRIPE_KEY|DATABASE)\w*",
        "confidence": "HIGH", "note": "Anything with a public prefix is bundled into the browser build and visible to every visitor.",
        "examples": {"match": ["NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_x", "const k = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY"],
                     "no_match": ["NEXT_PUBLIC_SUPABASE_ANON_KEY=x", "NEXT_PUBLIC_API_URL=https://api.example.com"]},
    },
    {
        "id": "sec-service-role-in-client", "check_id": "SEC-FRONT-001", "title": "Privileged backend key referenced in client code",
        "files": ["js", "web"], "pattern": r"(?i)(service_?role|serviceRoleKey|SERVICE_ROLE_KEY|admin_?api_?key|firebase-admin|stripe\(\s*['\"]sk_)",
        "path_includes": "{{PUBLIC_DIR}}", "path_excludes": r"(?i)(server|api/|functions/|backend|\.server\.)",
        "confidence": "MEDIUM",
        "examples": {"match": ["const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)"]},
    },
    # ------------------------------------------------------------------ CI / Docker
    {
        "id": "sec-ci-echo-secret", "check_id": "SEC-CI-001", "title": "CI step prints a secret",
        "files": ["any"],
        "path_includes": r"(?i)(\.github/workflows/|\.gitlab-ci|\.circleci/|azure-pipelines|Jenkinsfile|bitbucket-pipelines|\.travis|buildkite|cloudbuild|\.drone)",
        "pattern": r"(?i)\b(echo|print|printf|cat|Write-Host|Write-Output)\b.{0,80}(\$\{\{\s*secrets\.|\$\{?[A-Z_]*(TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIALS)\b)",
        "confidence": "HIGH",
        "examples": {"match": ["      - run: echo ${{ secrets.NPM_TOKEN }}"], "no_match": ["      - run: echo \"building\""]},
    },
    {
        "id": "sec-ci-dump-env", "check_id": "SEC-CI-001", "title": "CI step dumps the whole environment or enables shell tracing",
        "files": ["any"],
        "path_includes": r"(?i)(\.github/workflows/|\.gitlab-ci|\.circleci/|azure-pipelines|Jenkinsfile|bitbucket-pipelines|\.travis|buildkite|cloudbuild|\.drone)",
        "pattern": r"(?i)(^|[\s;&|])(printenv|env|set\s+-x|set\s+-o\s+xtrace|Get-ChildItem\s+env:)\s*($|[;&|])",
        "confidence": "MEDIUM",
        "examples": {"match": ["      - run: printenv"], "no_match": ["      - run: npm test"]},
    },
    {
        "id": "sec-ci-inline-secret", "check_id": "SEC-CI-001", "title": "Secret value written inline in a CI file",
        "files": ["any"],
        "path_includes": r"(?i)(\.github/workflows/|\.gitlab-ci|\.circleci/|azure-pipelines|Jenkinsfile|bitbucket-pipelines|\.travis|buildkite|cloudbuild|\.drone)",
        "pattern": r"\b({{SECRET_NAME}})\s*[:=]\s*['\"]?(?!\$|{{PLACEHOLDER}})([^'\"\s]{12,})",
        "entropy": {"group": 2, "min": 3.4}, "redact": 2, "confidence": "HIGH",
        "examples": {"match": ["      API_TOKEN: q8Zr2LmXv9Tn4KwPd7Ys1Hb"], "no_match": ["      API_TOKEN: ${{ secrets.API_TOKEN }}"]},
    },
    {
        "id": "sec-docker-env-secret", "check_id": "SEC-DOCKER-001", "title": "Secret baked into the image via ENV/ARG",
        "files": ["docker"],
        "pattern": r"(?i)^\s*(ENV|ARG)\s+\w*(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE|ACCESS_?KEY|CREDENTIAL)\w*",
        "confidence": "HIGH", "note": "ENV values and ARG values used in RUN persist in image layers and `docker history`. Use build secrets (--mount=type=secret) or runtime env.",
        "examples": {"match": ["ENV STRIPE_SECRET_KEY=sk_live_x", "ARG NPM_TOKEN"], "no_match": ["ENV NODE_ENV=production"]},
    },
    {
        "id": "sec-docker-copy-secret-file", "check_id": "SEC-DOCKER-001", "title": "Secret file copied into the image",
        "files": ["docker"],
        "pattern": r"(?i)^\s*(COPY|ADD)\s+.*(\.env\b|id_rsa|\.pem\b|\.key\b|credentials|\.npmrc|\.pypirc|serviceAccount|\.aws)",
        "confidence": "HIGH",
        "examples": {"match": ["COPY .env /app/.env", "COPY .npmrc ./"], "no_match": ["COPY package.json ./"]},
    },
    {
        "id": "sec-docker-copy-all", "check_id": "SEC-DOCKER-001", "title": "Whole build context copied without a .dockerignore",
        "type": "absence", "scope": "project", "files": ["docker", ".dockerignore"],
        "when": r"(?im)^\s*(COPY|ADD)\s+\.\s+", "missing": r"(?i)(\.env|\.git|node_modules|\*)",
        "confidence": "LOW", "note": "Without .dockerignore, `COPY . .` also copies .env files, .git and keys into the image.",
        "examples": {"match": ["FROM node:20\nCOPY . ."], "no_match": [".env\n.git\nnode_modules"]},
    },
    # ------------------------------------------------------------------ logging
    {
        "id": "sec-log-env", "check_id": "SEC-LOG-001", "title": "Whole environment or config object logged",
        "files": ["code"],
        "pattern": r"{{LOG_CALL}}.{0,40}\b(process\.env|os\.environ|System\.getenv\(\)|settings|config|Config|ENV)\s*\)",
        "confidence": "HIGH",
        "examples": {"match": ["console.log(process.env)", "print(os.environ)"], "no_match": ["console.log(process.env.NODE_ENV)"]},
    },
    {
        "id": "sec-log-secret-var", "check_id": "SEC-LOG-001", "title": "Secret variable logged",
        "files": ["code"],
        "pattern": r"(?i){{LOG_CALL}}.{0,100}\b\w*(secret|password|passwd|api_?key|apikey|private_?key|access_?key|credentials?)\w*\s*[,)+}]",
        "confidence": "MEDIUM",
        "examples": {"match": ["console.log('key', stripeSecret)", "logger.info(f'connecting with {db_password}')"],
                     "no_match": ["console.log('missing secret')"]},
    },
    # ------------------------------------------------------------------ management
    {
        "id": "sec-gitignore-env", "check_id": "SEC-ENV-001", "title": ".gitignore does not exclude .env files",
        "type": "absence", "scope": "file", "files": [".gitignore"],
        "when": r".", "missing": r"(?m)^\s*/?\*?\.env(\*|\.\*|\.local)?\s*$|^\s*\.env\b",
        "confidence": "MEDIUM",
        "examples": {"match": ["node_modules/\ndist/"], "no_match": ["node_modules/\n.env\n"]},
    },
]
