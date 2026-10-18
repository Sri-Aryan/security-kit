# Dependency and supply-chain guide

Sources: OWASP Vulnerable Dependency Management, NPM Security, Software Supply Chain Security cheat sheets; OWASP
Top 10 A06/A08; OpenSSF guidance.

Most of an application's code is other people's code. Two different risks: **known vulnerabilities** in honest
packages (patch them) and **malicious packages** (typosquats, hijacked releases, dependency confusion, install
scripts), which are stopped by controlling *what* gets installed.

## Vulnerabilities (DEPS-VULN-001)

Use the ecosystem's own scanner, run locally with the user's consent (they send package names and versions, not
code, to an advisory database): `npm audit`/`pnpm audit`/`yarn npm audit`, `pip-audit`, `govulncheck` (also checks
whether vulnerable functions are reachable), `bundle-audit`, `cargo audit`, `composer audit`,
`dotnet list package --vulnerable`, or cross-ecosystem `osv-scanner`, `trivy fs`, `grype`.
For each result decide: **affected?** (is the vulnerable function/feature used?), **fix** (upgrade, override/resolution,
replace), or **accept** with a reason and review date (`.securitykit/ignore.json`). Prioritise reachable, network-facing,
exploited-in-the-wild (CISA KEV) issues.

## Control what is installed

| Check | Do |
|---|---|
| Lockfiles (DEPS-LOCK-001) | commit them; install with `npm ci` / `pnpm i --frozen-lockfile` / `yarn --immutable` / `pip install -r requirements.txt --require-hashes` (pip-tools, uv) / `poetry install --sync`; `go mod verify` |
| Pinning (DEPS-PIN-001) | ranges are fine in libraries; in applications the lockfile pins. Without a lockfile, pin exact versions (`==`). Never `*`/`latest`/`LATEST`/`+` |
| Sources (DEPS-SOURCE-001) | registry packages; if git is unavoidable, pin a commit SHA and review it |
| Typosquats (DEPS-TYPO-001) | check names against the official docs before adding; `expres`, `reqeusts`, `python-dateutils`, `crossenv` are classic squats |
| Confusion (DEPS-CONFUSION-001) | scope private npm packages (`@company/*`) with `@company:registry=` in `.npmrc`; one pip index (or a proxy like Artifactory/Nexus/CodeArtifact that blocks public shadowing); claim your names publicly |
| Install scripts (DEPS-SCRIPT-001) | `npm config set ignore-scripts true` (or `.npmrc ignore-scripts=true`) plus an allow-list (`@lavamoat/allow-scripts`, pnpm `onlyBuiltDependencies`) |
| Compromised/unmaintained (DEPS-KNOWN-001) | remove hijacked versions immediately and rotate any secrets the build machine had; plan replacements for unmaintained packages |
| Updates (DEPS-UPDATE-001) | Dependabot or Renovate with grouped minor updates, security updates fast-tracked, a short cooldown before adopting brand-new releases |
| SBOM (DEPS-SBOM-001) | `cyclonedx-npm`, `cyclonedx-py`, `syft`, `trivy sbom` in the release pipeline |

## Before adding a package (DEPS-MIN-001)

Is it needed (could 20 lines of code replace it)? Is it maintained (recent releases, more than one maintainer)?
Popular and widely depended on? Does it run install scripts? What permissions/network/file access does it need?
