# Dependency and supply-chain checklist

Source of truth for `sk-deps` check IDs. Covers third-party packages in any ecosystem (npm/yarn/pnpm/bun, pip/Poetry/
Pipenv/uv, Go modules, Bundler, Composer, Cargo, Maven/Gradle, NuGet, pub, SwiftPM): known vulnerabilities, lockfiles,
pinning, package sources, typosquats, dependency confusion, install scripts, compromised and unmaintained packages,
update automation and SBOMs. CI action pinning: `sk-cicd`. Base images: `sk-docker`. Based on the OWASP Vulnerable
Dependency Management, NPM Security and Software Supply Chain Security cheat sheets and Top 10 A06/A08.

Columns: **Mode** S = static (offline), T = uses a local vulnerability tool (contacts an advisory database, with consent). OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DEPS-VULN-001 | No dependency (direct or transitive) has a known vulnerability that affects how the project uses it, or each one has a tracked decision | T | High | A06 | CWE-1395 |
| DEPS-LOCK-001 | Every manifest has a committed lockfile, and CI installs from it (`npm ci`, `--frozen-lockfile`, `pip install --require-hashes`, `go mod verify`) | S | Medium | A08 | CWE-1357 |
| DEPS-PIN-001 | Versions are pinned or bounded; no `*`, `latest`, open-ended `>=`, or Maven/Gradle dynamic versions in applications | S | Medium | A08 | CWE-1104 |
| DEPS-SOURCE-001 | Packages come from the registry, not git URLs, tarballs or local paths (or those are pinned to a commit and reviewed) | S | Medium | A08 | CWE-829 |
| DEPS-TYPO-001 | Package names are the intended ones: no typosquats or lookalikes of popular packages | S | High | A08 | CWE-506 |
| DEPS-CONFUSION-001 | Private package names cannot be claimed on public registries: scoped registries, a single index or a proxy, no `--extra-index-url` mixing | S | High | A08 | CWE-427 |
| DEPS-SCRIPT-001 | Install-time scripts from dependencies are known and expected; untrusted ones are blocked (`ignore-scripts`, allow-lists) | S | Medium | A08 | CWE-506 |
| DEPS-KNOWN-001 | No package versions that were hijacked or sabotaged, and no unmaintained/deprecated packages without a replacement plan | S | High | A06 | CWE-1104 |
| DEPS-UPDATE-001 | Updates are automated and reviewed (Dependabot, Renovate), security updates are applied within a defined time | S | Low | A06 | CWE-1104 |
| DEPS-SBOM-001 | A software bill of materials can be produced for each release (CycloneDX or SPDX) | S | Low | A06 | CWE-1104 |
| DEPS-MIN-001 | Dependencies are necessary: unused packages removed, trivial ones avoided, heavy ones justified | S | Low | A06 | CWE-1104 |
