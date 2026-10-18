# Container security checklist

Source of truth for `sk-docker` check IDs. Covers Dockerfiles, Compose files, Kubernetes workload manifests
(and Helm/Kustomize output), and Docker host/daemon configuration in the repository. Based on the OWASP Docker
Security Cheat Sheet (rules #0–#13) and the Kubernetes Security Cheat Sheet. `references/guide.md` explains
each check.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021.

## Host and daemon (HOST / DAEMON)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DOCKER-HOST-001 | The Docker daemon is not exposed over TCP without TLS and authentication | S | Critical | A05 | CWE-306 |
| DOCKER-HOST-002 | The Docker socket (`/var/run/docker.sock`) is never mounted into containers (read-only does not help) | S | Critical | A05 | CWE-250 |
| DOCKER-HOST-003 | Host kernel and engine are patched; rootless mode or user-namespace remapping is used where possible | S | Low | A06 | CWE-1104 |
| DOCKER-DAEMON-001 | Daemon log level is `info` (not `debug`) | S | Low | A09 | CWE-532 |

## Users and privileges (USER / PRIV)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DOCKER-USER-001 | Containers run as a non-root user (`USER` in the Dockerfile, `runAsNonRoot` / non-zero `runAsUser`) | S | High | A05 | CWE-250 |
| DOCKER-PRIV-001 | No privileged containers (`--privileged`, `privileged: true`) | S | Critical | A05 | CWE-250 |
| DOCKER-PRIV-002 | Capabilities: drop ALL and add back only what is needed; never SYS_ADMIN, SYS_MODULE, SYS_PTRACE, NET_ADMIN or ALL | S | High | A05 | CWE-250 |
| DOCKER-PRIV-003 | Privilege escalation is blocked (`no-new-privileges`, `allowPrivilegeEscalation: false`) | S | Medium | A05 | CWE-269 |
| DOCKER-PRIV-004 | Containers do not share host namespaces (network, PID, IPC, user) | S | High | A05 | CWE-653 |
| DOCKER-PRIV-005 | No sensitive host paths are mounted (`/`, `/etc`, `/proc`, `/sys`, `/root`, `/var/run`, `/var/lib/docker`, `/dev`, SSH keys) | S | High | A05 | CWE-668 |
| DOCKER-LSM-001 | seccomp, AppArmor and SELinux profiles are not disabled (`unconfined`, `label:disable`) | S | High | A05 | CWE-693 |

## Network, resources, filesystem (NET / RES / FS)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DOCKER-NET-001 | Only intended ports are published; internal services bind to 127.0.0.1 or stay on internal networks; Kubernetes uses NetworkPolicies; no SSH server in containers | S | Medium | A05 | CWE-668 |
| DOCKER-RES-001 | Memory, CPU and process limits are set (and restart policies bounded) | S | Medium | A05 | CWE-770 |
| DOCKER-FS-001 | Root filesystem is read-only where possible (with tmpfs for scratch) and volumes are mounted read-only when only read | S | Low | A05 | CWE-732 |

## Images (IMG)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DOCKER-IMG-001 | Base and service images are pinned (explicit tag, ideally digest), never `latest` or untagged | S | Medium | A08 | CWE-1104 |
| DOCKER-IMG-002 | Base images are minimal, trusted and supported (no end-of-life runtimes or distributions) | S | Medium | A06 | CWE-1104 |
| DOCKER-IMG-003 | `COPY` is used instead of `ADD` for local files; no `ADD` of remote URLs or archives | S | Low | A08 | CWE-829 |
| DOCKER-IMG-004 | Builds do not pipe remote scripts into a shell; downloads are verified | S | High | A08 | CWE-494 |
| DOCKER-IMG-005 | Multi-stage builds keep compilers, package managers, sources and build secrets out of the final image | S | Low | A05 | CWE-1188 |
| DOCKER-IMG-006 | A `.dockerignore` keeps `.git`, `.env`, keys and local artifacts out of the build context | S | Medium | A05 | CWE-538 |

## Secrets (SECRET)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DOCKER-SECRET-001 | Secrets are not baked into images (`ENV`, `ARG`, copied files) or written as literals in Compose/Kubernetes files; build secrets and runtime secret stores are used | S | High | A07 | CWE-798 |

## Kubernetes workloads (K8S)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DOCKER-K8S-001 | Workload identities are least-privilege: no cluster-admin or wildcard RBAC for apps, service-account tokens not automounted unless needed | S | High | A01 | CWE-269 |

## Supply chain (SUPPLY)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DOCKER-SUPPLY-001 | Images and Dockerfiles are scanned and linted in CI (vulnerabilities, secrets, misconfiguration) | S | Low | A06 | CWE-1104 |
| DOCKER-SUPPLY-002 | Published images are signed, have provenance and an SBOM, and live in a trusted, access-controlled registry | S | Low | A08 | CWE-345 |
