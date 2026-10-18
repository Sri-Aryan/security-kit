# Container security guide: how to verify and fix each concept

Sources: OWASP Docker Security Cheat Sheet (rules #0–#13), OWASP Kubernetes Security Cheat Sheet, OWASP
NodeJS Docker Cheat Sheet. A container is a process with a restricted view of the host. Every finding
here is about **how much of the host that process can reach** (user, capabilities, namespaces, mounts,
daemon access, kernel filters), **what is inside the image** (base, tools, secrets), and **how the image
got there** (pinning, scanning, signing).

---

## Daemon access: the most severe class (DOCKER-HOST-*)

Access to the Docker API equals root on the host. Never expose `tcp://…:2375`; if remote access is needed,
use TLS with client certificates (2376) or SSH. Never mount `/var/run/docker.sock` into an application
container (read-only mounts still allow full API use). If a tool needs it (CI agents, Traefik), isolate that
container and consider a socket proxy with an allow-list. Keep the kernel and engine patched; prefer rootless
Docker/Podman or `userns-remap`.

## Users and privileges (DOCKER-USER-*, DOCKER-PRIV-*, DOCKER-LSM-*)

```dockerfile
FROM node:22-slim@sha256:<digest>
WORKDIR /app
COPY --chown=node:node . .
USER node                         # rule #2
```
```yaml
# compose                                   # kubernetes securityContext
user: "1000:1000"                           runAsNonRoot: true
cap_drop: [ALL]                             runAsUser: 10001
cap_add: [NET_BIND_SERVICE]  # only if needed   allowPrivilegeEscalation: false
security_opt: ["no-new-privileges:true"]     readOnlyRootFilesystem: true
read_only: true                              capabilities: { drop: [ALL] }
tmpfs: [/tmp]                                seccompProfile: { type: RuntimeDefault }
```
Never `privileged`, never host namespaces (`network_mode: host`, `pid: host`, `hostNetwork/hostPID/hostIPC`),
never mount `/`, `/etc`, `/proc`, `/sys`, `/root`, `/var/run`, `/var/lib/docker`, `/dev` or SSH keys, and
never disable seccomp/AppArmor/SELinux. In Kubernetes enforce the `restricted` Pod Security Standard.

## Network, resources, filesystem (DOCKER-NET-*, DOCKER-RES-*, DOCKER-FS-*)

Docker publishes ports through iptables and bypasses host firewalls like ufw: bind internal services to
`127.0.0.1:PORT:PORT` or leave them unpublished on a user-defined network. No SSH servers in containers. In
Kubernetes, default-deny NetworkPolicies. Set memory/CPU/pids limits and bounded restarts
(`on-failure:5`) so one container cannot exhaust the host. Read-only root filesystem with tmpfs scratch space;
`:ro` on read-only volumes.

## Images (DOCKER-IMG-*)

- Pin bases: `FROM node:22.11-slim@sha256:…` (tag for humans, digest for immutability); keep them fresh
  with Dependabot/Renovate. Pin service images in Compose/Kubernetes the same way.
- Prefer minimal, maintained bases (distroless, `-slim`, Alpine, Chainguard/Wolfi); no end-of-life runtimes.
- `COPY` instead of `ADD`; never `ADD https://…` or `curl | sh`. Download, verify the checksum, then run.
- Multi-stage builds: compile in a builder stage, copy only the artifact into a minimal runtime stage.
- `.dockerignore`: `.git`, `.env*`, `*.pem`, `*.key`, `node_modules`, local caches, test data.

## Secrets (DOCKER-SECRET-001)

`ENV` values and build `ARG`s are visible in `docker history` and image layers; files deleted in a later layer
still exist in earlier ones. Build-time: `RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci`.
Runtime: environment injection from a secret store, Docker/Compose secrets (`/run/secrets/…`), or Kubernetes
Secrets backed by encryption at rest / External Secrets / SealedSecrets / SOPS. Plain `kind: Secret` manifests
in Git are only base64.

## Kubernetes identity (DOCKER-K8S-001)

Apps rarely need the Kubernetes API: `automountServiceAccountToken: false`, a dedicated service account per
workload, namespaced Roles with explicit verbs/resources, never `cluster-admin` or `*`.

## Supply chain (DOCKER-SUPPLY-*)

In CI: lint Dockerfiles (hadolint), scan images (Trivy/Grype), scan for secrets, check configs (KICS/Checkov/
Docker Bench). On publish: sign (cosign/Notation), attach provenance and an SBOM, push to an access-controlled
registry, and verify signatures at deploy time (admission policy).
