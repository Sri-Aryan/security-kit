"""sk-docker rules: Dockerfiles, Compose files, Kubernetes manifests."""

SKILL = "sk-docker"

DOCKERFILE = r"(?i)(^|/)(Dockerfile[^/]*|[^/]*\.dockerfile|Containerfile)$"
COMPOSE = r"(?i)(^|/)(docker-)?compose[^/]*\.ya?ml$"
K8S_KIND = r"(?m)^\s*kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet|ReplicationController)\b"


def dockerfile(rule):
    rule.setdefault("files", ["docker"])
    rule["path_includes"] = DOCKERFILE
    return rule


def compose(rule):
    rule.setdefault("files", ["docker", "config"])
    rule["path_includes"] = COMPOSE
    return rule


def k8s(rule):
    rule.setdefault("files", ["config"])
    rule["file_requires"] = K8S_KIND
    return rule


RULES = [
    # ------------------------------------------------------------------ HOST / DAEMON
    {
        "id": "docker-daemon-tcp", "check_id": "DOCKER-HOST-001", "title": "Docker daemon exposed over TCP",
        "files": ["any"], "pattern": r"-H\s+tcp://|tcp://0\.0\.0\.0:2375|tcp://[^\s'\"]+:2375\b|\"hosts\"\s*:\s*\[[^\]]*tcp://",
        "confidence": "HIGH", "note": "Port 2375 is unauthenticated root on the host. Use the Unix socket or TLS (2376) with client certs.",
        "examples": {"match": ["ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2375"], "no_match": ["DOCKER_HOST=unix:///var/run/docker.sock"]},
    },
    {
        "id": "docker-socket-mount", "check_id": "DOCKER-HOST-002", "title": "Docker socket mounted into a container",
        "files": ["docker", "config", "shell"], "pattern": r"/var/run/docker\.sock\s*:|-v\s+/var/run/docker\.sock|path\s*:\s*['\"]?/var/run/docker\.sock",
        "confidence": "HIGH", "note": "Anyone in the container controls the Docker daemon and therefore the host.",
        "examples": {"match": ["    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock:ro"], "no_match": ["    volumes:\n      - ./data:/data"]},
    },
    {
        "id": "docker-daemon-debug", "check_id": "DOCKER-DAEMON-001", "title": "Docker daemon in debug mode",
        "files": ["config"], "path_includes": r"(?i)daemon\.json$", "pattern": r"\"debug\"\s*:\s*true|\"log-level\"\s*:\s*\"debug\"",
        "confidence": "MEDIUM", "examples": {"match": ["{ \"debug\": true }"], "no_match": ["{ \"log-level\": \"info\" }"]},
    },
    # ------------------------------------------------------------------ USER
    dockerfile({
        "id": "docker-no-user", "check_id": "DOCKER-USER-001", "type": "absence", "scope": "file",
        "title": "Dockerfile has no non-root USER (container runs as root)",
        "when": r"(?im)^\s*FROM\s+", "missing": r"(?im)^\s*USER\s+(?!root\b|0\b|0:)\S+|:nonroot\b|distroless[^\n]*nonroot",
        "confidence": "HIGH",
        "examples": {"match": ["FROM node:20-slim\nCOPY . .\nCMD [\"node\", \"server.js\"]"], "no_match": ["FROM node:20-slim\nUSER node\nCMD [\"node\", \"server.js\"]"]},
    }),
    dockerfile({
        "id": "docker-user-root", "check_id": "DOCKER-USER-001", "title": "Dockerfile switches to root",
        "pattern": r"(?i)^\s*USER\s+(root|0)(:\S+)?\s*$", "confidence": "MEDIUM",
        "note": "Fine mid-build if a later USER drops privileges; check the final stage.",
        "examples": {"match": ["USER root"], "no_match": ["USER app"]},
    }),
    {
        "id": "docker-run-as-root-config", "check_id": "DOCKER-USER-001", "title": "Workload configured to run as root",
        "files": ["docker", "config"],
        "pattern": r"(?i)^\s*user\s*:\s*['\"]?(root|0)(:\d+)?['\"]?\s*$|runAsUser\s*:\s*0\b|runAsNonRoot\s*:\s*false",
        "confidence": "HIGH", "examples": {"match": ["    user: root", "        runAsUser: 0"], "no_match": ["    user: \"1000:1000\""]},
    },
    k8s({
        "id": "k8s-no-run-as-non-root", "check_id": "DOCKER-USER-001", "type": "absence", "scope": "file",
        "title": "Kubernetes workload does not require a non-root user",
        "when": r"(?m)^\s*containers\s*:", "missing": r"runAsNonRoot\s*:\s*true|runAsUser\s*:\s*[1-9]",
        "confidence": "MEDIUM",
        "examples": {"match": ["kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: app"],
                     "no_match": ["kind: Deployment\nspec:\n  securityContext:\n    runAsNonRoot: true\n  containers:\n    - name: app"]},
    }),
    # ------------------------------------------------------------------ PRIV
    {
        "id": "docker-privileged", "check_id": "DOCKER-PRIV-001", "title": "Privileged container",
        "files": ["docker", "config", "shell"], "pattern": r"--privileged\b|^\s*privileged\s*:\s*true",
        "confidence": "HIGH", "examples": {"match": ["    privileged: true", "docker run --privileged app"], "no_match": ["    privileged: false"]},
    },
    {
        "id": "docker-dangerous-cap-inline", "check_id": "DOCKER-PRIV-002", "title": "Dangerous Linux capability added",
        "files": ["docker", "config", "shell"],
        "pattern": r"(cap_add\s*:|--cap-add[= ]|\badd\s*:)\s*\[?[^\n\]]*\b(SYS_ADMIN|SYS_MODULE|SYS_PTRACE|NET_ADMIN|DAC_READ_SEARCH|SYS_RAWIO|ALL)\b",
        "confidence": "HIGH", "examples": {"match": ["docker run --cap-add=SYS_ADMIN app", "          add: [\"NET_ADMIN\"]"], "no_match": ["          drop: [\"ALL\"]"]},
    },
    {
        "id": "docker-dangerous-cap-list", "check_id": "DOCKER-PRIV-002", "title": "Dangerous Linux capability added",
        "files": ["docker", "config"],
        "pattern": r"^\s*-\s*['\"]?(CAP_)?(SYS_ADMIN|SYS_MODULE|SYS_PTRACE|NET_ADMIN|DAC_READ_SEARCH|SYS_RAWIO|ALL)['\"]?\s*$",
        "near": {"pattern": r"(cap_add\s*:|^\s*add\s*:)", "lines": 3}, "not_near": {"pattern": r"(cap_drop\s*:|^\s*drop\s*:)", "lines": 1},
        "confidence": "HIGH", "examples": {"match": ["    cap_add:\n      - SYS_ADMIN"], "no_match": ["    cap_drop:\n      - ALL"]},
    },
    compose({
        "id": "compose-no-cap-drop", "check_id": "DOCKER-PRIV-002", "type": "absence", "scope": "file",
        "title": "Compose services keep the default capability set (no cap_drop)",
        "when": r"(?m)^services\s*:", "missing": r"cap_drop\s*:", "confidence": "LOW",
        "examples": {"match": ["services:\n  web:\n    image: app:1.2"], "no_match": ["services:\n  web:\n    cap_drop: [ALL]"]},
    }),
    {
        "id": "docker-priv-escalation-allowed", "check_id": "DOCKER-PRIV-003", "title": "Privilege escalation explicitly allowed",
        "files": ["config"], "pattern": r"allowPrivilegeEscalation\s*:\s*true", "confidence": "HIGH",
        "examples": {"match": ["          allowPrivilegeEscalation: true"], "no_match": ["          allowPrivilegeEscalation: false"]},
    },
    k8s({
        "id": "k8s-no-priv-escalation-block", "check_id": "DOCKER-PRIV-003", "type": "absence", "scope": "file",
        "title": "Kubernetes workload does not set allowPrivilegeEscalation: false",
        "when": r"(?m)^\s*containers\s*:", "missing": r"allowPrivilegeEscalation\s*:\s*false", "confidence": "LOW",
        "examples": {"match": ["kind: Pod\nspec:\n  containers:\n    - name: a"], "no_match": ["kind: Pod\nspec:\n  containers:\n    - securityContext:\n        allowPrivilegeEscalation: false"]},
    }),
    compose({
        "id": "compose-no-new-privileges", "check_id": "DOCKER-PRIV-003", "type": "absence", "scope": "file",
        "title": "Compose services without no-new-privileges", "when": r"(?m)^services\s*:", "missing": r"no-new-privileges",
        "confidence": "LOW",
        "examples": {"match": ["services:\n  web:\n    image: app:1"], "no_match": ["services:\n  web:\n    security_opt: [\"no-new-privileges:true\"]"]},
    }),
    {
        "id": "docker-host-namespaces", "check_id": "DOCKER-PRIV-004", "title": "Container shares a host namespace",
        "files": ["docker", "config", "shell"],
        "pattern": r"(?i)network_mode\s*:\s*['\"]?host|--net(work)?[= ]host\b|^\s*pid\s*:\s*['\"]?host|--pid[= ]host\b|^\s*ipc\s*:\s*['\"]?host|--ipc[= ]host\b|host(Network|PID|IPC)\s*:\s*true|userns_mode\s*:\s*['\"]?host",
        "confidence": "HIGH", "examples": {"match": ["    network_mode: host", "      hostPID: true"], "no_match": ["    network_mode: bridge"]},
    },
    {
        "id": "docker-sensitive-host-mount", "check_id": "DOCKER-PRIV-005", "title": "Sensitive host path mounted into a container",
        "files": ["docker", "config", "shell"],
        "pattern": r"(^\s*-\s*['\"]?|-v\s+['\"]?|path\s*:\s*['\"]?)(/|/etc|/proc|/sys|/root|/var/run|/var/lib/docker|/var/lib/kubelet|/boot|/dev|/home|~/\.ssh|\$HOME/\.ssh)(/[^:'\"\s]*)?['\"]?(:|\s*$)",
        "not_near": {"pattern": r"docker\.sock", "lines": 0},
        "confidence": "HIGH", "examples": {"match": ["      - /:/host", "      - /etc:/host-etc:ro", "        hostPath:\n          path: /proc"],
                                         "no_match": ["      - ./app:/app", "      - data:/var/lib/postgresql/data"]},
    },
    {
        "id": "docker-lsm-disabled", "check_id": "DOCKER-LSM-001", "title": "seccomp / AppArmor / SELinux confinement disabled",
        "files": ["docker", "config", "shell"],
        "pattern": r"(?i)(seccomp|apparmor)[:=]\s*['\"]?unconfined|label[:=]\s*['\"]?disable|type\s*:\s*['\"]?Unconfined",
        "confidence": "HIGH", "examples": {"match": ["    security_opt:\n      - seccomp:unconfined", "        seccompProfile:\n          type: Unconfined"], "no_match": ["      type: RuntimeDefault"]},
    },
    # ------------------------------------------------------------------ NET / RES / FS
    compose({
        "id": "compose-port-all-interfaces", "check_id": "DOCKER-NET-001", "title": "Port published on all host interfaces",
        "pattern": r"^\s*-\s*['\"]?(0\.0\.0\.0:)?\d{2,5}:\d{2,5}(/(tcp|udp))?['\"]?\s*$", "confidence": "LOW",
        "note": "Docker bypasses host firewalls such as ufw. Bind internal services to 127.0.0.1:PORT:PORT.",
        "examples": {"match": ["    ports:\n      - \"8080:8080\""], "no_match": ["    ports:\n      - \"127.0.0.1:8080:8080\""]},
    }),
    dockerfile({
        "id": "docker-expose-ssh", "check_id": "DOCKER-NET-001", "title": "SSH exposed from a container",
        "pattern": r"(?i)^\s*EXPOSE\s+[^\n]*\b22\b|openssh-server|sshd\b", "confidence": "MEDIUM",
        "examples": {"match": ["EXPOSE 22 8080"], "no_match": ["EXPOSE 8080"]},
    }),
    compose({
        "id": "compose-no-limits", "check_id": "DOCKER-RES-001", "type": "absence", "scope": "file",
        "title": "Compose services without memory/CPU/pids limits",
        "when": r"(?m)^services\s*:", "missing": r"mem_limit|memory\s*:|cpus\s*:|pids_limit|resources\s*:", "confidence": "LOW",
        "examples": {"match": ["services:\n  web:\n    image: app:1"], "no_match": ["services:\n  web:\n    mem_limit: 512m"]},
    }),
    k8s({
        "id": "k8s-no-limits", "check_id": "DOCKER-RES-001", "type": "absence", "scope": "file",
        "title": "Kubernetes workload without resource limits", "when": r"(?m)^\s*containers\s*:", "missing": r"(?m)^\s*limits\s*:",
        "confidence": "MEDIUM",
        "examples": {"match": ["kind: Deployment\nspec:\n  containers:\n    - name: a"], "no_match": ["kind: Deployment\n  containers:\n    - resources:\n        limits:\n          memory: 256Mi"]},
    }),
    k8s({
        "id": "k8s-writable-rootfs", "check_id": "DOCKER-FS-001", "type": "absence", "scope": "file",
        "title": "Kubernetes workload with a writable root filesystem",
        "when": r"(?m)^\s*containers\s*:", "missing": r"readOnlyRootFilesystem\s*:\s*true", "confidence": "LOW",
        "examples": {"match": ["kind: Pod\nspec:\n  containers:\n    - name: a"], "no_match": ["kind: Pod\n  containers:\n    - securityContext:\n        readOnlyRootFilesystem: true"]},
    }),
    # ------------------------------------------------------------------ IMG
    dockerfile({
        "id": "docker-from-latest", "check_id": "DOCKER-IMG-001", "title": "Base image untagged or :latest",
        "pattern": r"(?i)^\s*FROM\s+(--platform=\S+\s+)?(?!scratch\b)[\w./${}-]+(:latest)?(\s+AS\s+\S+)?\s*$",
        "confidence": "MEDIUM", "note": "Ignore if the name refers to an earlier build stage (FROM builder).",
        "examples": {"match": ["FROM node", "FROM python:latest AS build"], "no_match": ["FROM node:20.11-slim", "FROM scratch"]},
    }),
    dockerfile({
        "id": "docker-from-no-digest", "check_id": "DOCKER-IMG-001", "title": "Base image pinned by tag but not by digest",
        "pattern": r"(?i)^\s*FROM\s+(--platform=\S+\s+)?[\w./-]+:(?!latest\b)[\w.-]+(?!@sha256)(\s+AS\s+\S+)?\s*$",
        "confidence": "LOW",
        "examples": {"match": ["FROM node:20-slim"], "no_match": ["FROM node:20-slim@sha256:" + "a" * 64]},
    }),
    {
        "id": "docker-image-unpinned", "check_id": "DOCKER-IMG-001", "title": "Service image untagged or :latest",
        "files": ["docker", "config"], "pattern": r"^\s*(-\s*)?image\s*:\s*['\"]?(?!\$|\{\{)[\w./-]+(:latest)?['\"]?\s*$",
        "confidence": "MEDIUM", "examples": {"match": ["    image: redis", "        image: nginx:latest"], "no_match": ["    image: redis:7.2-alpine"]},
    },
    {
        "id": "docker-eol-base", "check_id": "DOCKER-IMG-002", "title": "End-of-life or deprecated base image",
        "files": ["docker", "config"],
        "pattern": r"(?i)(FROM\s+(--platform=\S+\s+)?|image\s*:\s*['\"]?)(node:(4|6|8|10|12|14|16|17|19|21)(\b|[.-])|python:(2|3\.[0-8])(\b|-)|ubuntu:(1[0-8]\.\d\d|14|16|18)\b|debian:(jessie|stretch|buster|[6-9]|10)\b|alpine:3\.(\d|1[0-7])\b|centos(:|\s|$)|php:(5|7|8\.0)(\b|[.-])|ruby:2\.|openjdk:|golang:1\.(1\d|20)\b|mysql:(5\.[0-6])|postgres:(9|10|11)\b|mongo:([2-4])\b)",
        "confidence": "MEDIUM", "examples": {"match": ["FROM node:14-alpine", "    image: postgres:11"], "no_match": ["FROM node:22-alpine"]},
    },
    dockerfile({
        "id": "docker-add-remote", "check_id": "DOCKER-IMG-003", "title": "ADD of a remote URL or archive",
        "pattern": r"(?i)^\s*ADD\s+(--\S+\s+)*(https?://|\S+\.(tar|tgz|tar\.gz|tar\.xz|zip)\b)", "confidence": "MEDIUM",
        "examples": {"match": ["ADD https://example.com/tool.tar.gz /opt/"], "no_match": ["COPY app.tar.gz /opt/"]},
    }),
    dockerfile({
        "id": "docker-add-local", "check_id": "DOCKER-IMG-003", "title": "ADD used for local files (prefer COPY)",
        "pattern": r"(?i)^\s*ADD\s+(?!https?://)(--\S+\s+)*\S+", "confidence": "LOW",
        "examples": {"match": ["ADD . /app"], "no_match": ["COPY . /app"]},
    }),
    dockerfile({
        "id": "docker-curl-pipe-shell", "check_id": "DOCKER-IMG-004", "title": "Remote script piped into a shell during build",
        "pattern": r"(?i)(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", "confidence": "HIGH",
        "examples": {"match": ["RUN curl -fsSL https://get.example.sh | sh"], "no_match": ["RUN curl -fsSLo /tmp/x.sh https://x && echo \"$SHA  /tmp/x.sh\" | sha256sum -c"]},
    }),
    dockerfile({
        "id": "docker-single-stage-build-tools", "check_id": "DOCKER-IMG-005", "type": "absence", "scope": "file",
        "title": "Single-stage image that installs build tooling",
        "when": r"(?i)(npm\s+(ci|install)|pip\s+install|go\s+build|mvn\s+|gradle\s+|cargo\s+build|apt-get\s+install[^\n]*(build-essential|gcc|make))",
        "missing": r"(?im)^\s*FROM\s+[^\n]+\s+AS\s+\S+", "confidence": "LOW",
        "examples": {"match": ["FROM node:20\nCOPY . .\nRUN npm ci && npm run build"], "no_match": ["FROM node:20 AS build\nRUN npm ci\nFROM node:20-slim\nCOPY --from=build /app /app"]},
    }),
    {
        "id": "docker-no-dockerignore", "check_id": "DOCKER-IMG-006", "type": "absence", "scope": "project",
        "title": "Whole build context copied but no .dockerignore excludes secrets",
        "files": ["docker", ".dockerignore"], "when": r"(?im)^\s*(COPY|ADD)\s+(--\S+\s+)*\.\s+", "missing": r"(?m)^\s*!?(\.env|\.git|\*\*?)",
        "confidence": "MEDIUM",
        "examples": {"match": ["FROM node:20\nCOPY . ."], "no_match": [".git\n.env\nnode_modules"]},
    },
    # ------------------------------------------------------------------ SECRET
    dockerfile({
        "id": "docker-env-arg-secret", "check_id": "DOCKER-SECRET-001", "title": "Secret baked into the image via ENV/ARG",
        "pattern": r"(?i)^\s*(ENV|ARG)\s+\w*(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE|ACCESS_?KEY|CREDENTIAL)\w*", "confidence": "HIGH",
        "note": "Use RUN --mount=type=secret for build time and runtime env/secrets for the app.",
        "examples": {"match": ["ENV DB_PASSWORD=hunter2", "ARG NPM_TOKEN"], "no_match": ["ENV NODE_ENV=production"]},
    }),
    dockerfile({
        "id": "docker-copy-secret-file", "check_id": "DOCKER-SECRET-001", "title": "Secret file copied into the image",
        "pattern": r"(?i)^\s*(COPY|ADD)\s+[^\n]*(\.env\b|id_rsa|\.pem\b|\.key\b|credentials|\.npmrc|\.pypirc|serviceAccount|\.aws\b|\.ssh\b)",
        "confidence": "HIGH", "examples": {"match": ["COPY .env /app/.env"], "no_match": ["COPY package.json ./"]},
    }),
    compose({
        "id": "compose-literal-secret", "check_id": "DOCKER-SECRET-001", "title": "Literal secret in Compose environment",
        "pattern": r"(?i)^\s*-?\s*['\"]?\w*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)\w*['\"]?\s*[:=]\s*['\"]?(?!\$\{|\$\$|\s*$)([^'\"\s#]{4,})",
        "redact": 3, "confidence": "MEDIUM", "note": "Fine for throwaway local dev databases; use env files or Docker secrets for anything shared.",
        "examples": {"match": ["    environment:\n      POSTGRES_PASSWORD: s3cretpw"], "no_match": ["      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}"]},
    }),
    {
        "id": "k8s-plain-secret-manifest", "check_id": "DOCKER-SECRET-001", "title": "Kubernetes Secret with values committed to the repository",
        "files": ["config"], "file_requires": r"(?m)^\s*kind\s*:\s*Secret\b", "pattern": r"(?m)^\s*(data|stringData)\s*:\s*$",
        "confidence": "MEDIUM", "note": "Base64 is not encryption. Use SealedSecrets/SOPS/External Secrets.",
        "examples": {"match": ["apiVersion: v1\nkind: Secret\nstringData:\n  password: x"], "no_match": ["kind: ConfigMap\ndata:\n  a: b"]},
    },
    {
        "id": "k8s-literal-secret-env", "check_id": "DOCKER-SECRET-001", "title": "Secret passed as a literal env value in a manifest",
        "files": ["config"], "multiline": True,
        "pattern": r"-\s*name\s*:\s*['\"]?\w*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY)\w*['\"]?\s*\n\s*value\s*:\s*['\"]?[^'\"\s{$][^\n]*",
        "confidence": "MEDIUM", "redact": True,
        "examples": {"match": ["        env:\n          - name: DB_PASSWORD\n            value: hunter2"], "no_match": ["          - name: DB_PASSWORD\n            valueFrom:\n              secretKeyRef:"]},
    },
    # ------------------------------------------------------------------ K8S identity
    {
        "id": "k8s-cluster-admin-binding", "check_id": "DOCKER-K8S-001", "title": "Workload bound to cluster-admin",
        "files": ["config"], "file_requires": r"kind\s*:\s*(Cluster)?RoleBinding", "pattern": r"name\s*:\s*['\"]?cluster-admin\b",
        "confidence": "HIGH", "examples": {"match": ["kind: ClusterRoleBinding\nroleRef:\n  kind: ClusterRole\n  name: cluster-admin"], "no_match": ["kind: RoleBinding\nroleRef:\n  name: app-reader"]},
    },
    {
        "id": "k8s-rbac-wildcard", "check_id": "DOCKER-K8S-001", "title": "RBAC rule with wildcard verbs or resources",
        "files": ["config"], "file_requires": r"kind\s*:\s*(Cluster)?Role\b", "pattern": r"(verbs|resources|apiGroups)\s*:\s*\[\s*['\"]\*['\"]\s*\]|^\s*-\s*['\"]\*['\"]\s*$",
        "confidence": "HIGH", "examples": {"match": ["kind: ClusterRole\nrules:\n  - verbs: [\"*\"]"], "no_match": ["kind: Role\nrules:\n  - verbs: [\"get\", \"list\"]"]},
    },
    {
        "id": "k8s-automount-token", "check_id": "DOCKER-K8S-001", "title": "Service-account token explicitly automounted",
        "files": ["config"], "pattern": r"automountServiceAccountToken\s*:\s*true", "confidence": "LOW",
        "examples": {"match": ["  automountServiceAccountToken: true"], "no_match": ["  automountServiceAccountToken: false"]},
    },
    # ------------------------------------------------------------------ SUPPLY
    {
        "id": "docker-no-image-scanning", "check_id": "DOCKER-SUPPLY-001", "type": "absence", "scope": "project",
        "title": "No image scanning or Dockerfile linting found", "files": ["any"],
        "when": r"(?im)^\s*FROM\s+\S+", "missing": r"(?i)(trivy|grype|hadolint|docker\s+scout|snyk\s+container|clair|dockle|anchore|kics|checkov)",
        "confidence": "LOW", "examples": {"match": ["FROM node:20"], "no_match": ["      - uses: aquasecurity/trivy-action@0123"]},
    },
    {
        "id": "docker-no-image-signing", "check_id": "DOCKER-SUPPLY-002", "type": "absence", "scope": "project",
        "title": "Images are pushed but not signed or attested", "files": ["any"],
        "when": r"(?i)docker\s+push|docker/build-push-action|kaniko|buildah\s+push|ko\s+publish",
        "missing": r"(?i)(cosign|notation|sigstore|attest|provenance\s*:\s*true|sbom\s*:\s*true|slsa)", "confidence": "LOW",
        "examples": {"match": ["      - run: docker push ghcr.io/acme/app:1.0"], "no_match": ["      - run: cosign sign ghcr.io/acme/app@sha256:x"]},
    },
]
