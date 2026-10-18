# Cloud and infrastructure-as-code checklist

Source of truth for `sk-cloud` check IDs. Covers cloud resources defined as code (Terraform/OpenTofu, CloudFormation,
AWS CDK/SAM, Pulumi, Azure Bicep/ARM, Google Deployment Manager, Serverless Framework) on any provider: storage
exposure, IAM, network exposure, encryption, databases, logging, secrets, instance metadata, serverless and API
gateways, state files, keys, TLS and module pinning. Containers and Kubernetes: `sk-docker`. Pipelines: `sk-cicd`.
Based on the OWASP Infrastructure as Code Security and Secure Cloud Architecture cheat sheets and the CIS benchmarks.
`references/guide.md` has the safe setting per provider.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| CLOUD-STORAGE-001 | Buckets, blobs and object stores are private: public-access blocks on, no `public-read`/`allUsers`/anonymous access, no public containers | S | Critical | A01 | CWE-284 |
| CLOUD-IAM-001 | IAM follows least privilege: no `Action: "*"` / `Resource: "*"` allows, no admin/owner roles attached to workloads, no wildcard principals in resource policies | S | High | A01 | CWE-250 |
| CLOUD-NET-001 | Admin and data ports (SSH, RDP, databases, caches, search, Docker/Kubernetes APIs) are not open to 0.0.0.0/0 or ::/0; no "all ports" ingress from the internet | S | High | A05 | CWE-284 |
| CLOUD-DB-001 | Managed databases are not publicly accessible, have backups and deletion protection | S | High | A05 | CWE-284 |
| CLOUD-ENC-001 | Encryption at rest is enabled for storage, databases, volumes, queues and snapshots (customer-managed keys for sensitive data) | S | Medium | A02 | CWE-311 |
| CLOUD-KEY-001 | KMS keys have rotation enabled and restrictive key policies | S | Low | A02 | CWE-320 |
| CLOUD-TLS-001 | Load balancers, CDNs and APIs enforce HTTPS (redirect HTTP, modern TLS policies, viewer protocol HTTPS-only) | S | Medium | A02 | CWE-319 |
| CLOUD-LOG-001 | Audit and access logging is on: CloudTrail/Activity Log/Cloud Audit Logs, VPC flow logs, bucket and load-balancer access logs | S | Medium | A09 | CWE-778 |
| CLOUD-SECRET-001 | No secrets in IaC (literal passwords, keys in variables defaults, user-data, environment blocks, outputs); secrets come from a secret manager | S | Critical | A07 | CWE-798 |
| CLOUD-META-001 | Instance metadata requires IMDSv2 (session tokens) with a low hop limit | S | Medium | A05 | CWE-918 |
| CLOUD-FN-001 | Serverless functions and API gateways require authentication (no `NONE` authorizers or public function URLs for private APIs) and use narrow execution roles | S | High | A01 | CWE-306 |
| CLOUD-STATE-001 | IaC state is stored in an encrypted, access-controlled remote backend; `*.tfstate` files are not committed | S | High | A05 | CWE-312 |
| CLOUD-PIN-001 | Providers and modules are pinned to versions (and module sources to tags/commits) | S | Low | A08 | CWE-829 |
