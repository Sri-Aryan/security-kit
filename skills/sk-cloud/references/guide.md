# Cloud and IaC guide

Sources: OWASP Infrastructure as Code Security and Secure Cloud Architecture cheat sheets, CIS AWS/Azure/GCP
Foundations benchmarks. Tool-neutral: the same settings exist in Terraform, CloudFormation/CDK, Pulumi and Bicep.

Infrastructure defined in code can be reviewed like code, so the cheapest place to stop a public bucket is the pull
request that creates it. Most cloud breaches are **misconfigurations**, not exploits.

## Safe settings

| Check | AWS | Azure | GCP |
|---|---|---|---|
| Private storage (CLOUD-STORAGE-001) | `aws_s3_bucket_public_access_block` all four `true`; no `public-read` ACLs; bucket policies without `Principal: "*"` | `allow_nested_items_to_be_public = false`, containers `private` | `uniform_bucket_level_access = true`, `public_access_prevention = "enforced"`, no `allUsers` |
| Least privilege (CLOUD-IAM-001) | specific actions and ARNs; no `AdministratorAccess` on workloads; conditions on resource policies | custom roles; avoid `Owner`/`Contributor` at subscription scope | predefined narrow roles; avoid `roles/owner`/`roles/editor` |
| Network (CLOUD-NET-001) | security groups: admin/DB ports only from VPN/bastion CIDRs or SSM; DBs in private subnets | NSGs: no `*`/`Internet` source to 22/3389/DB ports; Bastion | firewall rules: no `0.0.0.0/0` to admin ports; IAP for SSH |
| Databases (CLOUD-DB-001) | `publicly_accessible = false`, `deletion_protection = true`, backups ≥ 7 days | `public_network_access_enabled = false`, private endpoints | `ipv4_enabled = false` (private IP), backups on |
| Encryption (CLOUD-ENC-001, CLOUD-KEY-001) | `storage_encrypted`, `encrypted`, SSE-KMS; `enable_key_rotation = true` | encryption on with CMK for sensitive data; key rotation policy | CMEK for sensitive data; rotation period |
| TLS (CLOUD-TLS-001) | ALB HTTP→HTTPS redirect, `ELBSecurityPolicy-TLS13-1-2-*`; CloudFront `redirect-to-https` | `https_only = true`, `min_tls_version = "1.2"` | HTTPS load balancers, SSL policy `MODERN`/`RESTRICTED` |
| Logging (CLOUD-LOG-001) | CloudTrail multi-region with log file validation; VPC flow logs; S3/ALB access logs | Activity Log export, diagnostic settings, NSG flow logs | Cloud Audit Logs (data access for sensitive services), VPC flow logs |
| Metadata (CLOUD-META-001) | `metadata_options { http_tokens = "required", http_put_response_hop_limit = 1 }` | (IMDS requires a header by default) | (metadata requires `Metadata-Flavor` header) |
| Serverless/API (CLOUD-FN-001) | authorizers (Cognito/JWT/IAM) on API Gateway; function URLs `AWS_IAM`; one role per function | Functions `auth_level` not anonymous for private APIs | Cloud Run/Functions without `allUsers` invoker unless public |

## Secrets and state (CLOUD-SECRET-001, CLOUD-STATE-001)

Never put secrets in `.tf`/templates, variable defaults, `user_data` or outputs: they end up in state and plan files.
Use secret-manager data sources, provider-generated passwords (`manage_master_user_password = true`), or ephemeral
resources. Keep state in an encrypted remote backend with locking and restricted access; never commit `*.tfstate`
(add it to `.gitignore`). A committed state file means: rotate everything in it.

## Supply chain (CLOUD-PIN-001)

Pin provider versions in `required_providers`, pin module sources (`?ref=v1.2.3` or a commit SHA), commit
`.terraform.lock.hcl`. Run plans in CI with policy checks (Checkov, tfsec/Trivy, KICS, OPA/Conftest) if available.
