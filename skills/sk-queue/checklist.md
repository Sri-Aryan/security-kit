# Queues, background jobs and scheduled tasks checklist

Source of truth for `sk-queue` check IDs. Covers asynchronous processing in any stack: message brokers (RabbitMQ,
Kafka, SQS/SNS, Pub/Sub, Azure Service Bus, NATS, Redis streams), job systems (Sidekiq, Celery, BullMQ, RQ, Resque,
Hangfire, Laravel queues, Oban, Temporal), and cron/scheduled tasks. Broker authentication, who may publish,
message validation and safe serialization, authorization when the job runs, idempotency, poison messages, secrets
in payloads, job dashboards, scheduled tasks, and backpressure. Based on the OWASP Microservices Security and
Deserialization cheat sheets. `references/guide.md` explains each check.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| QUEUE-AUTH-001 | Brokers require authentication with per-service credentials and TLS; no default accounts (`guest/guest`), password-less Redis or `PLAINTEXT` Kafka outside local development; brokers aren't publicly reachable | S | High | A07 | CWE-306 |
| QUEUE-PUB-001 | Only intended producers can publish to each queue/topic (ACLs, IAM policies); consumers of cross-boundary messages verify origin (signatures) | S | High | A01 | CWE-345 |
| QUEUE-INPUT-001 | Consumers validate message payloads against schemas and never use unsafe serializers (pickle, Java/JMS object messages, YAML object tags) | S | High | A08 | CWE-502 |
| QUEUE-AUTHZ-001 | Jobs re-establish identity and tenant from trusted data and re-check permissions when they run (the user may have lost access since enqueueing) | S | Medium | A01 | CWE-863 |
| QUEUE-IDEMP-001 | Handlers are idempotent under at-least-once delivery and retries (dedupe keys, conditional updates) | S | Medium | A04 | CWE-841 |
| QUEUE-POISON-001 | Failures are bounded: retry limits with backoff, dead-letter queues, alerting on DLQ growth; one bad message can't block a queue | S | Low | A04 | CWE-400 |
| QUEUE-SECRET-001 | Job/message payloads carry IDs, not secrets or sensitive personal data (payloads are stored in brokers, Redis, logs and dashboards) | S | Medium | A04 | CWE-312 |
| QUEUE-DASH-001 | Job dashboards and admin UIs (Sidekiq Web, Bull Board, Flower, Hangfire, Horizon, RabbitMQ management, Kafka UIs) require authentication and aren't public | S | High | A01 | CWE-306 |
| QUEUE-CRON-001 | Scheduled tasks run with least privilege, are defined in code/config (not user-editable), and dangerous ones are logged and alerting on failure | S | Low | A04 | CWE-250 |
| QUEUE-LIMIT-001 | Producers can't flood queues: message size limits, per-user enqueue limits, queue length limits/backpressure | S | Medium | API4 | CWE-770 |
