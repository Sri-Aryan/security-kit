# Queues, jobs and scheduled tasks guide

Sources: OWASP Microservices Security and Deserialization cheat sheets; broker vendor security guides.

Asynchronous work moves trust across time and processes: a message written now is acted on later, by a worker with
its own (often broad) privileges. Treat every message as **untrusted input from whoever can publish to that queue**,
and every job as **a request made on behalf of a user who may have lost access since**.

## Brokers (QUEUE-AUTH-001, QUEUE-PUB-001)

- Per-service credentials (RabbitMQ users + vhost permissions, Kafka SASL/SCRAM or mTLS + ACLs, SQS/SNS/PubSub IAM per
  queue, Redis ACL users with `requirepass`/`protected-mode yes`), TLS on all connections, no default `guest` user.
- Brokers live on private networks only. Producers get publish rights only to their topics; consumers read only theirs.
- Messages crossing trust boundaries (from another team, tenant or the internet via a webhook) carry a signature or
  come through an authenticated gateway.

## Payloads (QUEUE-INPUT-001, QUEUE-SECRET-001, QUEUE-LIMIT-001)

- JSON/Avro/Protobuf with a schema; validate in the consumer. Never pickle (Celery: `task_serializer = 'json'`,
  `accept_content = ['json']`), never JMS `ObjectMessage` or Jackson/Spring trusted packages `*`.
- Send IDs, not secrets or personal data: payloads end up in Redis, DLQs, logs and dashboards.
- Size limits per message; per-user enqueue limits on request handlers that create jobs.

## Running jobs (QUEUE-AUTHZ-001, QUEUE-IDEMP-001, QUEUE-POISON-001)

- Load the user/tenant from the database by ID and re-check permission before acting (they may have been removed).
  Never trust roles or flags carried in the payload.
- At-least-once delivery means duplicates: use idempotency keys or conditional updates (`UPDATE ... WHERE status =
  'pending'`) so a retried "charge" or "send" runs once.
- Bounded retries with exponential backoff, a dead-letter queue, alerts on DLQ growth.

## Dashboards and cron (QUEUE-DASH-001, QUEUE-CRON-001)

Sidekiq Web, Bull Board, Arena, Flower, Hangfire, Laravel Horizon, RabbitMQ management, Kafka UI/AKHQ/Kafdrop can
show payloads and retry/delete jobs: require admin authentication and keep them off the public internet. Scheduled
tasks are code-reviewed config, run with the minimum privileges, log what they did and alert when they fail.
