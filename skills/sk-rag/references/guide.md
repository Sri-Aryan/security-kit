# RAG security guide: how to verify and fix each concept

Source: OWASP RAG Security Cheat Sheet. Framework- and store-neutral. RAG does not remove risk; it moves it
into the data pipeline. Trace each stage and ask: **who can write here, who can read here, and what happens
when it fails?**

```
sources → connectors → ingestion (parse, scan, chunk) → embedding → vector store/index
        → query → retrieval (filter!) → context assembly → model → output validation → user / tools
                                    ↘ caches ↗                         ↘ logs / traces
```

OWASP's implementation priority: **immediately** provenance, context delimiters, per-chunk ACLs, tenant
isolation, query normalization, output validation, observability, fail-closed behaviour. **Next** signed
attribution, index integrity monitoring, tool controls, cache isolation, connector vetting, deletion
controls. **Advanced** embedding-distribution monitoring, cross-model validation, embedding privacy.

---

## Poisoning and supply chain (RAG-POISON-*, RAG-SUPPLY-001)

Anyone who can write to an ingested source can write instructions into every user's answers.
- Allow-list sources; new sources need approval; inventory connectors with owners, credentials, schedules.
- Record provenance per document (source, uploader, timestamp, approval) and keep it on every chunk.
- Before indexing: extract text the way the model will see it, strip invisible/zero-width Unicode, hidden
  HTML/CSS text, comments and metadata, scan for injection markers, and validate content type by content.
- User uploads go to quarantine/review, or into a per-user space that only that user's queries can reach.
- High assurance: SHA-256 digests in a separately controlled, signed manifest, verified before retrieval.
  A matching digest proves consistency, not safety.
- Connectors run with least privilege (specific folders/spaces), pinned versions, staging before searchable.

## Embeddings (RAG-EMBED-*)

Embeddings are invertible and leak membership. Treat them as the source documents: same ACLs, encryption at
rest, no raw embedding endpoint for untrusted callers (or authenticated + rate-limited). Pin embedding model
and library versions, record the model version per document, never `trust_remote_code` from unvetted repos.

## Access control and isolation: the most critical part (RAG-ACL-*, RAG-ISO-001)

```
ingest:   chunk.metadata = { tenant_id, owner_id, allowed_groups, classification, doc_id, source, version }
retrieve: store.search(query_vector, k=4,
                       filter = { tenant_id: user.tenant, allowed_groups ∩ user.groups, classification ≤ user.clearance })
```
- Enforce in the **query** (pre-filter). Retrieve-then-filter leaks via ranking/scores and returns fewer results.
- Never ask the model to "only use documents the user may see".
- Tenants: separate collections/namespaces, or a mandatory server-side filter that cannot be omitted.
  Run cross-tenant canary queries in CI.
- Changes: when source permissions change or a document is deleted, update/delete its chunks, embeddings,
  index entries and cached answers; keep a deletion log; audit for orphaned chunks.

## Context assembly (RAG-CTX-*)

- Retrieved text goes into a user/tool message inside explicit delimiters
  (`<documents><document id="…">…</document></documents>`), followed by a reminder that it is data. Never in
  the system prompt.
- Bound it: about 3–5 chunks, 2,000–4,000 tokens, a relevance threshold.
- Scan chunks for injection patterns before inclusion. See `/sk-prompt-injection` for model-side defenses.

## Vector store (RAG-INDEX-*)

Many vector databases ship with authentication disabled. Enable auth (API keys/OIDC), keep them on private
networks (no published ports), no default credentials. Only the ingestion pipeline can write; log inserts,
updates and deletes with identity; keep snapshots; alert on sudden growth (bulk poisoning) or shrinkage.

## Queries (RAG-QUERY-*)

Rate-limit per user/agent, watch for enumeration (systematic term variation), log query IDs and identity (not
raw text), and do not return similarity scores or rank internals.

## Output, attribution, tools (RAG-OUT-001, RAG-ATTR-001, RAG-TOOL-001)

Validate outputs before returning: redact PII/secrets according to the requester's access, schema-validate
structured outputs, never execute output. Return document/chunk attribution with every answer (with hashes or
signatures in regulated settings). Tool calls influenced by retrieved content: authorized independently of the
model, per-context allow-lists, explicit user confirmation for payments/deletions/external calls, full chain
logged (query → retrieval → output → tool call).

## Caches (RAG-CACHE-001)

Key caches by user, tenant and permission level (not just the question), set TTLs by sensitivity, invalidate on
document update/deletion/permission change, do not cache highly sensitive answers, and re-check cached entries
when a document is later found to be poisoned.

## Fail closed (RAG-FAIL-001)

| Failure | Correct behaviour |
|---|---|
| Retrieval error/empty | refuse with "knowledge base unavailable"; do not answer from model memory |
| Access check fails | return nothing |
| Hash/integrity check fails | exclude the document and alert |
| Attribution unavailable (regulated) | block the response |
| Cache error | compute fresh, never serve stale |
Make degraded states visible to operators and users; treat repeated failures as possible attacks.

## Monitoring and testing (RAG-MON-001, RAG-TEST-001)

Trace with correlation IDs, document IDs, authorization decisions, model versions and tool outcomes; do not log
raw prompts/content by default (use a restricted, redacted evidence store if needed). Alert on anomalous
retrieval, repeated injection attempts and access violations. Red-team in CI with: a poisoned test document
carrying a harmless marker, a cross-tenant canary document, a revoked-permission document, a deleted
document, cache cross-user checks, and an instrumented no-op tool.
