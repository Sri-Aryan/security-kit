# RAG security checklist

Source of truth for `sk-rag` check IDs. Covers retrieval-augmented generation pipelines end to end:
ingestion, chunking, embedding, vector store, retrieval, prompt assembly, generation, tools, caching and
operations, in any language, framework (LangChain, LlamaIndex, Haystack, Semantic Kernel, custom) or vector
store (pgvector, Qdrant, Weaviate, Pinecone, Chroma, Milvus, Elasticsearch/OpenSearch, Redis…). Based on the
OWASP RAG Security Cheat Sheet. Injection into the model itself is covered in depth by `sk-prompt-injection`.
`references/guide.md` explains each check.

Columns: **Mode** S = static, D = dynamic (test documents and queries). OWASP = OWASP Top 10 2021.

## Document poisoning (POISON)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| RAG-POISON-001 | Ingestion sources are allow-listed and approved; provenance (source, uploader, time, approval) is recorded; untrusted uploads are reviewed or quarantined before they become searchable | S | High | A08 | CWE-345 |
| RAG-POISON-002 | Documents are scanned before indexing for injection markers, hidden text and invisible Unicode; content type is validated by content, not extension | S | High | A03 | CWE-1427 |
| RAG-POISON-003 | Approved documents have digests in a separately controlled (signed) manifest that is verified before retrieval | S | Medium | A08 | CWE-354 |

## Embeddings (EMBED)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| RAG-EMBED-001 | Embedding endpoints are not exposed to untrusted users or agents; any exposed endpoint is authenticated and rate-limited | S | High | A01 | CWE-306 |
| RAG-EMBED-002 | Embeddings get the same access controls as their source documents and are encrypted at rest (they are invertible) | S | Medium | A02 | CWE-311 |
| RAG-EMBED-003 | Embedding models and ingestion libraries are pinned; the model version is recorded per document; no `trust_remote_code` from unvetted repositories | S | Medium | A08 | CWE-829 |

## Context window (CTX)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| RAG-CTX-001 | Retrieved content is placed in the context as delimited data (never in the system prompt), with instructions reinforced after it | S | High | A03 | CWE-1427 |
| RAG-CTX-002 | Retrieval is bounded (about 3–5 chunks, a token budget, a relevance threshold) so retrieved text cannot crowd out instructions | S | Medium | A04 | CWE-770 |
| RAG-CTX-003 | Chunks are checked for injection patterns before being added to the context | S | Medium | A03 | CWE-1427 |

## Access control and isolation (ACL / ISO)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| RAG-ACL-001 | Every chunk carries ACL metadata (tenant, owner, roles, classification) preserved through chunking and embedding | S | Critical | A01 | CWE-284 |
| RAG-ACL-002 | Access is enforced at retrieval time as a pre-filter in the vector query, before content reaches the model (not by the model, not retrieve-then-filter) | S+D | Critical | A01 | CWE-863 |
| RAG-ACL-003 | Permission changes and deletions propagate to chunks, embeddings, indexes and caches; orphaned chunks are audited | S | High | A01 | CWE-459 |
| RAG-ISO-001 | Tenants or classification levels are isolated (separate namespaces/collections or mandatory filters); tenant-tuned embedding models are not shared | S+D | Critical | A01 | CWE-668 |

## Vector store and queries (INDEX / QUERY)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| RAG-INDEX-001 | The vector store requires authentication, is network-isolated, and uses no default credentials | S | Critical | A05 | CWE-306 |
| RAG-INDEX-002 | Index writes are limited to the ingestion pipeline; inserts/updates/deletes are logged; snapshots exist; size anomalies alert | S | Medium | A08 | CWE-284 |
| RAG-QUERY-001 | Retrieval queries are rate-limited per user/agent and reconnaissance patterns are monitored | S | Medium | A04 | CWE-770 |
| RAG-QUERY-002 | Similarity scores and internal ranking data are not exposed to users or agents | S | Low | A01 | CWE-203 |

## Output, tools, caching (OUT / TOOL / CACHE)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| RAG-OUT-001 | Outputs are validated before returning or passing downstream: PII/secret redaction by requester access level, schema validation, never executed | S | High | A04 | CWE-200 |
| RAG-ATTR-001 | Responses carry document/chunk attribution that cannot be silently altered (hashes or signatures for regulated use) | S | Medium | A08 | CWE-345 |
| RAG-TOOL-001 | Tool calls influenced by retrieved content are authorized independently, allow-listed per context, and high-risk ones need user confirmation | S | High | A01 | CWE-862 |
| RAG-CACHE-001 | Response and retrieval caches are scoped by user, tenant and permission level, invalidated on document or permission change, and never hold highly sensitive data | S | High | A01 | CWE-524 |

## Operations (MON / SUPPLY / FAIL)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| RAG-MON-001 | Requests are traced (correlation IDs, document IDs, authorization decisions, model versions) without logging raw queries or content by default; anomalies alert | S | Medium | A09 | CWE-778 |
| RAG-SUPPLY-001 | Connectors are vetted and least-privilege (specific folders/spaces); sources are inventoried; external data is validated and staged before it is searchable | S | Medium | A08 | CWE-829 |
| RAG-FAIL-001 | The pipeline fails closed: retrieval, access-check or integrity failures deny the request instead of falling back to model memory, unfiltered results or stale cache | S | High | A04 | CWE-636 |

## Tests (TEST)

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| RAG-TEST-001 | Red-team tests cover poisoned documents, indirect injection, cross-tenant retrieval, stale permissions, cache leakage, unauthorized tool use and deletion propagation | S+D | Low | A04 | CWE-1125 |
