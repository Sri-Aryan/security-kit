# Denial-of-service guide

Sources: OWASP Denial of Service cheat sheet, OWASP API4:2023 Unrestricted Resource Consumption.

Application-level DoS rarely needs a botnet: one request with a 50 MB JSON body, `?limit=1000000`, a 10 KB string that
makes a regex backtrack for minutes, or a 40 KB zip that inflates to 10 GB is enough. The fix is a **limit at every
place work grows with input**, set at the edge (proxy) and again in the app.

## Starting limits

| Area | Check | Suggested default |
|---|---|---|
| JSON/form body | DOS-BODY-001 | 100 KB-1 MB (bigger only on specific upload routes); nginx `client_max_body_size`, Express `express.json({ limit })`, Django `DATA_UPLOAD_MAX_MEMORY_SIZE`, Spring `max-http-request-header-size`/multipart limits, ASP.NET `MaxRequestBodySize` |
| Fields / depth | DOS-BODY-001 | max form fields (Django `DATA_UPLOAD_MAX_NUMBER_FIELDS`), JSON nesting depth, array lengths in schemas |
| Page size | DOS-PAGE-001 | default 20-50, maximum 100-500, enforced with `min()`/schema `max` |
| Input-sized work | DOS-COMPLEX-001 | clamp every number that sizes a loop, allocation, `repeat`, export or batch; cap password length (128) before hashing |
| Regex | DOS-REGEX-001 | no nested quantifiers (`(a+)+`, `(\w+\s?)*`); cap input length; RE2/`re2`/Rust `regex`/Go `regexp` are linear-time |
| Decompression | DOS-DECOMPRESS-001 | `maxOutputLength` (Node zlib), `io.LimitReader` (Go), read in chunks with a running total; image pixel limits (Pillow `MAX_IMAGE_PIXELS`, sharp `limitInputPixels`); XML entity expansion off (`/sk-inject`) |
| Timeouts | DOS-TIMEOUT-001 | outbound HTTP 5-10 s (`requests(..., timeout=)`, `AbortSignal.timeout`, `http.Client{Timeout}`), DB `statement_timeout`, server read-header/idle timeouts (slowloris) |
| Memory | DOS-RESOURCE-001 | bounded LRU caches with TTL; no module-level maps keyed by request data; bounded queues |
| Expensive work | DOS-COST-001 | move PDF/report/media/AI/bulk-email work to a queue with per-user quotas and worker concurrency limits; return 202 |
| Retries | DOS-RETRY-001 | 3-5 attempts, exponential backoff with jitter, circuit breaker for failing dependencies |

## Verifying

Static hits are leads: check whether a framework default, proxy limit or validation schema already caps the value
before reporting. Dynamic testing for DoS is out of scope: never send heavy or high-volume requests, even to localhost,
unless the user explicitly asks and the environment is disposable.
