# gRPC checklist

Source of truth for `sk-grpc` check IDs. Covers gRPC services and clients in any language (Go, Java/Kotlin, Python,
Node, C#, Rust/tonic, C++), plus grpc-web, gRPC-Gateway and Connect: transport security, authentication interceptors,
per-method and per-object authorization, server reflection, input validation of proto messages, message size limits
and deadlines, error detail leaks, gateway/grpc-web exposure, and service-to-service identity. Based on the OWASP
Microservices Security and REST/Web Service cheat sheets applied to RPC, and gRPC's own security guidance.
`references/guide.md` explains each check.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021 / API Top 10 2023.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| GRPC-TLS-001 | Channels and servers use TLS (or run inside a mesh that enforces mTLS); insecure credentials are limited to localhost/tests | S | High | A02 | CWE-319 |
| GRPC-AUTH-001 | Servers authenticate callers in an interceptor/middleware (tokens from metadata verified, or mTLS identity), applied to all services | S | High | A07 | CWE-306 |
| GRPC-AUTHZ-001 | Each method checks the caller's permission, and object-level access is checked for IDs in requests | S | High | API1 | CWE-863 |
| GRPC-REFLECT-001 | Server reflection (and other introspection/health detail) is disabled or protected in production | S | Low | A05 | CWE-200 |
| GRPC-INPUT-001 | Request messages are validated (protovalidate/buf.validate/protoc-gen-validate or explicit checks): proto3 fields are optional and default to zero values | S | Medium | A03 | CWE-20 |
| GRPC-LIMIT-001 | Message size limits stay small, client calls set deadlines, and servers cap concurrent streams and enforce keepalive policies | S | Medium | API4 | CWE-770 |
| GRPC-ERROR-001 | Error statuses carry generic messages; internal errors, stack traces and queries aren't returned in status messages or details | S | Low | A05 | CWE-209 |
| GRPC-GATEWAY-001 | grpc-web/gateway/Connect endpoints exposed to browsers have the same auth as the gRPC service and strict CORS | S | Medium | A05 | CWE-942 |
| GRPC-MTLS-001 | Internal service-to-service calls use workload identity (mTLS, SPIFFE, signed tokens) rather than network location alone | S | Medium | A07 | CWE-923 |
