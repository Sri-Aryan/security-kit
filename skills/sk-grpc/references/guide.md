# gRPC guide

Sources: gRPC authentication and security docs, OWASP Microservices Security cheat sheet, OWASP API Security Top 10.

gRPC services are APIs: everything in `/sk-api` applies, but the mechanics differ. Auth lives in **interceptors**,
identity often comes from **mTLS**, schemas are **proto files** (where every field is optional), and the protocol
adds **reflection**, **message limits** and **deadlines**.

## Transport and identity (GRPC-TLS-001, GRPC-MTLS-001)

TLS on every channel (`credentials.NewTLS`, `grpc.ssl_channel_credentials`, `useTransportSecurity`) unless a service
mesh (Istio, Linkerd, Consul) enforces mTLS between pods, and then document that. For service-to-service calls use
workload identity (mTLS certificates, SPIFFE IDs, short-lived signed tokens) and check it, rather than trusting
"it came from inside the cluster".

## Auth and authorization (GRPC-AUTH-001, GRPC-AUTHZ-001)

One authentication interceptor (unary **and** stream) for all services: read the token from metadata
(`authorization`), verify it, attach the principal to the context; reject missing/invalid with `UNAUTHENTICATED`.
Authorization per method (a method → permission map checked in an interceptor, or checks in handlers) plus object
checks for IDs in requests (`PERMISSION_DENIED`/`NOT_FOUND`). Health and reflection services are the only exceptions.

## Inputs, limits, errors (GRPC-INPUT-001, GRPC-LIMIT-001, GRPC-ERROR-001)

- proto3 fields default to zero values: "not set" and "0" look the same. Validate with protovalidate (`buf.validate`),
  protoc-gen-validate, or explicit checks; use `optional`/wrapper types where presence matters.
- Default max receive size is 4 MB; keep it small and raise it per method only when needed. Set client deadlines on
  every call; servers cap `MaxConcurrentStreams` and enforce keepalive (`KeepaliveEnforcementPolicy`).
- Return generic status messages; log details server-side. Don't put stack traces in status details.

## Exposure (GRPC-REFLECT-001, GRPC-GATEWAY-001)

Reflection lets anyone list every method and message: enable it only in development or behind auth. grpc-web,
gRPC-Gateway and Connect turn gRPC into browser-callable HTTP: same interceptors, strict CORS origins, and remember
REST-side issues (CSRF if cookies are used, `/sk-csrf`).
