# WebSocket and real-time checklist

Source of truth for `sk-websocket` check IDs. Covers real-time channels in any stack: WebSockets (ws, Socket.IO,
uWebSockets, gorilla/nhooyr, Django Channels, Flask-SocketIO, Spring WebSocket/STOMP, ASP.NET SignalR, Phoenix
Channels, Action Cable), Server-Sent Events and long polling, and hosted pub/sub (Pusher, Ably, Supabase Realtime,
Firebase). Handshake authentication and Origin checks, per-channel authorization, message validation and size,
TLS, connection and rate limits, session changes on long-lived connections, and broadcast leaks. Based on the OWASP
WebSocket Security cheat sheet. `references/guide.md` explains each check.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| WS-AUTH-001 | Connections are authenticated during the handshake (or before any data is sent) and unauthenticated sockets are closed | S+D | High | A07 | CWE-306 |
| WS-ORIGIN-001 | The handshake validates `Origin` against an allow-list when cookies authenticate (cross-site WebSocket hijacking) | S+D | High | A01 | CWE-1385 |
| WS-AUTHZ-001 | Joining rooms/channels/topics and every message action checks the user's permission for that resource; channel names from clients are not trusted | S+D | High | A01 | CWE-639 |
| WS-INPUT-001 | Every message is parsed safely and validated against a schema; malformed messages don't crash the server | S | Medium | A03 | CWE-20 |
| WS-TLS-001 | Only `wss://` (and HTTPS for SSE/polling) is used outside local development | S | Medium | A02 | CWE-319 |
| WS-LIMIT-001 | Message size limits, per-connection message rate limits, per-user/IP connection caps, heartbeats and idle timeouts are set | S | Medium | API4 | CWE-770 |
| WS-SESSION-001 | Long-lived connections follow session changes: expired tokens, logout, password change or permission removal close or re-authorize the socket | S | Medium | A07 | CWE-613 |
| WS-OUTPUT-001 | Broadcasts reach only intended recipients; payloads contain no other users' data; received content is rendered safely on clients | S | High | A01 | CWE-200 |
