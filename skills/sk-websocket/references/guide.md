# WebSocket and real-time guide

Source: OWASP WebSocket Security cheat sheet. Library-neutral.

A WebSocket is one HTTP request (the upgrade) followed by a long-lived, bidirectional channel. Two consequences:
**authenticate and check Origin at the handshake**, because that is the only HTTP request you get; and **authorize
every message**, because one connection carries many actions over hours.

## Handshake (WS-AUTH-001, WS-ORIGIN-001)

- Authenticate before accepting: a session cookie (then Origin checks are mandatory), a short-lived single-use ticket
  obtained over normal HTTPS, or the first message / Socket.IO `auth` payload with a timeout to close silent sockets.
  Avoid long-lived tokens in the URL.
- Validate `Origin` against an exact allow-list: Node `ws` `verifyClient` or `handleUpgrade`, gorilla `CheckOrigin`,
  Socket.IO `cors.origin` list, Spring `setAllowedOrigins("https://app...")`, Django Channels `AllowedHostsOriginValidator`,
  SignalR CORS policy.

## Messages (WS-AUTHZ-001, WS-INPUT-001, WS-OUTPUT-001)

- Treat every message like an API request: parse inside `try`, validate with a schema, check the user may perform this
  action on this resource.
- Joining a room/channel is an authorization decision: check membership server-side; derive personal channel names
  from the authenticated user (`user:${socket.user.id}`), never from client input. Hosted services (Pusher, Ably)
  use private/presence channel auth endpoints: implement them with real checks.
- Send per-user data to that user's room only; review every broadcast-to-all. Clients render received content as text.

## Limits and lifetime (WS-LIMIT-001, WS-SESSION-001, WS-TLS-001)

- Max message size (`maxPayload`, `SetReadLimit`, `maxHttpBufferSize`, SignalR `MaximumReceiveMessageSize`), messages
  per second per connection, connections per user/IP, ping/pong heartbeats, idle timeouts.
- On logout, password change, role removal or token expiry, close the user's sockets or require re-auth (keep a
  user → connections map; check token `exp` periodically).
- `wss://` only outside local development; terminate TLS at a proxy that supports upgrades.
