# Game security checklist

Source of truth for `sk-game` check IDs. Covers the server/client trust boundary in games: Unity (Netcode for
GameObjects, Mirror, Photon, Unity Gaming Services, Unity IAP), Godot, Unreal, Roblox (Luau RemoteEvents), web games
(Phaser, three.js, Colyseus, Socket.IO) and game backends (PlayFab, Nakama, Firebase or Supabase used as a game
backend). The rule of thumb: **the client is in the cheater's hands**, so anything that matters (score, currency,
purchases, hits) is decided or verified by the server. Based on the OWASP Mobile Application Security Verification
Standard (resilience), store and ad-network server-side verification guidance, and the OWASP cheat sheets.
`references/guide.md` explains each check.

Columns: **Mode** S = static, D = dynamic. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| GAME-AUTH-001 | The server is authoritative for state that matters (position for hits, health, inventory, currency, score, cooldowns); clients send inputs, not outcomes | S | Critical | A04 | CWE-602 |
| GAME-SCORE-001 | Leaderboard scores are submitted to server code that validates (plausibility, server-measured time, replay/seed) rather than written directly by the client | S | High | A04 | CWE-602 |
| GAME-ECON-001 | Virtual-economy changes (rewards, shop prices, trades, crafting) are server-side, atomic and idempotent, with prices from server data | S | High | A04 | CWE-840 |
| GAME-IAP-001 | In-app purchases are verified server-side with the store (App Store Server API, Google Play Developer API, Steam), transaction IDs are recorded once, refunds revoke items | S | Critical | A08 | CWE-345 |
| GAME-ADS-001 | Rewarded-ad rewards are granted from the ad network's server-side verification callback, not the client callback | S | Medium | A08 | CWE-345 |
| GAME-NET-001 | Multiplayer messages and RPCs check the sender's authority (ownership, sender ID) and validate types and ranges | S | High | A04 | CWE-20 |
| GAME-RATE-001 | Per-connection message rates, sizes and lobby/matchmaking actions are limited | S | Medium | A04 | CWE-770 |
| GAME-SAVE-001 | Progress and currency that affect purchases, leaderboards or multiplayer are stored server-side (or signed), not in editable local storage or client-writable user data | S | Medium | A08 | CWE-345 |
| GAME-SECRET-001 | No server, admin or developer secret keys are compiled into the game client (PlayFab developer key, server API defines, service accounts) | S | Critical | A07 | CWE-798 |
| GAME-BACKEND-001 | The game backend's client APIs that write statistics, currency or data directly are disabled; writes go through server code (CloudScript, Cloud Code, RPCs) | S | High | A01 | CWE-284 |
| GAME-DEBUG-001 | Cheat/debug commands and dev consoles are stripped from release builds and refused by the server | S | Medium | A05 | CWE-489 |
| GAME-CHAT-001 | Chat, usernames and other player content are length-limited, filtered and reportable; content shown in web views is escaped | S | Low | A03 | CWE-20 |
| GAME-ANTICHEAT-001 | Client anti-cheat is treated as a deterrent only; the server keeps telemetry to detect impossible stats and supports bans | S | Low | A09 | CWE-778 |
